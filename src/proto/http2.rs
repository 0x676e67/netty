//! HTTP/2 protocol implementation and utilities.

pub(crate) mod client;
pub(crate) mod ping;
pub(crate) mod upgrade;

use std::{
    future::Future,
    io::{Cursor, IoSlice},
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use bytes::Buf;
use http_body::Body;
use http2::SendStream;
pub use http2::{
    StreamId,
    ext::{HeadersDependency, HeadersPriority},
    frame::{
        Priorities, PrioritiesBuilder, Priority, PseudoId, PseudoOrder, Setting, SettingId,
        SettingsOrder, SettingsOrderBuilder, StreamDependency,
    },
};
use pin_project_lite::pin_project;

use crate::{Error, Result, error::BoxError};

/// Default initial stream window size defined in HTTP2 spec.
const SPEC_WINDOW_SIZE: u32 = 65_535;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024 * 5; // 5mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024 * 2; // 2mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 1024; // 1mb
const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb

// The maximum number of concurrent streams that the client is allowed to open
// before it receives the initial SETTINGS frame from the server.
// This default value is derived from what the HTTP/2 spec recommends as the
// minimum value that endpoints advertise to their peers. It means that using
// this value will minimize the chance of the failure where the local endpoint
// attempts to open too many streams and gets rejected by the remote peer with
// the `REFUSED_STREAM` error.
const DEFAULT_INITIAL_MAX_SEND_STREAMS: usize = 100;

struct Peeked<D> {
    data: D,
    is_eos: bool,
}

// body adapters used by both Client
pin_project! {
    pub(crate) struct PipeToSendStream<S>
    where
        S: Body,
    {
        #[pin]
        stream: S,
        body_tx: SendStream<SendBuf<S::Data>>,
        data_done: bool,
                // A data chunk that has been polled from the body but is still waiting
        // for stream-level capacity before it can be shipped. Stored here so
        // it survives across `Poll::Pending` returns from `poll_capacity`; if
        // we left the chunk in a local, it would be dropped on every repoll.
        buffered_data: Option<Peeked<S::Data>>,
    }
}

impl<S> PipeToSendStream<S>
where
    S: Body,
{
    #[inline]
    fn new(stream: S, body_tx: SendStream<SendBuf<S::Data>>) -> PipeToSendStream<S> {
        PipeToSendStream {
            stream,
            body_tx,
            data_done: false,
            buffered_data: None,
        }
    }

    #[inline]
    fn send_reset(self: Pin<&mut Self>, reason: http2::Reason) {
        self.project().body_tx.send_reset(reason);
    }
}

impl<S> Future for PipeToSendStream<S>
where
    S: Body,
    S::Error: Into<BoxError>,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut me = self.project();
        loop {
            // Register for RST_STREAM notification while we wait for the next
            // body chunk or for send capacity, so the task wakes up if the
            // peer resets the stream.
            if let Poll::Ready(reason) = me
                .body_tx
                .poll_reset(cx)
                .map_err(crate::Error::new_body_write)?
            {
                debug!("stream received RST_STREAM: {:?}", reason);
                return Poll::Ready(Err(Error::new_body_write(::http2::Error::from(reason))));
            }

            // If a previously-polled chunk is still waiting for stream-level
            // send capacity, drive that to completion before touching the
            // body again.
            if me.buffered_data.is_some() {
                while me.body_tx.capacity() == 0 {
                    match ready!(me.body_tx.poll_capacity(cx)) {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        Some(Err(e)) => {
                            return Poll::Ready(Err(Error::new_body_write(e)));
                        }
                        None => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                    }
                }

                let peeked = me.buffered_data.take().expect("checked is_some above");
                let buf = SendBuf::Buf(peeked.data);
                me.body_tx
                    .send_data(buf, peeked.is_eos)
                    .map_err(Error::new_body_write)?;

                if peeked.is_eos {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            // Poll for the next body frame *before* reserving any connection
            // flow-control capacity. Reserving capacity speculatively (even a
            // single byte) pins that capacity on the connection-level window,
            // which can deadlock a second stream when talking to peers that
            // only emit WINDOW_UPDATE once their receive window is fully
            // exhausted. See https://github.com/hyperium/hyper/issues/4003.
            match ready!(me.stream.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if frame.is_data() {
                        let chunk = frame.into_data().unwrap_or_else(|_| unreachable!());
                        let is_eos = me.stream.is_end_stream();
                        let len = chunk.remaining();
                        trace!("send body chunk: {} bytes, eos={}", len, is_eos);

                        if len == 0 {
                            // Zero-length data frames need no capacity; send
                            // them straight through so trailing empty frames
                            // (e.g. an explicit end-of-stream marker) are
                            // delivered.
                            let buf = SendBuf::Buf(chunk);
                            me.body_tx
                                .send_data(buf, is_eos)
                                .map_err(Error::new_body_write)?;

                            if is_eos {
                                return Poll::Ready(Ok(()));
                            }
                            continue;
                        }

                        // Reserve a minimal claim on the connection-level
                        // flow-control window rather than the whole chunk. The
                        // chunk is already in hand, so this still cannot pin
                        // capacity against a body that never produces data
                        // (#4003), and http2 raises the request to the buffered
                        // length inside `send_data`, so the demand eventually
                        // signalled to the peer is unchanged. Claiming the full
                        // length up front instead makes every in-flight stream a
                        // heavyweight claimant while it waits, which is costly
                        // once the streams on a connection collectively demand
                        // more than the window the peer advertises. Stash the
                        // chunk in `self` so it survives the upcoming
                        // `poll_capacity` wait even if it returns
                        // `Poll::Pending`.
                        me.body_tx.reserve_capacity(1);
                        *me.buffered_data = Some(Peeked {
                            data: chunk,
                            is_eos,
                        });
                    } else if frame.is_trailers() {
                        // no more DATA, so give any capacity back
                        me.body_tx.reserve_capacity(0);
                        me.body_tx
                            .send_trailers(frame.into_trailers().unwrap_or_else(|_| unreachable!()))
                            .map_err(Error::new_body_write)?;
                        return Poll::Ready(Ok(()));
                    } else {
                        trace!("discarding unknown frame");
                        // loop again
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(me.body_tx.on_user_err(e))),
                None => {
                    // no more frames means we're done here
                    // but at this point, we haven't sent an EOS DATA, or
                    // any trailers, so send an empty EOS DATA.
                    return Poll::Ready(me.body_tx.send_eos_frame());
                }
            }
        }
    }
}

trait SendStreamExt {
    fn on_user_err<E>(&mut self, err: E) -> Error
    where
        E: Into<BoxError>;

    fn send_eos_frame(&mut self) -> Result<()>;
}

impl<B: Buf> SendStreamExt for SendStream<SendBuf<B>> {
    fn on_user_err<E>(&mut self, err: E) -> Error
    where
        E: Into<BoxError>,
    {
        let err = Error::new_user_body(err);
        debug!("send body user stream error: {}", err);
        self.send_reset(err.h2_reason());
        err
    }

    fn send_eos_frame(&mut self) -> Result<()> {
        trace!("send body eos");
        self.send_data(SendBuf::None, true)
            .map_err(Error::new_body_write)
    }
}

#[repr(usize)]
enum SendBuf<B> {
    Buf(B),
    Cursor(Cursor<Box<[u8]>>),
    None,
}

impl<B: Buf> Buf for SendBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        match *self {
            Self::Buf(ref b) => b.remaining(),
            Self::Cursor(ref c) => Buf::remaining(c),
            Self::None => 0,
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match *self {
            Self::Buf(ref b) => b.chunk(),
            Self::Cursor(ref c) => c.chunk(),
            Self::None => &[],
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match *self {
            Self::Buf(ref mut b) => b.advance(cnt),
            Self::Cursor(ref mut c) => c.advance(cnt),
            Self::None => {}
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        match *self {
            Self::Buf(ref b) => b.chunks_vectored(dst),
            Self::Cursor(ref c) => c.chunks_vectored(dst),
            Self::None => 0,
        }
    }
}

/// Builder for `Http2Options`.
#[must_use]
#[derive(Debug)]
pub struct Http2OptionsBuilder {
    opts: Http2Options,
}

/// Options for tuning HTTP/2 connections.
///
/// `Http2Options` lets you adjust how HTTP/2 works—stream limits, window sizes, frame and header
/// settings, and more. Most fields are optional and have sensible defaults. See each field for
/// details.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Http2Options {
    /// Whether to use adaptive flow control.
    pub adaptive_window: bool,

    /// The initial stream ID for the connection.
    pub initial_stream_id: Option<u32>,

    /// The initial window size for HTTP/2 connection-level flow control.
    pub initial_conn_window_size: u32,

    /// The initial window size for HTTP/2 streams.
    pub initial_window_size: u32,

    /// The initial maximum number of locally initiated (send) streams.
    pub initial_max_send_streams: usize,

    /// The maximum frame size to use for HTTP/2.
    pub max_frame_size: Option<u32>,

    /// The read-idle time after which a keep-alive PING is sent; needs a timer.
    pub keep_alive_interval: Option<Duration>,

    /// How long an unanswered keep-alive PING may go without reads before the connection closes.
    pub keep_alive_timeout: Duration,

    /// Whether HTTP/2 keep-alive should apply while the connection is idle.
    pub keep_alive_while_idle: bool,

    /// The payload of PING frames sent for keep-alive and adaptive flow control.
    /// `None` uses the default from `http2`.
    pub ping_payload: Option<[u8; 8]>,

    /// The read-idle threshold after which a PING goes with the next HEADERS or DATA frame.
    pub preface_ping: Option<Duration>,

    /// How long an unanswered preface PING may go without reads before the connection closes.
    pub preface_ping_timeout: Option<Duration>,

    /// The maximum number of concurrent locally reset streams.
    pub max_concurrent_reset_streams: Option<usize>,

    /// How long locally reset stream state is retained.
    /// `None` uses the default from `http2`.
    pub reset_stream_duration: Option<Duration>,

    /// The maximum size of the send buffer for HTTP/2 streams.
    pub max_send_buffer_size: usize,

    /// The cap on sent DATA payloads, within the peer's max frame size.
    pub max_send_data_frame_size: Option<u32>,

    /// The cap on sent HEADERS and CONTINUATION payloads, within the peer's max frame size.
    pub max_send_header_frame_size: Option<u32>,

    /// Whether each frame after the initial write takes a write of its own.
    pub one_frame_per_write: bool,

    /// The maximum number of concurrent streams initiated by the remote peer.
    pub max_concurrent_streams: Option<u32>,

    /// The maximum size of the header list.
    pub max_header_list_size: Option<u32>,

    /// The maximum number of pending accept reset streams.
    pub max_pending_accept_reset_streams: Option<usize>,

    /// The maximum number of local stream resets generated by HTTP/2 error handling.
    /// Defaults to `Some(1024)`; `None` disables the limit.
    pub max_local_error_reset_streams: Option<usize>,

    /// Whether the server may push, sent as `SETTINGS_ENABLE_PUSH`. `None`
    /// sends nothing, which leaves push enabled.
    pub enable_push: Option<bool>,

    /// The header table size for HPACK compression.
    pub header_table_size: Option<u32>,

    /// Whether to enable the CONNECT protocol.
    pub enable_connect_protocol: Option<bool>,

    /// Whether to disable RFC 7540 Stream Priorities.
    pub no_rfc7540_priorities: Option<bool>,

    /// The HTTP/2 pseudo-header field order for outgoing HEADERS frames.
    pub headers_pseudo_order: Option<PseudoOrder>,

    /// The default priority fields of outgoing request HEADERS frames.
    pub headers_priority: Option<HeadersPriority>,

    /// The order of settings parameters in the initial SETTINGS frame.
    pub settings_order: Option<SettingsOrder>,

    /// The list of PRIORITY frames to be sent after connection establishment.
    pub priorities: Option<Priorities>,
}

impl Http2OptionsBuilder {
    /// Sets the [`SETTINGS_INITIAL_WINDOW_SIZE`][spec] option for HTTP2
    /// stream-level flow control.
    ///
    /// Passing `None` will do nothing.
    ///
    /// Default is 2 MiB.
    ///
    /// [spec]: https://httpwg.org/specs/rfc9113.html#SETTINGS_INITIAL_WINDOW_SIZE
    #[inline]
    pub fn initial_window_size(mut self, sz: impl Into<Option<u32>>) -> Self {
        if let Some(sz) = sz.into() {
            self.opts.adaptive_window = false;
            self.opts.initial_window_size = sz;
        }
        self
    }

    /// Sets the max connection-level flow control for HTTP2
    ///
    /// Passing `None` will do nothing.
    ///
    /// Default is 5 MiB.
    #[inline]
    pub fn initial_connection_window_size(mut self, sz: impl Into<Option<u32>>) -> Self {
        if let Some(sz) = sz.into() {
            self.opts.adaptive_window = false;
            self.opts.initial_conn_window_size = sz;
        }
        self
    }

    /// Sets the initial maximum of locally initiated (send) streams.
    ///
    /// This value will be overwritten by the value included in the initial
    /// SETTINGS frame received from the peer as part of a [connection preface].
    ///
    /// Passing `None` will do nothing.
    ///
    /// Default is 100.
    ///
    /// [connection preface]: https://httpwg.org/specs/rfc9113.html#preface
    #[inline]
    pub fn initial_max_send_streams(mut self, initial: impl Into<Option<usize>>) -> Self {
        if let Some(initial) = initial.into() {
            self.opts.initial_max_send_streams = initial;
        }
        self
    }

    /// Sets the initial stream id for the connection.
    #[inline]
    pub fn initial_stream_id(mut self, id: impl Into<Option<u32>>) -> Self {
        if let Some(id) = id.into() {
            self.opts.initial_stream_id = Some(id);
        }
        self
    }

    /// Sets whether to use adaptive flow control, which sizes the windows from
    /// BDP PING round trips.
    ///
    /// Enabling it resets [`initial_window_size`](Self::initial_window_size) and
    /// [`initial_connection_window_size`](Self::initial_connection_window_size)
    /// to 65,535, and a size passed to either later disables it.
    ///
    /// Default is `false`.
    #[inline]
    pub fn adaptive_window(mut self, enabled: bool) -> Self {
        self.opts.adaptive_window = enabled;
        if enabled {
            self.opts.initial_window_size = SPEC_WINDOW_SIZE;
            self.opts.initial_conn_window_size = SPEC_WINDOW_SIZE;
        }
        self
    }

    /// Sets the maximum frame size to use for HTTP2.
    ///
    /// Default is currently 16KB, but can change.
    #[inline]
    pub fn max_frame_size(mut self, sz: impl Into<Option<u32>>) -> Self {
        if let Some(sz) = sz.into() {
            self.opts.max_frame_size = Some(sz);
        }
        self
    }

    /// Sets `SETTINGS_MAX_HEADER_LIST_SIZE`, the limit on received header lists.
    ///
    /// Default is unset: nothing is sent and `http2` accepts header lists up to
    /// 16 MiB. `Http2Options::default()` uses 16 KiB.
    #[inline]
    pub fn max_header_list_size(mut self, max: u32) -> Self {
        self.opts.max_header_list_size = Some(max);
        self
    }

    /// Sets the header table size.
    ///
    /// This setting informs the peer of the maximum size of the header compression
    /// table used to encode header blocks, in octets. The encoder may select any value
    /// equal to or less than the header table size specified by the sender.
    ///
    /// Default is unset, which leaves the protocol default of 4,096.
    #[inline]
    pub fn header_table_size(mut self, size: impl Into<Option<u32>>) -> Self {
        if let Some(size) = size.into() {
            self.opts.header_table_size = Some(size);
        }
        self
    }

    /// Sets the maximum number of concurrent streams.
    ///
    /// The maximum concurrent streams setting only controls the maximum number
    /// of streams that can be initiated by the remote peer. In other words,
    /// when this setting is set to 100, this does not limit the number of
    /// concurrent streams that can be created by the caller.
    ///
    /// It is recommended that this value be no smaller than 100, so as to not
    /// unnecessarily limit parallelism. However, any value is legal, including
    /// 0. If `max` is set to 0, then the remote will not be permitted to
    /// initiate streams.
    ///
    /// Although the HTTP/2 specification excludes streams in the reserved state
    /// from this limit, `http2` counts reserved push streams against it, so on a
    /// client this limits pushes.
    ///
    /// Also note that if the remote *does* exceed the value set here, it is not
    /// a protocol level error. Instead, `http2` will immediately reset the
    /// stream.
    ///
    /// See [Section 5.1.2] in the HTTP/2 spec for more details.
    ///
    /// [Section 5.1.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1.2
    #[inline]
    pub fn max_concurrent_streams(mut self, max: impl Into<Option<u32>>) -> Self {
        if let Some(max) = max.into() {
            self.opts.max_concurrent_streams = Some(max);
        }
        self
    }

    /// Sets how long the connection may go without reads before a keep-alive
    /// PING is sent.
    ///
    /// It needs a [`timer`](crate::conn::http2::Builder::timer): the handshake
    /// fails without one. Pass `None` to disable HTTP2 keep-alive.
    ///
    /// Default is currently disabled.
    #[inline]
    pub fn keep_alive_interval(mut self, interval: impl Into<Option<Duration>>) -> Self {
        self.opts.keep_alive_interval = interval.into();
        self
    }

    /// Closes the connection once a keep-alive PING is unanswered and nothing
    /// has been read for `timeout`, counted from when the PING is queued or the
    /// last read, whichever is later.
    ///
    /// The connection then closes with a GOAWAY of `INTERNAL_ERROR` if it can
    /// be written right away. Does nothing if `keep_alive_interval` is
    /// disabled.
    ///
    /// Default is 20 seconds.
    #[inline]
    pub fn keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.opts.keep_alive_timeout = timeout;
        self
    }

    /// Sets whether HTTP2 keep-alive should apply while the connection is idle.
    ///
    /// If disabled, keep-alive pings are only sent while a stream is open or a
    /// request waits to open, even after every handle but a body or upgraded
    /// connection is dropped. If enabled, pings are also sent when nothing is
    /// in progress. Does nothing if `keep_alive_interval` is disabled.
    ///
    /// Default is `false`.
    #[inline]
    pub fn keep_alive_while_idle(mut self, enabled: bool) -> Self {
        self.opts.keep_alive_while_idle = enabled;
        self
    }

    /// Sets the payload of PING frames sent for keep-alive and adaptive flow
    /// control.
    ///
    /// Pass `None` to use the default from `http2`.
    #[inline]
    pub fn ping_payload(mut self, payload: impl Into<Option<[u8; 8]>>) -> Self {
        self.opts.ping_payload = payload.into();
        self
    }

    /// Sends a PING with the next HEADERS or non-empty DATA frame once nothing
    /// has been read from the connection for longer than `threshold`.
    ///
    /// The PING follows HEADERS but precedes DATA, and its payload is a
    /// big-endian counter starting at 1. It is skipped while the previous one
    /// or a keep-alive or adaptive window PING awaits an ACK, and those PINGs
    /// are held back until it is acknowledged. An ACK with any payload
    /// acknowledges it, and a missing ACK closes the connection only with
    /// [`preface_ping_timeout`](Self::preface_ping_timeout). Pass `None` to
    /// disable it.
    ///
    /// Default is disabled.
    #[inline]
    pub fn preface_ping(mut self, threshold: impl Into<Option<Duration>>) -> Self {
        self.opts.preface_ping = threshold.into();
        self
    }

    /// Closes the connection once a preface PING is unanswered and nothing has
    /// been read for `timeout`, counted from when the PING is queued or the
    /// last read, whichever is later.
    ///
    /// The connection then closes with a GOAWAY of `PROTOCOL_ERROR` and the
    /// debug data `Failed ping.` if it can be written right away, failing its
    /// streams with that error, which [`Error::is_timeout`](crate::Error::is_timeout)
    /// does not report. Without a [`timer`](crate::conn::http2::Builder::timer),
    /// the timeout is only checked when the connection is polled for other
    /// reasons, and a paused runtime clock never fires it. Does nothing if
    /// `preface_ping` is disabled. Pass `None` to disable it.
    ///
    /// Default is disabled.
    #[inline]
    pub fn preface_ping_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.opts.preface_ping_timeout = timeout.into();
        self
    }

    /// Sets whether the server may push responses, sent as `SETTINGS_ENABLE_PUSH`.
    ///
    /// Default is unset: no setting is sent, which leaves push enabled
    /// ([RFC 9113 §6.5.2]). Pushed responses are not exposed, so they are
    /// discarded with their request's stream.
    ///
    /// [RFC 9113 §6.5.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.2
    #[inline]
    pub fn enable_push(mut self, opt: bool) -> Self {
        self.opts.enable_push = Some(opt);
        self
    }

    /// Sets the enable connect protocol.
    #[inline]
    pub fn enable_connect_protocol(mut self, opt: bool) -> Self {
        self.opts.enable_connect_protocol = Some(opt);
        self
    }

    /// Disable RFC 7540 Stream Priorities (set to `true` to disable).
    /// [RFC 9218]: <https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1>
    #[inline]
    pub fn no_rfc7540_priorities(mut self, opt: bool) -> Self {
        self.opts.no_rfc7540_priorities = Some(opt);
        self
    }

    /// Sets the maximum number of HTTP2 concurrent locally reset streams.
    ///
    /// See the documentation of [`http2::client::Builder::max_concurrent_reset_streams`] for more
    /// details.
    ///
    /// Default is 50.
    #[inline]
    pub fn max_concurrent_reset_streams(mut self, max: usize) -> Self {
        self.opts.max_concurrent_reset_streams = Some(max);
        self
    }

    /// Sets how long locally reset stream state is retained to handle late frames
    /// as described in [RFC 9113 §5.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1).
    /// The default comes from [`http2::client::Builder::reset_stream_duration`],
    /// currently 1 second.
    #[inline]
    pub fn reset_stream_duration(mut self, dur: Duration) -> Self {
        self.opts.reset_stream_duration = Some(dur);
        self
    }

    /// Set the maximum write buffer size for each HTTP/2 stream.
    ///
    /// Default is currently 1MB, but may change. A `max` above `u32::MAX` is
    /// treated as `u32::MAX`.
    #[inline]
    pub fn max_send_buf_size(mut self, max: usize) -> Self {
        self.opts.max_send_buffer_size = max;
        self
    }

    /// Caps the payload of sent DATA frames, within the peer's max frame size.
    ///
    /// Each capped frame starts a write and shares none. DATA queued on a
    /// stream is coalesced into frames of up to `max` bytes, but without
    /// vectored writes only while capped frames are at most 16,384 bytes. A
    /// `max` of 0 is treated as 1. With 16,375 bytes, a full frame and its
    /// 9-byte header fit one TLS record of 2^14 bytes ([RFC 8446 §5.1]). Very
    /// small values send many small frames, which peers may treat as abuse. See
    /// [`http2::client::Builder::max_send_data_frame_size`]. Pass `None` to
    /// disable it.
    ///
    /// Default is disabled.
    ///
    /// [RFC 8446 §5.1]: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1
    #[inline]
    pub fn max_send_data_frame_size(mut self, max: impl Into<Option<u32>>) -> Self {
        self.opts.max_send_data_frame_size = max.into();
        self
    }

    /// Caps the payload of sent HEADERS and CONTINUATION frames, within the
    /// peer's max frame size.
    ///
    /// A header block is split into frames of at most `max` bytes, and a `max`
    /// under 5 is treated as 5. Small values split a block into many
    /// CONTINUATION frames, which peers may limit or treat as abuse. See
    /// [`http2::client::Builder::max_send_header_frame_size`]. Pass `None` to
    /// disable it.
    ///
    /// Default is disabled.
    #[inline]
    pub fn max_send_header_frame_size(mut self, max: impl Into<Option<u32>>) -> Self {
        self.opts.max_send_header_frame_size = max.into();
        self
    }

    /// Sets whether each frame takes a write of its own.
    ///
    /// The preface, SETTINGS and the initial WINDOW_UPDATE and PRIORITY frames
    /// still share the first write. After it, each frame is written alone,
    /// except that a header block goes out in one write with its CONTINUATION
    /// frames and the stream WINDOW_UPDATE after it. TLS stacks commonly seal
    /// each write into its own records, though [RFC 8446 §5.1] lets them split
    /// or coalesce application data. Each frame costs a write, so this lowers
    /// throughput when many small frames are queued at once. See
    /// [`http2::client::Builder::one_frame_per_write`].
    ///
    /// Default is `false`.
    ///
    /// [RFC 8446 §5.1]: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1
    #[inline]
    pub fn one_frame_per_write(mut self, enabled: bool) -> Self {
        self.opts.one_frame_per_write = enabled;
        self
    }

    /// Configures the maximum number of pending reset streams allowed before a GOAWAY will be sent.
    ///
    /// See <https://github.com/hyperium/hyper/issues/2877> for more information.
    #[inline]
    pub fn max_pending_accept_reset_streams(mut self, max: impl Into<Option<usize>>) -> Self {
        if let Some(max) = max.into() {
            self.opts.max_pending_accept_reset_streams = Some(max);
        }
        self
    }

    /// Sets the limit on local stream resets generated by HTTP/2 error handling.
    ///
    /// Defaults to `Some(1024)`; `None` disables the limit.
    /// See [`http2::client::Builder::max_local_error_reset_streams`] for details.
    #[inline]
    pub fn max_local_error_reset_streams(mut self, max: impl Into<Option<usize>>) -> Self {
        self.opts.max_local_error_reset_streams = max.into();
        self
    }

    /// Sets the default priority fields of outgoing request HEADERS frames.
    ///
    /// A request carrying its own [`HeadersPriority`] extension replaces this default. The
    /// handshake fails if a [`HeadersDependency::Declared`] parent is missing from
    /// [`priorities`](Self::priorities) or could be a later request's own stream.
    ///
    /// These priority fields are deprecated by [RFC 9113 §5.3.2].
    ///
    /// [RFC 9113 §5.3.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.3.2
    #[inline]
    pub fn headers_priority<T>(mut self, priority: T) -> Self
    where
        T: Into<Option<HeadersPriority>>,
    {
        if let Some(priority) = priority.into() {
            self.opts.headers_priority = Some(priority);
        }
        self
    }

    /// Sets the HTTP/2 pseudo-header field order for outgoing HEADERS frames.
    ///
    /// This determines the order in which pseudo-header fields (such as `:method`, `:scheme`, etc.)
    /// are encoded in the HEADERS frame. Customizing the order may be useful for interoperability
    /// or testing purposes.
    #[inline]
    pub fn headers_pseudo_order<T>(mut self, headers_pseudo_order: T) -> Self
    where
        T: Into<Option<PseudoOrder>>,
    {
        if let Some(headers_pseudo_order) = headers_pseudo_order.into() {
            self.opts.headers_pseudo_order = Some(headers_pseudo_order);
        }
        self
    }

    /// Sets the order of settings parameters in the initial SETTINGS frame.
    ///
    /// This determines the order in which settings are sent during the HTTP/2 handshake.
    /// Customizing the order may be useful for testing or protocol compliance.
    #[inline]
    pub fn settings_order<T>(mut self, settings_order: T) -> Self
    where
        T: Into<Option<SettingsOrder>>,
    {
        if let Some(settings_order) = settings_order.into() {
            self.opts.settings_order = Some(settings_order);
        }
        self
    }

    /// Sets the list of PRIORITY frames to be sent immediately after the connection is established,
    /// but before the first request is sent.
    ///
    /// This allows you to pre-configure the HTTP/2 stream dependency tree by specifying a set of
    /// PRIORITY frames that will be sent as part of the connection preface. This can be useful for
    /// optimizing resource allocation or testing custom stream prioritization strategies.
    ///
    /// Each `Priority` in the list must have a valid (non-zero) stream ID. Any priority with a
    /// stream ID of zero will be ignored.
    #[inline]
    pub fn priorities<T>(mut self, priorities: T) -> Self
    where
        T: Into<Option<Priorities>>,
    {
        if let Some(priorities) = priorities.into() {
            self.opts.priorities = Some(priorities);
        }
        self
    }

    /// Builds the `Http2Options` instance.
    #[inline]
    pub fn build(self) -> Http2Options {
        self.opts
    }
}

impl Http2Options {
    /// Creates a new `Http2OptionsBuilder` instance.
    pub fn builder() -> Http2OptionsBuilder {
        // Reset optional frame size and header size settings to None to allow explicit
        // customization This ensures users can configure these via builder methods without
        // being constrained by defaults
        Http2OptionsBuilder {
            opts: Http2Options {
                max_frame_size: None,
                max_header_list_size: None,
                ..Default::default()
            },
        }
    }
}

impl Default for Http2Options {
    #[inline]
    fn default() -> Self {
        Http2Options {
            adaptive_window: false,
            initial_stream_id: None,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_window_size: DEFAULT_STREAM_WINDOW,
            initial_max_send_streams: DEFAULT_INITIAL_MAX_SEND_STREAMS,
            max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
            max_header_list_size: Some(DEFAULT_MAX_HEADER_LIST_SIZE),
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            keep_alive_while_idle: false,
            ping_payload: None,
            preface_ping: None,
            preface_ping_timeout: None,
            max_concurrent_reset_streams: None,
            reset_stream_duration: None,
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_send_data_frame_size: None,
            max_send_header_frame_size: None,
            one_frame_per_write: false,
            max_pending_accept_reset_streams: None,
            max_local_error_reset_streams: Some(1024),
            header_table_size: None,
            max_concurrent_streams: None,
            enable_push: None,
            enable_connect_protocol: None,
            no_rfc7540_priorities: None,
            settings_order: None,
            headers_pseudo_order: None,
            headers_priority: None,
            priorities: None,
        }
    }
}
