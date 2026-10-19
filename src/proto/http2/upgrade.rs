// Adapted from Hyper's HTTP/2 CONNECT upgrade implementation.
// Copyright (c) 2014-2026 Sean McArthur
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#[cfg(feature = "masque")]
use std::sync::{Arc, Mutex};
use std::{
    future::Future,
    io::{self, Cursor},
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures_channel::{mpsc, oneshot};
use futures_util::Stream;
use http2::{Reason, RecvStream, SendStream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{SendBuf, ping::Recorder};

/// Splits an upgraded CONNECT stream into its IO and send task. With MASQUE, `extensions`
/// receives a [`StreamReset`] for the stream.
pub(super) fn pair<B>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    ping: Recorder,
    #[cfg(feature = "masque")] extensions: Option<&mut http::Extensions>,
) -> (H2Upgraded, UpgradedSendStreamTask<B>) {
    let (tx, rx) = mpsc::channel(1);
    let (error_tx, error_rx) = oneshot::channel();
    #[cfg(feature = "masque")]
    let (reset, alive) = ResetRx::new(extensions);
    #[cfg(not(feature = "masque"))]
    let reset = ResetRx;

    (
        H2Upgraded {
            send_stream: UpgradedSendStreamBridge { tx, error_rx },
            recv_stream,
            ping,
            buf: Bytes::new(),
            #[cfg(feature = "masque")]
            _alive: alive,
        },
        UpgradedSendStreamTask {
            h2_tx: send_stream,
            rx,
            buffered: None,
            error_tx: Some(error_tx),
            reset,
        },
    )
}

/// The application-facing CONNECT stream; a separate task owns its HTTP/2 sender.
pub(super) struct H2Upgraded {
    ping: Recorder,
    send_stream: UpgradedSendStreamBridge,
    recv_stream: RecvStream,
    buf: Bytes,
    /// Dropped with the stream, which ends the send task's wait for a reset.
    #[cfg(feature = "masque")]
    _alive: Option<oneshot::Sender<()>>,
}

/// Relays accepted writes and terminal errors while the upgraded stream is alive.
struct UpgradedSendStreamBridge {
    tx: mpsc::Sender<Cursor<Box<[u8]>>>,
    error_rx: oneshot::Receiver<crate::Error>,
}

pin_project! {
    /// Drives CONNECT writes until the upgraded stream shuts down or fails.
    #[must_use = "futures do nothing unless polled"]
    pub struct UpgradedSendStreamTask<B> {
        #[pin]
        h2_tx: SendStream<SendBuf<B>>,
        #[pin]
        rx: mpsc::Receiver<Cursor<Box<[u8]>>>,
        buffered: Option<Cursor<Box<[u8]>>>,
        error_tx: Option<oneshot::Sender<crate::Error>>,
        reset: ResetRx,
    }
}

/// Resets an upgraded CONNECT stream with a chosen code, for a protocol on the stream that finds
/// the peer's data malformed. The send task outlives END_STREAM to apply it until the upgraded
/// IO or every clone drops.
#[cfg(feature = "masque")]
#[derive(Clone)]
pub(crate) struct StreamReset(Arc<Mutex<Option<oneshot::Sender<Reason>>>>);

/// The send task's end of a [`StreamReset`].
#[cfg(feature = "masque")]
#[derive(Default)]
struct ResetRx {
    /// The reset request, and a receiver whose sender lives in the upgraded IO; `None` once
    /// nothing can ask for a reset.
    rx: Option<(oneshot::Receiver<Reason>, oneshot::Receiver<()>)>,
    /// Whether END_STREAM went out.
    ended: bool,
}

/// Nothing resets the stream without MASQUE.
#[cfg(not(feature = "masque"))]
struct ResetRx;

// ===== impl UpgradedSendStreamTask =====

impl<B> UpgradedSendStreamTask<B>
where
    B: Buf,
{
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
        let mut me = self.project();

        // Once per tick: the registration stays, so a later request wakes the task.
        if let Poll::Ready(reason) = me.reset.poll(cx) {
            me.h2_tx.send_reset(reason);
            return Poll::Ready(Err(crate::Error::new_body_write(::http2::Error::from(
                reason,
            ))));
        }

        // this is a manual `select()` over 3 "futures", so we always need
        // to be sure they are ready and/or we are waiting notification of
        // one of the sides hanging up, so the task doesn't live around
        // longer than it's meant to.
        loop {
            match me.h2_tx.poll_reset(cx) {
                Poll::Ready(Ok(reason)) => {
                    trace!("stream received RST_STREAM: {:?}", reason);
                    return Poll::Ready(Err(crate::Error::new_body_write(::http2::Error::from(
                        reason,
                    ))));
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(crate::Error::new_body_write(err)));
                }
                Poll::Pending => (),
            }

            // After END_STREAM only a reset can follow.
            if me.reset.ended() {
                return if me.reset.waiting() {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                };
            }

            // A write taken from the mpsc receiver waits here for h2 capacity,
            // and the next one isn't pulled until it has been handed to h2, so
            // the writer still sees h2 backpressure.
            if me.buffered.is_some() {
                // poll_capacity oddly needs a loop
                while me.h2_tx.capacity() == 0 {
                    match ready!(me.h2_tx.poll_capacity(cx)) {
                        Some(Ok(0)) => {}
                        Some(Ok(_)) => break,
                        Some(Err(e)) => return Poll::Ready(Err(crate::Error::new_body_write(e))),
                        None => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                    }
                }

                let cursor = me.buffered.take().expect("checked is_some above");
                me.h2_tx
                    .send_data(SendBuf::Cursor(cursor), false)
                    .map_err(crate::Error::new_body_write)?;
                continue;
            }

            match me.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(cursor)) => {
                    // Only reserve capacity once there is something to send.
                    // Reserving while idle, even a single byte, pins that
                    // capacity on the connection-level window (#4003). As in
                    // `PipeToSendStream`, h2 raises the request to the
                    // buffered length inside `send_data`.
                    me.h2_tx.reserve_capacity(1);
                    *me.buffered = Some(cursor);
                }
                Poll::Ready(None) => {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    if me.reset.end() {
                        // Shutdown completes here; the task stays only to apply a reset.
                        me.error_tx.take();
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<B> Future for UpgradedSendStreamTask<B>
where
    B: Buf,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().tick(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(err)) => {
                if let Some(tx) = self.error_tx.take() {
                    let _oh_well = tx.send(err);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== impl StreamReset =====

#[cfg(feature = "masque")]
impl StreamReset {
    /// Resets the stream with `reason`; only the first call takes effect.
    pub(crate) fn reset(&self, reason: Reason) {
        let tx = self
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(tx) = tx {
            let _ = tx.send(reason);
        }
    }
}

// ===== impl ResetRx =====

#[cfg(feature = "masque")]
impl ResetRx {
    /// Puts a [`StreamReset`] in `extensions`, if given, and returns the sender the upgraded IO
    /// keeps alive.
    fn new(extensions: Option<&mut http::Extensions>) -> (Self, Option<oneshot::Sender<()>>) {
        let Some(extensions) = extensions else {
            return (Self::default(), None);
        };
        let (tx, rx) = oneshot::channel();
        let (alive_tx, alive_rx) = oneshot::channel();
        extensions.insert(StreamReset(Arc::new(Mutex::new(Some(tx)))));
        let reset = Self {
            rx: Some((rx, alive_rx)),
            ended: false,
        };
        (reset, Some(alive_tx))
    }

    /// Polls for a requested reset; none can come once every handle or the IO dropped.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Reason> {
        let Some((rx, alive)) = self.rx.as_mut() else {
            return Poll::Pending;
        };
        // Checked first: a reset requested before the IO dropped is then visible below, even
        // when another thread does both between the two polls.
        let gone = Pin::new(alive).poll(cx).is_ready();
        match Pin::new(rx).poll(cx) {
            Poll::Ready(Ok(reason)) => return Poll::Ready(reason),
            Poll::Ready(Err(_dropped)) => self.rx = None,
            Poll::Pending if gone => self.rx = None,
            Poll::Pending => {}
        }
        Poll::Pending
    }

    /// Records END_STREAM, returning whether the task waits for a reset.
    fn end(&mut self) -> bool {
        self.ended = true;
        self.waiting()
    }

    /// Whether END_STREAM went out.
    fn ended(&self) -> bool {
        self.ended
    }

    /// Whether a handle can still reset the stream.
    fn waiting(&self) -> bool {
        self.rx.is_some()
    }
}

#[cfg(not(feature = "masque"))]
impl ResetRx {
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<Reason> {
        Poll::Pending
    }

    fn end(&mut self) -> bool {
        false
    }

    fn ended(&self) -> bool {
        false
    }

    fn waiting(&self) -> bool {
        false
    }
}

// ===== impl H2Upgraded =====

impl AsyncRead for H2Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {
                        continue;
                    }
                    Some(Ok(buf)) => {
                        self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        });
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        let _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                return match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            Poll::Pending => return Poll::Pending,
        }

        let n = buf.len();
        match self.send_stream.tx.start_send(Cursor::new(buf.into())) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_task_dropped) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise it was a clean close
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send_stream.tx.close_channel();
        match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn io_error(e: crate::Error) -> std::io::Error {
    io::Error::other(e)
}

fn h2_to_io_error(e: http2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io()
            .expect("[BUG] http2::Error::is_io() is true, but into_io() failed")
    } else {
        io::Error::other(e)
    }
}
