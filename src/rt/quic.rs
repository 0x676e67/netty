//! QUIC transport contracts used by the HTTP/3 connection API.
//!
//! A connection provides independent stream openers and stream IDs, not a single
//! byte stream. The traits do not create UDP sockets, perform TLS, or choose a
//! runtime. Adapters provide unframed writes and an owned stop notification
//! so cancellation remains observable after HTTP/3 takes ownership of a stream.
//!
//! Every poll method returning `Pending` must arrange for the current task to
//! wake when progress or a terminal error becomes observable. Implementations
//! must retain any pending backend operation needed to preserve that wakeup.
use std::{
    future::Future,
    task::{Context, Poll},
};

use bytes::Buf;
pub use http3::quic::{
    ConnectionErrorIncoming as ConnectionError, StreamErrorIncoming as StreamError, StreamId,
};

#[cfg(feature = "http3-datagram")]
pub use self::datagram::{DatagramConnection, DatagramError, RecvDatagram, SendDatagram};
#[cfg(feature = "http3-datagram")]
mod datagram;

/// A multiplexed QUIC connection owned by one HTTP/3 driver.
pub trait Connection<B: Buf>: OpenStreams<B> {
    /// Incoming unidirectional streams, including control and QPACK streams.
    type RecvStream: RecvStream;

    /// Independent stream creation handle; cloning it must not close the driver.
    type OpenStreams: OpenStreams<B, SendStream = Self::SendStream, BidiStream = Self::BidiStream>;

    /// Polls an incoming unidirectional stream; `None` means normal shutdown.
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, ConnectionError>>;

    /// Polls an incoming bidirectional stream; `None` means normal shutdown.
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, ConnectionError>>;

    /// Obtains an opener without transferring the connection driver.
    fn opener(&self) -> Self::OpenStreams;
}

/// Creates outgoing QUIC streams, waiting for peer credit when necessary.
///
/// Each handle owns its pending opens. When a handle is cloned, the clone starts
/// with no pending operations and can wait independently of the original.
/// Dropping a handle cancels its pending opens without closing the connection,
/// consuming unused stream credit, or preventing other waiters from progressing.
pub trait OpenStreams<B: Buf> {
    /// Outgoing unidirectional stream.
    type SendStream: SendStream<B>;

    /// Outgoing bidirectional stream, with independently usable halves.
    type BidiStream: BidiStream<B>;

    /// Polls for one bidirectional stream without reserving additional streams.
    /// After `Pending`, the next call resumes the same open operation. A
    /// successful call transfers one stream; the next call starts another open.
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamError>>;

    /// Polls for one outgoing unidirectional stream.
    /// Pending operations and successful calls follow [`Self::poll_open_bidi`].
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamError>>;

    /// Closes the entire connection with a QUIC application error code.
    fn close(&mut self, code: u64, reason: &[u8]);
}

/// Writes unframed bytes to a QUIC send half with explicit FIN and reset.
/// `B` identifies the backend's application buffer type; writes may use any Buf.
pub trait SendStream<B: Buf> {
    /// Accepts bytes and advances `buf` by exactly the returned count.
    /// Pending must leave `buf` unchanged and arrange a wakeup. Nonempty writes
    /// must make progress or return an error; no borrowed bytes may be retained.
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamError>>;

    /// Observes peer STOP_SENDING independently of pending application writes.
    /// The owned future returns the stop code, or None after an acknowledged FIN.
    /// It must remain usable while the send half is owned by HTTP/3.
    fn stopped(&self) -> impl Future<Output = Result<Option<u64>, StreamError>> + Send + 'static;

    /// Submits FIN after previously accepted bytes; this does not await an ACK.
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>>;

    /// Aborts the send half with a QUIC application error code.
    fn reset(&mut self, code: u64);

    /// Returns the wire stream ID, stable for the lifetime of this half.
    fn send_id(&self) -> StreamId;
}

/// Reads a QUIC receive half without interpreting HTTP frames.
pub trait RecvStream {
    /// An owned receive buffer; implementations should avoid unnecessary copies.
    type Buf: Buf;

    /// Receives bytes, FIN (`None`), or a typed stream/connection error.
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamError>>;

    /// Requests the peer stop sending, without resetting the local send half.
    fn stop_sending(&mut self, code: u64);

    /// Returns the wire stream ID, stable for the lifetime of this half.
    fn recv_id(&self) -> StreamId;
}

/// Splits a bidirectional stream without changing either half's wire ID.
pub trait BidiStream<B: Buf>: SendStream<B> + RecvStream {
    /// Independently driven send half.
    type SendStream: SendStream<B>;

    /// Independently driven receive half.
    type RecvStream: RecvStream;

    /// Transfers ownership to two independently cancelable halves.
    fn split(self) -> (Self::SendStream, Self::RecvStream);
}
