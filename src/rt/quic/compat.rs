//! Adapts transports written against http3's own `quic` traits to the
//! [`rt::quic`](super) contract.

use std::task::{Context, Poll};

use bytes::Buf;

use super::{
    BidiStream, Connection, ConnectionError, OpenStreams, RecvStream, SendStream, StreamError,
    StreamId,
};

/// Adapts a transport implementing http3's own [`http3::quic`] traits, such as
/// `http3-quic`, to the [`rt::quic`](super) contract.
///
/// Send halves must implement [`http3::quic::SendStreamUnframed`].
/// Cloned openers must start without pending opens and cancel their own pending
/// opens on drop. Connection closure is reported as an error, never as `None`.
/// Datagrams are not adapted.
#[derive(Clone, Debug)]
pub struct Compat<T>(T);

// ===== impl Compat =====

impl<T> Compat<T> {
    /// Wraps a transport whose QUIC and TLS handshakes have completed.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Returns the wrapped transport.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<B, T> Connection<B> for Compat<T>
where
    B: Buf,
    T: http3::quic::Connection<B>,
    T::SendStream: http3::quic::SendStreamUnframed<B>,
    T::BidiStream: http3::quic::BidiStream<B> + http3::quic::SendStreamUnframed<B>,
    <T::BidiStream as http3::quic::BidiStream<B>>::SendStream: http3::quic::SendStreamUnframed<B>,
{
    type RecvStream = Compat<T::RecvStream>;
    type OpenStreams = Compat<T::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, ConnectionError>> {
        self.0
            .poll_accept_recv(cx)
            .map_ok(|stream| Some(Compat(stream)))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, ConnectionError>> {
        self.0
            .poll_accept_bidi(cx)
            .map_ok(|stream| Some(Compat(stream)))
    }

    fn opener(&self) -> Self::OpenStreams {
        Compat(self.0.opener())
    }
}

impl<B, T> OpenStreams<B> for Compat<T>
where
    B: Buf,
    T: http3::quic::OpenStreams<B>,
    T::SendStream: http3::quic::SendStreamUnframed<B>,
    T::BidiStream: http3::quic::BidiStream<B> + http3::quic::SendStreamUnframed<B>,
    <T::BidiStream as http3::quic::BidiStream<B>>::SendStream: http3::quic::SendStreamUnframed<B>,
{
    type SendStream = Compat<T::SendStream>;
    type BidiStream = Compat<T::BidiStream>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamError>> {
        self.0.poll_open_bidi(cx).map_ok(Compat)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamError>> {
        self.0.poll_open_send(cx).map_ok(Compat)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.0.close(http3::error::Code::from(code), reason);
    }
}

impl<B, T> SendStream<B> for Compat<T>
where
    B: Buf,
    T: http3::quic::SendStreamUnframed<B>,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamError>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<u64>, StreamError>> {
        self.0.poll_stopped(cx)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        self.0.poll_finish(cx)
    }

    fn reset(&mut self, code: u64) {
        self.0.reset(code);
    }

    fn send_id(&self) -> StreamId {
        self.0.send_id()
    }
}

impl<T: http3::quic::RecvStream> RecvStream for Compat<T> {
    type Buf = T::Buf;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, StreamError>> {
        self.0.poll_data(cx)
    }

    fn stop_sending(&mut self, code: u64) {
        self.0.stop_sending(code);
    }

    fn recv_id(&self) -> StreamId {
        self.0.recv_id()
    }
}

impl<B, T> BidiStream<B> for Compat<T>
where
    B: Buf,
    T: http3::quic::BidiStream<B> + http3::quic::SendStreamUnframed<B>,
    T::SendStream: http3::quic::SendStreamUnframed<B>,
{
    type SendStream = Compat<T::SendStream>;
    type RecvStream = Compat<T::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.0.split();
        (Compat(send), Compat(recv))
    }
}
