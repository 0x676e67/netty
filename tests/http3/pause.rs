//! Pauses the first request after one byte, leaving control streams untouched.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use netty::rt::quic::{self, BidiStream, Connection, OpenStreams, RecvStream, SendStream};
use tokio::sync::Notify;

#[derive(Clone, Default)]
pub struct Pause(Arc<State>);

#[derive(Default)]
struct State {
    written: AtomicBool,
    resumed: AtomicBool,
    blocked: Notify,
    credit: Notify,
    writer: AtomicWaker,
    hold_finish_ack: AtomicBool,
    fail_finish_ack: AtomicBool,
    waiting_for_ack: Notify,
    ack_released: AtomicBool,
    ack_waker: AtomicWaker,
}

#[derive(Clone)]
pub struct Transport<T> {
    inner: T,
    pause: Pause,
    credit_reported: bool,
    holding_ack: bool,
}

// ===== impl Pause =====

impl Pause {
    pub fn wrap<T>(&self, inner: T) -> Transport<T> {
        Transport {
            inner,
            pause: self.clone(),
            credit_reported: false,
            holding_ack: false,
        }
    }

    pub async fn blocked(&self) {
        self.0.blocked.notified().await;
    }

    pub async fn waiting_for_credit(&self) {
        self.0.credit.notified().await;
    }

    pub fn resume(&self) {
        self.0.resumed.store(true, Ordering::Release);
        self.0.writer.wake();
    }

    pub fn hold_finish_ack(&self) {
        self.resume();
        self.0.hold_finish_ack.store(true, Ordering::Release);
    }

    /// Reports a stream error instead of the FIN acknowledgment.
    pub fn fail_finish_ack(&self) {
        self.resume();
        self.0.fail_finish_ack.store(true, Ordering::Release);
    }

    pub async fn waiting_for_finish_ack(&self) {
        self.0.waiting_for_ack.notified().await;
    }

    pub fn release_finish_ack(&self) {
        self.0.ack_released.store(true, Ordering::Release);
        self.0.ack_waker.wake();
    }
}

// ===== impl Transport =====

impl<T: Connection<Bytes>> Connection<Bytes> for Transport<T> {
    type RecvStream = T::RecvStream;

    type OpenStreams = Transport<T::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, quic::ConnectionError>> {
        self.inner.poll_accept_recv(cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, quic::ConnectionError>> {
        self.inner
            .poll_accept_bidi(cx)
            .map_ok(|stream| stream.map(|stream| self.pause.wrap(stream)))
    }

    fn opener(&self) -> Self::OpenStreams {
        self.pause.wrap(self.inner.opener())
    }
}

impl<T: OpenStreams<Bytes>> OpenStreams<Bytes> for Transport<T> {
    type SendStream = T::SendStream;

    type BidiStream = Transport<T::BidiStream>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamError>> {
        let result = self.inner.poll_open_bidi(cx);
        if result.is_pending() && !self.credit_reported {
            self.credit_reported = true;
            self.pause.0.credit.notify_one();
        }
        result.map_ok(|stream| self.pause.wrap(stream))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamError>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

impl<T: SendStream<Bytes>> SendStream<Bytes> for Transport<T> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, quic::StreamError>> {
        if self.inner.send_id().into_inner() != 0 {
            return self.inner.poll_send(cx, buf);
        }
        self.pause.0.writer.register(cx.waker());
        if self.pause.0.resumed.load(Ordering::Acquire) {
            return self.inner.poll_send(cx, buf);
        }
        if self.pause.0.written.load(Ordering::Acquire) {
            self.pause.0.blocked.notify_one();
            return Poll::Pending;
        }
        let result = self.inner.poll_send(cx, &mut buf.take(1));
        if let Poll::Ready(Ok(written)) = result {
            assert_eq!(written, 1);
            self.pause.0.written.store(true, Ordering::Release);
        }
        result
    }

    fn poll_stopped(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<u64>, quic::StreamError>> {
        if self.pause.0.fail_finish_ack.load(Ordering::Acquire) {
            return Poll::Ready(Err(quic::StreamError::Unknown(Box::new(
                std::io::Error::other("FIN acknowledgment failed"),
            ))));
        }
        if !self.holding_ack {
            let result = ready!(self.inner.poll_stopped(cx));
            if !matches!(result, Ok(None)) || !self.pause.0.hold_finish_ack.load(Ordering::Acquire)
            {
                return Poll::Ready(result);
            }
            // Model an acknowledged FIN whose completion is not yet visible to
            // the client, without delaying peer stream reads.
            self.holding_ack = true;
            self.pause.0.waiting_for_ack.notify_one();
        }
        self.pause.0.ack_waker.register(cx.waker());
        if self.pause.0.ack_released.load(Ordering::Acquire) {
            return Poll::Ready(Ok(None));
        }
        Poll::Pending
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamError>> {
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }

    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}

impl<T: RecvStream> RecvStream for Transport<T> {
    type Buf = T::Buf;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, quic::StreamError>> {
        self.inner.poll_data(cx)
    }

    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }

    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}

impl<T: BidiStream<Bytes>> BidiStream<Bytes> for Transport<T> {
    type SendStream = Transport<T::SendStream>;

    type RecvStream = Transport<T::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (self.pause.wrap(send), self.pause.wrap(recv))
    }
}
