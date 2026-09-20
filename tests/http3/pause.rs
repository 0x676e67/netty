//! Pauses the first request after one byte, leaving control streams untouched.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use tokio::sync::Notify;
use wreq_proto::rt::quic::{self, BidiStream, Connection, OpenStreams, RecvStream, SendStream};

#[derive(Clone, Default)]
pub struct Pause(Arc<State>);

#[derive(Default)]
struct State {
    observers: AtomicUsize,
    written: AtomicBool,
    resumed: AtomicBool,
    blocked: Notify,
    credit: Notify,
    received_fin: Notify,
    writer: AtomicWaker,
}

#[derive(Clone)]
pub struct Transport<T> {
    inner: T,
    pause: Pause,
    credit_reported: bool,
}

struct Observer(Pause);

// ===== impl Observer =====

impl Drop for Observer {
    fn drop(&mut self) {
        self.0 .0.observers.fetch_sub(1, Ordering::AcqRel);
    }
}

// ===== impl Pause =====

impl Pause {
    pub fn wrap<T>(&self, inner: T) -> Transport<T> {
        Transport {
            inner,
            pause: self.clone(),
            credit_reported: false,
        }
    }

    pub async fn blocked(&self) {
        self.0.blocked.notified().await;
    }

    pub async fn waiting_for_credit(&self) {
        self.0.credit.notified().await;
    }

    pub async fn received_fin(&self) {
        self.0.received_fin.notified().await;
    }

    pub fn observers(&self) -> usize {
        self.0.observers.load(Ordering::Acquire)
    }

    pub fn resume(&self) {
        self.0.resumed.store(true, Ordering::Release);
        self.0.writer.wake();
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

    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<u64>, quic::StreamError>> + Send + 'static {
        let stopped = self.inner.stopped();
        self.pause.0.observers.fetch_add(1, Ordering::AcqRel);
        let observer = Observer(self.pause.clone());
        async move {
            let _observer = observer;
            stopped.await
        }
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
        let result = self.inner.poll_data(cx);
        if matches!(&result, Poll::Ready(Ok(None))) {
            self.pause.0.received_fin.notify_one();
        }
        result
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
