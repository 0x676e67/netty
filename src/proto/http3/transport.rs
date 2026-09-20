use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};

use bytes::Buf;
use http3::quic::{self as h3, WriteBuf};

use crate::rt::quic;

#[derive(Clone)]
pub(crate) struct Transport<T>(pub(crate) T, pub(crate) Stops);

pub(super) type Stopped =
    Pin<Box<dyn Future<Output = Result<Option<u64>, quic::StreamError>> + Send>>;

#[derive(Clone, Default)]
pub(crate) struct Stops(Arc<Mutex<BTreeMap<u64, Stopped>>>);

struct Registration {
    stops: Stops,
    id: u64,
}

// ===== impl Stops =====

impl Stops {
    pub(super) fn take(&self, id: h3::StreamId) -> Option<Stopped> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id.into_inner())
    }
}

// ===== impl Registration =====

impl Drop for Registration {
    fn drop(&mut self) {
        self.stops
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

pub(crate) struct Stream<T, B> {
    inner: T,
    pending: Option<WriteBuf<B>>,
    registration: Option<Registration>,
}

fn closed() -> h3::ConnectionErrorIncoming {
    h3::ConnectionErrorIncoming::ApplicationClose {
        error_code: http3::error::Code::H3_NO_ERROR.value(),
    }
}

fn contract_error(reason: &str) -> h3::StreamErrorIncoming {
    h3::StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: h3::ConnectionErrorIncoming::InternalError(reason.into()),
    }
}

// ===== impl Transport =====

impl<B: Buf, Q: quic::Connection<B>> h3::Connection<B> for Transport<Q> {
    type RecvStream = Stream<Q::RecvStream, B>;

    type OpenStreams = Transport<Q::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, h3::ConnectionErrorIncoming>> {
        self.0
            .poll_accept_recv(cx)
            .map(|res| res.and_then(|stream| stream.map(Stream::new).ok_or_else(closed)))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::ConnectionErrorIncoming>> {
        self.0
            .poll_accept_bidi(cx)
            .map(|res| res.and_then(|stream| stream.map(Stream::new).ok_or_else(closed)))
    }

    fn opener(&self) -> Self::OpenStreams {
        Transport(self.0.opener(), self.1.clone())
    }
}

impl<B: Buf, Q: quic::OpenStreams<B>> h3::OpenStreams<B> for Transport<Q> {
    type SendStream = Stream<Q::SendStream, B>;

    type BidiStream = Stream<Q::BidiStream, B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::StreamErrorIncoming>> {
        self.0.poll_open_bidi(cx).map_ok(|inner| {
            use quic::SendStream;
            let id = inner.send_id().into_inner();
            // Capture cancellation before HEADERS consumes the stream. The guard
            // removes it if initialization is canceled; exchange takes it on success.
            self.1
                 .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id, Box::pin(inner.stopped()));
            let mut stream = Stream::new(inner);
            stream.registration = Some(Registration {
                stops: self.1.clone(),
                id,
            });
            stream
        })
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::StreamErrorIncoming>> {
        self.0.poll_open_send(cx).map_ok(Stream::new)
    }

    fn close(&mut self, code: http3::error::Code, reason: &[u8]) {
        self.0.close(code.value(), reason);
    }
}

// ===== impl Stream =====

impl<T, B> Stream<T, B> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            pending: None,
            registration: None,
        }
    }
}

impl<T: quic::SendStream<B>, B: Buf> h3::SendStream<B> for Stream<T, B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::StreamErrorIncoming>> {
        if let Some(buf) = self.pending.as_mut() {
            let mut budget = 0;
            while buf.has_remaining() {
                let before = buf.remaining();
                let written = ready!(self.inner.poll_send(cx, buf))?;
                if written == 0 || before.checked_sub(buf.remaining()) != Some(written) {
                    return Poll::Ready(Err(contract_error(
                        "QUIC send did not advance its buffer consistently",
                    )));
                }
                budget += 1;
                if budget == 32 && buf.has_remaining() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
        self.pending = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), h3::StreamErrorIncoming> {
        if self.pending.is_some() {
            return Err(contract_error("send_data called without QUIC readiness"));
        }
        self.pending = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::StreamErrorIncoming>> {
        ready!(h3::SendStream::poll_ready(self, cx))?;
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, code: u64) {
        self.pending = None;
        self.inner.reset(code);
    }

    fn send_id(&self) -> h3::StreamId {
        self.inner.send_id()
    }
}

impl<T: quic::SendStream<B>, B: Buf> h3::SendStreamUnframed<B> for Stream<T, B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, h3::StreamErrorIncoming>> {
        ready!(h3::SendStream::poll_ready(self, cx))?;
        self.inner.poll_send(cx, buf)
    }
}

impl<T: quic::RecvStream, B: Buf> h3::RecvStream for Stream<T, B> {
    type Buf = T::Buf;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, h3::StreamErrorIncoming>> {
        self.inner.poll_data(cx)
    }

    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }

    fn recv_id(&self) -> h3::StreamId {
        self.inner.recv_id()
    }
}

impl<T: quic::BidiStream<B>, B: Buf> h3::BidiStream<B> for Stream<T, B> {
    type SendStream = Stream<T::SendStream, B>;

    type RecvStream = Stream<T::RecvStream, B>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (
            Stream {
                inner: send,
                pending: self.pending,
                registration: self.registration,
            },
            Stream::new(recv),
        )
    }
}
