//! Observes bytes delivered to the upstream h3 server without changing them.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use h3::quic;

#[derive(Clone, Default)]
pub struct Capture(Arc<State>);

#[derive(Default)]
struct State {
    streams: Mutex<BTreeMap<u64, BytesMut>>,
    changed: AtomicWaker,
}

pub struct Connection<T> {
    inner: T,
    capture: Capture,
}

// ===== impl Capture =====

impl Capture {
    pub fn connection(&self, connection: quinn::Connection) -> Connection<h3_quinn::Connection> {
        self.wrap(h3_quinn::Connection::new(connection))
    }

    fn wrap<T>(&self, inner: T) -> Connection<T> {
        Connection {
            inner,
            capture: self.clone(),
        }
    }

    pub fn header_names(&self, stream_id: u64) -> Vec<String> {
        let streams = self.0.streams.lock().unwrap();
        let mut bytes = streams.get(&stream_id).expect("captured request").as_ref();
        assert_eq!(varint(&mut bytes), Some(1), "HEADERS must be first");
        let len = usize::try_from(varint(&mut bytes).expect("HEADERS length")).unwrap();
        let mut encoded = bytes.get(..len).expect("complete HEADERS payload");
        http3::qpack::decode_stateless(&mut encoded, u64::MAX)
            .unwrap()
            .fields
            .into_iter()
            .map(|field| String::from_utf8(field.name.into_owned()).unwrap())
            .collect()
    }

    pub async fn settings(&self) -> Vec<(u64, u64)> {
        std::future::poll_fn(|cx| {
            self.0.changed.register(cx.waker());
            for (&id, bytes) in self.0.streams.lock().unwrap().iter() {
                if id % 4 != 2 {
                    continue;
                }
                let mut bytes = bytes.as_ref();
                if varint(&mut bytes) != Some(0) {
                    continue;
                }
                let Some(kind) = varint(&mut bytes) else {
                    continue;
                };
                assert_eq!(kind, 4, "SETTINGS must be first");
                let Some(len) = varint(&mut bytes).and_then(|n| usize::try_from(n).ok()) else {
                    continue;
                };
                let Some(mut payload) = bytes.get(..len) else {
                    continue;
                };
                let mut settings = Vec::new();
                while !payload.is_empty() {
                    let id = varint(&mut payload).expect("setting id");
                    let value = varint(&mut payload).expect("setting value");
                    settings.push((id, value));
                }
                return Poll::Ready(settings);
            }
            Poll::Pending
        })
        .await
    }
}

fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let size = 1 << (*bytes.first()? >> 6);
    let encoded = bytes.get(..size)?;
    let mut value = u64::from(encoded[0] & 63);
    for &byte in &encoded[1..] {
        value = (value << 8) | u64::from(byte);
    }
    *bytes = &bytes[size..];
    Some(value)
}

// ===== impl Connection =====

impl<T> quic::Connection<Bytes> for Connection<T>
where
    T: quic::Connection<Bytes>,
    T::RecvStream: quic::RecvStream<Buf = Bytes>,
    T::BidiStream: quic::RecvStream<Buf = Bytes>,
{
    type RecvStream = Connection<T::RecvStream>;

    type OpenStreams = Connection<T::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        self.inner
            .poll_accept_recv(cx)
            .map_ok(|inner| self.capture.wrap(inner))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::ConnectionErrorIncoming>> {
        self.inner
            .poll_accept_bidi(cx)
            .map_ok(|inner| self.capture.wrap(inner))
    }

    fn opener(&self) -> Self::OpenStreams {
        self.capture.wrap(self.inner.opener())
    }
}

impl<T> quic::OpenStreams<Bytes> for Connection<T>
where
    T: quic::OpenStreams<Bytes>,
    T::BidiStream: quic::RecvStream<Buf = Bytes>,
{
    type SendStream = T::SendStream;

    type BidiStream = Connection<T::BidiStream>;

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamErrorIncoming>> {
        self.inner
            .poll_open_bidi(cx)
            .map_ok(|inner| self.capture.wrap(inner))
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

impl<T: quic::RecvStream<Buf = Bytes>> quic::RecvStream for Connection<T> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
        let result = self.inner.poll_data(cx);
        if let Poll::Ready(Ok(Some(data))) = &result {
            let mut streams = self.capture.0.streams.lock().unwrap();
            let prefix = streams
                .entry(self.inner.recv_id().into_inner())
                .or_default();
            let len = data.len().min(4096 - prefix.len());
            prefix.extend_from_slice(&data[..len]);
            drop(streams);
            self.capture.0.changed.wake();
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

impl<T: quic::SendStream<Bytes>> quic::SendStream<Bytes> for Connection<T> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }

    fn send_data<D: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: D,
    ) -> Result<(), quic::StreamErrorIncoming> {
        self.inner.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }

    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}

impl<T> quic::BidiStream<Bytes> for Connection<T>
where
    T: quic::BidiStream<Bytes> + quic::RecvStream<Buf = Bytes>,
    T::RecvStream: quic::RecvStream<Buf = Bytes>,
{
    type SendStream = T::SendStream;

    type RecvStream = Connection<T::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (send, self.capture.wrap(recv))
    }
}
