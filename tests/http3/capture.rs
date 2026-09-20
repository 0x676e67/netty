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

pub struct Connection {
    inner: h3_quinn::Connection,
    capture: Capture,
}

pub struct RecvStream {
    inner: h3_quinn::RecvStream,
    capture: Capture,
}

// ===== impl Capture =====

impl Capture {
    pub fn connection(&self, connection: quinn::Connection) -> Connection {
        Connection {
            inner: h3_quinn::Connection::new(connection),
            capture: self.clone(),
        }
    }

    pub async fn settings(&self) -> Vec<(u64, u64)> {
        std::future::poll_fn(|cx| {
            self.0.changed.register(cx.waker());
            for bytes in self.0.streams.lock().unwrap().values() {
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

impl quic::Connection<Bytes> for Connection {
    type RecvStream = RecvStream;

    type OpenStreams = h3_quinn::OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
            .map_ok(|inner| RecvStream {
                inner,
                capture: self.capture.clone(),
            })
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::ConnectionErrorIncoming>> {
        self.inner.poll_accept_bidi(cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&self.inner)
    }
}

impl quic::OpenStreams<Bytes> for Connection {
    type SendStream = h3_quinn::SendStream<Bytes>;

    type BidiStream = h3_quinn::BidiStream<Bytes>;

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
        self.inner.poll_open_bidi(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}

// ===== impl RecvStream =====

impl quic::RecvStream for RecvStream {
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
