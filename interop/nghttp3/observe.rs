//! Local wire observation and independent QPACK encoder-stream backpressure.
use std::{
    collections::BTreeMap,
    future::{poll_fn, Future},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{ready, Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use wreq_proto::rt::quic::{self, BidiStream, Connection, OpenStreams, RecvStream, SendStream};

#[derive(Default)]
pub struct State {
    rx: Mutex<BTreeMap<u64, Vec<u8>>>,
    tx: Mutex<BTreeMap<u64, Vec<u8>>>,
    paused: AtomicBool,
    capturing: AtomicBool,
    pause_request: AtomicU64,
    encoder_held: AtomicBool,
    gate: AtomicWaker,
    changed: AtomicWaker,
}
#[derive(Clone)]
pub struct Observe<T> {
    inner: T,
    state: Arc<State>,
    prefix: Vec<u8>,
    held: Option<Bytes>,
}
// ===== impl State =====

impl State {
    pub fn new(paused: bool) -> Arc<Self> {
        Arc::new(Self {
            paused: AtomicBool::new(paused),
            capturing: AtomicBool::new(true),
            pause_request: AtomicU64::new(u64::MAX),
            ..Self::default()
        })
    }
    pub fn wrap<T>(self: &Arc<Self>, inner: T) -> Observe<T> {
        Observe {
            inner,
            state: self.clone(),
            prefix: Vec::new(),
            held: None,
        }
    }
    pub fn pause_request_headers(&self, id: u64) {
        self.pause_request.store(id, Ordering::Release);
    }
    pub fn pause_encoder(&self) {
        self.encoder_held.store(false, Ordering::Release);
        self.paused.store(true, Ordering::Release);
    }
    pub fn encoder_is_held(&self) -> bool {
        self.encoder_held.load(Ordering::Acquire)
    }
    pub async fn request_headers_partial(&self, id: u64) {
        poll_fn(|cx| {
            self.changed.register(cx.waker());
            if self
                .tx
                .lock()
                .unwrap()
                .get(&id)
                .is_some_and(|bytes| bytes.len() == 8)
            {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
    pub fn request_insert_counts(&self) -> Vec<(u64, u64)> {
        self.tx
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&id, bytes)| {
                if id % 4 != 0 {
                    return None;
                }
                let mut bytes = bytes.as_slice();
                if varint(&mut bytes)? != 1 {
                    return None;
                }
                let _length = varint(&mut bytes)?;
                Some((id, integer(&mut bytes, 8)?))
            })
            .collect()
    }
    pub fn stop_capture(&self) {
        assert!(!self.paused.load(Ordering::Acquire));
        self.capturing.store(false, Ordering::Release);
        self.rx.lock().unwrap().clear();
        self.tx.lock().unwrap().clear();
    }
    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        self.gate.wake();
    }
    pub fn dynamic(&self) -> Option<u64> {
        self.rx.lock().unwrap().iter().find_map(|(&id, data)| {
            if id % 4 != 0 {
                return None;
            }
            let mut data = data.as_slice();
            if varint(&mut data)? != 1 {
                return None;
            }
            let _length = varint(&mut data)?;
            (integer(&mut data, 8)? != 0).then_some(id)
        })
    }
    pub fn response_insert_counts(&self) -> Vec<(u64, u64)> {
        self.rx
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&id, bytes)| {
                if id % 4 != 0 {
                    return None;
                }
                let mut bytes = bytes.as_slice();
                if varint(&mut bytes)? != 1 {
                    return None;
                }
                let _length = varint(&mut bytes)?;
                Some((id, integer(&mut bytes, 8)?))
            })
            .collect()
    }
    pub fn request_dynamic(&self) -> bool {
        self.tx.lock().unwrap().iter().any(|(&id, data)| {
            if id % 4 != 0 {
                return false;
            }
            let mut data = data.as_slice();
            if varint(&mut data) != Some(1) || varint(&mut data).is_none() {
                return false;
            }
            integer(&mut data, 8).is_some_and(|count| count != 0)
        })
    }
    pub fn has_cancel(&self, id: u64) -> bool {
        self.tx.lock().unwrap().values().any(|data| {
            let mut data = data.as_slice();
            if varint(&mut data) != Some(3) {
                return false;
            }
            while let Some(&first) = data.first() {
                let Some(value) = integer(&mut data, if first & 0x80 != 0 { 7 } else { 6 }) else {
                    break;
                };
                if first & 0xc0 == 0x40 && value == id {
                    return true;
                }
            }
            false
        })
    }
    pub async fn canceled(&self, id: u64) {
        poll_fn(|cx| {
            self.changed.register(cx.waker());
            if self.has_cancel(id) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}
fn varint(data: &mut &[u8]) -> Option<u64> {
    let len = 1 << (*data.first()? >> 6);
    let bytes = data.get(..len)?;
    let mut value = u64::from(bytes[0] & 63);
    for &byte in &bytes[1..] {
        value = (value << 8) | u64::from(byte);
    }
    *data = &data[len..];
    Some(value)
}
fn integer(data: &mut &[u8], bits: u8) -> Option<u64> {
    let mask = (1_u64 << bits) - 1;
    let mut value = u64::from(*data.first()?) & mask;
    *data = &data[1..];
    if value < mask {
        return Some(value);
    }
    for shift in (0..63).step_by(7) {
        let byte = *data.first()?;
        *data = &data[1..];
        value = value.checked_add(u64::from(byte & 127).checked_shl(shift)?)?;
        if byte & 128 == 0 {
            return Some(value);
        }
    }
    None
}
// ===== impl Observe =====

impl<T> Connection<Bytes> for Observe<T>
where
    T: Connection<Bytes>,
    T::RecvStream: RecvStream<Buf = Bytes>,
    T::BidiStream: RecvStream<Buf = Bytes>,
    <T::BidiStream as BidiStream<Bytes>>::RecvStream: RecvStream<Buf = Bytes>,
{
    type RecvStream = Observe<T::RecvStream>;
    type OpenStreams = Observe<T::OpenStreams>;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, quic::ConnectionError>> {
        self.inner
            .poll_accept_recv(cx)
            .map_ok(|s| s.map(|s| self.state.wrap(s)))
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, quic::ConnectionError>> {
        self.inner
            .poll_accept_bidi(cx)
            .map_ok(|s| s.map(|s| self.state.wrap(s)))
    }
    fn opener(&self) -> Self::OpenStreams {
        self.state.wrap(self.inner.opener())
    }
}
impl<T> OpenStreams<Bytes> for Observe<T>
where
    T: OpenStreams<Bytes>,
    T::BidiStream: RecvStream<Buf = Bytes>,
    <T::BidiStream as BidiStream<Bytes>>::RecvStream: RecvStream<Buf = Bytes>,
{
    type SendStream = Observe<T::SendStream>;
    type BidiStream = Observe<T::BidiStream>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, quic::StreamError>> {
        self.inner.poll_open_bidi(cx).map_ok(|s| self.state.wrap(s))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamError>> {
        self.inner.poll_open_send(cx).map_ok(|s| self.state.wrap(s))
    }
    fn close(&mut self, code: u64, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}
impl<T: SendStream<Bytes>> SendStream<Bytes> for Observe<T> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, quic::StreamError>> {
        if !self.state.capturing.load(Ordering::Acquire) {
            return self.inner.poll_send(cx, buf);
        }
        let id = self.inner.send_id().into_inner();
        // Limit this diagnostic write to the observed chunk without modifying bytes.
        let bytes = buf.chunk().to_vec();
        let limit = if id == self.state.pause_request.load(Ordering::Acquire) {
            let sent = self.state.tx.lock().unwrap().get(&id).map_or(0, Vec::len);
            if sent == 8 {
                // This request stays blocked until its owner cancels it. No
                // gate-opening transition exists; cancellation wakes the task.
                return Poll::Pending;
            }
            bytes.len().min(8 - sent)
        } else {
            bytes.len()
        };
        let n = ready!(self.inner.poll_send(cx, &mut buf.take(limit)))?;
        let mut tx = self.state.tx.lock().unwrap();
        let entry = tx.entry(id).or_default();
        if id % 4 == 2 {
            assert!(entry.len() + n <= 65536, "diagnostic capture limit");
            entry.extend_from_slice(&bytes[..n]);
        } else if entry.len() < 32 {
            entry.extend_from_slice(&bytes[..n.min(32 - entry.len())]);
        }
        self.state.changed.wake();
        Poll::Ready(Ok(n))
    }
    fn stopped(
        &self,
    ) -> impl Future<Output = Result<Option<u64>, quic::StreamError>> + Send + 'static {
        self.inner.stopped()
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
impl<T: RecvStream<Buf = Bytes>> RecvStream for Observe<T> {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, quic::StreamError>> {
        if let Some(bytes) = self.held.take() {
            self.state.gate.register(cx.waker());
            if self.state.paused.load(Ordering::Acquire) {
                self.state.encoder_held.store(true, Ordering::Release);
                self.held = Some(bytes);
                return Poll::Pending;
            }
            return Poll::Ready(Ok(Some(bytes)));
        }
        if !self.state.capturing.load(Ordering::Acquire) {
            return self.inner.poll_data(cx);
        }
        let Some(bytes) = ready!(self.inner.poll_data(cx))? else {
            return Poll::Ready(Ok(None));
        };
        let id = self.inner.recv_id().into_inner();
        if self.prefix.len() < 32 {
            self.prefix
                .extend_from_slice(&bytes[..bytes.len().min(32 - self.prefix.len())]);
            self.state
                .rx
                .lock()
                .unwrap()
                .insert(id, self.prefix.clone());
            self.state.changed.wake();
        }
        let mut prefix = self.prefix.as_slice();
        if id % 4 == 3 && varint(&mut prefix) == Some(2) {
            self.state.gate.register(cx.waker());
            if self.state.paused.load(Ordering::Acquire) {
                self.state.encoder_held.store(true, Ordering::Release);
                self.held = Some(bytes);
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(Some(bytes)))
    }
    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }
    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}
impl<T> BidiStream<Bytes> for Observe<T>
where
    T: BidiStream<Bytes> + RecvStream<Buf = Bytes>,
    T::RecvStream: RecvStream<Buf = Bytes>,
{
    type SendStream = Observe<T::SendStream>;
    type RecvStream = Observe<T::RecvStream>;
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (self.state.wrap(send), self.state.wrap(recv))
    }
}
