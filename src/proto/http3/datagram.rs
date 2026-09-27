//! Routes HTTP Datagrams between one QUIC connection and its request streams.
//!
//! The [`Registry`] keys every registered request by its Quarter Stream ID and
//! keeps bounded send and receive queues per session and per connection; the
//! newest packet is dropped when a queue is full, since Datagrams are
//! unreliable. A Datagram for a registered request without Datagram semantics
//! is a stream error, one for an unknown or closed stream is ignored.
//! <https://www.rfc-editor.org/rfc/rfc9297.html>

use std::{
    any::Any,
    collections::{BTreeMap, VecDeque},
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, OnceLock, Weak},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{future::BoxFuture, task::AtomicWaker};
use http3::{
    error::{Code, ConnectionError},
    quic::StreamId,
};
use http3_datagram::datagram::Datagram;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{rt::quic, Error, Result};

/// Packets queued per session and direction. The limits are also stated on
/// `conn::http3::datagram::Sender::try_send`.
const PACKETS: usize = 64;

/// Bytes queued per session and direction.
const SESSION_BYTES: usize = 128 * 1024;

/// Bytes queued per connection and direction.
const CONNECTION_BYTES: usize = 1024 * 1024;

/// Per-connection Datagram state shared by the driver, the request handles and
/// the response bodies.
pub(crate) struct Registry {
    state: Mutex<State>,
    waker: AtomicWaker,
    capacity_notify: Arc<Notify>,
}

/// Registry state under its lock: sessions by Quarter Stream ID, the send
/// round robin and the byte budgets.
#[derive(Default)]
struct State {
    streams: BTreeMap<u64, Entry>,
    ready: VecDeque<u64>,
    incoming: usize,
    outgoing: usize,
    max_size: Option<usize>,
    negotiated: bool,
    closed: bool,
}

/// One registered request stream: whether it has Datagram semantics, which
/// directions are open and both queues.
struct Entry {
    request: Weak<RequestState>,
    semantics: bool,
    send_open: bool,
    recv_open: bool,
    incoming: VecDeque<Bytes>,
    outgoing: VecDeque<Bytes>,
    incoming_bytes: usize,
    outgoing_bytes: usize,
}

/// Datagram state of one request, shared by its send and receive handles, its
/// stream guards and the response body hook.
pub(crate) struct RequestState {
    id: StreamId,
    registry: Arc<Registry>,
    received: AtomicWaker,
    /// Response body to stop when a Datagram invalidates the request, erased
    /// together with the function that knows its concrete type.
    stop_state: OnceLock<Weak<dyn Any + Send + Sync>>,
    stop: OnceLock<fn(&(dyn Any + Send + Sync))>,
    pub(super) invalid: CancellationToken,
}

/// Keeps a request registered; dropping it removes the session.
pub(crate) struct Registration(pub(super) Arc<RequestState>);

/// Moves packets between the QUIC Datagram transport and the registry; the
/// connection task polls it.
pub(crate) type Drive = BoxFuture<'static, Result<(), (Code, Error)>>;

/// Drives a backend sender and receiver with bounded work per poll.
struct Driver<S, R> {
    sender: S,
    receiver: R,
    registry: Arc<Registry>,
    pending: Option<(u64, Bytes)>,
}

/// Why an HTTP Datagram was not admitted to the local send queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendErrorKind {
    /// HTTP Datagrams or the QUIC Datagram transport are unavailable.
    Unavailable,
    /// The payload exceeds the current transport or local buffer limit.
    TooLarge,
    /// The bounded session or connection queue has no capacity.
    Full,
    /// The request send half or its connection has closed.
    Closed,
}

// ===== impl Registry =====

impl Registry {
    /// Creates the registry and the driver for the transport's Datagram halves.
    pub(crate) fn new<S, R>(sender: S, receiver: R) -> (Arc<Self>, Drive)
    where
        S: quic::SendDatagram + Send + 'static,
        R: quic::RecvDatagram + Send + 'static,
    {
        let registry = Arc::new(Self {
            state: Mutex::new(State {
                max_size: sender.max_datagram_size(),
                ..State::default()
            }),
            waker: AtomicWaker::new(),
            capacity_notify: Arc::new(Notify::new()),
        });
        let driver = Driver {
            sender,
            receiver,
            registry: registry.clone(),
            pending: None,
        };
        (registry, Box::pin(driver))
    }

    /// Locks the state, recovering a poisoned lock.
    fn lock(&self) -> MutexGuard<'_, State> {
        // No user code runs under this lock. Preserve cleanup if another thread
        // unwinds while manipulating an internal queue.
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Registers a request stream; `semantics` marks a Datagram request, any other
    /// fails on its first Datagram.
    pub(crate) fn register(
        self: &Arc<Self>,
        id: StreamId,
        semantics: bool,
        invalid: CancellationToken,
    ) -> Registration {
        let request = Arc::new(RequestState {
            id,
            registry: self.clone(),
            invalid,
            received: AtomicWaker::new(),
            stop_state: OnceLock::new(),
            stop: OnceLock::new(),
        });
        let mut state = self.lock();
        if !state.closed {
            state.streams.insert(
                id.into_inner(),
                Entry {
                    request: Arc::downgrade(&request),
                    semantics,
                    send_open: true,
                    recv_open: true,
                    incoming: VecDeque::new(),
                    outgoing: VecDeque::new(),
                    incoming_bytes: 0,
                    outgoing_bytes: 0,
                },
            );
        }
        Registration(request)
    }

    /// Records whether the peer enabled H3_DATAGRAM.
    pub(crate) fn negotiated(&self, enabled: bool) {
        self.lock().negotiated = enabled;
    }

    /// Drops every session once the connection ends.
    pub(crate) fn close(&self) {
        let entries = {
            let mut state = self.lock();
            state.closed = true;
            state.incoming = 0;
            state.outgoing = 0;
            state.ready.clear();
            mem::take(&mut state.streams)
        };
        for entry in entries.into_values() {
            if let Some(request) = entry.request.upgrade() {
                request.received.wake();
            }
        }
        self.waker.wake();
        self.capacity_notify.notify_waiters();
    }

    /// Routes one received QUIC Datagram to its session, or invalidates a request
    /// without Datagram semantics.
    fn receive(&self, packet: Bytes) -> Result<()> {
        let packet = Datagram::decode(packet).map_err(|error| {
            Error::new_h3(ConnectionError::Local {
                error: error.into(),
            })
        })?;
        let mut state = self.lock();
        let capacity = CONNECTION_BYTES - state.incoming;
        let Some(entry) = state.streams.get_mut(&packet.stream_id().into_inner()) else {
            // Unknown and late associations may be dropped (RFC 9297 §2.1).
            return Ok(());
        };
        if !entry.recv_open {
            return Ok(());
        }
        let Some(request) = entry.request.upgrade() else {
            return Ok(());
        };
        if !entry.semantics {
            drop(state);
            // An active request without Datagram semantics is a stream error,
            // unlike an unknown stream (RFC 9297 §2).
            request.invalid.cancel();
            if let Some((state, stop)) = request.stop_state.get().zip(request.stop.get()) {
                if let Some(state) = state.upgrade() {
                    stop(&*state);
                }
            }
            return Ok(());
        }
        let payload = packet.into_payload();
        let size = payload.len();
        if entry.incoming.len() == PACKETS
            || size > SESSION_BYTES - entry.incoming_bytes
            || size > capacity
        {
            // Unreliable receive queues drop the newest packet.
            return Ok(());
        }
        entry.incoming.push_back(payload);
        entry.incoming_bytes += size;
        state.incoming += size;
        drop(state);
        request.received.wake();
        Ok(())
    }

    /// Takes the next packet to send, rotating between sessions.
    fn next(&self) -> Option<(u64, Bytes)> {
        let mut state = self.lock();
        while let Some(id) = state.ready.pop_front() {
            let Some(entry) = state.streams.get_mut(&id) else {
                continue;
            };
            let Some(packet) = entry.outgoing.pop_front() else {
                continue;
            };
            entry.outgoing_bytes -= packet.len();
            if !entry.outgoing.is_empty() {
                state.ready.push_back(id);
            }
            state.outgoing -= packet.len();
            drop(state);
            self.capacity_notify.notify_waiters();
            return Some((id, packet));
        }
        None
    }
}

// ===== impl RequestState =====

impl RequestState {
    /// The connection-wide capacity notifier senders wait on.
    pub(crate) fn capacity_notify(&self) -> Arc<Notify> {
        self.registry.capacity_notify.clone()
    }

    /// The request stream ID.
    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    /// Largest payload the session can send now, if Datagrams are negotiated and
    /// its send direction is open.
    pub(crate) fn max_size(&self) -> Option<usize> {
        let state = self.registry.lock();
        let entry = state.streams.get(&self.id.into_inner())?;
        if !state.negotiated || !entry.send_open {
            return None;
        }
        state.max_size?.checked_sub(self.prefix_size())
    }

    /// Encoded size of the Quarter Stream ID prefix.
    fn prefix_size(&self) -> usize {
        match self.id.into_inner() / 4 {
            0..=63 => 1,
            64..=16383 => 2,
            16384..=1073741823 => 4,
            _ => 8,
        }
    }

    /// Tries to frame and queue one payload within the session and connection
    /// budgets. Returns `Full` immediately when either queue has no capacity.
    pub(crate) fn try_send(&self, payload: &Bytes) -> std::result::Result<(), SendErrorKind> {
        let mut state = self.registry.lock();
        let Some(entry) = state.streams.get(&self.id.into_inner()) else {
            return Err(SendErrorKind::Closed);
        };
        if !entry.send_open {
            return Err(SendErrorKind::Closed);
        }
        let Some(max) = state.max_size.filter(|_| state.negotiated) else {
            return Err(SendErrorKind::Unavailable);
        };
        let size = payload
            .len()
            .checked_add(self.prefix_size())
            .ok_or(SendErrorKind::TooLarge)?;
        if size > max || size > SESSION_BYTES {
            return Err(SendErrorKind::TooLarge);
        }
        if entry.outgoing.len() == PACKETS
            || size > SESSION_BYTES - entry.outgoing_bytes
            || size > CONNECTION_BYTES - state.outgoing
        {
            return Err(SendErrorKind::Full);
        }
        let mut packet = Datagram::new(self.id, payload.clone()).encode();
        // The raw QUIC API takes contiguous Bytes. This is the single framing
        // copy; neither queueing nor routing copies the packet again.
        let packet = packet.copy_to_bytes(packet.remaining());
        let entry = state
            .streams
            .get_mut(&self.id.into_inner())
            .ok_or(SendErrorKind::Closed)?;
        let empty = entry.outgoing.is_empty();
        entry.outgoing.push_back(packet);
        entry.outgoing_bytes += size;
        state.outgoing += size;
        if empty {
            state.ready.push_back(self.id.into_inner());
        }
        drop(state);
        self.registry.waker.wake();
        Ok(())
    }

    /// Polls the next received payload; `None` once the receive direction closed.
    pub(crate) fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.received.register(cx.waker());
        let mut state = self.registry.lock();
        let Some(entry) = state.streams.get_mut(&self.id.into_inner()) else {
            return Poll::Ready(None);
        };
        if let Some(packet) = entry.incoming.pop_front() {
            entry.incoming_bytes -= packet.len();
            state.incoming -= packet.len();
            Poll::Ready(Some(packet))
        } else if !entry.recv_open {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    /// Registers the response body an invalid Datagram must stop; `stop`
    /// downcasts the erased state back to its concrete type.
    pub(crate) fn attach<T: Any + Send + Sync>(
        &self,
        state: Weak<T>,
        stop: fn(&(dyn Any + Send + Sync)),
    ) {
        // The function is visible before the state, so a reader never sees
        // a state without its downcast.
        let _ = self.stop.set(stop);
        let _ = self.stop_state.set(state);
    }

    /// Closes the send direction and discards its queue.
    pub(crate) fn close_send(&self) {
        let mut state = self.registry.lock();
        if let Some(entry) = state.streams.get_mut(&self.id.into_inner()) {
            entry.send_open = false;
            let size = entry.outgoing_bytes;
            entry.outgoing_bytes = 0;
            entry.outgoing.clear();
            state.outgoing -= size;
            state.ready.retain(|&id| id != self.id.into_inner());
        }
        drop(state);
        self.registry.waker.wake();
        self.registry.capacity_notify.notify_waiters();
    }

    /// Closes the receive direction and discards its queue.
    pub(crate) fn close_recv(&self) {
        let mut state = self.registry.lock();
        if let Some(entry) = state.streams.get_mut(&self.id.into_inner()) {
            entry.recv_open = false;
            let size = entry.incoming_bytes;
            entry.incoming_bytes = 0;
            entry.incoming.clear();
            state.incoming -= size;
        }
        drop(state);
        self.received.wake();
    }

    /// Removes the session; both handles observe the end.
    pub(crate) fn close(&self) {
        let mut state = self.registry.lock();
        if let Some(entry) = state.streams.remove(&self.id.into_inner()) {
            state.incoming -= entry.incoming_bytes;
            state.outgoing -= entry.outgoing_bytes;
            state.ready.retain(|&id| id != self.id.into_inner());
        }
        drop(state);
        self.received.wake();
        self.registry.waker.wake();
        self.registry.capacity_notify.notify_waiters();
    }
}

// ===== impl Registration =====

impl Drop for Registration {
    fn drop(&mut self) {
        self.0.close();
    }
}

// ===== impl Driver =====

impl<S, R> Unpin for Driver<S, R> {}

impl<S, R> Future for Driver<S, R>
where
    S: quic::SendDatagram,
    R: quic::RecvDatagram,
{
    type Output = std::result::Result<(), (Code, Error)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.registry.waker.register(cx.waker());
        let max_size = this.sender.max_datagram_size();
        this.registry.lock().max_size = max_size;
        // Independent bounded budgets keep control/QPACK and both Datagram
        // directions moving even under a continuously ready producer.
        for index in 0..32 {
            match this.receiver.poll_recv(cx) {
                Poll::Ready(Ok(Some(packet))) => this
                    .registry
                    .receive(packet)
                    .map_err(|error| (Code::H3_DATAGRAM_ERROR, error))?,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err((Code::H3_INTERNAL_ERROR, Error::new_h3(error))))
                }
                Poll::Pending => break,
            }
            if index == 31 {
                cx.waker().wake_by_ref();
            }
        }
        for index in 0..32 {
            if this.pending.is_none() {
                this.pending = this.registry.next();
            }
            let Some((id, packet)) = this.pending.as_ref() else {
                break;
            };
            let open = this
                .registry
                .lock()
                .streams
                .get(id)
                .is_some_and(|entry| entry.send_open);
            if !open {
                this.pending = None;
                if index == 31 {
                    cx.waker().wake_by_ref();
                }
                continue;
            }
            match this.sender.poll_send(cx, packet) {
                Poll::Pending => break,
                Poll::Ready(Err(quic::DatagramError::Connection(error))) => {
                    return Poll::Ready(Err((Code::H3_INTERNAL_ERROR, Error::new_h3(error))));
                }
                // MTU/availability can change after local admission. Datagram
                // delivery is unreliable; never turn TooLarge into Capsules.
                Poll::Ready(_) => this.pending = None,
            }
            if index == 31 {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Arc<Registry> {
        Arc::new(Registry {
            state: Mutex::new(State {
                negotiated: true,
                max_size: Some(65536),
                ..State::default()
            }),
            waker: AtomicWaker::new(),
            capacity_notify: Arc::new(Notify::new()),
        })
    }

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);

    impl futures_util::task::ArcWake for Wakes {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn blocked_senders_wake_independently_and_never_enqueue_while_pending() {
        use crate::conn::http3::datagram::Sender;
        let registry = registry();
        let request = registry.register(
            StreamId::try_from(0).unwrap(),
            true,
            CancellationToken::new(),
        );
        for _ in 0..PACKETS {
            request.0.try_send(&Bytes::new()).unwrap();
        }
        let mut first = Sender::new(request.0.clone());
        let mut second = first.clone();
        let first_wakes = Arc::new(Wakes::default());
        let second_wakes = Arc::new(Wakes::default());
        let first_waker = futures_util::task::waker(first_wakes.clone());
        let second_waker = futures_util::task::waker(second_wakes.clone());
        let mut cx1 = Context::from_waker(&first_waker);
        let mut cx2 = Context::from_waker(&second_waker);
        assert!(first
            .poll_send(&mut cx1, &Bytes::from_static(b"first"))
            .is_pending());
        assert!(second
            .poll_send(&mut cx2, &Bytes::from_static(b"second"))
            .is_pending());
        assert_eq!(registry.lock().streams[&0].outgoing.len(), PACKETS);
        registry.next().unwrap();
        assert!(first_wakes.0.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert!(second_wakes.0.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert!(matches!(
            first.poll_send(&mut cx1, &Bytes::from_static(b"first")),
            Poll::Ready(Ok(()))
        ));
        // Reusing the second sender may first consume the broadcast notification.
        assert!(second
            .poll_send(&mut cx2, &Bytes::from_static(b"second"))
            .is_pending());
        assert!(second
            .poll_send(&mut cx2, &Bytes::from_static(b"second"))
            .is_pending());
        let before_close = second_wakes.0.load(std::sync::atomic::Ordering::Relaxed);
        request.0.close_send();
        assert!(second_wakes.0.load(std::sync::atomic::Ordering::Relaxed) > before_close);
        assert_eq!(
            second.poll_send(&mut cx2, &Bytes::from_static(b"second")),
            Poll::Ready(Err(SendErrorKind::Closed))
        );
        assert!(registry.next().is_none());
    }

    #[test]
    fn empty_packets_are_bounded_and_sessions_are_served_round_robin() {
        let registry = registry();
        let first = registry.register(
            StreamId::try_from(0).unwrap(),
            true,
            CancellationToken::new(),
        );
        let second = registry.register(
            StreamId::try_from(4).unwrap(),
            true,
            CancellationToken::new(),
        );
        for _ in 0..PACKETS {
            first.0.try_send(&Bytes::new()).unwrap();
            second.0.try_send(&Bytes::from_static(b"other")).unwrap();
        }
        assert_eq!(first.0.try_send(&Bytes::new()), Err(SendErrorKind::Full));
        for _ in 0..PACKETS {
            assert_eq!(registry.next().unwrap().0, 0);
            assert_eq!(registry.next().unwrap().0, 4);
        }
        assert!(registry.next().is_none());
        assert_eq!(registry.lock().outgoing, 0);
        first.0.try_send(&Bytes::new()).unwrap();
        drop(first);
        drop(second);
        let state = registry.lock();
        assert!(state.streams.is_empty());
        assert!(state.ready.is_empty());
        assert_eq!(state.outgoing, 0);
    }

    #[test]
    fn connection_byte_budget_is_reclaimed_on_close() {
        let registry = registry();
        let requests: Vec<_> = (0..9)
            .map(|n| {
                registry.register(
                    StreamId::try_from(n * 4).unwrap(),
                    true,
                    CancellationToken::new(),
                )
            })
            .collect();
        let payload = Bytes::from(vec![0; 65535]);
        for request in &requests[..8] {
            request.0.try_send(&payload).unwrap();
            request.0.try_send(&payload).unwrap();
            assert_eq!(request.0.try_send(&Bytes::new()), Err(SendErrorKind::Full));
        }
        assert_eq!(registry.lock().outgoing, CONNECTION_BYTES);
        assert_eq!(
            requests[8].0.try_send(&Bytes::new()),
            Err(SendErrorKind::Full)
        );
        requests[0].0.close_send();
        requests[8].0.try_send(&payload).unwrap();
        registry.close();
        assert_eq!(registry.lock().outgoing, 0);
        assert_eq!(
            requests[8].0.try_send(&Bytes::new()),
            Err(SendErrorKind::Closed)
        );
    }

    #[test]
    fn dropping_datagram_receiver_reclaims_connection_budget() {
        use crate::conn::http3::datagram::{self, Pending};
        let registry = registry();
        let requests: Vec<_> = (0..9)
            .map(|n| {
                registry.register(
                    StreamId::try_from(n * 4).unwrap(),
                    true,
                    CancellationToken::new(),
                )
            })
            .collect();
        let (control, _peer) = tokio::io::duplex(1);
        let mut response = http::Response::new(());
        response.extensions_mut().insert(Pending::new(
            crate::upgrade::Upgraded::new(control, Bytes::new()),
            requests[0].0.clone(),
        ));
        let (_control, sender, receiver) = datagram::on(&mut response).unwrap().into_parts();
        let payload = Bytes::from(vec![0; SESSION_BYTES / 4]);
        for request in &requests[..8] {
            let mut encoded = Datagram::new(request.0.id(), payload.clone()).encode();
            let packet = encoded.copy_to_bytes(encoded.remaining());
            for _ in 0..4 {
                registry.receive(packet.clone()).unwrap();
            }
        }
        assert_eq!(registry.lock().incoming, CONNECTION_BYTES);
        let mut encoded = Datagram::new(requests[8].0.id(), Bytes::from_static(b"live")).encode();
        let live = encoded.copy_to_bytes(encoded.remaining());
        registry.receive(live.clone()).unwrap();
        assert!(registry.lock().streams[&32].incoming.is_empty());
        drop(receiver);
        assert_eq!(registry.lock().incoming, CONNECTION_BYTES - SESSION_BYTES);
        assert!(registry.lock().streams[&0].incoming.is_empty());
        // Unread late packets cannot occupy the budget again while the caller
        // keeps this session's control and send handles alive.
        registry.receive(Bytes::from_static(&[0, 7])).unwrap();
        assert_eq!(registry.lock().incoming, CONNECTION_BYTES - SESSION_BYTES);
        registry.receive(live).unwrap();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            requests[8].0.poll_recv(&mut cx),
            Poll::Ready(Some(Bytes::from_static(b"live")))
        );
        sender.try_send(Bytes::from_static(b"outgoing")).unwrap();
        let (id, packet) = registry.next().unwrap();
        assert_eq!(id, 0);
        assert_eq!(Datagram::decode(packet).unwrap().into_payload(), "outgoing");
        assert!(!requests[0].0.invalid.is_cancelled());
    }

    #[test]
    fn receive_budget_drops_newest_and_fin_clears_queued_packets() {
        let registry = registry();
        let request = registry.register(
            StreamId::try_from(0).unwrap(),
            true,
            CancellationToken::new(),
        );
        for _ in 0..PACKETS {
            registry.receive(Bytes::from_static(&[0])).unwrap();
        }
        registry.receive(Bytes::from_static(&[0, 9])).unwrap();
        assert_eq!(registry.lock().streams[&0].incoming.len(), PACKETS);
        assert_eq!(registry.lock().incoming, 0);
        request.0.close_recv();
        registry.receive(Bytes::from_static(&[0, 9])).unwrap();
        assert!(registry.lock().streams[&0].incoming.is_empty());
        assert!(registry.receive(Bytes::new()).is_err());
    }

    struct DatagramSender {
        max: usize,
        blocked: bool,
        wake: Option<std::task::Waker>,
        accepted: Vec<Bytes>,
    }

    struct DatagramReceiver;

    // ===== impl DatagramSender =====

    impl quic::SendDatagram for DatagramSender {
        fn max_datagram_size(&self) -> Option<usize> {
            Some(self.max)
        }

        fn poll_send(
            &mut self,
            cx: &mut Context<'_>,
            packet: &Bytes,
        ) -> Poll<std::result::Result<(), quic::DatagramError>> {
            if self.blocked {
                self.wake = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if packet.len() > self.max {
                return Poll::Ready(Err(quic::DatagramError::TooLarge));
            }
            self.accepted.push(packet.clone());
            Poll::Ready(Ok(()))
        }
    }

    // ===== impl DatagramReceiver =====

    impl quic::RecvDatagram for DatagramReceiver {
        fn poll_recv(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<std::result::Result<Option<Bytes>, quic::ConnectionError>> {
            Poll::Pending
        }
    }

    #[test]
    fn closing_session_discards_blocked_datagram_and_preserves_other_sessions() {
        for drop_session in [false, true] {
            let registry = registry();
            let closed = registry.register(
                StreamId::try_from(0).unwrap(),
                true,
                CancellationToken::new(),
            );
            let request = closed.0.clone();
            let live = registry.register(
                StreamId::try_from(4).unwrap(),
                true,
                CancellationToken::new(),
            );
            request.try_send(&Bytes::from_static(b"canceled")).unwrap();
            live.0.try_send(&Bytes::from_static(b"live")).unwrap();
            let mut driver = Driver {
                sender: DatagramSender {
                    max: 1300,
                    blocked: true,
                    wake: None,
                    accepted: Vec::new(),
                },
                receiver: DatagramReceiver,
                registry: registry.clone(),
                pending: None,
            };
            let wakes = Arc::new(Wakes::default());
            let waker = futures_util::task::waker(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
            assert_eq!(driver.pending.as_ref().unwrap().0, 0);
            assert!(driver.sender.accepted.is_empty());
            let before_close = wakes.0.load(std::sync::atomic::Ordering::Relaxed);
            if drop_session {
                drop(closed);
            } else {
                request.close_send();
            }
            // Closure must wake the driver even while QUIC remains blocked.
            assert!(wakes.0.load(std::sync::atomic::Ordering::Relaxed) > before_close);
            assert_eq!(request.try_send(&Bytes::new()), Err(SendErrorKind::Closed));
            assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
            assert_eq!(driver.pending.as_ref().unwrap().0, 4);
            assert!(driver.sender.accepted.is_empty());
            driver.sender.blocked = false;
            driver.sender.wake.take().unwrap().wake();
            assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
            assert!(driver.pending.is_none());
            assert_eq!(driver.sender.accepted.len(), 1);
            let packet = Datagram::decode(driver.sender.accepted.pop().unwrap()).unwrap();
            assert_eq!(packet.stream_id(), live.0.id());
            assert_eq!(packet.into_payload(), "live");
            assert_eq!(registry.lock().outgoing, 0);
            assert!(!live.0.invalid.is_cancelled());
            live.0.try_send(&Bytes::from_static(b"reused")).unwrap();
            assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
            assert_eq!(driver.sender.accepted.len(), 1);
        }
    }

    #[test]
    fn mtu_reduction_drops_pending_packet_without_closing_session() {
        let registry = registry();
        // Quarter Stream ID 64 needs two bytes, which must count toward MTU.
        let request = registry.register(
            StreamId::try_from(256).unwrap(),
            true,
            CancellationToken::new(),
        );
        let mut driver = Driver {
            sender: DatagramSender {
                max: 1300,
                blocked: true,
                wake: None,
                accepted: Vec::new(),
            },
            receiver: DatagramReceiver,
            registry: registry.clone(),
            pending: None,
        };
        let wakes = Arc::new(Wakes::default());
        let waker = futures_util::task::waker(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
        assert_eq!(request.0.max_size(), Some(1298));
        request.0.try_send(&Bytes::from(vec![7; 1298])).unwrap();
        request.0.try_send(&Bytes::from_static(b"next")).unwrap();
        assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
        assert!(driver.pending.is_some());
        assert!(driver.sender.accepted.is_empty());
        driver.sender.max = 1200;
        driver.sender.blocked = false;
        driver.sender.wake.take().unwrap().wake();
        assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
        assert!(driver.pending.is_none());
        assert_eq!(request.0.max_size(), Some(1198));
        assert_eq!(registry.lock().outgoing, 0);
        assert!(!request.0.invalid.is_cancelled());
        assert_eq!(driver.sender.accepted.len(), 1);
        let received = Datagram::decode(driver.sender.accepted.pop().unwrap()).unwrap();
        assert_eq!(received.into_payload(), "next");
        assert_eq!(
            request.0.try_send(&Bytes::from(vec![7; 1199])),
            Err(SendErrorKind::TooLarge)
        );
        request.0.try_send(&Bytes::from(vec![7; 1198])).unwrap();
        assert!(Pin::new(&mut driver).poll(&mut cx).is_pending());
        assert_eq!(driver.sender.accepted[0].len(), 1200);
        assert_eq!(registry.lock().outgoing, 0);
    }
}
