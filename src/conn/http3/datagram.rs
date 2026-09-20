//! HTTP Datagram sessions carried by an Extended CONNECT request.
//!
//! Insert [`DatagramRequest`] alongside `http3::ext::Protocol`. After a successful
//! response, [`on`] takes the session, including its reliable Capsule byte stream.
//! Capsule and CONNECT-UDP Context ID encoding belong to the caller.
use std::{
    future::{poll_fn, Future},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use http::Response;
use tokio::sync::futures::OwnedNotified;

pub use crate::proto::http3::datagram::SendErrorKind;
use crate::{proto::http3::datagram::RequestState, rt::quic::StreamId, upgrade::Upgraded};

/// Declares that this Extended CONNECT protocol defines HTTP Datagram semantics.
/// It does not negotiate a protocol or assert successful proxy authorization.
#[derive(Clone, Copy, Debug)]
pub struct DatagramRequest;

/// A successful CONNECT and its request-associated Datagram handles.
/// Dropping the control stream invalidates both handles, even if they outlive it.
pub struct Session {
    control: Upgraded,
    sender: Sender,
    receiver: Receiver,
}

/// Sends whole HTTP Datagram payloads, excluding the Quarter Stream ID prefix.
pub struct Sender {
    state: Arc<RequestState>,
    waiting: Option<Pin<Box<OwnedNotified>>>,
}

/// Receives whole HTTP Datagram payloads for exactly one request stream.
/// Dropping it discards queued and future payloads for this receiver without
/// closing the reliable control stream or the Datagram send direction.
pub struct Receiver(Arc<RequestState>);

/// A rejected send, retaining ownership of the caller's unchanged payload.
#[derive(Debug)]
pub struct SendError {
    kind: SendErrorKind,
    payload: Bytes,
}

#[derive(Clone)]
pub(crate) struct Pending(Arc<Mutex<Option<Session>>>);

/// Takes the unique session from a successful Datagram CONNECT response.
/// Returns `None` for ordinary requests, failed CONNECTs, or an already-taken session.
pub fn on<B>(response: &mut Response<B>) -> Option<Session> {
    response
        .extensions_mut()
        .remove::<Pending>()?
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
}

// ===== impl Session =====

impl Session {
    /// Separates the reliable control stream and the two Datagram directions.
    /// Native sends may be unavailable while the control stream supports Capsules.
    pub fn into_parts(self) -> (Upgraded, Sender, Receiver) {
        (self.control, self.sender, self.receiver)
    }
}

// ===== impl Pending =====

impl Pending {
    pub(crate) fn new(control: Upgraded, state: Arc<RequestState>) -> Self {
        Self(Arc::new(Mutex::new(Some(Session {
            control,
            sender: Sender::new(state.clone()),
            receiver: Receiver(state),
        }))))
    }
}

// ===== impl Sender =====

impl Clone for Sender {
    fn clone(&self) -> Self {
        Self::new(self.state.clone())
    }
}

impl Sender {
    pub(crate) fn new(state: Arc<RequestState>) -> Self {
        Self {
            state,
            waiting: None,
        }
    }

    /// Waits for queue space and admits exactly one payload; success is not delivery.
    /// Pending retains no payload and never sends it in the background. Cloned
    /// senders have independent waiters; capacity is a hint, not a reservation.
    pub fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        payload: &Bytes,
    ) -> Poll<Result<(), SendErrorKind>> {
        let result = self.state.send(payload);
        if result != Err(SendErrorKind::Full) {
            self.waiting = None;
            return Poll::Ready(result);
        }
        let waiting = self
            .waiting
            .get_or_insert_with(|| Box::pin(self.state.capacity().notified_owned()));
        if waiting.as_mut().poll(cx).is_ready() {
            self.waiting = None;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        // Register before rechecking capacity so a concurrent dequeue cannot
        // leave this sender asleep with room available.
        match self.state.send(payload) {
            Err(SendErrorKind::Full) => Poll::Pending,
            result => {
                self.waiting = None;
                Poll::Ready(result)
            }
        }
    }

    /// Waits for local admission, returning the unchanged payload on error.
    /// Canceling while Pending does not enqueue or transmit the payload.
    pub async fn send(&mut self, payload: Bytes) -> Result<(), SendError> {
        poll_fn(|cx| self.poll_send(cx, &payload))
            .await
            .map_err(|kind| SendError { kind, payload })
    }

    /// Returns the CONNECT request's QUIC stream ID.
    pub fn stream_id(&self) -> StreamId {
        self.state.id()
    }

    /// Returns the latest payload limit, excluding Quarter Stream ID overhead.
    /// `None` means the send half is closed or native Datagrams are unavailable.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.state.max_size()
    }

    /// Admits one payload to a bounded local queue; success is not delivery.
    /// Queues hold at most 64 packets/128 KiB per session and 1 MiB per connection,
    /// plus one packet being sent. Congestion or a later MTU change may drop it.
    pub fn try_send(&self, payload: Bytes) -> Result<(), SendError> {
        self.state
            .send(&payload)
            .map_err(|kind| SendError { kind, payload })
    }
}

// ===== impl Receiver =====

impl Receiver {
    /// Polls the next payload; `None` means this receive half or session ended.
    /// The reliable control stream carries errors. Overflow drops newest packets.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        self.0.poll_recv(cx)
    }

    /// Waits for the next payload. Canceling this wait does not consume a packet.
    pub async fn recv(&mut self) -> Option<Bytes> {
        poll_fn(|cx| self.poll_recv(cx)).await
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.0.close_recv();
    }
}

// ===== impl SendError =====

impl SendError {
    /// Returns the admission failure category.
    pub fn kind(&self) -> SendErrorKind {
        self.kind
    }

    /// Returns the original unsent payload.
    pub fn into_payload(self) -> Bytes {
        self.payload
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP Datagram send rejected: {:?}", self.kind)
    }
}

impl std::error::Error for SendError {}
