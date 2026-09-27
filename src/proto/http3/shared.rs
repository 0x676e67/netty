//! Connection state shared by the driver, request handles, response bodies and body pipes:
//! peer settings, local admission, the drain and the published connection error.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    task::Context,
};

use futures_util::task::AtomicWaker;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "http3-datagram")]
use super::datagram::Registry;
use crate::{Error, Result};

/// Connection state shared by the driver, request handles, response bodies and body pipes.
pub(crate) struct Shared {
    #[cfg(feature = "http3-datagram")]
    pub(crate) datagrams: Option<Arc<Registry>>,
    pub(crate) peer_extended_connect: OnceLock<bool>,
    pub(crate) settings_ready: CancellationToken,
    pub(crate) draining: AtomicBool,
    pub(crate) error: OnceLock<Arc<Error>>,

    /// Local admission; closed by a shutdown so waiting requests are returned.
    pub(crate) permits: Semaphore,

    /// Requests created but not yet admitted. A drain waits for them unless
    /// admission is closed, which returns them on their next poll.
    pub(crate) reserved: AtomicUsize,

    /// Admitted exchanges: pending heads, unread bodies, body pipes and tunnels.
    /// A permit the semaphore assigned to a waiter does not count until that
    /// request runs, so a shutdown can finish without it being polled.
    pub(crate) active: AtomicUsize,

    /// Public request handles; the last one starts draining.
    pub(crate) senders: AtomicUsize,

    /// The driver's waker, for drain, shutdown and completion events.
    pub(crate) waker: AtomicWaker,
}

/// Keeps the connection open until dropped. A reservation is taken when the
/// request future is created; admission adds the permit, which the exchange
/// holds until both of its directions are done.
pub(crate) struct Active {
    shared: Arc<Shared>,
    permit: bool,
}

// ===== impl Shared =====

impl Shared {
    /// `limit` caps admitted requests.
    pub(crate) fn new(
        limit: usize,
        #[cfg(feature = "http3-datagram")] datagrams: Option<Arc<Registry>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(feature = "http3-datagram")]
            datagrams,
            peer_extended_connect: OnceLock::new(),
            settings_ready: CancellationToken::new(),
            draining: AtomicBool::new(false),
            permits: Semaphore::new(limit.min(Semaphore::MAX_PERMITS)),
            reserved: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            senders: AtomicUsize::new(1),
            waker: AtomicWaker::new(),
            error: OnceLock::new(),
        })
    }

    /// Stops accepting new requests; requests created earlier still run.
    pub(crate) fn drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    /// Drains and returns requests waiting for SETTINGS or admission. The driver
    /// calls this on every poll while closing, so only a change wakes it.
    pub(crate) fn shutdown(&self) {
        let admission_open = !self.permits.is_closed();
        if admission_open {
            self.permits.close();
        }
        self.drain();
        if admission_open {
            // A sender-drop drain leaves admission and SETTINGS waiting open.
            // Closing admission must wake them even when already draining.
            self.settings_ready.cancel();
            self.waker.wake();
        }
    }

    /// Publishes the connection error and fails everything still waiting on it.
    pub(crate) fn terminate(&self, error: Error) {
        self.error.get_or_init(|| Arc::new(error));
        self.shutdown();
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &self.datagrams {
            datagrams.close();
        }
    }

    /// Whether draining has started. Existing requests may still be admitted
    /// until an explicit shutdown closes the semaphore.
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Whether every exchange the drain waits for has finished. Unadmitted
    /// requests only count while admission is open; a shutdown returns them.
    ///
    /// Reservations are read before admitted exchanges: admission counts the
    /// exchange first and releases its reservation last, so a request no
    /// longer seen as reserved is already visible as admitted.
    pub(crate) fn is_idle(&self) -> bool {
        let reserved = self.reserved.load(Ordering::Acquire);
        (self.permits.is_closed() || reserved == 0) && self.active.load(Ordering::Acquire) == 0
    }

    /// The published connection error, or a cancellation before any was published.
    pub(crate) fn error(&self) -> Error {
        self.error
            .get()
            .map_or_else(Error::new_canceled, |e| Error::from_shared(e.clone()))
    }

    /// Prefers the published connection error over a later stream-level one.
    pub(crate) fn error_or(&self, error: Error) -> Error {
        self.error
            .get()
            .map_or(error, |e| Error::from_shared(e.clone()))
    }

    /// Registers the driver for drain, shutdown and completion wakeups.
    pub(crate) fn register(&self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

// ===== impl Active =====

impl Active {
    /// Counts a created request so a drain waits for it.
    pub(crate) fn reserve(shared: &Arc<Shared>) -> Self {
        shared.reserved.fetch_add(1, Ordering::AcqRel);
        Self {
            shared: shared.clone(),
            permit: false,
        }
    }

    /// Waits for local admission; fails once admission is closed.
    pub(crate) async fn admit(mut self) -> Result<Self> {
        match self.shared.permits.acquire().await {
            Ok(permit) => permit.forget(),
            Err(_) => return Err(self.shared.error().with("connection closed")),
        }
        // Count the exchange before releasing the reservation, so the driver
        // never observes the request as finished in between.
        self.permit = true;
        self.shared.active.fetch_add(1, Ordering::AcqRel);
        self.shared.reserved.fetch_sub(1, Ordering::AcqRel);
        Ok(self)
    }

    /// The connection state this exchange belongs to.
    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        if self.permit {
            self.shared.permits.add_permits(1);
            self.shared.active.fetch_sub(1, Ordering::AcqRel);
        } else {
            self.shared.reserved.fetch_sub(1, Ordering::AcqRel);
        }
        if self.shared.draining.load(Ordering::Acquire) {
            self.shared.waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An admission counts the exchange before it releases its reservation;
    /// the idle check must see it in every state, open or shut. A permit the
    /// semaphore assigned to a waiter that has not run yet must not count.
    #[test]
    fn admission_stays_visible_between_its_count_and_its_reservation() {
        let shared = Shared::new(
            1,
            #[cfg(feature = "http3-datagram")]
            None,
        );
        shared.reserved.fetch_add(1, Ordering::AcqRel);
        shared.drain();
        assert!(!shared.is_idle());
        shared.permits.try_acquire().unwrap().forget();
        shared.active.fetch_add(1, Ordering::AcqRel);
        assert!(!shared.is_idle());
        shared.reserved.fetch_sub(1, Ordering::AcqRel);
        assert!(!shared.is_idle());
        shared.permits.add_permits(1);
        shared.active.fetch_sub(1, Ordering::AcqRel);
        assert!(shared.is_idle());
        // A shutdown skips a request still waiting for admission, even one
        // the semaphore already assigned a permit to.
        shared.reserved.fetch_add(1, Ordering::AcqRel);
        shared.permits.try_acquire().unwrap().forget();
        shared.shutdown();
        assert!(shared.is_idle());
    }
}
