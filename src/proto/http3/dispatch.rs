use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    task::Context,
};

use futures_util::task::AtomicWaker;
use http::{Request, Response};
use tokio_util::sync::CancellationToken;

use crate::{body::Incoming, Error};

pub(crate) type Callback<B> = crate::dispatch::Callback<Request<B>, Response<Incoming>>;

pub(crate) struct Shared {
    #[cfg(feature = "http3-datagram")]
    pub(crate) datagrams: Option<Arc<super::datagram::Registry>>,
    pub(crate) peer_extended_connect: OnceLock<bool>,
    pub(crate) settings_ready: CancellationToken,
    pub(crate) draining: AtomicBool,
    pub(crate) active: AtomicUsize,
    pub(crate) waker: AtomicWaker,
    pub(crate) active_waker: AtomicWaker,
    pub(crate) closed: CancellationToken,
    pub(crate) error: OnceLock<Arc<Error>>,
}

pub(crate) struct Active(pub(crate) Arc<Shared>);

// ===== impl Shared =====

impl Shared {
    pub(crate) fn new(
        #[cfg(feature = "http3-datagram")] datagrams: Option<Arc<super::datagram::Registry>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(feature = "http3-datagram")]
            datagrams,
            peer_extended_connect: OnceLock::new(),
            settings_ready: CancellationToken::new(),
            draining: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            waker: AtomicWaker::new(),
            active_waker: AtomicWaker::new(),
            closed: CancellationToken::new(),
            error: OnceLock::new(),
        })
    }

    pub(crate) fn drain(&self) {
        if !self.draining.swap(true, Ordering::AcqRel) {
            self.waker.wake();
        }
    }

    pub(crate) fn terminate(&self, error: Error) {
        self.error.get_or_init(|| Arc::new(error));
        self.drain();
        self.closed.cancel();
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &self.datagrams {
            datagrams.close();
        }
    }

    pub(crate) fn error(&self) -> Error {
        self.error
            .get()
            .map_or_else(Error::new_canceled, |e| Error::from_shared(e.clone()))
    }

    pub(crate) fn register(&self, cx: &Context<'_>) {
        self.waker.register(cx.waker());
    }
}

// ===== impl Active =====

impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.active_waker.wake();
    }
}
