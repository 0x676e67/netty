//! Response futures the dispatcher hands to the connection task.
//!
//! The connection's reads complete responses, so the connection task drives them, instead of
//! a spawned task per request.

use std::{
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures_util::{
    stream::{FuturesUnordered, Stream},
    task::AtomicWaker,
};

use crate::lock::LockResultExt;

/// Creates the dispatcher's and the connection task's ends.
pub(super) fn channel<F>() -> (ResponseTx<F>, Responses<F>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            queued: Vec::new(),
            tx_closed: false,
            rx_closed: false,
        }),
        waker: AtomicWaker::new(),
    });
    let responses = Responses {
        shared: shared.clone(),
        running: FuturesUnordered::new(),
        spare: Vec::new(),
    };
    (ResponseTx { shared }, responses)
}

/// The dispatcher's end, which hands over response futures.
pub(super) struct ResponseTx<F> {
    shared: Arc<Shared<F>>,
}

/// The connection task's end, a future driving the response futures handed over.
///
/// It completes once the dispatcher dropped its end and every response future completed.
pub(super) struct Responses<F> {
    shared: Arc<Shared<F>>,
    running: FuturesUnordered<F>,
    // Swapped with the queue, so taking futures reuses its allocation.
    spare: Vec<F>,
}

struct Shared<F> {
    state: Mutex<State<F>>,
    waker: AtomicWaker,
}

struct State<F> {
    queued: Vec<F>,
    // The dispatcher dropped its end; no more futures arrive.
    tx_closed: bool,
    // The connection task dropped its end; futures are no longer driven.
    rx_closed: bool,
}

// ===== impl ResponseTx =====

impl<F> ResponseTx<F> {
    /// Hands `fut` to the connection task, or drops it once that task is gone, as a shut down
    /// executor would.
    pub(super) fn send(&self, fut: F) {
        let rejected = {
            let mut state = self.shared.state.lock().ignore_poison();
            if state.rx_closed {
                Some(fut)
            } else {
                state.queued.push(fut);
                None
            }
        };
        if rejected.is_none() {
            self.shared.waker.wake();
        }
    }
}

impl<F> Drop for ResponseTx<F> {
    fn drop(&mut self) {
        self.shared.state.lock().ignore_poison().tx_closed = true;
        self.shared.waker.wake();
    }
}

// ===== impl Responses =====

// Futures are only moved while queued; `FuturesUnordered` pins them in its own allocations.
impl<F> Unpin for Responses<F> {}

impl<F> Future for Responses<F>
where
    F: Future<Output = ()>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        this.shared.waker.register(cx.waker());
        let tx_closed = {
            let mut state = this.shared.state.lock().ignore_poison();
            mem::swap(&mut state.queued, &mut this.spare);
            state.tx_closed
        };
        this.running.extend(this.spare.drain(..));
        while let Poll::Ready(Some(())) = Pin::new(&mut this.running).poll_next(cx) {}

        if tx_closed && this.running.is_empty() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl<F> Drop for Responses<F> {
    fn drop(&mut self) {
        let queued = {
            let mut state = self.shared.state.lock().ignore_poison();
            state.rx_closed = true;
            mem::take(&mut state.queued)
        };
        drop(queued);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{self, Future},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    use super::channel;

    /// Counts its drops.
    struct Counted(Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn responses_end_with_the_dispatcher() {
        let done = Arc::new(AtomicUsize::new(0));
        let mut cx = Context::from_waker(Waker::noop());
        let response = |done: &Arc<AtomicUsize>| {
            let counted = Counted(done.clone());
            Box::pin(future::poll_fn(move |_| {
                let _ = &counted;
                Poll::Ready(())
            })) as Pin<Box<dyn Future<Output = ()>>>
        };

        // Responses run as they are handed over, and the end waits for the dispatcher.
        let (tx, mut responses) = channel();
        tx.send(response(&done));
        assert!(Pin::new(&mut responses).poll(&mut cx).is_pending());
        assert_eq!(done.load(Ordering::Relaxed), 1);
        drop(tx);
        assert!(Pin::new(&mut responses).poll(&mut cx).is_ready());

        // Once the connection task is gone, a handed over response is dropped.
        let (tx, responses) = channel();
        drop(responses);
        tx.send(response(&done));
        assert_eq!(done.load(Ordering::Relaxed), 2);
    }
}
