//! A future that polls a task's parts in passes, which turns wakeups from the task's own work
//! into another pass.
//!
//! One part's work often wakes another, and so the task it runs in. Rescheduling the running
//! task for that would push it through the run queue, where an idle worker may steal it.
//!
//! A pass polls the parts in order, each with a waker of its own. A part woken before its turn
//! is polled in that pass anyway, so only one woken since its turn takes another pass, which
//! starts at that part.

use std::{
    future::Future,
    ops::ControlFlow,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use futures_util::task::AtomicWaker;
use pin_project_lite::pin_project;

/// Set in the state while the task is polled, next to the bits of the woken parts.
const POLLING: u8 = 1 << 7;

/// Passes in one poll before a task that keeps waking itself yields.
const MAX_PASSES: usize = 4;

/// A task that [`Passes`] polls in parts.
pub trait Parts {
    /// Names a part.
    type Part: Copy;

    /// What the task ends with.
    type Output;

    /// Polls `part` in its turn of a pass.
    ///
    /// A pending part waits for its waker, and the pass moves on to the next part. A ready one
    /// breaks with the task's output, or continues once the task has yielded to its executor.
    fn poll_part(
        self: Pin<&mut Self>,
        part: Self::Part,
        cx: &mut Context<'_>,
    ) -> Poll<ControlFlow<Self::Output>>;
}

pin_project! {
    /// Polls the parts of a task in passes, until the task ends. A `P` names a part.
    pub struct Passes<T, P> {
        #[pin]
        task: T,
        shared: Arc<Shared>,
        // In the order a pass polls them.
        parts: Box<[(P, Waker)]>,
    }
}

struct Shared {
    state: AtomicU8,
    // Wakes the task.
    waker: AtomicWaker,
}

/// Wakes a part of the task.
struct PartWaker {
    shared: Arc<Shared>,
    bit: u8,
}

// ===== impl Passes =====

impl<T, P> Passes<T, P> {
    /// Wraps `task`, with its `parts` in the order a pass polls them.
    pub(super) fn new<const N: usize>(task: T, parts: [P; N]) -> Self {
        // Each part has a bit of the state, below `POLLING`.
        const { assert!(N < 8) };

        let shared = Arc::new(Shared {
            state: AtomicU8::new(0),
            waker: AtomicWaker::new(),
        });
        let mut bit = 1;
        let parts = parts.map(|part| {
            let waker = PartWaker {
                shared: shared.clone(),
                bit,
            };
            bit <<= 1;
            (part, Waker::from(Arc::new(waker)))
        });
        Self {
            task,
            shared,
            parts: Box::new(parts),
        }
    }
}

impl<T: Parts> Future for Passes<T, T::Part> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let state = &this.shared.state;
        this.shared.waker.register(cx.waker());
        state.fetch_or(POLLING, Ordering::AcqRel);
        'passes: for pass in 0..MAX_PASSES {
            // The first pass polls every part. Another one skips the parts ahead of the first
            // one woken since its turn; those after it follow, as it may hand them work
            // without waking them.
            let mut skip = pass > 0;
            for (index, (part, waker)) in this.parts.iter().enumerate() {
                // The turn takes the part's wakeups so far.
                let bit = 1 << index;
                let woken = state.fetch_and(!bit, Ordering::AcqRel) & bit != 0;
                skip &= !woken;
                if skip {
                    continue;
                }
                let cx = &mut Context::from_waker(waker);
                match this.task.as_mut().poll_part(*part, cx) {
                    Poll::Pending => {}
                    Poll::Ready(ControlFlow::Continue(())) => break 'passes,
                    Poll::Ready(ControlFlow::Break(output)) => {
                        state.fetch_and(!POLLING, Ordering::AcqRel);
                        return Poll::Ready(output);
                    }
                }
            }
            // Idle, unless a part was woken since its turn.
            if state
                .compare_exchange(POLLING, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Poll::Pending;
            }
        }
        // The task yields, by its choice or for waking itself pass after pass.
        state.fetch_and(!POLLING, Ordering::AcqRel);
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ===== impl PartWaker =====

impl Wake for PartWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // A poll in progress sees the part woken as its pass ends; otherwise the task is idle.
        if self.shared.state.fetch_or(self.bit, Ordering::AcqRel) & POLLING == 0 {
            self.shared.waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        ops::ControlFlow,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use super::{MAX_PASSES, Parts, Passes};

    /// Counts the wakeups of the task.
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A task of three parts that counts their turns.
    #[derive(Default)]
    struct Turns {
        turns: usize,
        wakers: [Option<Waker>; 3],
        // The part whose turn wakes part 1, in the first pass or in `every` pass.
        waking: Option<usize>,
        every: bool,
        // What the next turn of part 1 is ready with.
        ready: Option<ControlFlow<usize>>,
    }

    impl Parts for Turns {
        type Part = usize;
        type Output = usize;

        fn poll_part(
            mut self: Pin<&mut Self>,
            part: usize,
            cx: &mut Context<'_>,
        ) -> Poll<ControlFlow<usize>> {
            self.wakers[part] = Some(cx.waker().clone());
            if self.waking == Some(part)
                && (self.every || self.turns < 3)
                && let Some(waker) = &self.wakers[1]
            {
                waker.wake_by_ref();
            }
            self.turns += 1;
            if part == 1
                && let Some(ready) = self.ready.take()
            {
                return Poll::Ready(ready);
            }
            Poll::Pending
        }
    }

    #[test]
    fn parts_woken_since_their_turn_take_another_pass() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let task = Waker::from(count.clone());
        let mut cx = Context::from_waker(&task);
        let woken = || count.0.load(Ordering::Relaxed);

        // Polls the task, returning the turns taken.
        let mut passes = Passes::new(Turns::default(), [0, 1, 2]);
        let mut poll = |waking, every| {
            passes.task.turns = 0;
            passes.task.waking = waking;
            passes.task.every = every;
            assert!(Pin::new(&mut passes).poll(&mut cx).is_pending());
            passes.task.turns
        };
        assert_eq!(poll(None, false), 3);

        // A part woken before its turn is polled in the same pass.
        assert_eq!(poll(Some(0), true), 3);

        // One woken since its turn takes another pass from that part on, without waking the
        // task.
        assert_eq!(poll(Some(2), false), 3 + 2);
        assert_eq!(woken(), 0);

        // A part that keeps waking itself yields after a few passes.
        assert_eq!(poll(Some(1), true), 3 + 2 * (MAX_PASSES - 1));
        assert_eq!(woken(), 1);

        // Once idle, a wakeup wakes the task.
        assert_eq!(poll(None, false), 3);
        passes.task.wakers[0].take().unwrap().wake();
        assert_eq!(woken(), 2);

        // A part yields the task, then ends it.
        passes.task.ready = Some(ControlFlow::Continue(()));
        assert!(Pin::new(&mut passes).poll(&mut cx).is_pending());
        assert_eq!(woken(), 3);
        passes.task.ready = Some(ControlFlow::Break(7));
        assert_eq!(Pin::new(&mut passes).poll(&mut cx), Poll::Ready(7));
    }
}
