//! A waker for a task that polls its parts in passes, which turns wakeups from the task's own
//! work into another pass.
//!
//! One part's work often wakes another, and so the task it runs in. Rescheduling the running
//! task for that would push it through the run queue, where an idle worker may steal it.
//!
//! A pass polls the parts in order, each with a waker of its own. A part woken before its turn
//! is polled in that pass anyway, so only one woken since its turn takes another pass, which
//! starts at that part.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use futures_util::task::AtomicWaker;

/// Set in the state while the task is polled, next to the bits of the woken parts.
const POLLING: u8 = 1 << 7;

/// Passes in one poll before a task that keeps waking itself yields.
const MAX_PASSES: usize = 4;

/// The waker of a task with `N` parts, each named by a `P`.
pub(super) struct TaskWaker<P, const N: usize> {
    shared: Arc<Shared>,
    // In the order a pass polls them.
    parts: [(P, Waker); N],
}

struct Shared {
    state: AtomicU8,
    task: AtomicWaker,
}

/// Wakes a part of the task.
struct PartWaker {
    shared: Arc<Shared>,
    bit: u8,
}

// ===== impl TaskWaker =====

impl<P: Copy, const N: usize> TaskWaker<P, N> {
    /// Creates the waker of a task with `parts`, in the order a pass polls them.
    pub(super) fn new(parts: [P; N]) -> Arc<Self> {
        // Each part has a bit of the state, below `POLLING`.
        const { assert!(N < 8) };

        let shared = Arc::new(Shared {
            state: AtomicU8::new(0),
            task: AtomicWaker::new(),
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
        Arc::new(Self { shared, parts })
    }

    /// Gives the parts their turns, each with its own waker, pass after pass, until a turn is
    /// ready or a pass ends with no part woken since its turn.
    pub(super) fn poll<T>(
        &self,
        cx: &mut Context<'_>,
        mut turn: impl FnMut(P, &mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        let Shared { state, task } = &*self.shared;
        task.register(cx.waker());
        state.fetch_or(POLLING, Ordering::AcqRel);
        for pass in 0..MAX_PASSES {
            // The first pass polls every part. Another one skips the parts ahead of the first
            // one woken since its turn; those after it follow, as it may hand them work
            // without waking them.
            let mut skip = pass > 0;
            for (index, (part, waker)) in self.parts.iter().enumerate() {
                // The turn takes the part's wakeups so far.
                let bit = 1 << index;
                let woken = state.fetch_and(!bit, Ordering::AcqRel) & bit != 0;
                skip &= !woken;
                if skip {
                    continue;
                }
                if let Poll::Ready(output) = turn(*part, &mut Context::from_waker(waker)) {
                    state.fetch_and(!POLLING, Ordering::AcqRel);
                    return Poll::Ready(output);
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
            self.shared.task.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use super::{MAX_PASSES, TaskWaker};

    /// Counts the wakeups of the task.
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn parts_woken_since_their_turn_take_another_pass() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let task = Waker::from(count.clone());
        let mut cx = Context::from_waker(&task);
        let waker = TaskWaker::new([0, 1, 2]);
        let woken = || count.0.load(Ordering::Relaxed);

        // Polls the task, returning the turns taken. The turn of part `waking` wakes part 1,
        // in the first pass or in `every` pass.
        let mut wakers: [Option<Waker>; 3] = [None, None, None];
        let mut poll = |waking: Option<usize>, every: bool| {
            let mut turns = 0;
            let poll = waker.poll(&mut cx, |part: usize, cx| {
                wakers[part] = Some(cx.waker().clone());
                if waking == Some(part)
                    && (every || turns < 3)
                    && let Some(waker) = &wakers[1]
                {
                    waker.wake_by_ref();
                }
                turns += 1;
                Poll::<()>::Pending
            });
            assert!(poll.is_pending());
            turns
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
        wakers[0].take().unwrap().wake();
        assert_eq!(woken(), 2);
    }
}
