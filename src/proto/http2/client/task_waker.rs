//! The connection task's waker, which turns wakeups from the task's own work into another pass.
//!
//! A request wakes the connection to write its frames, and a read completes responses the task
//! drives itself. Rescheduling the running task for those would push it through the run queue,
//! where an idle worker may steal it.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use futures_util::task::AtomicWaker;

const IDLE: u8 = 0;
const POLLING: u8 = 1;
const WOKEN: u8 = 2;

/// Passes in one poll before a task that keeps waking itself yields.
const MAX_PASSES: usize = 4;

pub(super) struct TaskWaker {
    state: AtomicU8,
    task: AtomicWaker,
}

impl TaskWaker {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(IDLE),
            task: AtomicWaker::new(),
        })
    }

    /// Runs `pass` with this waker until a pass ends without a wakeup, or is ready.
    pub(super) fn poll<T>(
        self: &Arc<Self>,
        cx: &mut Context<'_>,
        mut pass: impl FnMut(&mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        self.task.register(cx.waker());
        let waker = Waker::from(self.clone());
        let mut inner = Context::from_waker(&waker);
        for _ in 0..MAX_PASSES {
            self.state.store(POLLING, Ordering::Release);
            let poll = pass(&mut inner);
            let woken = self.state.swap(IDLE, Ordering::AcqRel) == WOKEN;
            if poll.is_ready() || !woken {
                return poll;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // A pass in progress sees the wakeup as it ends; otherwise the task is idle.
        if self
            .state
            .compare_exchange(POLLING, WOKEN, Ordering::AcqRel, Ordering::Acquire)
            == Err(IDLE)
        {
            self.task.wake();
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
    fn wakeups_during_a_pass_take_another_pass() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let task = Waker::from(count.clone());
        let mut cx = Context::from_waker(&task);
        let waker = TaskWaker::new();
        let woken = || count.0.load(Ordering::Relaxed);

        // A pass that wakes itself runs again instead of waking the task.
        let mut passes = 0;
        let poll = waker.poll(&mut cx, |cx| {
            passes += 1;
            if passes == 1 {
                cx.waker().wake_by_ref();
            }
            Poll::<()>::Pending
        });
        assert!(poll.is_pending());
        assert_eq!((passes, woken()), (2, 0));

        // Once idle, a wakeup wakes the task.
        Waker::from(waker.clone()).wake();
        assert_eq!(woken(), 1);

        // A pass that keeps waking itself yields after a few passes.
        passes = 0;
        let poll = waker.poll(&mut cx, |cx| {
            passes += 1;
            cx.waker().wake_by_ref();
            Poll::<()>::Pending
        });
        assert!(poll.is_pending());
        assert_eq!((passes, woken()), (MAX_PASSES, 2));
    }
}
