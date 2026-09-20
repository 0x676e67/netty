use std::{
    future::{poll_fn, Future},
    pin::pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Waker},
    time::Instant,
};

use futures_util::task::{waker_ref, ArcWake};

#[derive(Default)]
pub(super) struct Stats {
    tasks: AtomicU64,
    polls: AtomicU64,
    wakes: AtomicU64,
    poll_ns: AtomicU64,
}

struct ObservedWaker {
    inner: Waker,
    stats: Arc<Stats>,
}

impl ArcWake for ObservedWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.stats.wakes.fetch_add(1, Ordering::Relaxed);
        arc_self.inner.wake_by_ref();
    }
}

impl Stats {
    pub(super) fn report(&self, context: &str, role: &str, requests: u64) {
        eprintln!(
            "task-profile,{context},{role},{requests},{},{},{},{}",
            self.tasks.load(Ordering::Relaxed),
            self.polls.load(Ordering::Relaxed),
            self.wakes.load(Ordering::Relaxed),
            self.poll_ns.load(Ordering::Relaxed),
        );
    }
}

// Poll durations include preemption, but exclude time spent suspended between
// polls. The extra waker and counters perturb scheduling: this is diagnostic
// evidence, not a CPU profile or an uninstrumented throughput measurement.
pub(super) async fn observe<F: Future>(future: F, stats: Arc<Stats>) -> F::Output {
    stats.tasks.fetch_add(1, Ordering::Relaxed);
    let mut future = pin!(future);
    let mut observed: Option<Arc<ObservedWaker>> = None;
    poll_fn(|cx| {
        if observed
            .as_ref()
            .is_none_or(|waker| !waker.inner.will_wake(cx.waker()))
        {
            observed = Some(Arc::new(ObservedWaker {
                inner: cx.waker().clone(),
                stats: stats.clone(),
            }));
        }
        let waker = waker_ref(observed.as_ref().unwrap());
        let mut context = Context::from_waker(&waker);
        let started = Instant::now();
        let result = future.as_mut().poll(&mut context);
        stats.poll_ns.fetch_add(
            u64::try_from(started.elapsed().as_nanos()).unwrap(),
            Ordering::Relaxed,
        );
        stats.polls.fetch_add(1, Ordering::Relaxed);
        result
    })
    .await
}
