//! Compio-based executor and timer for the test fixtures.
#[path = "compio/future.rs"]
pub mod future;
#[path = "compio/io.rs"]
pub mod io;

use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures_util::future::LocalBoxFuture;
use netty::rt::{Executor, Sleep, Timer};
use send_wrapper::SendWrapper;

/// Future executor that utilises the `compio` runtime.
#[non_exhaustive]
#[derive(Default, Clone, Debug)]
pub struct CompioExecutor {
    _priv: (),
}

impl CompioExecutor {
    /// Create a new [`CompioExecutor`].
    #[inline]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl<Fut> Executor<Fut> for CompioExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    #[inline]
    fn execute(&self, fut: Fut) {
        compio::runtime::spawn(fut).detach();
    }
}

/// A Timer that uses the compio runtime.
#[non_exhaustive]
#[derive(Default, Clone, Debug)]
pub struct CompioTimer {
    _priv: (),
}

impl CompioTimer {
    /// Create a new [`CompioTimer`].
    #[inline]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

/// A sleep future wrapping a compio timer via SendWrapper.
///
/// compio futures are `!Send` (thread-per-core), so we wrap in `SendWrapper`
/// to satisfy the `Sleep` trait's `Send` bound.
struct CompioSleep {
    inner: SendWrapper<LocalBoxFuture<'static, ()>>,
}

impl CompioSleep {
    #[inline]
    fn new<Fut>(fut: Fut) -> Self
    where
        Fut: Future<Output = ()> + 'static,
    {
        Self {
            inner: SendWrapper::new(Box::pin(fut)),
        }
    }
}

impl Timer for CompioTimer {
    #[inline]
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        Box::pin(CompioSleep::new(compio::time::sleep(duration)))
    }

    #[inline]
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(CompioSleep::new(compio::time::sleep_until(deadline)))
    }

    #[inline]
    fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
        sleep.as_mut().reset(new_deadline);
    }
}

impl Future for CompioSleep {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

impl Sleep for CompioSleep {
    #[inline]
    fn reset(self: Pin<&mut Self>, deadline: Instant) {
        self.get_mut().inner = SendWrapper::new(Box::pin(compio::time::sleep_until(deadline)));
    }
}

impl Debug for CompioSleep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompioSleep").finish()
    }
}
