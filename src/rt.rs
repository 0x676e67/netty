//! Runtime components
//!
//! This module provides traits and types that allow netty to be runtime-agnostic.
//! By abstracting over async runtimes, netty can work with different executors, timers, and IO
//! transports.
//!
//! The main runtime components are:
//!
//! - **Executors**: Traits for spawning and running futures, enabling integration with any async
//!   runtime.
//! - **Timers**: Abstractions for sleeping and scheduling tasks, allowing time-based operations to
//!   be runtime-independent.
//! - **IO Transports**: [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] provide asynchronous
//!   reading and writing; applications provide adapters for other IO backends.
//!
//! By implementing these traits, you can customize how netty interacts with your chosen
//! runtime environment. Concrete runtime adapters in this repository are test utilities only.

pub mod bounds;
#[cfg(feature = "http3")]
pub mod quic;
mod timer;

pub use self::timer::{Sleep, Time, Timer};

/// An executor of futures.
///
/// This trait allows abstract over async runtimes. Implement this trait for your own type.
pub trait Executor<Fut> {
    /// Place the future into the executor to be run.
    fn execute(&self, fut: Fut);
}
