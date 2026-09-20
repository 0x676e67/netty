//! Runtime components
//!
//! The traits and types within this module are used to allow plugging in
//! runtime types. These include:
//!
//! - Executors
//! - Timers
//! - IO transports
//!
//! Applications provide implementations for their runtime and transport.
//! Concrete runtime adapters in this repository are test utilities only.

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
