#![deny(unused)]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)]
#![cfg_attr(test, deny(rust_2018_idioms))]
#![cfg_attr(test, deny(warnings))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(all(test, feature = "nightly"), feature(test))]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # netty
//!
//! An asynchronous HTTP library with streaming bodies and pluggable runtime and transport
//! interfaces.
//!
//! Much of this codebase is adapted and refined from [hyper](https://github.com/hyperium/hyper),
//! aiming to match its performance and reliability for asynchronous HTTP/1 and HTTP/2.
//! HTTP/3 over a QUIC connection the caller establishes is available with the `http3`
//! feature, and HTTP Datagram sessions with `http3-datagram`.
//!
//! # Cancel safety
//!
//! Request futures support cancellation: dropping a future before it
//! completes is the supported way to cancel the operation. The protocol in
//! use changes what that cancellation actually does on the wire:
//!
//! - **HTTP/1** has no in-protocol way to abort a single request without affecting the shared
//!   connection, so dropping an in-flight request future closes the underlying I/O when the
//!   connection driver observes the cancellation. Any subsequent call on the same `SendRequest`
//!   returns a `canceled` error; the connection cannot be reused.
//! - **HTTP/2**, if a stream has been opened, resets the single stream with `RST_STREAM` (`CANCEL`
//!   error code) and notifies the peer as its background tasks are driven rather than continuing to
//!   deliver a response body that would be discarded. The shared connection stays usable for other
//!   in-flight and future requests.
//! - **HTTP/3**, if a stream has been opened, cancels its unfinished send and receive directions
//!   with `H3_REQUEST_CANCELLED`, leaving the shared connection usable. After the response has been
//!   delivered, dropping its body only cancels receiving; unfinished request body sending can
//!   continue independently.
//!
//! Keep driving the connection and its background tasks to complete cancellation.
//!
//! See the documentation on individual futures — for example
//! [`conn::http1::SendRequest::try_send_request`], the equivalent in
//! [`conn::http2::SendRequest::try_send_request`] and, with the `http3` feature,
//! `conn::http3::SendRequest::try_send_request` — for the protocol-specific behavior on
//! cancellation.

#[macro_use]
mod trace;
mod dispatch;
mod error;
mod lock;
mod proto;

pub mod body;
pub mod conn;
pub mod ext;
pub mod rt;
pub mod upgrade;
#[cfg(feature = "http3")]
pub use self::proto::http3;
pub use self::{
    error::{Error, Result},
    proto::{http1, http2},
};
