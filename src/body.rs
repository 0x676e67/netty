//! Streaming bodies for Requests and Responses
//!
//! Both clients and servers use streaming bodies for requests and responses, instead of fully
//! buffering them. This approach avoids unnecessary memory usage and enables back-pressure by only
//! reading when needed.
//!
//! There are two main components:
//!
//! - **[`http_body::Body`] trait**: Describes all possible body types. Any type implementing this
//!   trait can be used as a body, allowing applications to have fine-grained control over
//!   streaming.
//! - **[`Incoming`] concrete type**: An implementation of `Body` provided by this module, used as a
//!   receive stream (for server requests and client responses).
//!
//! Additional implementations are available in [`http-body-util`][], such as `Full` or `Empty`
//! bodies.
//!
//! ## Reading a body
//!
//! The [`BodyExt`][] extension trait provides an asynchronous way to read the
//! frames of a body. A frame can contain either data or trailers:
//!
//! ```
//! use http_body_util::BodyExt as _;
//! use wreq_proto::body::Incoming;
//!
//! async fn read_body(mut body: Incoming) -> Result<(), wreq_proto::Error> {
//!     while let Some(frame) = body.frame().await {
//!         let frame = frame?;
//!
//!         if let Some(data) = frame.data_ref() {
//!             println!("received {} bytes", data.len());
//!         }
//!
//!         if let Some(trailers) = frame.trailers_ref() {
//!             println!("received trailers: {trailers:?}");
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! A body only advances when it is polled. Processing each frame before
//! polling for the next one preserves back-pressure on the connection.
//!
//! If a body is known to be small, it can be collected into memory instead:
//!
//! ```
//! use http_body_util::BodyExt as _;
//! use bytes::Bytes;
//! use wreq_proto::body::Incoming;
//!
//! /// Consider using `Limited` if the body is untrusted.
//! async fn read_entire_body(body: Incoming) -> Result<Bytes, wreq_proto::Error> {
//!     Ok(body.collect().await?.to_bytes())
//! }
//! ```
//!
//! Collecting buffers the whole body, so it should be avoided for large or
//! untrusted bodies unless their size is limited.
//!
//! [`http-body-util`]: https://docs.rs/http-body-util
//! [`BodyExt`]: https://docs.rs/http-body-util/latest/http_body_util/trait.BodyExt.html
//! [`http_body::Body`]: https://docs.rs/http-body

mod chan;
mod incoming;
mod length;

pub use self::incoming::Incoming;
pub(crate) use self::{incoming::Sender, length::DecodedLength};

fn _assert_send_sync() {
    fn _assert_send<T: Send>() {}

    fn _assert_sync<T: Sync>() {}

    _assert_send::<Incoming>();
    _assert_sync::<Incoming>();
}
