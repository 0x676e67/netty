//! Extensions for HTTP messages in netty.
//!
//! Extensions carry metadata and callbacks alongside a message's headers and body.
//! Use [`http::Request::extensions`] or [`http::Response::extensions`] to read the
//! message's [`http::Extensions`] map.
//!
//! This module provides:
//!
//! - [`ReasonPhrase`]: a non-canonical reason phrase received in an HTTP/1 response.
//! - [`on_informational`]: a callback for HTTP/1 informational responses, excluding 101.
//! - [`on_preserve_header`]: custom request header handling, including HTTP/1 casing and order.
//!
//! For example, a response may carry a reason phrase:
//!
//! ```
//! # let response = http::Response::new(());
//! let reason = response.extensions().get::<netty::ext::ReasonPhrase>();
//! if let Some(reason) = reason {
//!     println!("{reason:?}");
//! }
//! ```

mod h1_reason_phrase;
mod informational;
mod preserve_header;

pub use self::{
    h1_reason_phrase::ReasonPhrase,
    informational::on_informational,
    preserve_header::{on_preserve_header, OnPreserveHeaderCallback},
};
pub(crate) use self::{informational::OnInformational, preserve_header::OnPreserveHeader};
