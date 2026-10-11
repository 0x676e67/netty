//! Proxy connectors.
//!
//! Each connector wraps an inner [`tower_service::Service<Uri>`] that connects to the proxy,
//! then runs the proxy handshake for the destination passed to `call`. DNS, TLS and the
//! transport itself stay with the inner connector.

#[cfg(feature = "tunnel")]
pub mod tunnel;

use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::{Uri, uri::Scheme};

/// Future returned by the proxy connectors.
#[must_use = "futures do nothing unless polled"]
pub struct Tunneling<T, E> {
    fut: BoxFuture<'static, Result<T, E>>,
}

// ===== impl Tunneling =====

impl<T, E> Tunneling<T, E> {
    fn new<F>(fut: F) -> Self
    where
        F: Future<Output = Result<T, E>> + Send + 'static,
    {
        Tunneling { fut: Box::pin(fut) }
    }
}

impl<T, E> Future for Tunneling<T, E> {
    type Output = Result<T, E>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

impl<T, E> fmt::Debug for Tunneling<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunneling").finish_non_exhaustive()
    }
}

/// Returns the destination host, rejecting an empty one (RFC 9110 §4.2.1).
fn dst_host(uri: &Uri) -> Option<&str> {
    uri.host().filter(|host| !matches!(*host, "" | "[]"))
}

/// Returns the destination port, defaulting by scheme.
fn port_or_default(uri: &Uri) -> u16 {
    match uri.port_u16() {
        Some(port) => port,
        None if uri.scheme() == Some(&Scheme::HTTPS) => 443,
        None => 80,
    }
}

/// Debug view of a proxy URI without its userinfo, which may hold credentials.
struct ProxyDst<'a>(&'a Uri);

impl fmt::Debug for ProxyDst<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = self.0.scheme_str() {
            write!(f, "{scheme}://")?;
        }
        let authority = self.0.authority().map_or("", |a| a.as_str());
        f.write_str(
            authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host),
        )
    }
}
