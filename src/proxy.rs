//! Proxy connectors.
//!
//! Each connector wraps an inner [`tower_service::Service<Uri>`] that connects to the proxy,
//! then runs the proxy handshake for the destination passed to `call`. TLS and the transport
//! stay with the inner connector; SOCKS local DNS goes through a caller-supplied resolver.

#[cfg(feature = "masque")]
pub mod masque;
#[cfg(feature = "socks")]
pub mod socks;
#[cfg(feature = "tunnel")]
pub mod tunnel;

use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::Uri;

#[cfg(any(feature = "tunnel", feature = "socks"))]
use self::io::{read, send};

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

/// Returns the destination host, rejecting an empty one
/// ([RFC 9110 §4.2.1](https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1)).
fn dst_host(uri: &Uri) -> Option<&str> {
    uri.host().filter(|host| !matches!(*host, "" | "[]"))
}

/// Returns the destination port, or `None` if it is zero or not a valid `u16`.
///
/// Without a port, `http` and `ws` default to 80 and anything else, no scheme included, to 443.
#[cfg(any(feature = "tunnel", feature = "socks"))]
fn dst_port(uri: &Uri) -> Option<u16> {
    let authority = uri.authority()?;
    if let Some(port) = authority.port_u16() {
        return (port != 0).then_some(port);
    }
    // `port_u16` is also `None` for a port `Uri` accepts but a u16 cannot hold, so only an
    // absent or empty port, right after the host, takes the default.
    let host_port = authority.as_str().rsplit('@').next()?;
    if !matches!(host_port.strip_prefix(authority.host())?, "" | ":") {
        return None;
    }
    let insecure = uri.scheme_str().is_some_and(|scheme| {
        scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("ws")
    });
    Some(if insecure { 80 } else { 443 })
}

/// Debug view of a proxy URI without its userinfo, which may hold credentials.
#[cfg(any(feature = "tunnel", feature = "socks"))]
struct ProxyDst<'a>(&'a Uri);

// ===== impl ProxyDst =====

#[cfg(any(feature = "tunnel", feature = "socks"))]
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

/// Byte-stream helpers for handshakes over the caller's IO.
#[cfg(any(feature = "tunnel", feature = "socks"))]
mod io {
    use std::{
        future::poll_fn,
        io,
        pin::Pin,
        task::{Poll, ready},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// Writes all of `buf` and flushes, so a request reaches the proxy before its reply is awaited.
    pub(super) async fn send<T>(io: &mut T, mut buf: &[u8]) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        while !buf.is_empty() {
            let n = poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, buf)).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
        }
        poll_fn(|cx| Pin::new(&mut *io).poll_flush(cx)).await
    }

    pub(super) async fn read<T>(io: &mut T, buf: &mut [u8]) -> io::Result<usize>
    where
        T: AsyncRead + Unpin,
    {
        poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut *buf);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
            Poll::Ready(Ok(buf.filled().len()))
        })
        .await
    }
}
