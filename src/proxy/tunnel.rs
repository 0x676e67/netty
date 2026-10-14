//! HTTP CONNECT tunnels.
//!
//! See [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6): any 2xx
//! response switches the connection to tunnel mode.

use std::{
    error::Error as StdError,
    fmt, future,
    io::{self, Write as _},
    task::{Context, Poll},
};

use http::{
    HeaderMap, HeaderValue, StatusCode, Uri,
    header::{CONTENT_LENGTH, Entry, HOST, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;

use super::{ProxyDst, Tunneling, dst_host, dst_port, read, send};
use crate::error::BoxError;

/// Maximum number of headers accepted in the proxy response.
const MAX_HEADERS: usize = 64;

/// Maximum size of the proxy response, counting interim 1xx heads and the final head.
const MAX_RESPONSE_HEAD: usize = 8192;

/// Connector that opens an HTTP CONNECT tunnel.
///
/// The inner connector connects to `proxy_dst`; the destination passed to `call` is only used
/// in the CONNECT request sent over that connection. The handshake has no timeout of its own,
/// so bound the returned future, e.g. with a connect timeout around the whole connector.
#[derive(Clone)]
pub struct TunnelConnector<C> {
    headers: HeaderMap,
    inner: C,
    proxy_dst: Uri,
}

/// Errors that can occur while opening a tunnel.
#[derive(Debug)]
#[non_exhaustive]
pub enum TunnelError {
    /// The inner connector failed to connect to the proxy.
    ConnectFailed(BoxError),
    /// An I/O error occurred during the handshake.
    Io(io::Error),
    /// The proxy response could not be parsed.
    Parse(BoxError),
    /// The destination URI has no host.
    MissingHost,
    /// The destination port is zero or not a valid `u16`.
    InvalidPort,
    /// The proxy answered `407 Proxy Authentication Required`.
    ProxyAuthRequired,
    /// The proxy response heads, interim 1xx included, exceeded the size or header count limit.
    ProxyHeadersTooLong,
    /// The proxy closed the connection before completing its response.
    TunnelUnexpectedEof,
    /// The proxy refused the tunnel with this status.
    TunnelUnsuccessful(StatusCode),
}

// ===== impl TunnelConnector =====

impl<C> TunnelConnector<C> {
    /// Creates a connector that tunnels through the proxy at `proxy_dst`.
    ///
    /// Userinfo in `proxy_dst` is not sent; pass credentials with [`with_auth`](Self::with_auth).
    pub fn new(proxy_dst: Uri, inner: C) -> Self {
        TunnelConnector {
            headers: HeaderMap::new(),
            inner,
            proxy_dst,
        }
    }

    /// Sends `auth` as the `Proxy-Authorization` header, marked sensitive.
    pub fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        auth.set_sensitive(true);
        self.headers.insert(PROXY_AUTHORIZATION, auth);
        self
    }

    /// Adds extra headers to the CONNECT request, replacing any set earlier under the same name.
    ///
    /// A `Host` replaces the generated one and `Proxy-Authorization` is marked sensitive.
    /// `Content-Length` and `Transfer-Encoding` are dropped, since a CONNECT request has no
    /// content ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)).
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        if let Entry::Occupied(mut auth) = headers.entry(PROXY_AUTHORIZATION) {
            auth.iter_mut().for_each(|value| value.set_sensitive(true));
        }
        headers.remove(CONTENT_LENGTH);
        headers.remove(TRANSFER_ENCODING);
        if self.headers.is_empty() {
            self.headers = headers;
        } else {
            self.headers.extend(headers);
        }
        self
    }
}

impl<C: fmt::Debug> fmt::Debug for TunnelConnector<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConnector")
            .field("headers", &self.headers)
            .field("inner", &self.inner)
            .field("proxy_dst", &ProxyDst(&self.proxy_dst))
            .finish()
    }
}

impl<C> Service<Uri> for TunnelConnector<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = C::Response;
    type Error = TunnelError;
    type Future = Tunneling<C::Response, TunnelError>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|err| TunnelError::ConnectFailed(err.into()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        // Reject a bad destination before the inner connector starts connecting to the proxy.
        let req = match connect_request(&dst, &self.headers) {
            Ok(req) => req,
            Err(err) => return Tunneling::new(future::ready(Err(err))),
        };
        let connecting = self.inner.call(self.proxy_dst.clone());

        Tunneling::new(async move {
            let io = connecting
                .await
                .map_err(|err| TunnelError::ConnectFailed(err.into()))?;
            tunnel(io, &req).await
        })
    }
}

/// Serializes the CONNECT request for `dst`.
fn connect_request(dst: &Uri, headers: &HeaderMap) -> Result<Vec<u8>, TunnelError> {
    let host = dst_host(dst).ok_or(TunnelError::MissingHost)?;
    let port = dst_port(dst).ok_or(TunnelError::InvalidPort)?;

    let fields: usize = headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    let mut req = Vec::with_capacity(2 * host.len() + 48 + fields);
    write!(req, "CONNECT {host}:{port} HTTP/1.1\r\nHost: ").map_err(TunnelError::Io)?;
    // A single Host line: the caller's if set, else the request target
    // (RFC 9112 §3.2: https://www.rfc-editor.org/rfc/rfc9112#section-3.2).
    match headers.get(HOST) {
        Some(value) => req.extend_from_slice(value.as_bytes()),
        None => write!(req, "{host}:{port}").map_err(TunnelError::Io)?,
    }
    req.extend_from_slice(b"\r\n");
    for (name, value) in headers.iter().filter(|(name, _)| *name != HOST) {
        req.extend_from_slice(name.as_str().as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(value.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    Ok(req)
}

/// Sends the CONNECT request and waits for a 2xx response.
async fn tunnel<T>(mut io: T, req: &[u8]) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    send(&mut io, req).await.map_err(TunnelError::Io)?;

    read_response(&mut io).await?;
    Ok(io)
}

async fn read_response<T>(io: &mut T) -> Result<(), TunnelError>
where
    T: AsyncRead + Unpin,
{
    // Interim 1xx heads stay at the front of `buf`, so all heads share the size limit.
    let mut buf = [0; MAX_RESPONSE_HEAD];
    let mut start = 0;
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Err(TunnelError::ProxyHeadersTooLong);
        }
        // Never read past the end of the head: bytes the origin sends right after the
        // response (e.g. a server-first protocol banner) must stay in `io`. The shortest
        // possible remainder is "\n" after a line break, otherwise "\n\n".
        let head = &buf[start..len];
        let want = if head.ends_with(b"\n") || head.ends_with(b"\n\r") {
            1
        } else {
            2
        };
        let end = (len + want).min(buf.len());
        let n = read(io, &mut buf[len..end])
            .await
            .map_err(TunnelError::Io)?;
        if n == 0 {
            return Err(TunnelError::TunnelUnexpectedEof);
        }
        len += n;
        // A head ends with an empty line, so parse only there, plus while the version and
        // status code arrive so that a non-HTTP reply fails fast.
        let head = &buf[start..len];
        if !(head.ends_with(b"\n\n") || head.ends_with(b"\n\r\n"))
            && head.trim_ascii_start().len() > b"HTTP/1.1 200 ".len()
        {
            continue;
        }

        let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut res = httparse::Response::new(&mut slots);
        let parsed = match res.parse(head) {
            Ok(httparse::Status::Complete(parsed)) => parsed,
            Ok(httparse::Status::Partial) => continue,
            Err(httparse::Error::TooManyHeaders) => {
                return Err(TunnelError::ProxyHeadersTooLong);
            }
            Err(err) => return Err(TunnelError::Parse(err.into())),
        };
        let status = res
            .code
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| TunnelError::Parse(httparse::Error::Status.into()))?;
        match status {
            // Skip interim responses and keep reading the final one:
            // https://www.rfc-editor.org/rfc/rfc9110#section-15.2
            s if s.is_informational() && s != StatusCode::SWITCHING_PROTOCOLS => start += parsed,
            s if s.is_success() => {
                // The reads stop at the end of the head, so no tunneled byte sits in `buf`.
                debug_assert_eq!(start + parsed, len);
                return Ok(());
            }
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
                return Err(TunnelError::ProxyAuthRequired);
            }
            s => return Err(TunnelError::TunnelUnsuccessful(s)),
        }
    }
}

// ===== impl TunnelError =====

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("tunnel error: ")?;
        match self {
            TunnelError::ConnectFailed(_) => f.write_str("failed to create underlying connection"),
            TunnelError::Io(_) => f.write_str("io error establishing tunnel"),
            TunnelError::Parse(_) => f.write_str("invalid proxy response"),
            TunnelError::MissingHost => f.write_str("missing destination host"),
            TunnelError::InvalidPort => f.write_str("invalid destination port"),
            TunnelError::ProxyAuthRequired => f.write_str("proxy authorization required"),
            TunnelError::ProxyHeadersTooLong => f.write_str("proxy response headers too long"),
            TunnelError::TunnelUnexpectedEof => f.write_str("unexpected end of file"),
            TunnelError::TunnelUnsuccessful(status) => write!(f, "unsuccessful: {status}"),
        }
    }
}

impl StdError for TunnelError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            TunnelError::ConnectFailed(err) | TunnelError::Parse(err) => Some(&**err),
            TunnelError::Io(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Ready, poll_fn};

    use tokio::io::{DuplexStream, duplex};

    use super::*;

    /// Connector handing out one end of an in-memory pipe, refusing once it has none.
    struct Pipe(Option<DuplexStream>);

    impl Service<Uri> for Pipe {
        type Response = DuplexStream;
        type Error = io::Error;
        type Future = Ready<io::Result<DuplexStream>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(match self.0 {
                Some(_) => Ok(()),
                None => Err(io::ErrorKind::ConnectionRefused.into()),
            })
        }

        fn call(&mut self, dst: Uri) -> Self::Future {
            assert_eq!(dst, "http://proxy.local:3128");
            std::future::ready(
                self.0
                    .take()
                    .ok_or_else(|| io::ErrorKind::ConnectionRefused.into()),
            )
        }
    }

    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "reads an 8 KiB response head one or two bytes at a time"
    )]
    async fn response_head_outcomes() {
        let long = format!(
            "HTTP/1.1 200 OK\r\nx: {}\r\n\r\n",
            "a".repeat(MAX_RESPONSE_HEAD)
        );
        // Interim heads share the size limit, so endless 1xx responses cannot stall the loop.
        let interim = "HTTP/1.1 103 Early Hints\r\n\r\n".repeat(MAX_RESPONSE_HEAD / 16);
        let crowded = format!(
            "HTTP/1.1 200 OK\r\n{}\r\n",
            "x: 1\r\n".repeat(MAX_HEADERS + 1)
        );
        let at_header_limit = format!(
            "HTTP/1.1 200 OK\r\n{}\r\nbanner",
            "x: 1\r\n".repeat(MAX_HEADERS)
        );
        let padded_head = |len: usize| {
            let prefix = "HTTP/1.1 200 OK\r\nx: ";
            format!("{prefix}{}\r\n\r\n", "a".repeat(len - prefix.len() - 4))
        };
        let at_size_limit = format!("{}banner", padded_head(MAX_RESPONSE_HEAD));
        let interim_head = "HTTP/1.1 100 Continue\r\n\r\n";
        let at_cumulative_limit = format!(
            "{interim_head}{}banner",
            padded_head(MAX_RESPONSE_HEAD - interim_head.len())
        );
        // `Ok` holds the bytes that must remain readable after the head.
        type Expected = Result<&'static [u8], fn(&TunnelError) -> bool>;
        let cases: [(&[u8], Expected); 17] = [
            (b"HTTP/1.1 204 No Content\r\n\r\n", Ok(b"")),
            (
                b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-banner",
                Ok(b"SSH-2.0-banner"),
            ),
            (b"HTTP/1.1 200 OK\n\nbanner", Ok(b"banner")),
            (b"\r\nHTTP/1.1 200 OK\r\n\r\nbanner", Ok(b"banner")),
            (
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nbanner",
                Ok(b"banner"),
            ),
            // A 101 hands the connection to another protocol, so it is not skipped.
            (
                b"HTTP/1.1 101 Switching Protocols\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
                Err(|e| {
                    matches!(
                        e,
                        TunnelError::TunnelUnsuccessful(StatusCode::SWITCHING_PROTOCOLS)
                    )
                }),
            ),
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
                Err(|e| matches!(e, TunnelError::ProxyAuthRequired)),
            ),
            (
                b"HTTP/1.1 302 Found\r\n\r\n",
                Err(|e| matches!(e, TunnelError::TunnelUnsuccessful(StatusCode::FOUND))),
            ),
            (
                b"SSH-2.0-OpenSSH_9.6\r\n",
                Err(|e| matches!(e, TunnelError::Parse(_))),
            ),
            // A SOCKS5 server refusing the greeting: rejected on its first bytes, not at EOF.
            (b"\x05\xff", Err(|e| matches!(e, TunnelError::Parse(_)))),
            (
                b"HTTP/1.1 200 OK\r\n",
                Err(|e| matches!(e, TunnelError::TunnelUnexpectedEof)),
            ),
            (
                long.as_bytes(),
                Err(|e| matches!(e, TunnelError::ProxyHeadersTooLong)),
            ),
            (
                interim.as_bytes(),
                Err(|e| matches!(e, TunnelError::ProxyHeadersTooLong)),
            ),
            (
                crowded.as_bytes(),
                Err(|e| matches!(e, TunnelError::ProxyHeadersTooLong)),
            ),
            (at_header_limit.as_bytes(), Ok(b"banner")),
            (at_size_limit.as_bytes(), Ok(b"banner")),
            (at_cumulative_limit.as_bytes(), Ok(b"banner")),
        ];

        for (response, expected) in cases {
            let mut io = response;
            let result = read_response(&mut io).await;
            match (result, expected) {
                (Ok(()), Ok(rest)) => assert_eq!(io, rest),
                (Err(err), Err(matches)) => assert!(matches(&err), "unexpected error: {err:?}"),
                (Ok(()), Err(_)) => panic!("unexpected success"),
                (Err(err), Ok(_)) => panic!("unexpected error: {err:?}"),
            }
        }
    }

    #[tokio::test]
    async fn fails_before_handshake() {
        type Expected = fn(&TunnelError) -> bool;
        let missing_host: Expected = |e| matches!(e, TunnelError::MissingHost);
        let invalid_port: Expected = |e| matches!(e, TunnelError::InvalidPort);
        let cases = [
            ("/relative", missing_host),
            ("http://:80/", missing_host),
            ("https://[]:443/", missing_host),
            // `Uri` accepts these ports, but none can be dialed.
            ("https://example.com:65536/", invalid_port),
            ("https://[2001:db8::1]:65536/", invalid_port),
            ("https://[x@example.com:1]", invalid_port),
            ("https://example.com:0/", invalid_port),
        ];
        for (dst, matches) in cases {
            // With the proxy end gone, a handshake attempt fails with an IO error.
            let (client, server) = duplex(64);
            drop(server);
            let mut connector = TunnelConnector::new(
                "http://proxy.local:3128".parse().unwrap(),
                Pipe(Some(client)),
            );
            let err = connector
                .call(dst.parse().unwrap())
                .await
                .expect_err("bad destination");
            assert!(matches(&err), "{dst}: {err:?}");
            assert!(connector.inner.0.is_some(), "{dst}: connected to the proxy");
        }

        // An unreachable proxy keeps the inner error as the source.
        let mut connector =
            TunnelConnector::new("http://proxy.local:3128".parse().unwrap(), Pipe(None));
        let errs = [
            poll_fn(|cx| connector.poll_ready(cx))
                .await
                .expect_err("proxy unreachable"),
            connector
                .call("https://example.com".parse().unwrap())
                .await
                .expect_err("proxy unreachable"),
        ];
        for err in errs {
            assert!(matches!(err, TunnelError::ConnectFailed(_)), "{err:?}");
            let source = err.source().and_then(|e| e.downcast_ref::<io::Error>());
            assert_eq!(
                source.map(io::Error::kind),
                Some(io::ErrorKind::ConnectionRefused)
            );
        }
    }

    #[test]
    fn debug_hides_credentials() {
        let proxy: Uri = "http://user:secret@proxy.local:3128".parse().unwrap();
        let auth = HeaderValue::from_static("Basic c2VjcmV0");
        let mut headers = HeaderMap::new();
        headers.insert(PROXY_AUTHORIZATION, auth.clone());
        headers.append(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic b3RoZXI="),
        );
        let mut trace = HeaderMap::new();
        trace.insert("x-trace", HeaderValue::from_static("1"));
        for connector in [
            TunnelConnector::new(proxy.clone(), ()).with_auth(auth),
            TunnelConnector::new(proxy.clone(), ()).with_headers(headers.clone()),
            TunnelConnector::new(proxy, ())
                .with_headers(trace)
                .with_headers(headers.clone()),
        ] {
            let debug = format!("{connector:?}");
            assert!(debug.contains("http://proxy.local:3128"), "{debug}");
            for secret in ["secret", "c2VjcmV0", "b3RoZXI="] {
                assert!(!debug.contains(secret), "{debug}");
            }
        }
    }
}
