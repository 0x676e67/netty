//! HTTP CONNECT tunnels.
//!
//! See [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6): any 2xx
//! response switches the connection to tunnel mode.

use std::{
    error::Error as StdError,
    fmt, io,
    task::{Context, Poll},
};

use http::{
    HeaderMap, HeaderValue, StatusCode, Uri,
    header::{Entry, PROXY_AUTHORIZATION},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;

use super::{ProxyDst, Tunneling, dst_host, port_or_default, read, send};
use crate::error::BoxError;

/// Maximum number of headers accepted in the proxy response.
const MAX_HEADERS: usize = 64;

/// Maximum size of the proxy response, counting interim 1xx heads and the final head.
const MAX_RESPONSE_HEAD: usize = 8192;

/// Connector that opens an HTTP CONNECT tunnel.
///
/// The inner connector connects to `proxy_dst`; the destination passed to `call` is only used
/// in the CONNECT request sent over that connection.
#[derive(Clone)]
pub struct TunnelConnector<C> {
    headers: Headers,
    inner: C,
    proxy_dst: Uri,
}

#[derive(Clone, Debug)]
enum Headers {
    Empty,
    Auth(HeaderValue),
    Extra(HeaderMap),
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
    /// The proxy answered `407 Proxy Authentication Required`.
    ProxyAuthRequired,
    /// The proxy response heads, interim 1xx included, exceeded the size limit.
    ProxyHeadersTooLong,
    /// The proxy closed the connection before completing its response.
    TunnelUnexpectedEof,
    /// The proxy refused the tunnel with this status.
    TunnelUnsuccessful(StatusCode),
}

// ===== impl TunnelConnector =====

impl<C> TunnelConnector<C> {
    /// Creates a connector that tunnels through the proxy at `proxy_dst`.
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        TunnelConnector {
            headers: Headers::Empty,
            inner: connector,
            proxy_dst,
        }
    }

    /// Sends `auth` as the `Proxy-Authorization` header, marked sensitive.
    pub fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        auth.set_sensitive(true);
        match self.headers {
            Headers::Empty => self.headers = Headers::Auth(auth),
            Headers::Auth(ref mut existing) => *existing = auth,
            Headers::Extra(ref mut extra) => {
                extra.insert(PROXY_AUTHORIZATION, auth);
            }
        }
        self
    }

    /// Adds extra headers to the CONNECT request, merged with any already set.
    ///
    /// A `Proxy-Authorization` among them is marked sensitive and replaces one set earlier.
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        if let Entry::Occupied(mut auth) = headers.entry(PROXY_AUTHORIZATION) {
            auth.iter_mut().for_each(|value| value.set_sensitive(true));
        }
        match self.headers {
            Headers::Empty => self.headers = Headers::Extra(headers),
            Headers::Auth(auth) => {
                headers.entry(PROXY_AUTHORIZATION).or_insert(auth);
                self.headers = Headers::Extra(headers);
            }
            Headers::Extra(ref mut extra) => extra.extend(headers),
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
        let connecting = self.inner.call(self.proxy_dst.clone());
        let headers = self.headers.clone();

        Tunneling::new(async move {
            let host = dst_host(&dst).ok_or(TunnelError::MissingHost)?;
            let conn = connecting
                .await
                .map_err(|err| TunnelError::ConnectFailed(err.into()))?;
            tunnel(conn, host, port_or_default(&dst), &headers).await
        })
    }
}

/// Sends the CONNECT request and waits for a 2xx response.
async fn tunnel<T>(mut io: T, host: &str, port: u16, headers: &Headers) -> Result<T, TunnelError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n").into_bytes();
    let mut put_header = |name: &[u8], value: &HeaderValue| {
        req.extend_from_slice(name);
        req.extend_from_slice(b": ");
        req.extend_from_slice(value.as_bytes());
        req.extend_from_slice(b"\r\n");
    };
    match headers {
        Headers::Empty => {}
        Headers::Auth(auth) => put_header(PROXY_AUTHORIZATION.as_str().as_bytes(), auth),
        Headers::Extra(extra) => {
            for (name, value) in extra {
                put_header(name.as_str().as_bytes(), value);
            }
        }
    }
    req.extend_from_slice(b"\r\n");

    send(&mut io, &req).await.map_err(TunnelError::Io)?;

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
        let n = read(&mut io, &mut buf[len..end])
            .await
            .map_err(TunnelError::Io)?;
        if n == 0 {
            return Err(TunnelError::TunnelUnexpectedEof);
        }
        len += n;

        let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut res = httparse::Response::new(&mut slots);
        let progress = res
            .parse(&buf[start..len])
            .map_err(|err| TunnelError::Parse(err.into()))?;
        if progress.is_partial() {
            continue;
        }
        let status = res
            .code
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| TunnelError::Parse(httparse::Error::Status.into()))?;
        match status {
            // RFC 9110 §15.2: skip interim responses and keep reading the final one.
            s if s.is_informational() && s != StatusCode::SWITCHING_PROTOCOLS => start = len,
            s if s.is_success() => return Ok(io),
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
    use std::{
        future::{Ready, poll_fn},
        time::Duration,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

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

    /// Answers one CONNECT request with `response`, returning the request it read.
    async fn proxy(mut io: DuplexStream, response: &[u8]) -> (DuplexStream, String) {
        let mut req = Vec::new();
        while !req.ends_with(b"\r\n\r\n") {
            req.push(io.read_u8().await.expect("read request"));
        }
        io.write_all(response).await.expect("write response");
        (io, String::from_utf8(req).expect("utf-8 request"))
    }

    /// Fails with `stalled` instead of hanging, e.g. when both ends wait on each other.
    async fn bounded<F: Future>(fut: F, stalled: &str) -> F::Output {
        // Miri runs too slowly for a wall-clock limit.
        if cfg!(miri) {
            return fut.await;
        }
        tokio::time::timeout(Duration::from_secs(5), fut)
            .await
            .expect(stalled)
    }

    #[tokio::test]
    async fn connector_establishes_tunnel() {
        fn auth() -> HeaderValue {
            HeaderValue::from_static("Basic Zm9vOmJhcg==")
        }
        fn header(name: &'static str, value: &'static str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static(value));
            headers
        }

        type Configure = fn(TunnelConnector<Pipe>) -> TunnelConnector<Pipe>;
        let cases: [(&str, Configure, &str); 5] = [
            (
                "https://example.com",
                |c| c.with_auth(auth()),
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
                 proxy-authorization: Basic Zm9vOmJhcg==\r\n\r\n",
            ),
            (
                "http://example.com",
                |c| c.with_auth(auth()).with_headers(header("x-trace", "1")),
                "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\
                 x-trace: 1\r\nproxy-authorization: Basic Zm9vOmJhcg==\r\n\r\n",
            ),
            (
                "https://example.com:8443",
                |c| c.with_headers(header("x-trace", "1")).with_auth(auth()),
                "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\
                 x-trace: 1\r\nproxy-authorization: Basic Zm9vOmJhcg==\r\n\r\n",
            ),
            (
                // The later Proxy-Authorization wins.
                "https://[2001:db8::1]",
                |c| {
                    c.with_auth(auth())
                        .with_headers(header("proxy-authorization", "Basic b3RoZXI="))
                },
                "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\
                 proxy-authorization: Basic b3RoZXI=\r\n\r\n",
            ),
            (
                "https://example.com",
                |c| {
                    c.with_headers(header("x-trace", "1"))
                        .with_auth(auth())
                        .with_headers(header("proxy-authorization", "Basic b3RoZXI="))
                },
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\
                 x-trace: 1\r\nproxy-authorization: Basic b3RoZXI=\r\n\r\n",
            ),
        ];

        for (dst, configure, expected) in cases {
            let (client, server) = duplex(64);
            let server = tokio::spawn(async move {
                let (mut io, req) =
                    proxy(server, b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                io.write_all(b"pong").await.expect("tunneled write");
                let mut ping = [0; 4];
                io.read_exact(&mut ping).await.expect("tunneled read");
                (req, ping)
            });

            let mut connector = configure(TunnelConnector::new(
                "http://proxy.local:3128".parse().unwrap(),
                Pipe(Some(client)),
            ));
            let handshake = connector.call(dst.parse().unwrap());
            let mut io = bounded(handshake, "handshake stalled; was the request terminated?")
                .await
                .expect("tunnel");

            let mut pong = [0; 4];
            bounded(io.read_exact(&mut pong), "tunneled read stalled")
                .await
                .expect("tunneled read");
            assert_eq!(&pong, b"pong");
            io.write_all(b"ping").await.expect("tunneled write");

            // The proxy reads "ping" right after the head, so stray request bytes show up here.
            let (req, ping) = bounded(server, "proxy stalled").await.expect("proxy task");
            assert_eq!(req, expected);
            assert_eq!(&ping, b"ping", "{dst}");
        }
    }

    #[tokio::test]
    #[cfg_attr(
        miri,
        ignore = "reads an 8 KiB response head one or two bytes at a time"
    )]
    async fn handshake_outcomes() {
        let long = format!(
            "HTTP/1.1 200 OK\r\nx: {}\r\n\r\n",
            "a".repeat(MAX_RESPONSE_HEAD)
        );
        // Interim heads share the size limit, so endless 1xx responses cannot stall the loop.
        let interim = "HTTP/1.1 103 Early Hints\r\n\r\n".repeat(MAX_RESPONSE_HEAD / 16);
        // `Ok` holds the bytes that must remain readable after the head.
        type Expected = Result<&'static [u8], fn(&TunnelError) -> bool>;
        let cases: [(&[u8], Expected); 11] = [
            (b"HTTP/1.1 204 No Content\r\n\r\n", Ok(b"")),
            (
                b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-banner",
                Ok(b"SSH-2.0-banner"),
            ),
            (b"HTTP/1.1 200 OK\n\nbanner", Ok(b"banner")),
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
        ];

        for (response, expected) in cases {
            let (client, server) = duplex(MAX_RESPONSE_HEAD * 2);
            let response = response.to_vec();
            // Dropping the proxy end after the response turns a short reply into EOF.
            let server = tokio::spawn(async move { drop(proxy(server, &response).await) });
            let result = bounded(
                tunnel(client, "example.com", 443, &Headers::Empty),
                "handshake stalled; was the request terminated and EOF handled?",
            )
            .await;
            bounded(server, "proxy stalled").await.expect("proxy task");
            match (result, expected) {
                (Ok(mut io), Ok(rest)) => {
                    let mut tail = Vec::new();
                    io.read_to_end(&mut tail)
                        .await
                        .expect("read tunneled bytes");
                    assert_eq!(tail, rest);
                }
                (Err(err), Err(matches)) => assert!(matches(&err), "unexpected error: {err:?}"),
                (Ok(_), Err(_)) => panic!("unexpected success"),
                (Err(err), Ok(_)) => panic!("unexpected error: {err:?}"),
            }
        }
    }

    #[tokio::test]
    async fn fails_before_handshake() {
        for dst in ["/relative", "http://:80/", "https://[]:443/"] {
            // With the proxy end gone, a handshake attempt would fail with an IO error.
            let (client, server) = duplex(64);
            drop(server);
            let err = TunnelConnector::new(
                "http://proxy.local:3128".parse().unwrap(),
                Pipe(Some(client)),
            )
            .call(dst.parse().unwrap())
            .await
            .expect_err("no host");
            assert!(matches!(err, TunnelError::MissingHost), "{dst}: {err:?}");
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
