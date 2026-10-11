//! SOCKS4/4a and SOCKS5/5h connectors.
//!
//! The CONNECT handshakes are delegated to [tokio-socks](https://docs.rs/tokio-socks);
//! [`udp`] implements SOCKS5 UDP ASSOCIATE.

pub mod udp;

use std::{
    borrow::Cow,
    error::Error as StdError,
    fmt,
    future::poll_fn,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::Utf8Error,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_socks::{
    TargetAddr,
    io::AsyncSocket,
    tcp::{Socks4Stream, Socks5Stream},
};
use tower_service::Service;

use super::{ProxyDst, Tunneling, dst_host, port_or_default};
use crate::error::BoxError;

/// Longest domain a SOCKS request can carry (RFC 1928 §5: one length octet).
const MAX_HOST_LEN: usize = 255;

/// Longest SOCKS4 user ID tokio-socks accepts.
const MAX_USER_ID_LEN: usize = 255;

/// Longest SOCKS4a user ID plus domain tokio-socks can encode: its request buffer is 513 bytes,
/// of which 8 are the header and 2 are NUL terminators.
const SOCKS4A_MAX_ID_AND_HOST: usize = 503;

/// SOCKS protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// SOCKS4, or SOCKS4a with remote DNS.
    V4,
    /// SOCKS5, or SOCKS5h with remote DNS.
    V5,
}

/// Where the destination host name is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsResolve {
    /// Resolve with the connector's resolver and send an IP address (`socks4`, `socks5`).
    Local,
    /// Send the host name for the proxy to resolve (`socks4a`, `socks5h`).
    Remote,
}

/// Connector that establishes connections through a SOCKS proxy.
///
/// The inner connector connects to `proxy_dst`. With [`DnsResolve::Local`], the resolver is a
/// `Service<Box<str>>` taking the host name and yielding socket addresses; SOCKS4 uses the
/// first IPv4 address it returns.
#[derive(Clone)]
pub struct SocksConnector<C, R> {
    inner: C,
    resolver: R,
    proxy_dst: Uri,
    auth: Option<(Bytes, Bytes)>,
    version: Version,
    dns_resolve: DnsResolve,
}

/// Errors that can occur while connecting through a SOCKS proxy.
#[derive(Debug)]
#[non_exhaustive]
pub enum SocksError {
    /// The inner connector failed to connect to the proxy.
    ConnectFailed(BoxError),
    /// The resolver failed to resolve the destination host.
    DnsResolveFailure(BoxError),
    /// The resolver returned no address usable by the SOCKS version.
    DnsFailure,
    /// The SOCKS handshake failed.
    Handshake(BoxError),
    /// SOCKS4 cannot reach an IPv6 destination.
    AddressNotSupported,
    /// The destination host does not fit in the SOCKS request.
    HostTooLong,
    /// The SOCKS4 user ID is longer than 255 bytes or contains a NUL byte.
    InvalidUserId,
    /// The credentials are not valid UTF-8.
    Utf8(Utf8Error),
    /// The destination URI has no host.
    MissingHost,
}

// ===== impl SocksConnector =====

impl<C, R> SocksConnector<C, R> {
    /// Creates a SOCKS5 connector with local DNS and no authentication.
    pub fn new(proxy_dst: Uri, inner: C, resolver: R) -> Self {
        SocksConnector {
            inner,
            resolver,
            proxy_dst,
            auth: None,
            version: Version::V5,
            dns_resolve: DnsResolve::Local,
        }
    }

    /// Sets the username and password; SOCKS4 sends the username as its user ID.
    #[inline]
    pub fn set_auth(&mut self, auth: Option<(Bytes, Bytes)>) {
        self.auth = auth;
    }

    /// Sets the SOCKS version.
    #[inline]
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    /// Sets where the destination host name is resolved.
    #[inline]
    pub fn set_dns_mode(&mut self, dns_resolve: DnsResolve) {
        self.dns_resolve = dns_resolve;
    }
}

impl<C: fmt::Debug, R: fmt::Debug> fmt::Debug for SocksConnector<C, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksConnector")
            .field("inner", &self.inner)
            .field("resolver", &self.resolver)
            .field("proxy_dst", &ProxyDst(&self.proxy_dst))
            .field("auth", &self.auth.as_ref().map(|_| "Sensitive"))
            .field("version", &self.version)
            .field("dns_resolve", &self.dns_resolve)
            .finish()
    }
}

impl<C, R> Service<Uri> for SocksConnector<C, R>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C::Error: Into<BoxError>,
    R: Service<Box<str>> + Clone + Send + 'static,
    R::Response: Iterator<Item = SocketAddr>,
    R::Error: Into<BoxError>,
    R::Future: Send,
{
    type Response = C::Response;
    type Error = SocksError;
    type Future = Tunneling<C::Response, SocksError>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|err| SocksError::ConnectFailed(err.into()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(self.proxy_dst.clone());
        let resolver = self.resolver.clone();
        let auth = self.auth.clone();
        let (version, dns_resolve) = (self.version, self.dns_resolve);

        Tunneling::new(async move {
            let host = dst_host(&dst).ok_or(SocksError::MissingHost)?;
            let port = port_or_default(&dst);
            let (target, conn) = futures_util::future::try_join(
                target_addr(host, port, version, dns_resolve, resolver),
                async {
                    connecting
                        .await
                        .map_err(|err| SocksError::ConnectFailed(err.into()))
                },
            )
            .await?;
            handshake(conn, target, version, auth).await
        })
    }
}

/// Picks the address sent to the proxy, resolving it locally if asked to.
async fn target_addr<R>(
    host: &str,
    port: u16,
    version: Version,
    dns_resolve: DnsResolve,
    mut resolver: R,
) -> Result<TargetAddr<'static>, SocksError>
where
    R: Service<Box<str>>,
    R::Response: Iterator<Item = SocketAddr>,
    R::Error: Into<BoxError>,
{
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let addr = match host.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) if dns_resolve == DnsResolve::Remote => {
            if host.len() > MAX_HOST_LEN {
                return Err(SocksError::HostTooLong);
            }
            return Ok(TargetAddr::Domain(Cow::Owned(host.to_owned()), port));
        }
        Err(_) => {
            poll_fn(|cx| resolver.poll_ready(cx))
                .await
                .map_err(|err| SocksError::DnsResolveFailure(err.into()))?;
            let mut addrs = resolver
                .call(host.into())
                .await
                .map_err(|err| SocksError::DnsResolveFailure(err.into()))?;
            let addr = match version {
                Version::V4 => addrs.find(SocketAddr::is_ipv4),
                Version::V5 => addrs.next(),
            };
            let mut addr = addr.ok_or(SocksError::DnsFailure)?;
            addr.set_port(port);
            addr
        }
    };

    if version == Version::V4 && addr.is_ipv6() {
        return Err(SocksError::AddressNotSupported);
    }
    Ok(TargetAddr::Ip(addr))
}

async fn handshake<T>(
    conn: T,
    target: TargetAddr<'static>,
    version: Version,
    auth: Option<(Bytes, Bytes)>,
) -> Result<T, SocksError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let failed = |err: tokio_socks::Error| SocksError::Handshake(err.into());
    let utf8 = |bytes| std::str::from_utf8(bytes).map_err(SocksError::Utf8);
    let conn = Socket(conn);

    let stream = match version {
        Version::V4 => {
            // SOCKS4 carries only a NUL-terminated user ID; an empty one is sent as none.
            let user_id = match &auth {
                Some((user_id, _)) if user_id.is_empty() => None,
                Some((user_id, _)) if user_id.len() > MAX_USER_ID_LEN || user_id.contains(&0) => {
                    return Err(SocksError::InvalidUserId);
                }
                Some((user_id, _)) => Some(utf8(user_id)?),
                None => None,
            };
            if let (Some(user_id), TargetAddr::Domain(host, _)) = (user_id, &target)
                && user_id.len() + host.len() > SOCKS4A_MAX_ID_AND_HOST
            {
                return Err(SocksError::HostTooLong);
            }
            match user_id {
                Some(user_id) => {
                    Socks4Stream::connect_with_userid_and_socket(conn, target, user_id).await
                }
                None => Socks4Stream::connect_with_socket(conn, target).await,
            }
            .map_err(failed)?
            .into_inner()
        }
        Version::V5 => match &auth {
            Some((username, password)) => Socks5Stream::connect_with_password_and_socket(
                conn,
                target,
                utf8(username)?,
                utf8(password)?,
            )
            .await
            .map_err(failed)?
            .into_inner(),
            None => Socks5Stream::connect_with_socket(conn, target)
                .await
                .map_err(failed)?
                .into_inner(),
        },
    };
    Ok(stream.0)
}

/// Adapts the caller's IO for tokio-socks.
///
/// tokio-socks never flushes, so each read flushes first: a buffered request then reaches the
/// proxy before the handshake waits for its reply.
struct Socket<T>(T);

impl<T> AsyncSocket for Socket<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        ready!(Pin::new(&mut self.0).poll_flush(cx))?;
        let mut buf = ReadBuf::new(buf);
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
}

// ===== impl SocksError =====

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SOCKS error: ")?;
        match self {
            SocksError::ConnectFailed(_) => f.write_str("failed to create underlying connection"),
            SocksError::DnsResolveFailure(_) => {
                f.write_str("failed to resolve DNS for SOCKS target")
            }
            SocksError::DnsFailure => f.write_str("could not resolve to acceptable address type"),
            SocksError::Handshake(_) => f.write_str("error during SOCKS handshake"),
            SocksError::AddressNotSupported => {
                f.write_str("SOCKS4 does not support IPv6 destinations")
            }
            SocksError::HostTooLong => f.write_str("destination host too long for SOCKS"),
            SocksError::InvalidUserId => f.write_str("invalid SOCKS4 user ID"),
            SocksError::Utf8(_) => f.write_str("invalid UTF-8 in SOCKS credentials"),
            SocksError::MissingHost => f.write_str("missing destination host"),
        }
    }
}

impl StdError for SocksError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            SocksError::ConnectFailed(err)
            | SocksError::DnsResolveFailure(err)
            | SocksError::Handshake(err) => Some(&**err),
            SocksError::Utf8(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Ready, time::Duration, vec};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter, DuplexStream, duplex};

    use super::*;

    /// Resolver returning fixed addresses for `example.com`, failing when it has none.
    #[derive(Clone, Debug)]
    struct Fixed(Vec<SocketAddr>);

    impl Service<Box<str>> for Fixed {
        type Response = vec::IntoIter<SocketAddr>;
        type Error = io::Error;
        type Future = Ready<io::Result<Self::Response>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, name: Box<str>) -> Self::Future {
            assert_eq!(&*name, "example.com");
            std::future::ready(if self.0.is_empty() {
                Err(io::ErrorKind::NotFound.into())
            } else {
                Ok(self.0.clone().into_iter())
            })
        }
    }

    /// Connector handing out one end of an in-memory pipe behind a write buffer, so a
    /// handshake that forgets to flush hangs. Without a pipe it refuses to connect.
    #[derive(Debug)]
    struct Pipe(Option<BufWriter<DuplexStream>>);

    impl Service<Uri> for Pipe {
        type Response = BufWriter<DuplexStream>;
        type Error = io::Error;
        type Future = Ready<io::Result<Self::Response>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Uri) -> Self::Future {
            std::future::ready(
                self.0
                    .take()
                    .ok_or_else(|| io::ErrorKind::ConnectionRefused.into()),
            )
        }
    }

    async fn read_vec(io: &mut DuplexStream, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        io.read_exact(&mut buf).await.expect("read");
        buf
    }

    async fn read_cstr(io: &mut DuplexStream) -> String {
        let mut buf = Vec::new();
        loop {
            match io.read_u8().await.expect("read") {
                0 => return String::from_utf8(buf).expect("utf-8"),
                b => buf.push(b),
            }
        }
    }

    /// SOCKS5 proxy answering a domain CONNECT, with username/password auth if offered.
    async fn socks5_proxy(mut io: DuplexStream, grant: bool) -> (DuplexStream, String) {
        let mut greeting = read_vec(&mut io, 2).await;
        greeting.extend(read_vec(&mut io, greeting[1].into()).await);
        let creds = match greeting[..] {
            [0x05, 0x01, 0x00] => {
                io.write_all(&[0x05, 0x00]).await.expect("method");
                String::new()
            }
            [0x05, 0x02, 0x00, 0x02] => {
                io.write_all(&[0x05, 0x02]).await.expect("method");
                // RFC 1929: VER ULEN UNAME PLEN PASSWD
                let ulen = read_vec(&mut io, 2).await[1];
                let user = read_vec(&mut io, ulen.into()).await;
                let plen = read_vec(&mut io, 1).await[0];
                let pass = read_vec(&mut io, plen.into()).await;
                io.write_all(&[0x01, 0x00]).await.expect("auth");
                format!(
                    "{}:{}@",
                    String::from_utf8_lossy(&user),
                    String::from_utf8_lossy(&pass)
                )
            }
            _ => panic!("unexpected greeting {greeting:?}"),
        };

        let req = read_vec(&mut io, 5).await;
        assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x03], "CONNECT to a domain");
        let host = read_vec(&mut io, req[4].into()).await;
        let port = u16::from_be_bytes(read_vec(&mut io, 2).await.try_into().unwrap());
        // REP 0x05: connection refused (RFC 1928 §6).
        let rep = if grant { 0x00 } else { 0x05 };
        io.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");

        let seen = format!("{creds}{}:{port}", String::from_utf8_lossy(&host));
        (io, seen)
    }

    /// SOCKS4a proxy accepting a user ID and a domain CONNECT.
    async fn socks4a_proxy(mut io: DuplexStream) -> (DuplexStream, String) {
        let req = read_vec(&mut io, 8).await;
        assert_eq!(&req[..2], &[0x04, 0x01], "CONNECT");
        assert_eq!(&req[4..8], &[0, 0, 0, 1], "SOCKS4a marker address");
        let port = u16::from_be_bytes([req[2], req[3]]);
        let user = read_cstr(&mut io).await;
        let host = read_cstr(&mut io).await;
        io.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");
        (io, format!("{user}@{host}:{port}"))
    }

    #[tokio::test]
    async fn target_selection() {
        let (long, too_long) = ("a".repeat(255), "a".repeat(256));
        let v4: SocketAddr = "192.0.2.1:0".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:0".parse().unwrap();
        let ip = |addr: &str| Ok(TargetAddr::Ip(addr.parse().unwrap()));
        let cases = [
            (
                "example.com",
                Version::V5,
                DnsResolve::Local,
                vec![v6, v4],
                ip("[2001:db8::1]:443"),
            ),
            (
                "example.com",
                Version::V4,
                DnsResolve::Local,
                vec![v6, v4],
                ip("192.0.2.1:443"),
            ),
            (
                "example.com",
                Version::V4,
                DnsResolve::Local,
                vec![v6],
                Err("DnsFailure"),
            ),
            (
                "example.com",
                Version::V5,
                DnsResolve::Local,
                vec![],
                Err("DnsResolveFailure(Kind(NotFound))"),
            ),
            (
                "example.com",
                Version::V5,
                DnsResolve::Remote,
                vec![],
                Ok(TargetAddr::Domain("example.com".into(), 443)),
            ),
            (
                "[2001:db8::2]",
                Version::V5,
                DnsResolve::Local,
                vec![],
                ip("[2001:db8::2]:443"),
            ),
            (
                "[2001:db8::2]",
                Version::V4,
                DnsResolve::Remote,
                vec![],
                Err("AddressNotSupported"),
            ),
            // The SOCKS5 domain length is a single octet.
            (
                &long,
                Version::V5,
                DnsResolve::Remote,
                vec![],
                Ok(TargetAddr::Domain(long.as_str().into(), 443)),
            ),
            (
                &too_long,
                Version::V5,
                DnsResolve::Remote,
                vec![],
                Err("HostTooLong"),
            ),
        ];

        for (host, version, dns, addrs, expected) in cases {
            let result = target_addr(host, 443, version, dns, Fixed(addrs)).await;
            match (result, expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{host} {version:?} {dns:?}"),
                (Err(err), Err(want)) => assert_eq!(format!("{err:?}"), want),
                (got, want) => panic!("{host} {version:?} {dns:?}: got {got:?}, want {want:?}"),
            }
        }

        // SOCKS4 user ID checks run before any IO; with the peer gone, a request passing them
        // fails on write.
        let user_ids: [(Bytes, &str, &str); 5] = [
            // tokio-socks fits at most 503 bytes of user ID and host into a SOCKS4a request.
            (
                Bytes::from("u".repeat(255)),
                &"h".repeat(248),
                "Handshake(Io(Kind(BrokenPipe)))",
            ),
            (
                Bytes::from("u".repeat(255)),
                &"h".repeat(249),
                "HostTooLong",
            ),
            (Bytes::from("u".repeat(256)), "example.com", "InvalidUserId"),
            // A NUL would end the user ID early and let the rest pose as the host.
            (
                Bytes::from_static(b"alice\0evil.test"),
                "example.com",
                "InvalidUserId",
            ),
            (
                Bytes::from_static(b"\xff"),
                "example.com",
                "Utf8(Utf8Error { valid_up_to: 0, error_len: Some(1) })",
            ),
        ];
        for (user_id, host, expected) in user_ids {
            let (client, server) = duplex(64);
            drop(server);
            let host = TargetAddr::Domain(host.to_owned().into(), 443);
            let auth = Some((user_id, Bytes::new()));
            let err = handshake(client, host, Version::V4, auth)
                .await
                .expect_err("peer gone");
            assert_eq!(format!("{err:?}"), expected);
        }
    }

    #[tokio::test]
    async fn connector_handshakes() {
        // The request as the proxy saw it, `Ok` if granted and `Err` if refused.
        let cases = [
            (
                Version::V5,
                Some(("user", "secret")),
                "https://example.com:8443",
                Ok("user:secret@example.com:8443"),
            ),
            // Without credentials only "no authentication required" is offered.
            (
                Version::V5,
                None,
                "https://example.com",
                Ok("example.com:443"),
            ),
            // A refusal is a handshake failure, not a failure to reach the proxy.
            (
                Version::V5,
                None,
                "https://example.com",
                Err("example.com:443"),
            ),
            (
                Version::V4,
                Some(("user", "secret")),
                "https://example.com",
                Ok("user@example.com:443"),
            ),
            // An empty SOCKS4 user ID is sent as none rather than rejected.
            (
                Version::V4,
                Some(("", "")),
                "https://example.com",
                Ok("@example.com:443"),
            ),
        ];

        for (version, auth, dst, expected) in cases {
            let (client, server) = duplex(256);
            let proxy = match version {
                Version::V5 => tokio::spawn(socks5_proxy(server, expected.is_ok())),
                Version::V4 => tokio::spawn(socks4a_proxy(server)),
            };

            let mut connector = SocksConnector::new(
                "socks5h://user:secret@proxy.local:1080".parse().unwrap(),
                Pipe(Some(BufWriter::new(client))),
                Fixed(vec![]),
            );
            connector.set_auth(auth.map(|(username, password)| {
                (
                    Bytes::from_static(username.as_bytes()),
                    Bytes::from_static(password.as_bytes()),
                )
            }));
            connector.set_version(version);
            connector.set_dns_mode(DnsResolve::Remote);
            assert!(
                !format!("{connector:?}").contains("secret"),
                "credentials in Debug"
            );

            let handshake = connector.call(dst.parse().unwrap());
            let result = tokio::time::timeout(Duration::from_secs(5), handshake)
                .await
                .expect("handshake stalled; was the request flushed?");
            assert!(
                matches!(
                    (&result, expected),
                    (Ok(_), Ok(_)) | (Err(SocksError::Handshake(_)), Err(_))
                ),
                "{dst} {version:?}: {result:?}"
            );

            let (mut server, seen) = proxy.await.expect("proxy task");
            let (Ok(want) | Err(want)) = expected;
            assert_eq!(seen, want);
            if let Ok(mut io) = result {
                server.write_all(b"pong").await.expect("tunneled write");
                let mut pong = [0; 4];
                io.read_exact(&mut pong).await.expect("tunneled read");
                assert_eq!(&pong, b"pong");
            }
        }

        // Failing to reach the proxy is a connect failure, not a handshake one.
        let err = SocksConnector::new(
            "socks5h://proxy.local:1080".parse().unwrap(),
            Pipe(None),
            Fixed(vec![]),
        )
        .call("https://192.0.2.1".parse().unwrap())
        .await
        .expect_err("no proxy");
        assert_eq!(format!("{err:?}"), "ConnectFailed(Kind(ConnectionRefused))");
    }

    #[tokio::test]
    async fn missing_host_skips_handshake() {
        for dst in ["/relative", "http://:80/", "https://[]:443/"] {
            let (client, server) = duplex(64);
            drop(server);
            let err = SocksConnector::new(
                "socks5h://proxy.local:1080".parse().unwrap(),
                Pipe(Some(BufWriter::new(client))),
                Fixed(vec![]),
            )
            .call(dst.parse().unwrap())
            .await
            .expect_err("no host");
            assert!(matches!(err, SocksError::MissingHost), "{dst}: {err:?}");
        }
    }
}
