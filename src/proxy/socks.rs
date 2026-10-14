//! SOCKS4/4a and SOCKS5/5h connectors.
//!
//! The CONNECT handshakes are delegated to [tokio-socks](https://docs.rs/tokio-socks);
//! [`udp`] implements SOCKS5 UDP ASSOCIATE. SOCKS5 is
//! [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928), with username/password authentication
//! from [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929).

pub mod udp;

use std::{
    error::Error as StdError,
    fmt,
    future::{self, poll_fn},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::{self, Utf8Error},
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures_util::future::try_join;
use http::Uri;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_socks::{
    TargetAddr,
    io::AsyncSocket,
    tcp::{Socks4Stream, Socks5Stream},
};
use tower_service::Service;

use super::{ProxyDst, Tunneling, dst_host, dst_port};
use crate::error::BoxError;

/// Longest domain a SOCKS5 request can carry: one length octet
/// ([RFC 1928 §5](https://www.rfc-editor.org/rfc/rfc1928#section-5)).
const MAX_HOST_LEN: usize = 255;

/// Longest SOCKS4 user ID tokio-socks accepts.
const MAX_USER_ID_LEN: usize = 255;

/// Longest SOCKS5 username or password: one length octet
/// ([RFC 1929 §2](https://www.rfc-editor.org/rfc/rfc1929#section-2)).
const MAX_CREDENTIAL_LEN: usize = 255;

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
/// first IPv4 address it returns. The handshake has no timeout of its own, so bound the
/// returned future, e.g. with a connect timeout around the whole connector.
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
    /// The SOCKS5 username or password is empty or longer than 255 bytes.
    InvalidCredentials,
    /// The credentials are not valid UTF-8.
    Utf8(Utf8Error),
    /// The destination URI has no host.
    MissingHost,
    /// The destination port is zero or not a valid `u16`.
    InvalidPort,
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
    ///
    /// SOCKS5 needs both to be 1 to 255 bytes, and both versions need valid UTF-8.
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

    /// Checks the destination and credentials, returning the destination port and, for an IP
    /// literal, the address to send.
    fn check(&self, dst: &Uri) -> Result<(u16, Option<SocketAddr>), SocksError> {
        let host = dst_host(dst)
            .map(unbracket)
            .ok_or(SocksError::MissingHost)?;
        let port = dst_port(dst).ok_or(SocksError::InvalidPort)?;
        let remote = self.dns_resolve == DnsResolve::Remote;

        let addr = match host.parse::<IpAddr>() {
            Ok(ip) if self.version == Version::V4 && ip.is_ipv6() => {
                return Err(SocksError::AddressNotSupported);
            }
            Ok(ip) => Some(SocketAddr::new(ip, port)),
            Err(_) if remote && host.len() > MAX_HOST_LEN => return Err(SocksError::HostTooLong),
            Err(_) => None,
        };

        match (self.version, &self.auth) {
            (_, None) => {}
            (Version::V4, Some((user_id, _))) => {
                if user_id.len() > MAX_USER_ID_LEN || user_id.contains(&0) {
                    return Err(SocksError::InvalidUserId);
                }
                str::from_utf8(user_id).map_err(SocksError::Utf8)?;
                if remote && addr.is_none() && user_id.len() + host.len() > SOCKS4A_MAX_ID_AND_HOST
                {
                    return Err(SocksError::HostTooLong);
                }
            }
            (Version::V5, Some((username, password))) => {
                for value in [username, password] {
                    if !(1..=MAX_CREDENTIAL_LEN).contains(&value.len()) {
                        return Err(SocksError::InvalidCredentials);
                    }
                    str::from_utf8(value).map_err(SocksError::Utf8)?;
                }
            }
        }
        Ok((port, addr))
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
        // Reject a bad destination or credentials before the inner connector starts connecting
        // to the proxy.
        let (port, addr) = match self.check(&dst) {
            Ok(checked) => checked,
            Err(err) => return Tunneling::new(future::ready(Err(err))),
        };
        // Only a host name resolved here needs the resolver.
        let resolver = (addr.is_none() && self.dns_resolve == DnsResolve::Local)
            .then(|| self.resolver.clone());
        let connecting = self.inner.call(self.proxy_dst.clone());
        let auth = self.auth.clone();
        let version = self.version;

        Tunneling::new(async move {
            let host = dst_host(&dst)
                .map(unbracket)
                .ok_or(SocksError::MissingHost)?;
            let target = async {
                Ok(match (addr, resolver) {
                    (Some(addr), _) => TargetAddr::Ip(addr),
                    (None, Some(resolver)) => {
                        TargetAddr::Ip(resolve(resolver, host, port, version).await?)
                    }
                    (None, None) => TargetAddr::Domain(host.into(), port),
                })
            };
            let connect = async {
                connecting
                    .await
                    .map_err(|err| SocksError::ConnectFailed(err.into()))
            };
            let (target, io) = try_join(target, connect).await?;
            handshake(io, target, version, auth.as_ref()).await
        })
    }
}

/// Strips the brackets of an IPv6 literal.
fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

/// Resolves `host` with the connector's resolver; SOCKS4 takes the first IPv4 address.
async fn resolve<R>(
    mut resolver: R,
    host: &str,
    port: u16,
    version: Version,
) -> Result<SocketAddr, SocksError>
where
    R: Service<Box<str>>,
    R::Response: Iterator<Item = SocketAddr>,
    R::Error: Into<BoxError>,
{
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
    Ok(addr)
}

/// Runs the handshake for credentials that [`SocksConnector::check`] accepted.
async fn handshake<T>(
    io: T,
    target: TargetAddr<'_>,
    version: Version,
    auth: Option<&(Bytes, Bytes)>,
) -> Result<T, SocksError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let failed = |err: tokio_socks::Error| SocksError::Handshake(err.into());
    let utf8 = |bytes| str::from_utf8(bytes).map_err(SocksError::Utf8);
    let socket = Socket(io);

    let socket = match (version, auth) {
        // SOCKS4 carries only a NUL-terminated user ID; an empty one is sent as none.
        (Version::V4, Some((user_id, _))) if !user_id.is_empty() => {
            Socks4Stream::connect_with_userid_and_socket(socket, target, utf8(user_id)?)
                .await
                .map_err(failed)?
                .into_inner()
        }
        (Version::V4, _) => Socks4Stream::connect_with_socket(socket, target)
            .await
            .map_err(failed)?
            .into_inner(),
        (Version::V5, Some((username, password))) => {
            Socks5Stream::connect_with_password_and_socket(
                socket,
                target,
                utf8(username)?,
                utf8(password)?,
            )
            .await
            .map_err(failed)?
            .into_inner()
        }
        (Version::V5, None) => Socks5Stream::connect_with_socket(socket, target)
            .await
            .map_err(failed)?
            .into_inner(),
    };
    Ok(socket.0)
}

/// Adapts the caller's IO for tokio-socks.
///
/// tokio-socks never flushes, so each read flushes first: a buffered request then reaches the
/// proxy before the handshake waits for its reply.
struct Socket<T>(T);

// ===== impl Socket =====

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
            SocksError::InvalidCredentials => f.write_str("invalid SOCKS5 username or password"),
            SocksError::Utf8(_) => f.write_str("invalid UTF-8 in SOCKS credentials"),
            SocksError::MissingHost => f.write_str("missing destination host"),
            SocksError::InvalidPort => f.write_str("invalid destination port"),
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
    use std::{
        future::Ready,
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
        vec,
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter, DuplexStream, duplex};

    use super::*;

    const PROXY: &str = "socks5h://user:secret@proxy.local:1080";

    /// Username and password, or SOCKS4 user ID and an ignored password.
    type Auth<'a> = Option<(&'a [u8], &'a [u8])>;

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

        fn call(&mut self, dst: Uri) -> Self::Future {
            assert_eq!(dst, PROXY);
            std::future::ready(
                self.0
                    .take()
                    .ok_or_else(|| io::ErrorKind::ConnectionRefused.into()),
            )
        }
    }

    fn connector(
        pipe: Option<DuplexStream>,
        version: Version,
        dns_resolve: DnsResolve,
        auth: Auth<'_>,
    ) -> SocksConnector<Pipe, Fixed> {
        let mut connector = SocksConnector::new(
            PROXY.parse().unwrap(),
            Pipe(pipe.map(BufWriter::new)),
            Fixed(vec![
                "[2001:db8::1]:0".parse().unwrap(),
                "192.0.2.1:0".parse().unwrap(),
            ]),
        );
        connector.set_auth(auth.map(|(username, password)| {
            (
                Bytes::copy_from_slice(username),
                Bytes::copy_from_slice(password),
            )
        }));
        connector.set_version(version);
        connector.set_dns_mode(dns_resolve);
        connector
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

    /// SOCKS5 proxy answering a CONNECT, with username/password auth if offered.
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
                // VER ULEN UNAME PLEN PASSWD: https://www.rfc-editor.org/rfc/rfc1929#section-2
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

        let req = read_vec(&mut io, 4).await;
        assert_eq!(&req[..3], &[0x05, 0x01, 0x00], "CONNECT");
        // ATYP: https://www.rfc-editor.org/rfc/rfc1928#section-5
        let host = match req[3] {
            0x01 => {
                Ipv4Addr::from(<[u8; 4]>::try_from(read_vec(&mut io, 4).await).unwrap()).to_string()
            }
            0x04 => {
                let ip = <[u8; 16]>::try_from(read_vec(&mut io, 16).await).unwrap();
                format!("[{}]", Ipv6Addr::from(ip))
            }
            _ => {
                let len = read_vec(&mut io, 1).await[0];
                String::from_utf8(read_vec(&mut io, len.into()).await).expect("utf-8")
            }
        };
        let port = u16::from_be_bytes(read_vec(&mut io, 2).await.try_into().unwrap());
        // REP 0x05 is "connection refused": https://www.rfc-editor.org/rfc/rfc1928#section-6
        let rep = if grant { 0x00 } else { 0x05 };
        io.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");

        (io, format!("{creds}{host}:{port}"))
    }

    /// SOCKS4 proxy accepting a user ID and a CONNECT to an address or, as SOCKS4a, a domain.
    async fn socks4_proxy(mut io: DuplexStream) -> (DuplexStream, String) {
        let req = read_vec(&mut io, 8).await;
        assert_eq!(&req[..2], &[0x04, 0x01], "CONNECT");
        let port = u16::from_be_bytes([req[2], req[3]]);
        let ip = Ipv4Addr::new(req[4], req[5], req[6], req[7]);
        let user = read_cstr(&mut io).await;
        // 0.0.0.x with a nonzero x marks a SOCKS4a domain after the user ID.
        let host = match ip.octets() {
            [0, 0, 0, x] if x != 0 => read_cstr(&mut io).await,
            _ => ip.to_string(),
        };
        io.write_all(&[0x00, 0x5A, 0, 0, 0, 0, 0, 0])
            .await
            .expect("reply");
        (io, format!("{user}@{host}:{port}"))
    }

    #[tokio::test]
    async fn checks_before_connecting() {
        use DnsResolve::Remote;
        use Version::{V4, V5};

        let host = |len| format!("https://{}", "h".repeat(len));
        let (host_255, host_256, host_248, host_249) = (host(255), host(256), host(248), host(249));
        let (id_255, id_256) = ("u".repeat(255), "u".repeat(256));
        let (id_255, id_256) = (id_255.as_bytes(), id_256.as_bytes());

        // `Err` is rejected before the inner connector is called. `Ok` passes the checks and
        // fails writing to the closed proxy end.
        let broken = Ok("Handshake(Io(Kind(BrokenPipe)))");
        let cases: [(&str, Version, DnsResolve, Auth<'_>, _); 18] = [
            ("/relative", V5, Remote, None, Err("MissingHost")),
            ("http://:80/", V5, Remote, None, Err("MissingHost")),
            ("https://[]:443/", V5, Remote, None, Err("MissingHost")),
            (
                "https://example.com:0",
                V5,
                Remote,
                None,
                Err("InvalidPort"),
            ),
            (
                "https://example.com:65536",
                V5,
                Remote,
                None,
                Err("InvalidPort"),
            ),
            (
                "https://[2001:db8::2]",
                V4,
                Remote,
                None,
                Err("AddressNotSupported"),
            ),
            (&host_255, V5, Remote, None, broken),
            (&host_256, V5, Remote, None, Err("HostTooLong")),
            // tokio-socks fits at most 503 bytes of user ID and host into a SOCKS4a request.
            (&host_248, V4, Remote, Some((id_255, b"")), broken),
            (
                &host_249,
                V4,
                Remote,
                Some((id_255, b"")),
                Err("HostTooLong"),
            ),
            (
                "https://example.com",
                V4,
                Remote,
                Some((id_256, b"")),
                Err("InvalidUserId"),
            ),
            // A NUL would end the user ID early and let the rest pose as the host.
            (
                "https://example.com",
                V4,
                Remote,
                Some((b"alice\0evil.test", b"")),
                Err("InvalidUserId"),
            ),
            (
                "https://example.com",
                V4,
                Remote,
                Some((b"\xff", b"")),
                Err("Utf8(Utf8Error { valid_up_to: 0, error_len: Some(1) })"),
            ),
            // SOCKS4 sends an empty user ID as none, but SOCKS5 needs 1 to 255 bytes for each.
            ("https://example.com", V4, Remote, Some((b"", b"")), broken),
            (
                "https://example.com",
                V5,
                Remote,
                Some((b"user", b"")),
                Err("InvalidCredentials"),
            ),
            (
                "https://example.com",
                V5,
                Remote,
                Some((b"", b"secret")),
                Err("InvalidCredentials"),
            ),
            (
                "https://example.com",
                V5,
                Remote,
                Some((id_256, b"secret")),
                Err("InvalidCredentials"),
            ),
            (
                "https://example.com",
                V5,
                Remote,
                Some((id_255, id_255)),
                broken,
            ),
        ];

        for (dst, version, dns_resolve, auth, expected) in cases {
            let (client, server) = duplex(64);
            drop(server);
            let mut connector = connector(Some(client), version, dns_resolve, auth);
            let err = bounded(connector.call(dst.parse().unwrap()), "handshake stalled")
                .await
                .expect_err("bad destination or closed proxy end");
            let (Ok(want) | Err(want)) = expected;
            assert_eq!(
                format!("{err:?}"),
                want,
                "{dst} {version:?} {dns_resolve:?}"
            );
            assert_eq!(
                connector.inner.0.is_none(),
                expected.is_ok(),
                "{dst}: inner connector called"
            );
        }
    }

    #[tokio::test]
    async fn local_dns_failures() {
        let v6: SocketAddr = "[2001:db8::1]:0".parse().unwrap();
        let cases = [
            // SOCKS4 has no IPv6 address to fall back on.
            (Version::V4, vec![v6], "DnsFailure"),
            (Version::V5, vec![], "DnsResolveFailure(Kind(NotFound))"),
        ];
        for (version, addrs, expected) in cases {
            let err = resolve(Fixed(addrs), "example.com", 443, version)
                .await
                .expect_err("no usable address");
            assert_eq!(format!("{err:?}"), expected);
        }
    }

    #[tokio::test]
    async fn connector_handshakes() {
        use DnsResolve::{Local, Remote};
        use Version::{V4, V5};

        // The target as the proxy saw it, `Ok` if granted and `Err` if refused. The resolver
        // returns [2001:db8::1] and then 192.0.2.1 for example.com.
        let cases: [(Version, DnsResolve, Auth<'_>, &str, _); 8] = [
            (
                V5,
                Remote,
                Some((b"user", b"secret")),
                "https://example.com:8443",
                Ok("user:secret@example.com:8443"),
            ),
            // Without credentials only "no authentication required" is offered.
            (
                V5,
                Remote,
                None,
                "https://example.com",
                Ok("example.com:443"),
            ),
            // A refusal is a handshake failure, not a failure to reach the proxy.
            (
                V5,
                Remote,
                None,
                "https://example.com",
                Err("example.com:443"),
            ),
            (
                V4,
                Remote,
                Some((b"user", b"secret")),
                "https://example.com",
                Ok("user@example.com:443"),
            ),
            // An empty SOCKS4 user ID is sent as none rather than rejected.
            (
                V4,
                Remote,
                Some((b"", b"")),
                "https://example.com",
                Ok("@example.com:443"),
            ),
            // Local DNS sends the first address, the first IPv4 one for SOCKS4.
            (
                V5,
                Local,
                None,
                "https://example.com:8443",
                Ok("[2001:db8::1]:8443"),
            ),
            (
                V4,
                Local,
                None,
                "https://example.com:8443",
                Ok("@192.0.2.1:8443"),
            ),
            // An IP literal skips the resolver, which only knows example.com.
            (
                V5,
                Local,
                None,
                "https://[2001:db8::2]:8443",
                Ok("[2001:db8::2]:8443"),
            ),
        ];

        for (version, dns_resolve, auth, dst, expected) in cases {
            let (client, server) = duplex(256);
            let proxy = match version {
                Version::V5 => tokio::spawn(socks5_proxy(server, expected.is_ok())),
                Version::V4 => tokio::spawn(socks4_proxy(server)),
            };

            let mut connector = connector(Some(client), version, dns_resolve, auth);
            assert!(
                !format!("{connector:?}").contains("secret"),
                "credentials in Debug"
            );

            let result = bounded(
                connector.call(dst.parse().unwrap()),
                "handshake stalled; was the request flushed?",
            )
            .await;
            assert!(
                matches!(
                    (&result, expected),
                    (Ok(_), Ok(_)) | (Err(SocksError::Handshake(_)), Err(_))
                ),
                "{dst} {version:?}: {result:?}"
            );

            let (mut server, seen) = bounded(proxy, "proxy stalled").await.expect("proxy task");
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
        let err = connector(None, Version::V5, DnsResolve::Remote, None)
            .call("https://192.0.2.1".parse().unwrap())
            .await
            .expect_err("no proxy");
        assert_eq!(format!("{err:?}"), "ConnectFailed(Kind(ConnectionRefused))");
    }
}
