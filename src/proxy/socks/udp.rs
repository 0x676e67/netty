//! SOCKS5 UDP ASSOCIATE.
//!
//! See [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928): §4 for the UDP ASSOCIATE
//! command and §7 for the header prepended to every relayed datagram, and
//! [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) for username/password authentication.
//!
//! This module only speaks the protocol (sans-IO). The caller owns the UDP socket and
//! resolves domain names, sends datagrams framed with [`encode_header`] to
//! [`UdpAssociation::relay_addr`], and unframes received ones with [`unframe`], which also
//! drops datagrams that bypass the relay.

use std::{
    error::Error as StdError,
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str,
    task::{Context, Poll, ready},
};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{read, send};

const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const NO_AUTH: u8 = 0x00;
const USERNAME_PASSWORD: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// A SOCKS5 address (RFC 1928 §5): an IP address or a domain name, with a port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// An IPv4 or IPv6 address and port.
    Ip(SocketAddr),
    /// A domain name of 1 to 255 bytes and a port.
    Domain(Box<str>, u16),
}

/// A borrowed [`Address`], as [`decode_header`] returns it without allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressRef<'a> {
    /// An IPv4 or IPv6 address and port.
    Ip(SocketAddr),
    /// A domain name of 1 to 255 bytes and a port.
    Domain(&'a str, u16),
}

/// A UDP association, alive as long as its TCP control connection.
///
/// RFC 1928 ends the association when the control connection closes, so keep this value
/// for the association's lifetime and watch [`poll_closed`](Self::poll_closed).
#[derive(Debug)]
pub struct UdpAssociation<T> {
    io: T,
    bound: Address,
}

/// Errors from the UDP ASSOCIATE handshake.
#[derive(Debug)]
#[non_exhaustive]
pub enum AssociateError {
    /// An I/O error occurred on the control connection.
    Io(io::Error),
    /// The username or password is empty or longer than 255 bytes.
    InvalidCredentials,
    /// The proxy accepted none of the offered authentication methods.
    NoAcceptableAuth,
    /// The proxy rejected the username and password.
    AuthFailed,
    /// The proxy sent a malformed response, including a relay address with port 0.
    InvalidResponse,
    /// The proxy refused the association with this reply code.
    Reply(u8),
}

/// Errors from encoding or decoding a datagram header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderError {
    /// The datagram is shorter than its header.
    Truncated,
    /// The reserved bytes are not zero.
    Reserved,
    /// The datagram is a fragment; fragmentation is not supported.
    Fragmented,
    /// The address type is unknown.
    UnsupportedAddress,
    /// The domain name is empty, longer than 255 bytes or not UTF-8.
    InvalidDomain,
}

/// Performs the UDP ASSOCIATE handshake over a connected control stream.
///
/// `client_addr` is the address the caller will send datagrams from; many proxies accept
/// an unspecified address such as `0.0.0.0:0` when it is not yet known.
pub async fn associate<T>(
    mut io: T,
    auth: Option<(&str, &str)>,
    client_addr: SocketAddr,
) -> Result<UdpAssociation<T>, AssociateError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // RFC 1929 lengths are one byte and must be non-zero.
    let auth = match auth {
        Some((username, password)) => {
            let len = |s: &str| {
                u8::try_from(s.len())
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or(AssociateError::InvalidCredentials)
            };
            Some((username, len(username)?, password, len(password)?))
        }
        None => None,
    };

    let methods: &[u8] = match auth {
        Some(_) => &[VERSION, 2, NO_AUTH, USERNAME_PASSWORD],
        None => &[VERSION, 1, NO_AUTH],
    };
    send(&mut io, methods).await?;
    let [version, method] = read_array(&mut io).await?;
    if version != VERSION {
        return Err(AssociateError::InvalidResponse);
    }
    match (method, auth) {
        (NO_AUTH, _) => {}
        (USERNAME_PASSWORD, Some((username, ulen, password, plen))) => {
            let mut req = Vec::with_capacity(3 + username.len() + password.len());
            req.extend_from_slice(&[AUTH_VERSION, ulen]);
            req.extend_from_slice(username.as_bytes());
            req.push(plen);
            req.extend_from_slice(password.as_bytes());
            send(&mut io, &req).await?;
            let [version, status] = read_array(&mut io).await?;
            if version != AUTH_VERSION {
                return Err(AssociateError::InvalidResponse);
            }
            if status != 0 {
                return Err(AssociateError::AuthFailed);
            }
        }
        (NO_ACCEPTABLE_METHODS, _) => return Err(AssociateError::NoAcceptableAuth),
        _ => return Err(AssociateError::InvalidResponse),
    }

    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[VERSION, CMD_UDP_ASSOCIATE, 0x00]);
    put_ip(&mut req, client_addr);
    send(&mut io, &req).await?;

    let [version, reply, rsv, atyp] = read_array(&mut io).await?;
    if version != VERSION || rsv != 0 {
        return Err(AssociateError::InvalidResponse);
    }
    if reply != 0 {
        return Err(AssociateError::Reply(reply));
    }
    // BND.ADDR and BND.PORT; a domain name is prefixed with its length.
    let mut addr = [0; 1 + 255 + 2];
    let (start, end) = match atyp {
        ATYP_IPV4 => (0, 4 + 2),
        ATYP_IPV6 => (0, 16 + 2),
        ATYP_DOMAIN => {
            read_exact(&mut io, &mut addr[..1]).await?;
            (1, 1 + usize::from(addr[0]) + 2)
        }
        _ => return Err(AssociateError::InvalidResponse),
    };
    read_exact(&mut io, &mut addr[start..end]).await?;
    match decode_addr(atyp, &addr[..end]) {
        // Datagrams cannot be sent to port 0.
        Ok((bound, _)) if bound.port() != 0 => Ok(UdpAssociation {
            io,
            bound: bound.into(),
        }),
        _ => Err(AssociateError::InvalidResponse),
    }
}

/// Length of the header [`encode_header`] writes for `target`: 10 bytes for IPv4, 22 for
/// IPv6, and 7 plus the name for a domain.
///
/// Subtract it from the path MTU to size payloads.
pub fn header_len<'a>(target: impl Into<AddressRef<'a>>) -> usize {
    match target.into() {
        AddressRef::Ip(addr) => match addr.ip().to_canonical() {
            IpAddr::V4(_) => 10,
            IpAddr::V6(_) => 22,
        },
        AddressRef::Domain(name, _) => 7 + name.len(),
    }
}

/// Writes the header for a datagram relayed to `target`; append the payload after it.
///
/// An IPv4-mapped IPv6 `target`, as a dual-stack socket names IPv4 peers, is written as IPv4.
/// A domain name, as `socks5h` sends, is resolved by the proxy. Nothing is written on error.
pub fn encode_header<'a, B: BufMut>(
    target: impl Into<AddressRef<'a>>,
    buf: &mut B,
) -> Result<(), HeaderError> {
    // RSV (2 bytes) and FRAG (1 byte) lead; only unfragmented datagrams are sent.
    match target.into() {
        AddressRef::Ip(addr) => {
            buf.put_slice(&[0, 0, 0]);
            put_ip(buf, addr);
        }
        AddressRef::Domain(name, port) => {
            let len = u8::try_from(name.len())
                .ok()
                .filter(|&len| len > 0)
                .ok_or(HeaderError::InvalidDomain)?;
            buf.put_slice(&[0, 0, 0, ATYP_DOMAIN, len]);
            buf.put_slice(name.as_bytes());
            buf.put_u16(port);
        }
    }
    Ok(())
}

/// Splits a relayed datagram into its source address and payload, borrowing both.
pub fn decode_header(datagram: &[u8]) -> Result<(AddressRef<'_>, &[u8]), HeaderError> {
    let [rsv0, rsv1, frag, atyp, rest @ ..] = datagram else {
        return Err(HeaderError::Truncated);
    };
    if (*rsv0, *rsv1) != (0, 0) {
        return Err(HeaderError::Reserved);
    }
    if *frag != 0 {
        return Err(HeaderError::Fragmented);
    }
    decode_addr(*atyp, rest)
}

/// Payloads of a relayed datagram, unframed in place by [`unframe`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unframed {
    /// The target that sent the payloads.
    pub source: Address,
    /// Total length of the payloads, now packed at the front of the buffer.
    pub len: usize,
    /// Length of each payload; only the last may be shorter.
    pub stride: usize,
}

/// Unframes what the socket received from `from`, moving the payloads to the front of `buf`.
///
/// With UDP GRO, `buf` holds datagrams of `stride` bytes back to back, the last possibly
/// shorter; otherwise `stride` is `buf.len()`. Returns `None`, so the caller drops `buf`, if
/// it did not come from `relay`, a datagram is fragmented or malformed, or the datagrams
/// came from different sources: GRO only matches the outer addresses.
///
/// IPv4-mapped addresses, as a dual-stack socket reports them, match their IPv4 form. The
/// source is returned as the header names it; map it back with [`Ipv4Addr::to_ipv6_mapped`]
/// if the socket names peers that way.
pub fn unframe(
    relay: SocketAddr,
    from: SocketAddr,
    buf: &mut [u8],
    stride: usize,
) -> Option<Unframed> {
    let canonical = |addr: SocketAddr| SocketAddr::new(addr.ip().to_canonical(), addr.port());
    if canonical(from) != canonical(relay) {
        return None;
    }
    let (mut read, mut write) = (0, 0);
    let mut first = None;
    while read < buf.len() {
        let end = read.saturating_add(stride).min(buf.len());
        let (source, payload) = decode_header(&buf[read..end]).ok()?;
        let len = payload.len();
        match &first {
            None => first = Some((Address::from(source), len)),
            Some((first, _)) if AddressRef::from(first) != source => return None,
            Some(_) => {}
        }
        buf.copy_within(end - len..end, write);
        (read, write) = (end, write + len);
    }
    let (source, stride) = first?;
    Some(Unframed {
        source,
        len: write,
        stride,
    })
}

/// Parses ATYP's address and the port at the front of `bytes`, returning the rest.
fn decode_addr(atyp: u8, bytes: &[u8]) -> Result<(AddressRef<'_>, &[u8]), HeaderError> {
    let (addr, rest) = match atyp {
        ATYP_IPV4 => {
            let (ip, rest) = bytes
                .split_first_chunk::<4>()
                .ok_or(HeaderError::Truncated)?;
            (IpAddr::from(*ip), rest)
        }
        ATYP_IPV6 => {
            let (ip, rest) = bytes
                .split_first_chunk::<16>()
                .ok_or(HeaderError::Truncated)?;
            (IpAddr::from(*ip), rest)
        }
        ATYP_DOMAIN => {
            let (&len, rest) = bytes.split_first().ok_or(HeaderError::Truncated)?;
            let (name, rest) = rest
                .split_at_checked(usize::from(len))
                .ok_or(HeaderError::Truncated)?;
            let (port, rest) = rest.split_first_chunk().ok_or(HeaderError::Truncated)?;
            let name = str::from_utf8(name)
                .ok()
                .filter(|name| !name.is_empty())
                .ok_or(HeaderError::InvalidDomain)?;
            return Ok((AddressRef::Domain(name, u16::from_be_bytes(*port)), rest));
        }
        _ => return Err(HeaderError::UnsupportedAddress),
    };
    let (port, rest) = rest.split_first_chunk().ok_or(HeaderError::Truncated)?;
    Ok((
        AddressRef::Ip(SocketAddr::new(addr, u16::from_be_bytes(*port))),
        rest,
    ))
}

/// Writes ATYP, the IP address and the port; IPv4-mapped addresses as IPv4.
fn put_ip<B: BufMut>(buf: &mut B, addr: SocketAddr) {
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
    }
    buf.put_u16(addr.port());
}

async fn read_exact<T>(io: &mut T, buf: &mut [u8]) -> io::Result<()>
where
    T: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        match read(io, &mut buf[filled..]).await? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => filled += n,
        }
    }
    Ok(())
}

async fn read_array<T, const N: usize>(io: &mut T) -> io::Result<[u8; N]>
where
    T: AsyncRead + Unpin,
{
    let mut buf = [0; N];
    read_exact(io, &mut buf).await?;
    Ok(buf)
}

// ===== impl Address =====

impl Address {
    /// Returns the port.
    pub fn port(&self) -> u16 {
        match self {
            Address::Ip(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Ip(addr)
    }
}

impl From<AddressRef<'_>> for Address {
    fn from(addr: AddressRef<'_>) -> Self {
        match addr {
            AddressRef::Ip(addr) => Address::Ip(addr),
            AddressRef::Domain(name, port) => Address::Domain(name.into(), port),
        }
    }
}

// ===== impl AddressRef =====

impl AddressRef<'_> {
    /// Returns the port.
    pub fn port(&self) -> u16 {
        match self {
            AddressRef::Ip(addr) => addr.port(),
            AddressRef::Domain(_, port) => *port,
        }
    }
}

impl From<SocketAddr> for AddressRef<'_> {
    fn from(addr: SocketAddr) -> Self {
        AddressRef::Ip(addr)
    }
}

impl<'a> From<&'a Address> for AddressRef<'a> {
    fn from(addr: &'a Address) -> Self {
        match addr {
            Address::Ip(addr) => AddressRef::Ip(*addr),
            Address::Domain(name, port) => AddressRef::Domain(name, *port),
        }
    }
}

// ===== impl UdpAssociation =====

impl<T> UdpAssociation<T> {
    /// Returns the relay address as bound by the proxy (BND.ADDR and BND.PORT).
    pub fn bound_addr(&self) -> &Address {
        &self.bound
    }

    /// Returns where to send datagrams; resolve it first if it is a domain name.
    ///
    /// Proxies often bind an unspecified address such as `0.0.0.0`; it then means the
    /// proxy's own IP, which only the caller knows from the control connection.
    pub fn relay_addr(&self, proxy_ip: IpAddr) -> Address {
        match &self.bound {
            Address::Ip(addr) if addr.ip().is_unspecified() => {
                Address::Ip(SocketAddr::new(proxy_ip, addr.port()))
            }
            bound => bound.clone(),
        }
    }

    /// Returns the control connection.
    pub fn get_ref(&self) -> &T {
        &self.io
    }

    /// Consumes the association, returning the control connection.
    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T> UdpAssociation<T>
where
    T: AsyncRead + Unpin,
{
    /// Polls until the proxy closes the control connection, ending the association.
    ///
    /// Bytes the proxy sends on it are discarded.
    pub fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Bound the work per call: a proxy that keeps writing must not hold the task.
        let mut buf = [0; 512];
        for _ in 0..16 {
            let mut buf = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut self.io).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ===== impl AssociateError =====

impl From<io::Error> for AssociateError {
    fn from(err: io::Error) -> Self {
        AssociateError::Io(err)
    }
}

impl fmt::Display for AssociateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SOCKS5 UDP ASSOCIATE error: ")?;
        match self {
            AssociateError::Io(_) => f.write_str("io error on the control connection"),
            AssociateError::InvalidCredentials => f.write_str("invalid username or password"),
            AssociateError::NoAcceptableAuth => f.write_str("no acceptable auth methods"),
            AssociateError::AuthFailed => f.write_str("authentication failed"),
            AssociateError::InvalidResponse => f.write_str("invalid proxy response"),
            AssociateError::Reply(code) => write!(f, "proxy replied with code {code:#04x}"),
        }
    }
}

impl StdError for AssociateError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            AssociateError::Io(err) => Some(err),
            _ => None,
        }
    }
}

// ===== impl HeaderError =====

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HeaderError::Truncated => "truncated SOCKS5 UDP header",
            HeaderError::Reserved => "non-zero reserved bytes in SOCKS5 UDP header",
            HeaderError::Fragmented => "fragmented SOCKS5 UDP datagram",
            HeaderError::UnsupportedAddress => "unsupported SOCKS5 UDP address type",
            HeaderError::InvalidDomain => "invalid domain name in SOCKS5 UDP header",
        })
    }
}

impl StdError for HeaderError {}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Wake, Waker},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, BufWriter, duplex},
        time::timeout,
    };
    use tokio_test::io::Builder;

    use super::*;

    #[test]
    fn datagram_header() {
        // RFC 1928 §7: RSV, FRAG, ATYP, DST.ADDR, DST.PORT.
        let v4 = [0, 0, 0, 1, 192, 0, 2, 1, 0x01, 0xbb];
        let v6 = [
            0, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 0xfb,
        ];
        let domain = |name: &str| {
            [
                &[0, 0, 0, 3, name.len() as u8][..],
                name.as_bytes(),
                &[0, 80],
            ]
            .concat()
        };
        let longest = "a".repeat(255);
        let cases = [
            (Address::Ip("192.0.2.1:443".parse().unwrap()), v4.to_vec()),
            (
                Address::Ip("[2001:db8::1]:8443".parse().unwrap()),
                v6.to_vec(),
            ),
            (
                Address::Domain("example.com".into(), 80),
                domain("example.com"),
            ),
            (
                Address::Domain(longest.as_str().into(), 80),
                domain(&longest),
            ),
        ];
        for (target, header) in cases {
            let mut encoded = Vec::new();
            encode_header(&target, &mut encoded).unwrap();
            assert_eq!(encoded, header);
            assert_eq!(header_len(&target), header.len());

            let datagram = [&header[..], b"quic"].concat();
            let decoded = Ok((AddressRef::from(&target), &b"quic"[..]));
            assert_eq!(decode_header(&datagram), decoded);
            // Every cut inside the header is detected.
            for len in 0..header.len() {
                assert_eq!(decode_header(&datagram[..len]), Err(HeaderError::Truncated));
            }
        }

        // An IPv4-mapped target, as a dual-stack socket names it, goes out as IPv4.
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:443".parse().unwrap();
        let mut encoded = Vec::new();
        encode_header(mapped, &mut encoded).unwrap();
        assert_eq!(encoded, v4);
        assert_eq!(header_len(mapped), v4.len());

        // A domain name that does not fit its length octet writes nothing.
        for name in ["", &"a".repeat(256)] {
            let mut encoded = Vec::new();
            assert_eq!(
                encode_header(AddressRef::Domain(name, 80), &mut encoded),
                Err(HeaderError::InvalidDomain)
            );
            assert!(encoded.is_empty());
        }

        for (datagram, err) in [
            (
                &[1, 0, 0, 1, 192, 0, 2, 1, 0, 80][..],
                HeaderError::Reserved,
            ),
            (&[0, 1, 0, 1, 192, 0, 2, 1, 0, 80], HeaderError::Reserved),
            (&[0, 0, 1, 1, 192, 0, 2, 1, 0, 80], HeaderError::Fragmented),
            (
                &[0, 0, 0, 9, 192, 0, 2, 1, 0, 80],
                HeaderError::UnsupportedAddress,
            ),
            (&[0, 0, 0, 3, 0, 0, 80], HeaderError::InvalidDomain),
            (&[0, 0, 0, 3, 1, 0xff, 0, 80], HeaderError::InvalidDomain),
        ] {
            assert_eq!(decode_header(datagram), Err(err), "{datagram:?}");
        }
    }

    #[test]
    fn unframe_relayed_datagrams() {
        let relay: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let header = [0, 0, 0, 1, 192, 0, 2, 1, 0x01, 0xbb];
        let frame = |source: &[u8], payload: &[u8]| [source, payload].concat();

        // GRO packs equal-size datagrams back to back; only the last may be shorter. A
        // dual-stack socket reports the relay IPv4-mapped.
        let mut buf = [
            frame(&header, &[1; 20]),
            frame(&header, &[2; 20]),
            frame(&header, &[3; 7]),
        ]
        .concat();
        for from in [relay, "[::ffff:127.0.0.1]:1080".parse().unwrap()] {
            let mut buf = buf.clone();
            let unframed = unframe(relay, from, &mut buf, 30).expect("relayed");
            assert_eq!(
                unframed,
                Unframed {
                    source: Address::Ip(target),
                    len: 47,
                    stride: 20
                }
            );
            assert_eq!(buf[..47], [[1; 20].as_slice(), &[2; 20], &[3; 7]].concat());
        }

        // A relay may name the source by domain, as `socks5h` targets are.
        let mut named = frame(&[0, 0, 0, 3, 1, b'a', 0, 80], b"quic");
        let unframed = unframe(relay, relay, &mut named, 12).expect("relayed");
        assert_eq!(unframed.source, Address::Domain("a".into(), 80));
        assert_eq!(&named[..unframed.len], b"quic");

        let other = [0, 0, 0, 1, 192, 0, 2, 2, 0x01, 0xbb];
        let quic = frame(&header, b"quic");
        let cases: [(&str, Vec<u8>, &str, usize); 6] = [
            ("bypassing the relay", quic.clone(), "192.0.2.1:443", 14),
            (
                "from another relay port",
                quic.clone(),
                "127.0.0.1:1081",
                14,
            ),
            (
                "mixing sources",
                [quic.clone(), frame(&other, b"quic")].concat(),
                "127.0.0.1:1080",
                14,
            ),
            (
                "fragmented",
                frame(&[0, 0, 1, 1, 192, 0, 2, 1, 0x01, 0xbb], b"quic"),
                "127.0.0.1:1080",
                14,
            ),
            ("truncated", quic[..9].to_vec(), "127.0.0.1:1080", 9),
            ("without a stride", quic.clone(), "127.0.0.1:1080", 0),
        ];
        for (case, mut datagram, from, stride) in cases {
            let unframed = unframe(relay, from.parse().unwrap(), &mut datagram, stride);
            assert_eq!(unframed, None, "{case}");
        }
        buf.clear();
        assert_eq!(unframe(relay, relay, &mut buf, 30), None, "empty");
    }

    #[tokio::test]
    async fn associate_handshake() {
        // UDP ASSOCIATE from `client_addr`.
        const REQUEST: &[u8] = &[5, 3, 0, 1, 192, 0, 2, 5, 0x11, 0x51];
        let client_addr: SocketAddr = "192.0.2.5:4433".parse().unwrap();
        let proxy_ip: IpAddr = "198.51.100.7".parse().unwrap();
        let user = Some(("user", "secret"));
        let limit = Duration::from_secs(5);

        // Scripts check what the client writes and must be used up, so an error reply ends
        // where the client stops reading.
        let login = |reply: &[u8]| {
            let mut io = Builder::new();
            io.write(&[5, 2, 0, 2])
                .read(&[5, 2])
                .write(b"\x01\x04user\x06secret")
                .read(reply);
            io
        };
        let greet = |method: &[u8]| Builder::new().write(&[5, 1, 0]).read(method).build();
        let no_auth = |reply: &[u8]| {
            Builder::new()
                .write(&[5, 1, 0])
                .read(&[5, 0])
                .write(REQUEST)
                .read(reply)
                .build()
        };
        let mut split = login(&[1, 0]);
        split.write(REQUEST);
        for byte in [5, 0, 0, 1, 192, 0, 2, 9, 0x23, 0x28] {
            split.read(&[byte]);
        }
        let ipv6 = [
            5, 0, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0x23, 0x28,
        ];
        let domain = [&[5, 0, 0, 3, 13][..], b"relay.example", &[0x23, 0x28]].concat();
        let ip = |addr: &str| Address::Ip(addr.parse().unwrap());
        let relay = Address::Domain("relay.example".into(), 9000);

        let cases = [
            // An unspecified relay address stands for the proxy's IP.
            (
                None,
                no_auth(&[5, 0, 0, 1, 0, 0, 0, 0, 0x1f, 0x90]),
                Ok((ip("0.0.0.0:8080"), ip("198.51.100.7:8080"))),
            ),
            // A specific one is used as is, as is a domain name for the caller to resolve.
            (
                None,
                no_auth(&ipv6),
                Ok((ip("[2001:db8::9]:9000"), ip("[2001:db8::9]:9000"))),
            ),
            (None, no_auth(&domain), Ok((relay.clone(), relay))),
            // After logging in, the reply arrives one byte per read.
            (
                user,
                split.build(),
                Ok((ip("192.0.2.9:9000"), ip("192.0.2.9:9000"))),
            ),
            // Credentials are offered, but the proxy needs none: no login follows.
            (
                user,
                Builder::new()
                    .write(&[5, 2, 0, 2])
                    .read(&[5, 0])
                    .write(REQUEST)
                    .read(&[5, 0, 0, 1, 192, 0, 2, 9, 0x23, 0x28])
                    .build(),
                Ok((ip("192.0.2.9:9000"), ip("192.0.2.9:9000"))),
            ),
            (user, login(&[1, 1]).build(), Err("AuthFailed")),
            // RFC 1929 replies carry version 1.
            (user, login(&[5, 0]).build(), Err("InvalidResponse")),
            (None, greet(&[5, 0xff]), Err("NoAcceptableAuth")),
            // The proxy picks a method that was not offered.
            (None, greet(&[5, 2]), Err("InvalidResponse")),
            // Not SOCKS5 replies.
            (None, greet(&[4, 0]), Err("InvalidResponse")),
            (None, no_auth(&[4, 0, 0, 1]), Err("InvalidResponse")),
            // Refused: command not supported.
            (None, no_auth(&[5, 7, 0, 1]), Err("Reply(7)")),
            // Non-zero RSV, an unknown address type, an empty domain name, and a relay on
            // port 0.
            (None, no_auth(&[5, 0, 1, 1]), Err("InvalidResponse")),
            (None, no_auth(&[5, 0, 0, 9]), Err("InvalidResponse")),
            (
                None,
                no_auth(&[5, 0, 0, 3, 0, 0x23, 0x28]),
                Err("InvalidResponse"),
            ),
            (
                None,
                no_auth(&[5, 0, 0, 1, 192, 0, 2, 9, 0, 0]),
                Err("InvalidResponse"),
            ),
        ];
        for (auth, io, expected) in cases {
            let result = timeout(limit, associate(io, auth, client_addr))
                .await
                .expect("handshake stalled");
            match (result, expected) {
                (Ok(mut association), Ok((bound, relay))) => {
                    assert_eq!(*association.bound_addr(), bound);
                    assert_eq!(association.relay_addr(proxy_ip), relay);
                    // The script has ended, so the proxy closed the control connection.
                    timeout(limit, poll_fn(|cx| association.poll_closed(cx)))
                        .await
                        .expect("EOF not reported")
                        .expect("closed");
                }
                (Err(err), Err(want)) => assert_eq!(format!("{err:?}"), want),
                (got, want) => panic!("got {got:?}, want {want:?}"),
            }
        }

        // A reply cut inside BND.ADDR. The write buffer hides any request left unflushed.
        let (client, mut server) = duplex(64);
        server.write_all(&[5, 0, 5, 0, 0, 1, 192]).await.unwrap();
        server.shutdown().await.unwrap();
        let err = timeout(limit, associate(BufWriter::new(client), None, client_addr))
            .await
            .expect("EOF not reported")
            .expect_err("truncated reply");
        assert!(
            matches!(&err, AssociateError::Io(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{err:?}"
        );
        let mut written = Vec::new();
        server.read_to_end(&mut written).await.unwrap();
        assert_eq!(written, [5, 1, 0, 5, 3, 0, 1, 192, 0, 2, 5, 0x11, 0x51]);

        // Credentials are checked before any IO: with the peer gone, IO would fail differently.
        let long = "u".repeat(256);
        for auth in [("", "secret"), ("user", ""), (long.as_str(), "secret")] {
            let (client, server) = duplex(64);
            drop(server);
            let err = associate(client, Some(auth), client_addr)
                .await
                .expect_err("invalid credentials");
            assert!(matches!(err, AssociateError::InvalidCredentials), "{err:?}");
        }
    }

    /// Control stream that is always readable: `reads` chunks, then EOF.
    struct Chatty {
        reads: usize,
    }

    impl AsyncRead for Chatty {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.reads > 0 {
                self.reads -= 1;
                buf.put_slice(&[0; 32]);
            }
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct CountWakes(AtomicUsize);

    impl Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn poll_closed_yields_to_a_chatty_proxy() {
        let mut association = UdpAssociation {
            io: Chatty { reads: 64 },
            bound: Address::Ip("192.0.2.1:9000".parse().unwrap()),
        };
        let wakes = Arc::new(CountWakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);

        // The reader never returns Pending, so each yield must schedule its own wakeup.
        let mut polls = 0;
        let mut closed = association.poll_closed(&mut cx);
        while closed.is_pending() && polls < 8 {
            polls += 1;
            assert_eq!(
                wakes.0.load(Ordering::Relaxed),
                polls,
                "yielded without a wakeup"
            );
            closed = association.poll_closed(&mut cx);
        }
        assert!(
            matches!(closed, Poll::Ready(Ok(()))),
            "EOF not reported: {closed:?}"
        );
        assert!(polls > 1, "drained the proxy in one poll");
    }
}
