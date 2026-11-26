use std::{fmt, io, net::SocketAddr, str};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{AuthFailure, SocksError, Version, udp::AddressRef};
use crate::proxy::{read, send};

pub(super) const VERSION: u8 = 5;
pub(super) const ATYP_IPV4: u8 = 1;
pub(super) const ATYP_DOMAIN: u8 = 3;
pub(super) const ATYP_IPV6: u8 = 4;

const CONNECT: u8 = 1;
const AUTH_VERSION: u8 = 1;
const NO_AUTH: u8 = 0;
const USERNAME_PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const MAX_CREDENTIAL_REQUEST: usize = 3 + 2 * u8::MAX as usize;
const MAX_V4_REQUEST: usize = 10 + super::SOCKS4A_MAX_ID_AND_HOST;
const MAX_V5_REQUEST: usize = 7 + u8::MAX as usize;

pub(super) enum AuthError {
    Io(io::Error),
    InvalidCredentials,
    InvalidResponse(&'static str),
    Failed(AuthFailure),
}

#[derive(Debug)]
struct InvalidResponse(&'static str);

impl fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvalidResponse {}

/// Opens a SOCKS tunnel on the connected stream without reading application data.
pub(super) async fn connect<T>(
    io: &mut T,
    target: AddressRef<'_>,
    version: Version,
    auth: Option<(&[u8], &[u8])>,
) -> Result<(), SocksError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match version {
        Version::V4 => connect_v4(io, target, auth.map_or(&[], |(user, _)| user)).await,
        Version::V5 => {
            authenticate(io, auth).await.map_err(|error| match error {
                AuthError::Io(error) => io_error(error),
                AuthError::InvalidCredentials => SocksError::InvalidCredentials,
                AuthError::InvalidResponse(reason) => invalid_response(reason),
                AuthError::Failed(error) => SocksError::AuthFailed(error),
            })?;
            connect_v5(io, target).await
        }
    }
}

/// Negotiates SOCKS5 authentication (RFC 1928 §3 and RFC 1929 §2).
pub(super) async fn authenticate<T>(
    io: &mut T,
    auth: Option<(&[u8], &[u8])>,
) -> Result<(), AuthError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let auth = match auth {
        Some((user, pass)) => {
            let len = |value: &[u8]| {
                u8::try_from(value.len())
                    .ok()
                    .filter(|&len| len != 0)
                    .ok_or(AuthError::InvalidCredentials)
            };
            Some((user, len(user)?, pass, len(pass)?))
        }
        None => None,
    };

    let methods: &[u8] = if auth.is_some() {
        &[VERSION, 2, NO_AUTH, USERNAME_PASSWORD]
    } else {
        &[VERSION, 1, NO_AUTH]
    };
    send(io, methods).await.map_err(AuthError::Io)?;

    let [version, method] = read_array(io).await.map_err(AuthError::Io)?;
    if version != VERSION {
        return Err(AuthError::InvalidResponse(
            "invalid SOCKS5 method reply version",
        ));
    }

    match (method, auth) {
        (NO_AUTH, _) => Ok(()),
        (USERNAME_PASSWORD, Some((user, ulen, pass, plen))) => {
            let mut request = [0; MAX_CREDENTIAL_REQUEST];
            let mut remaining = &mut request[..];
            remaining.put_slice(&[AUTH_VERSION, ulen]);
            remaining.put_slice(user);
            remaining.put_u8(plen);
            remaining.put_slice(pass);
            let len = MAX_CREDENTIAL_REQUEST - remaining.len();
            send(io, &request[..len]).await.map_err(AuthError::Io)?;

            let [version, status] = read_array(io).await.map_err(AuthError::Io)?;
            match (version, status) {
                (AUTH_VERSION, 0) => Ok(()),
                (AUTH_VERSION, status) => Err(AuthError::Failed(AuthFailure::Rejected(status))),
                _ => Err(AuthError::InvalidResponse(
                    "invalid SOCKS5 auth reply version",
                )),
            }
        }
        (USERNAME_PASSWORD, None) => Err(AuthError::Failed(AuthFailure::Required)),
        (NO_ACCEPTABLE_METHODS, _) => Err(AuthError::Failed(AuthFailure::NoAcceptableMethod)),
        _ => Err(AuthError::InvalidResponse(
            "unsupported SOCKS5 authentication method",
        )),
    }
}

async fn connect_v4<T>(io: &mut T, target: AddressRef<'_>, user: &[u8]) -> Result<(), SocksError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = [0; MAX_V4_REQUEST];
    let mut remaining = &mut request[..];
    remaining.put_slice(&[4, CONNECT]);
    remaining.put_u16(target.port());
    match target {
        AddressRef::Ip(SocketAddr::V4(addr)) => remaining.put_slice(&addr.ip().octets()),
        AddressRef::Ip(SocketAddr::V6(_)) => return Err(SocksError::AddressNotSupported),
        AddressRef::Domain(..) => remaining.put_slice(&[0, 0, 0, 1]),
    }
    remaining.put_slice(user);
    remaining.put_u8(0);
    if let AddressRef::Domain(host, _) = target {
        remaining.put_slice(host.as_bytes());
        remaining.put_u8(0);
    }
    let len = MAX_V4_REQUEST - remaining.len();
    send(io, &request[..len]).await.map_err(io_error)?;

    match read_array::<_, 8>(io).await.map_err(io_error)? {
        [0, 90, ..] => Ok(()),
        [0, code, ..] => Err(SocksError::Reply {
            version: Version::V4,
            code,
        }),
        _ => Err(invalid_response("invalid SOCKS4 CONNECT reply version")),
    }
}

async fn connect_v5<T>(io: &mut T, target: AddressRef<'_>) -> Result<(), SocksError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0; MAX_V5_REQUEST];
    let mut remaining = &mut buf[..];
    remaining.put_slice(&[VERSION, CONNECT, 0]);
    match target {
        AddressRef::Ip(SocketAddr::V4(addr)) => {
            remaining.put_u8(ATYP_IPV4);
            remaining.put_slice(&addr.ip().octets());
        }
        AddressRef::Ip(SocketAddr::V6(addr)) => {
            remaining.put_u8(ATYP_IPV6);
            remaining.put_slice(&addr.ip().octets());
        }
        AddressRef::Domain(host, _) => {
            let len = u8::try_from(host.len()).map_err(|_| SocksError::HostTooLong)?;
            remaining.put_slice(&[ATYP_DOMAIN, len]);
            remaining.put_slice(host.as_bytes());
        }
    }
    remaining.put_u16(target.port());
    let len = MAX_V5_REQUEST - remaining.len();
    send(io, &buf[..len]).await.map_err(io_error)?;

    let [version, code, reserved, atyp] = read_array(io).await.map_err(io_error)?;
    if version != VERSION {
        return Err(invalid_response("invalid SOCKS5 CONNECT reply version"));
    }
    if reserved != 0 {
        return Err(invalid_response(
            "nonzero reserved byte in SOCKS5 CONNECT reply",
        ));
    }
    if code != 0 {
        return Err(SocksError::Reply {
            version: Version::V5,
            code,
        });
    }

    // Consume only BND.ADDR and BND.PORT: application data can already follow in the stream.
    let len = match atyp {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let [len] = read_array(io).await.map_err(io_error)?;
            usize::from(len)
        }
        _ => return Err(invalid_response("unsupported SOCKS5 bound address type")),
    };
    read_exact(io, &mut buf[..len + 2])
        .await
        .map_err(io_error)?;
    if atyp == ATYP_DOMAIN {
        str::from_utf8(&buf[..len])
            .map_err(|_| invalid_response("invalid UTF-8 in SOCKS5 bound domain"))?;
    }
    Ok(())
}

pub(super) async fn read_exact<T>(io: &mut T, mut buf: &mut [u8]) -> io::Result<()>
where
    T: AsyncRead + Unpin,
{
    while !buf.is_empty() {
        let len = read(io, buf).await?;
        if len == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[len..];
    }
    Ok(())
}

pub(super) async fn read_array<T, const N: usize>(io: &mut T) -> io::Result<[u8; N]>
where
    T: AsyncRead + Unpin,
{
    let mut buf = [0; N];
    read_exact(io, &mut buf).await?;
    Ok(buf)
}

fn io_error(error: io::Error) -> SocksError {
    SocksError::Handshake(error.into())
}

fn invalid_response(reason: &'static str) -> SocksError {
    SocksError::Handshake(Box::new(InvalidResponse(reason)))
}
