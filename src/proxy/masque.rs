//! MASQUE CONNECT-UDP clients ([RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)).
//!
//! [`ConnectUdp`] opens a [`UdpTunnel`] to a UDP target through a proxy over HTTP/3. For other
//! setups, build the request with [`http3_request`] or [`http2_request`] and open the tunnel from
//! the response with [`UdpTunnel::from_http3`] or [`UdpTunnel::from_http2`]. Over HTTP/2 every
//! payload travels as a DATAGRAM capsule (RFC 9297 §3.5). HTTP/1.1 Upgrade is not supported.

mod capsule;
mod template;
mod tunnel;

use std::{
    error::Error as StdError,
    fmt, io,
    task::{Context, Poll},
};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{CONTENT_LENGTH, CONTENT_TYPE, Entry, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
};
use http_body::Body;
use tower_service::Service;

pub use self::{template::Template, tunnel::UdpTunnel};
use super::{Tunneling, dst_host, port_or_default};
use crate::{
    conn::http3::{SendRequest, datagram::DatagramRequest},
    error::BoxError,
    http3::Protocol,
};

/// Largest UDP payload carried under Context ID 0 (RFC 9298 §5).
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// Signals the Capsule Protocol on the request stream (RFC 9297 §3.4).
const CAPSULE_PROTOCOL: HeaderName = HeaderName::from_static("capsule-protocol");

/// Builds an HTTP/3 CONNECT-UDP request for an expanded template (RFC 9298 §3.4).
///
/// The request declares HTTP Datagram semantics, so send it on a connection made with
/// `conn::http3::Builder::handshake_with_datagrams`.
pub fn http3_request<B: Default>(uri: Uri) -> Request<B> {
    let mut request = connect_request(uri);
    request.extensions_mut().insert(Protocol::CONNECT_UDP);
    request.extensions_mut().insert(DatagramRequest);
    request
}

/// Builds an HTTP/2 CONNECT-UDP request for an expanded template (RFC 9298 §3.4).
pub fn http2_request<B: Default>(uri: Uri) -> Request<B> {
    let mut request = connect_request(uri);
    request
        .extensions_mut()
        .insert(::http2::ext::Protocol::from_static("connect-udp"));
    request
}

fn connect_request<B: Default>(uri: Uri) -> Request<B> {
    let mut request = Request::new(B::default());
    *request.method_mut() = Method::CONNECT;
    *request.uri_mut() = uri;
    request
        .headers_mut()
        .insert(CAPSULE_PROTOCOL, HeaderValue::from_static("?1"));
    request
}

/// Checks that a response opens the tunnel (RFC 9298 §3.5, RFC 9297 §3.2).
fn validate<B>(response: &Response<B>) -> Result<(), MasqueError> {
    let status = response.status();
    if !status.is_success() {
        return Err(MasqueError::Unsuccessful(status));
    }
    let headers = response.headers();
    if matches!(status.as_u16(), 204..=206)
        || [CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING]
            .iter()
            .any(|name| headers.contains_key(name))
    {
        return Err(MasqueError::InvalidResponse);
    }
    Ok(())
}

/// Connector that opens CONNECT-UDP tunnels over HTTP/3.
///
/// The inner service yields an HTTP/3 [`SendRequest`] for the template's
/// [proxy](Template::proxy), so it can pool connections. `call` takes the UDP target as a URI
/// whose host and port fill `target_host` and `target_port`.
#[derive(Clone, Debug)]
pub struct ConnectUdp<S> {
    inner: S,
    template: Template,
    headers: HeaderMap,
}

/// Errors from opening or using a CONNECT-UDP tunnel.
#[derive(Debug)]
#[non_exhaustive]
pub enum MasqueError {
    /// The URI template breaks RFC 9298 §2, for the given reason.
    InvalidTemplate(&'static str),
    /// The target host is empty or has an IPv6 zone ID, or the port is 0.
    InvalidTarget,
    /// The inner connector failed to provide a connection to the proxy.
    ConnectFailed(BoxError),
    /// The CONNECT-UDP request failed.
    Request(crate::Error),
    /// The proxy refused the tunnel with this status.
    Unsuccessful(StatusCode),
    /// The response cannot start the Capsule Protocol or opened no tunnel.
    InvalidResponse,
    /// The proxy broke the Capsule Protocol or sent an oversized UDP payload.
    Malformed,
    /// An I/O error occurred on the request stream.
    Io(io::Error),
}

/// Why a UDP payload was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendError {
    /// The send queue is full; wait with [`UdpTunnel::poll_send_ready`].
    Full,
    /// The payload exceeds [`UdpTunnel::max_payload_size`].
    TooLarge,
    /// The tunnel can no longer send.
    Closed,
}

// ===== impl UdpTunnel =====

impl UdpTunnel {
    /// Opens the tunnel from a successful response to [`http3_request`].
    pub fn from_http3<B>(response: &mut Response<B>) -> Result<Self, MasqueError> {
        validate(response)?;
        let (control, sender, receiver) = crate::conn::http3::datagram::on(response)
            .ok_or(MasqueError::InvalidResponse)?
            .into_parts();
        Ok(UdpTunnel::new(control, Some((sender, receiver))))
    }

    /// Opens the tunnel from a successful response to [`http2_request`].
    pub async fn from_http2<B>(response: Response<B>) -> Result<Self, MasqueError> {
        validate(&response)?;
        let control = crate::upgrade::on(response)
            .await
            .map_err(|_| MasqueError::InvalidResponse)?;
        Ok(UdpTunnel::new(control, None))
    }
}

// ===== impl ConnectUdp =====

impl<S> ConnectUdp<S> {
    /// Creates a connector for the proxy described by `template`.
    pub fn new(template: Template, inner: S) -> Self {
        ConnectUdp {
            inner,
            template,
            headers: HeaderMap::new(),
        }
    }

    /// Sends `auth` as the `Proxy-Authorization` header, marked sensitive.
    pub fn with_auth(mut self, mut auth: HeaderValue) -> Self {
        auth.set_sensitive(true);
        self.headers.insert(PROXY_AUTHORIZATION, auth);
        self
    }

    /// Adds extra headers to each CONNECT-UDP request.
    ///
    /// A `Proxy-Authorization` among them is marked sensitive and replaces one set earlier.
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        if let Entry::Occupied(mut auth) = headers.entry(PROXY_AUTHORIZATION) {
            auth.iter_mut().for_each(|value| value.set_sensitive(true));
        }
        self.headers.extend(headers);
        self
    }
}

impl<S, B> Service<Uri> for ConnectUdp<S>
where
    S: Service<Uri, Response = SendRequest<B>>,
    S::Future: Send + 'static,
    S::Error: Into<BoxError>,
    B: Body + Default + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = UdpTunnel;
    type Error = MasqueError;
    type Future = Tunneling<UdpTunnel, MasqueError>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|err| MasqueError::ConnectFailed(err.into()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let target = dst_host(&dst)
            .ok_or(MasqueError::InvalidTarget)
            .and_then(|host| self.template.expand(host, port_or_default(&dst)));
        let connecting = self.inner.call(self.template.proxy().clone());
        let headers = self.headers.clone();

        Tunneling::new(async move {
            let uri = target?;
            let mut sender = connecting
                .await
                .map_err(|err| MasqueError::ConnectFailed(err.into()))?;
            let mut request = http3_request::<B>(uri);
            request.headers_mut().extend(headers);
            sender.ready().await.map_err(MasqueError::Request)?;
            let mut response = sender
                .try_send_request(request)
                .await
                .map_err(|err| MasqueError::Request(err.into_error()))?;
            UdpTunnel::from_http3(&mut response)
        })
    }
}

// ===== impl MasqueError =====

impl fmt::Display for MasqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MASQUE error: ")?;
        match self {
            MasqueError::InvalidTemplate(reason) => write!(f, "invalid URI template: {reason}"),
            MasqueError::InvalidTarget => f.write_str("invalid UDP target"),
            MasqueError::ConnectFailed(_) => f.write_str("failed to connect to the proxy"),
            MasqueError::Request(_) => f.write_str("CONNECT-UDP request failed"),
            MasqueError::Unsuccessful(status) => write!(f, "unsuccessful: {status}"),
            MasqueError::InvalidResponse => f.write_str("response did not open a tunnel"),
            MasqueError::Malformed => f.write_str("malformed capsule or UDP payload"),
            MasqueError::Io(_) => f.write_str("io error on the request stream"),
        }
    }
}

impl StdError for MasqueError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            MasqueError::ConnectFailed(err) => Some(&**err),
            MasqueError::Request(err) => Some(err),
            MasqueError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SendError::Full => "UDP payload queue full",
            SendError::TooLarge => "UDP payload too large",
            SendError::Closed => "tunnel closed",
        })
    }
}

impl StdError for SendError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_headers_stay_sensitive() {
        let template = Template::well_known(&"proxy.example".parse().unwrap()).unwrap();
        let auth = HeaderValue::from_static("Basic c2VjcmV0");
        let mut headers = HeaderMap::new();
        headers.insert(PROXY_AUTHORIZATION, auth.clone());
        for connector in [
            ConnectUdp::new(template.clone(), ()).with_auth(auth),
            // A later Proxy-Authorization replaces an earlier one.
            ConnectUdp::new(template, ())
                .with_auth(HeaderValue::from_static("Basic b3RoZXI="))
                .with_headers(headers),
        ] {
            let values: Vec<_> = connector
                .headers
                .get_all(PROXY_AUTHORIZATION)
                .iter()
                .collect();
            assert_eq!(values, ["Basic c2VjcmV0"]);
            assert!(values[0].is_sensitive());
            let debug = format!("{connector:?}");
            assert!(!debug.contains("c2VjcmV0"), "{debug}");
        }
    }

    #[test]
    fn responses_that_open_a_tunnel() {
        // `None` is `InvalidResponse`, `Some` is `Unsuccessful`.
        for (status, header, expected) in [
            (200, None, Ok(())),
            (207, None, Ok(())),
            (204, None, Err(None)),
            (205, None, Err(None)),
            (206, None, Err(None)),
            (200, Some(CONTENT_LENGTH), Err(None)),
            (200, Some(CONTENT_TYPE), Err(None)),
            (200, Some(TRANSFER_ENCODING), Err(None)),
            (101, None, Err(Some(101))),
            (302, None, Err(Some(302))),
            (403, None, Err(Some(403))),
        ] {
            let mut response = Response::new(());
            *response.status_mut() = StatusCode::from_u16(status).unwrap();
            if let Some(name) = &header {
                response
                    .headers_mut()
                    .insert(name, HeaderValue::from_static("0"));
            }
            let outcome = validate(&response).map_err(|err| match err {
                MasqueError::InvalidResponse => None,
                MasqueError::Unsuccessful(status) => Some(status.as_u16()),
                other => panic!("{other:?}"),
            });
            assert_eq!(outcome, expected, "{status} {header:?}");
        }

        // A refusal is reported before the missing session.
        let mut response = Response::new(());
        assert!(matches!(
            UdpTunnel::from_http3(&mut response),
            Err(MasqueError::InvalidResponse)
        ));
        *response.status_mut() = StatusCode::FORBIDDEN;
        assert!(matches!(
            UdpTunnel::from_http3(&mut response),
            Err(MasqueError::Unsuccessful(StatusCode::FORBIDDEN))
        ));
    }
}
