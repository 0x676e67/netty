//! MASQUE CONNECT-UDP clients ([RFC 9298](https://www.rfc-editor.org/rfc/rfc9298)).
//!
//! [`ConnectUdp`] opens a [`UdpTunnel`] to a UDP target through a proxy over HTTP/3. For other
//! setups, build the request with [`http3_request`] or [`http2_request`] and open the tunnel from
//! the response with [`UdpTunnel::from_http3`] or [`UdpTunnel::from_http2`]. Over HTTP/2 every
//! payload travels as a DATAGRAM capsule
//! ([RFC 9297 §3.5](https://www.rfc-editor.org/rfc/rfc9297.html#section-3.5)). HTTP/1.1 Upgrade
//! is not supported.

mod capsule;
mod template;
mod tunnel;

use std::{
    error::Error as StdError,
    fmt, future, io,
    task::{Context, Poll},
};

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{CONTENT_LENGTH, CONTENT_TYPE, Entry, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
};
use http_body::Body;
use tower_service::Service;

pub use self::{
    template::Template,
    tunnel::{UdpReceiver, UdpSender, UdpTunnel},
};
use super::{Tunneling, dst_host};
use crate::{
    conn::http3::{SendRequest, datagram::DatagramRequest},
    error::BoxError,
    http3::Protocol,
    proto::{
        headers,
        http2::upgrade::{CONNECT_UDP, StreamReset},
    },
};

/// Largest UDP payload carried under Context ID 0
/// ([RFC 9298 §5](https://www.rfc-editor.org/rfc/rfc9298.html#section-5)).
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// Signals the Capsule Protocol on the request stream
/// ([RFC 9297 §3.4](https://www.rfc-editor.org/rfc/rfc9297.html#section-3.4)).
const CAPSULE_PROTOCOL: HeaderName = HeaderName::from_static("capsule-protocol");

/// Builds an HTTP/3 CONNECT-UDP request for an expanded template ([RFC 9298 §3.4]).
///
/// The request declares HTTP Datagram semantics, so send it on a connection made with
/// [`Builder::handshake_with_datagrams`](crate::conn::http3::Builder::handshake_with_datagrams).
///
/// [RFC 9298 §3.4]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3.4
pub fn http3_request<B: Default>(uri: Uri) -> Request<B> {
    let mut request = connect_request(uri);
    request.extensions_mut().insert(Protocol::CONNECT_UDP);
    request.extensions_mut().insert(DatagramRequest);
    request
}

/// Builds an HTTP/2 CONNECT-UDP request for an expanded template ([RFC 9298 §3.4]).
///
/// Open the tunnel with [`UdpTunnel::from_http2`]. Taking the upgrade with
/// [`upgrade::on`](crate::upgrade::on) instead gives the bare CONNECT-UDP stream: trailers still
/// fail a read and reset it, but a drop ends it only after queued writes get flow control, while
/// an unclosed tunnel resets at once.
///
/// [RFC 9298 §3.4]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3.4
pub fn http2_request<B: Default>(uri: Uri) -> Request<B> {
    let mut request = connect_request(uri);
    request
        .extensions_mut()
        .insert(::http2::ext::Protocol::from_static(CONNECT_UDP));
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

/// Checks that a response opens the tunnel ([RFC 9298 §3.5], [RFC 9297 §3.2]).
///
/// [RFC 9298 §3.5]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3.5
/// [RFC 9297 §3.2]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
fn validate<B>(response: &Response<B>) -> Result<(), MasqueError> {
    let status = response.status();
    if !status.is_success() {
        return Err(MasqueError::Unsuccessful(status));
    }
    if headers::breaks_capsule_protocol(status, response.headers()) {
        return Err(MasqueError::InvalidResponse);
    }
    Ok(())
}

/// Connector that opens CONNECT-UDP tunnels over HTTP/3.
///
/// The inner service yields an HTTP/3 [`SendRequest`] for the template's
/// [proxy](Template::proxy), so it can pool connections. `call` takes the UDP target as a URI
/// whose host and port fill `target_host` and `target_port`; UDP has no default port, so the
/// URI must name one. The request declares HTTP Datagrams, so the connection must come from
/// [`Builder::handshake_with_datagrams`](crate::conn::http3::Builder::handshake_with_datagrams).
///
/// Each open tunnel holds a request stream and one
/// [`max_concurrent_requests`](crate::http3::Http3Options::max_concurrent_requests)
/// slot until both directions end or it is dropped, so further calls on a full connection
/// wait for a free slot. The handshake has no timeout of its own, so bound the returned
/// future, e.g. with a connect timeout around the whole connector.
///
/// A refusal yields only its status; to read its headers, such as `Proxy-Authenticate`, send
/// [`http3_request`] and open the tunnel with [`UdpTunnel::from_http3`].
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
    /// The URI template is invalid ([RFC 9298 §2]), for the given reason.
    ///
    /// [RFC 9298 §2]: https://www.rfc-editor.org/rfc/rfc9298.html#section-2
    InvalidTemplate(&'static str),
    /// The target host is neither an IPv6 literal nor a reg-name ([RFC 9298 §3]): it is empty,
    /// a bracketed literal other than IPv6, has an IPv6 zone ID or holds characters other than
    /// unreserved and sub-delims; or the port is missing, 0 or not a valid `u16`.
    ///
    /// [RFC 9298 §3]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3
    InvalidTarget,
    /// The inner connector failed to provide a connection to the proxy.
    ConnectFailed(BoxError),
    /// The CONNECT-UDP request failed, including a success response the client rejected as
    /// malformed ([RFC 9297 §3.2]).
    ///
    /// [RFC 9297 §3.2]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
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
    /// The send queue is full; wait with [`UdpSender::poll_send_ready`].
    Full,
    /// The payload exceeds [`UdpSender::max_payload_size`], or the limit fits no payload.
    TooLarge,
    /// The tunnel can no longer send.
    Closed,
}

// ===== impl UdpTunnel =====

impl UdpTunnel {
    /// Opens the tunnel from this crate's HTTP/3 client's successful response to
    /// [`http3_request`].
    ///
    /// A refusal is [`Unsuccessful`](MasqueError::Unsuccessful) and keeps its headers and body for
    /// the caller; once the body ends or is dropped, the client aborts the request stream with
    /// `H3_REQUEST_CANCELLED` ([RFC 9298 §3.1]). A success response that breaks the Capsule
    /// Protocol is malformed ([RFC 9297 §3.2]): the client resets its stream with
    /// `H3_MESSAGE_ERROR` and fails the request instead.
    ///
    /// [RFC 9298 §3.1]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3.1
    /// [RFC 9297 §3.2]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
    pub fn from_http3<B>(response: &mut Response<B>) -> Result<Self, MasqueError> {
        validate(response)?;
        let (control, sender, receiver) = crate::conn::http3::datagram::on(response)
            .ok_or(MasqueError::InvalidResponse)?
            .into_parts();
        Ok(UdpTunnel::new(control, Some((sender, receiver)), None))
    }

    /// Opens the tunnel from this crate's HTTP/2 client's successful response to
    /// [`http2_request`].
    ///
    /// A refusal is [`Unsuccessful`](MasqueError::Unsuccessful) and keeps its headers, body and
    /// upgrade for the caller; once the body is dropped, the client aborts the request stream
    /// with `CANCEL` ([RFC 9298 §3.1]). A success that is not the client's CONNECT-UDP tunnel is
    /// [`InvalidResponse`](MasqueError::InvalidResponse): an HTTP/1.1 response (a TCP tunnel),
    /// another CONNECT's, or one whose upgrade was already taken. A success response that breaks
    /// the Capsule Protocol is malformed ([RFC 9297 §3.2]): the client resets its stream with
    /// `PROTOCOL_ERROR` and fails the request instead.
    ///
    /// [RFC 9298 §3.1]: https://www.rfc-editor.org/rfc/rfc9298.html#section-3.1
    /// [RFC 9297 §3.2]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
    pub fn from_http2<B>(response: &mut Response<B>) -> Result<Self, MasqueError> {
        validate(response)?;
        let reset = response
            .extensions()
            .get::<StreamReset>()
            .cloned()
            .ok_or(MasqueError::InvalidResponse)?;
        let control = crate::upgrade::on(&mut *response)
            .take_fulfilled()
            .ok_or(MasqueError::InvalidResponse)?;
        response.extensions_mut().remove::<StreamReset>();
        Ok(UdpTunnel::new(control, None, Some(reset)))
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

    /// Adds extra headers to each CONNECT-UDP request, replacing any set earlier under the same
    /// name.
    ///
    /// A `Proxy-Authorization` among them is marked sensitive. `Content-Length`, `Content-Type` and
    /// `Transfer-Encoding` are dropped, as the Capsule Protocol forbids them ([RFC 9297 §3.2]),
    /// and so is `Capsule-Protocol`, which the request sets.
    ///
    /// [RFC 9297 §3.2]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
    pub fn with_headers(mut self, mut headers: HeaderMap) -> Self {
        for name in [
            CONTENT_LENGTH,
            CONTENT_TYPE,
            TRANSFER_ENCODING,
            CAPSULE_PROTOCOL,
        ] {
            headers.remove(name);
        }
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
        // A bad target fails before the inner connector starts connecting to the proxy.
        let target = dst_host(&dst)
            .zip(dst.port_u16())
            .ok_or(MasqueError::InvalidTarget)
            .and_then(|(host, port)| self.template.expand(host, port));
        let uri = match target {
            Ok(uri) => uri,
            Err(err) => return Tunneling::new(future::ready(Err(err))),
        };
        let connecting = self.inner.call(self.template.proxy().clone());
        let headers = self.headers.clone();

        Tunneling::new(async move {
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

// ===== impl SendError =====

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
    use std::{convert::Infallible, future::Pending};

    use bytes::Bytes;
    use futures_util::FutureExt;
    use http_body_util::Empty;

    use super::*;

    #[test]
    fn targets_need_a_valid_port() {
        /// Counts connection attempts to a proxy that never comes up.
        struct Unreachable(usize);

        impl Service<Uri> for Unreachable {
            type Response = SendRequest<Empty<Bytes>>;
            type Error = Infallible;
            type Future = Pending<Result<Self::Response, Infallible>>;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _: Uri) -> Self::Future {
                self.0 += 1;
                std::future::pending()
            }
        }

        let template = Template::well_known(&"proxy.example".parse().unwrap()).unwrap();
        let mut connector = ConnectUdp::new(template, Unreachable(0));
        // UDP has no default port to fall back on.
        let result = connector
            .call("udp://dns.example".parse().unwrap())
            .now_or_never();
        assert!(
            matches!(result, Some(Err(MasqueError::InvalidTarget))),
            "{result:?}"
        );
        assert_eq!(connector.inner.0, 0, "connected for a bad target");
    }

    #[test]
    fn extra_headers_keep_auth_sensitive_and_drop_framing() {
        let template = Template::well_known(&"proxy.example".parse().unwrap()).unwrap();
        let auth = HeaderValue::from_static("Basic c2VjcmV0");
        let mut headers = HeaderMap::new();
        headers.insert(PROXY_AUTHORIZATION, auth.clone());
        for name in [
            CONTENT_LENGTH,
            CONTENT_TYPE,
            TRANSFER_ENCODING,
            CAPSULE_PROTOCOL,
        ] {
            headers.insert(name, HeaderValue::from_static("0"));
        }
        headers.insert("x-trace", HeaderValue::from_static("1"));
        for (connector, names) in [
            (
                ConnectUdp::new(template.clone(), ()).with_auth(auth),
                &["proxy-authorization"][..],
            ),
            // A later Proxy-Authorization replaces an earlier one; framing headers go.
            (
                ConnectUdp::new(template, ())
                    .with_auth(HeaderValue::from_static("Basic b3RoZXI="))
                    .with_headers(headers),
                &["proxy-authorization", "x-trace"],
            ),
        ] {
            let values: Vec<_> = connector
                .headers
                .get_all(PROXY_AUTHORIZATION)
                .iter()
                .collect();
            assert_eq!(values, ["Basic c2VjcmV0"]);
            assert!(values[0].is_sensitive());
            let kept: Vec<_> = connector.headers.keys().map(HeaderName::as_str).collect();
            assert_eq!(kept, names);
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
