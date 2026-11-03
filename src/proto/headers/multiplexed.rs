//! Field rules shared by HTTP/2 ([RFC 9113 §8.2]) and HTTP/3 ([RFC 9114 §4.2]).
//!
//! [RFC 9113 §8.2]: https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2
//! [RFC 9114 §4.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2

use http::{
    HeaderMap, Method, StatusCode,
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue, TE, TRANSFER_ENCODING,
        UPGRADE,
    },
};

// List of connection headers from RFC 9110 Section 7.6.1
//
// TE headers are allowed in HTTP/2 or HTTP/3 requests as long as the value is "trailers", so
// they're tested separately.
static CONNECTION_HEADERS: [HeaderName; 4] = [
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    TRANSFER_ENCODING,
    UPGRADE,
];

pub(crate) fn strip_connection_headers(headers: &mut HeaderMap, is_request: bool) {
    for header in &CONNECTION_HEADERS {
        if headers.remove(header).is_some() {
            warn!(
                "Connection header illegal in HTTP/2 or HTTP/3: {}",
                header.as_str()
            );
        }
    }

    if is_request {
        if headers
            .get(TE)
            .is_some_and(|te_header| te_header != "trailers")
        {
            warn!("TE headers not set to \"trailers\" are illegal in HTTP/2 or HTTP/3 requests");
            headers.remove(TE);
        }
    } else if headers.remove(TE).is_some() {
        warn!("TE headers illegal in HTTP/2 or HTTP/3 responses");
    }

    if let Some(header) = headers.remove(CONNECTION) {
        warn!(
            "Connection header illegal in HTTP/2 or HTTP/3: {}",
            CONNECTION.as_str()
        );

        if let Ok(header_contents) = header.to_str() {
            // A `Connection` header may have a comma-separated list of names of other headers that
            // are meant for only this specific connection.
            //
            // Iterate these names and remove them as headers. Connection-specific headers are
            // forbidden in HTTP/2 and HTTP/3, as that information has been moved into frame types
            // of the multiplexed protocol.
            for name in header_contents.split(',') {
                let name = name.trim();
                headers.remove(name);
            }
        }
    }
}

/// Whether a success response breaks the Capsule Protocol, which makes it malformed
/// ([RFC 9297 §3.2](https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2)).
pub(crate) fn breaks_capsule_protocol(status: StatusCode, headers: &HeaderMap) -> bool {
    matches!(status.as_u16(), 204..=206)
        || [CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING]
            .iter()
            .any(|name| headers.contains_key(name))
}

#[inline]
pub(crate) fn method_has_defined_payload_semantics(method: &Method) -> bool {
    !matches!(
        *method,
        Method::GET | Method::HEAD | Method::DELETE | Method::CONNECT | Method::OPTIONS
    )
}

#[inline]
pub(crate) fn set_content_length_if_missing(headers: &mut HeaderMap, len: u64) {
    headers
        .entry(CONTENT_LENGTH)
        .or_insert_with(|| HeaderValue::from(len));
}
