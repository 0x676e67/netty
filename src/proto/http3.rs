//! HTTP/3 configuration for externally established QUIC connections.
//!
//! Extended CONNECT and pseudo-header ordering use request extensions:
//! ```
//! use netty::http3::{Protocol, PseudoId, PseudoOrder};
//!
//! let request = http::Request::connect("https://example.com/tunnel")
//!     .extension(Protocol::WEBSOCKET)
//!     .extension(PseudoOrder::builder().push(PseudoId::Method).build())
//!     .body(())?;
//! # Ok::<(), http::Error>(())
//! ```

pub use http3::{ext::Protocol, PseudoId, PseudoOrder, PseudoOrderBuilder, SettingId};

pub(crate) mod body;
pub(crate) mod client;
#[cfg(feature = "http3-datagram")]
pub(crate) mod datagram;
pub(crate) mod shared;
pub(crate) mod transport;
pub(crate) mod upgrade;

/// Builder for [`Http3Options`], applied when establishing an HTTP/3 connection.
#[must_use]
#[derive(Clone, Debug, Default)]
pub struct Http3OptionsBuilder {
    opts: Http3Options,
}

/// Options for tuning HTTP/3 connections.
///
/// Controls request admission, header limits, QPACK compression and SETTINGS.
/// Pass these options to [`crate::conn::http3::Builder`] before the handshake;
/// the caller configures QUIC transport parameters and TLS separately.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Http3Options {
    /// Maximum number of active requests, including requests waiting for QUIC stream credit.
    /// Defaults to 128; zero fails the handshake. This is a local admission limit.
    pub max_concurrent_requests: usize,

    /// Maximum decoded response field-section size in bytes; defaults to 64 KiB.
    /// Counts each name and value plus 32 bytes of overhead per field.
    /// Also advertised in SETTINGS unless omitted by [`Self::settings_order`].
    pub max_field_section_size: u64,

    /// Local limit for an encoded HEADERS payload or one QPACK encoder-stream string, in bytes.
    /// Defaults to 256 KiB. This limit is not advertised in SETTINGS.
    pub max_qpack_decode_buffer_size: usize,

    /// Maximum dynamic-table capacity used to encode requests, in bytes.
    /// Defaults to zero (stateless encoding); the peer's advertised capacity also limits it.
    pub qpack_encoder_table_capacity: usize,

    /// QPACK decoder table capacity advertised to the peer, in bytes.
    /// Defaults to `None`, omitting the setting and using the protocol default of zero.
    /// `Some(0)` explicitly advertises zero, subject to [`Self::settings_order`].
    pub qpack_max_table_capacity: Option<u64>,

    /// Maximum number of QPACK-blocked streams advertised to the peer.
    /// Defaults to `None`, omitting the setting and using the protocol default of zero.
    /// `Some(0)` explicitly advertises zero, subject to [`Self::settings_order`].
    pub qpack_blocked_streams: Option<u64>,

    /// Whether to send GREASE frames and settings. Defaults to `true`.
    pub send_grease: bool,

    /// Whether to advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`. Defaults to `false`.
    /// Sending Extended CONNECT requests still requires the peer to enable the protocol.
    pub enable_extended_connect: bool,

    /// Exact order of settings in the initial SETTINGS frame; defaults to the library order.
    /// `Some` omits unlisted or unconfigured entries; GREASE, if enabled, is appended.
    /// Datagram handshakes require `H3_DATAGRAM` in an explicit order.
    pub settings_order: Option<Vec<SettingId>>,
}

// ===== impl Http3Options =====

impl Default for Http3Options {
    #[inline]
    fn default() -> Self {
        Self {
            max_concurrent_requests: 128,
            max_field_section_size: 64 * 1024,
            max_qpack_decode_buffer_size: 256 * 1024,
            qpack_encoder_table_capacity: 0,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            send_grease: true,
            enable_extended_connect: false,
            settings_order: None,
        }
    }
}

impl Http3Options {
    /// Creates an [`Http3OptionsBuilder`] with the default connection options.
    #[inline]
    pub fn builder() -> Http3OptionsBuilder {
        Http3OptionsBuilder {
            opts: Self::default(),
        }
    }
}

// ===== impl Http3OptionsBuilder =====

impl Http3OptionsBuilder {
    /// Sets the active request limit, including requests waiting for QUIC credit.
    /// Zero fails the handshake.
    #[inline]
    pub fn max_concurrent_requests(mut self, value: usize) -> Self {
        self.opts.max_concurrent_requests = value;
        self
    }

    /// Limits decoded field sections, counting 32 bytes of overhead per field.
    /// Exceeding this limit cancels the affected response stream.
    #[inline]
    pub fn max_field_section_size(mut self, value: u64) -> Self {
        self.opts.max_field_section_size = value;
        self
    }

    /// Limits the encoded size of a received field section and decoder buffering.
    /// Exceeding this budget closes the connection with `H3_EXCESSIVE_LOAD`.
    #[inline]
    pub fn max_qpack_decode_buffer_size(mut self, value: usize) -> Self {
        self.opts.max_qpack_decode_buffer_size = value;
        self
    }

    /// Caps the local dynamic QPACK encoder table, also limited by the peer.
    #[inline]
    pub fn qpack_encoder_table_capacity(mut self, value: usize) -> Self {
        self.opts.qpack_encoder_table_capacity = value;
        self
    }

    /// Sets the advertised QPACK decoder table capacity; `None` omits it.
    #[inline]
    pub fn qpack_max_table_capacity(mut self, value: Option<u64>) -> Self {
        self.opts.qpack_max_table_capacity = value;
        self
    }

    /// Sets the advertised blocked-stream limit; `None` omits it.
    #[inline]
    pub fn qpack_blocked_streams(mut self, value: Option<u64>) -> Self {
        self.opts.qpack_blocked_streams = value;
        self
    }

    /// Enables GREASE frames and settings.
    #[inline]
    pub fn send_grease(mut self, value: bool) -> Self {
        self.opts.send_grease = value;
        self
    }

    /// Advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    /// Sending Extended CONNECT still requires permission from the peer.
    #[inline]
    pub fn enable_extended_connect(mut self, value: bool) -> Self {
        self.opts.enable_extended_connect = value;
        self
    }

    /// Selects settings in exact wire order; unlisted settings are omitted.
    /// Unconfigured entries are skipped and GREASE, if enabled, is appended.
    /// Datagram handshakes require `H3_DATAGRAM` in an explicit order.
    #[inline]
    pub fn settings_order(mut self, order: Vec<SettingId>) -> Self {
        self.opts.settings_order = Some(order);
        self
    }

    /// Finishes the configuration; the handshake validates resource limits.
    #[inline]
    pub fn build(self) -> Http3Options {
        self.opts
    }
}
