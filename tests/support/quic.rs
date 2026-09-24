//! Test transport over an externally established native QUIC connection.
//!
//! Streams and openers come from `http3-quic` through `rt::quic::Compat`; this
//! module only adds construction and the Datagram transport.
#![allow(dead_code)]

use std::task::{Context, Poll};

use ::quic as backend;
use bytes::Buf;
use netty::rt::quic::{self as rt, Compat, ConnectionError, StreamError};
#[cfg(feature = "http3-datagram")]
#[path = "quic/datagram.rs"]
mod datagram;

/// Owns the incoming streams of one established QUIC connection.
/// Use one adapter per HTTP/3 connection and keep other stream readers inactive.
pub struct Connection {
    inner: Compat<http3_quic::Connection>,
    #[cfg(feature = "http3-datagram")]
    connection: backend::Connection,
    #[cfg(feature = "http3-datagram")]
    datagrams_taken: bool,
}

// ===== impl Connection =====

impl Connection {
    /// Adapts a connection whose QUIC and TLS handshakes have completed.
    pub fn new(connection: backend::Connection) -> Self {
        Self {
            #[cfg(feature = "http3-datagram")]
            connection: connection.clone(),
            #[cfg(feature = "http3-datagram")]
            datagrams_taken: false,
            inner: Compat::new(http3_quic::Connection::new(connection)),
        }
    }
}

impl<B: Buf> rt::Connection<B> for Connection {
    type RecvStream = Compat<http3_quic::RecvStream>;

    type OpenStreams = Compat<http3_quic::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, ConnectionError>> {
        rt::Connection::<B>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, ConnectionError>> {
        rt::Connection::<B>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        rt::Connection::<B>::opener(&self.inner)
    }
}

impl<B: Buf> rt::OpenStreams<B> for Connection {
    type SendStream = Compat<http3_quic::SendStream<B>>;

    type BidiStream = Compat<http3_quic::BidiStream<B>>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamError>> {
        rt::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamError>> {
        rt::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        rt::OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}
