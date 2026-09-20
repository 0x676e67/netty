use std::{
    fmt,
    task::{Context, Poll},
};

use bytes::Bytes;

use super::ConnectionError;

/// Optional access to a QUIC connection's Datagram transport.
pub trait DatagramConnection {
    /// Sends complete QUIC Datagram payloads, without HTTP framing.
    type Sender: SendDatagram;

    /// The connection's sole Datagram receiver.
    type Receiver: RecvDatagram;

    /// Takes the Datagram reader and sender once. Returns None if already taken.
    /// Both handles must refer to this QUIC connection, including its lifetime.
    /// The caller must not receive Datagrams through another adapter, a retained
    /// transport handle, or a legacy API: those readers would compete for packets.
    fn take_datagrams(&mut self) -> Option<(Self::Sender, Self::Receiver)>;
}

/// Sends complete, unreliable QUIC Datagram payloads.
pub trait SendDatagram {
    /// Current maximum QUIC Datagram payload; None means unavailable.
    /// The value can change and is checked again when sending.
    fn max_datagram_size(&self) -> Option<usize>;

    /// Accepts an entire payload or returns an error. Pending must not accept it
    /// and must arrange a wakeup. Success does not guarantee delivery; bounded
    /// transport queues may discard accepted datagrams according to their policy.
    ///
    /// After Pending, the caller may supply a different payload or stop polling.
    /// The previous payload must not be sent later, including by a retained
    /// backend operation; only a successful poll accepts the supplied payload.
    fn poll_send(&mut self, cx: &mut Context<'_>, data: &Bytes) -> Poll<Result<(), DatagramError>>;
}

/// Receives whole QUIC Datagram payloads through one connection-level reader.
pub trait RecvDatagram {
    /// Returns one whole payload, normal closure (None), or a connection error.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, ConnectionError>>;
}

/// Failure to accept a QUIC Datagram into the local transport.
#[derive(Debug)]
#[non_exhaustive]
pub enum DatagramError {
    /// QUIC Datagrams were not enabled by both endpoints.
    Unavailable,

    /// The payload exceeds the current transport maximum.
    TooLarge,

    /// The QUIC connection failed.
    Connection(ConnectionError),
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("QUIC Datagrams unavailable"),
            Self::TooLarge => f.write_str("QUIC Datagram too large"),
            Self::Connection(error) => write!(f, "QUIC Datagram connection error: {error}"),
        }
    }
}

impl std::error::Error for DatagramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            _ => None,
        }
    }
}
