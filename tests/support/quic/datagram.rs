use std::{
    sync::Arc,
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use futures_util::{
    stream::{self, BoxStream},
    StreamExt,
};
use netty::rt::quic::{
    ConnectionError, DatagramConnection, DatagramError, RecvDatagram, SendDatagram,
};

use super::{backend, Connection};

/// Sends complete QUIC Datagram payloads over the adapted connection.
pub struct Sender(backend::Connection);

/// Receives complete QUIC Datagram payloads through the adapter's sole reader.
pub struct Receiver(BoxStream<'static, Result<Bytes, backend::ConnectionError>>);

// ===== impl Connection =====

impl DatagramConnection for Connection {
    type Sender = Sender;

    type Receiver = Receiver;

    fn take_datagrams(&mut self) -> Option<(Sender, Receiver)> {
        if self.datagrams_taken {
            return None;
        }
        self.datagrams_taken = true;
        let connection = self.connection.clone();
        let receiver = Box::pin(stream::unfold(connection.clone(), |connection| async {
            let data = connection.read_datagram().await;
            Some((data, connection))
        }));
        Some((Sender(connection), Receiver(receiver)))
    }
}

// ===== impl Sender =====

impl SendDatagram for Sender {
    fn max_datagram_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }

    fn poll_send(&mut self, _: &mut Context<'_>, data: &Bytes) -> Poll<Result<(), DatagramError>> {
        // Acceptance is into QUIC's bounded unreliable queue, not peer delivery.
        Poll::Ready(
            self.0
                .send_datagram(data.clone())
                .map_err(|error| match error {
                    backend::SendDatagramError::UnsupportedByPeer
                    | backend::SendDatagramError::Disabled => DatagramError::Unavailable,
                    backend::SendDatagramError::TooLarge => DatagramError::TooLarge,
                    backend::SendDatagramError::ConnectionLost(error) => {
                        DatagramError::Connection(connection_error(error))
                    }
                }),
        )
    }
}

// ===== impl Receiver =====

impl RecvDatagram for Receiver {
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, ConnectionError>> {
        Poll::Ready(
            ready!(self.0.poll_next_unpin(cx))
                .transpose()
                .map_err(connection_error),
        )
    }
}

fn connection_error(error: backend::ConnectionError) -> ConnectionError {
    match error {
        backend::ConnectionError::ApplicationClosed(error) => ConnectionError::ApplicationClose {
            error_code: error.error_code.into_inner(),
        },
        backend::ConnectionError::TimedOut => ConnectionError::Timeout,
        error => ConnectionError::Undefined(Arc::new(error)),
    }
}
