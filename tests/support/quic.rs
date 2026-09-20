//! Test transport over an externally established native QUIC connection.
#![allow(dead_code)]

use std::{
    future::Future,
    pin::{pin, Pin},
    sync::Arc,
    task::{ready, Context, Poll},
};

use ::quic as backend;
use bytes::{Buf, Bytes};
use futures_util::{stream, Stream, StreamExt};
use wreq_proto::rt::quic::{self as rt, ConnectionError, StreamError, StreamId};
#[cfg(feature = "http3-datagram")]
#[path = "quic/datagram.rs"]
mod datagram;

type Opening<T> = Pin<Box<dyn Future<Output = Result<T, backend::ConnectionError>> + Send>>;

type Incoming<T> = Pin<Box<dyn Stream<Item = Result<T, backend::ConnectionError>> + Send>>;

/// Owns the incoming streams of one established QUIC connection.
/// Use one adapter per HTTP/3 connection and keep other stream readers inactive.
pub struct Connection {
    open: OpenStreams,
    incoming_bidi: Incoming<(backend::SendStream, backend::RecvStream)>,
    incoming_recv: Incoming<backend::RecvStream>,
    #[cfg(feature = "http3-datagram")]
    datagrams_taken: bool,
}

/// Opens outgoing streams independently of the HTTP/3 connection driver.
pub struct OpenStreams {
    connection: backend::Connection,
    opening_bidi: Option<Opening<(backend::SendStream, backend::RecvStream)>>,
    opening_send: Option<Opening<backend::SendStream>>,
}

/// Sends bytes and observes peer cancellation on one QUIC stream direction.
pub struct SendStream {
    inner: backend::SendStream,
    id: StreamId,
}

/// Receives owned chunks from one QUIC stream direction.
pub struct RecvStream {
    inner: backend::RecvStream,
    id: StreamId,
}

/// A bidirectional request stream before its ownership is split by direction.
pub struct BidiStream {
    send: SendStream,
    recv: RecvStream,
}

// ===== impl Connection =====

impl Connection {
    /// Adapts a connection whose QUIC and TLS handshakes have completed.
    pub fn new(connection: backend::Connection) -> Self {
        Self {
            incoming_bidi: Box::pin(stream::unfold(connection.clone(), |connection| async {
                let stream = connection.accept_bi().await;
                Some((stream, connection))
            })),
            incoming_recv: Box::pin(stream::unfold(connection.clone(), |connection| async {
                let stream = connection.accept_uni().await;
                Some((stream, connection))
            })),
            open: OpenStreams {
                connection,
                opening_bidi: None,
                opening_send: None,
            },
            #[cfg(feature = "http3-datagram")]
            datagrams_taken: false,
        }
    }
}

impl<B: Buf> rt::Connection<B> for Connection {
    type RecvStream = RecvStream;

    type OpenStreams = OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RecvStream>, ConnectionError>> {
        self.incoming_recv.poll_next_unpin(cx).map(|result| {
            result
                .transpose()
                .map_err(connection_error)
                .and_then(|stream| stream.map(RecvStream::new).transpose())
        })
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<BidiStream>, ConnectionError>> {
        self.incoming_bidi.poll_next_unpin(cx).map(|result| {
            result
                .transpose()
                .map_err(connection_error)
                .and_then(|stream| stream.map(BidiStream::new).transpose())
        })
    }

    fn opener(&self) -> OpenStreams {
        self.open.clone()
    }
}

impl<B: Buf> rt::OpenStreams<B> for Connection {
    type SendStream = SendStream;

    type BidiStream = BidiStream;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream, StreamError>> {
        <OpenStreams as rt::OpenStreams<B>>::poll_open_bidi(&mut self.open, cx)
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendStream, StreamError>> {
        <OpenStreams as rt::OpenStreams<B>>::poll_open_send(&mut self.open, cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        <OpenStreams as rt::OpenStreams<B>>::close(&mut self.open, code, reason);
    }
}

// ===== impl OpenStreams =====

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            opening_bidi: None,
            opening_send: None,
        }
    }
}

impl<B: Buf> rt::OpenStreams<B> for OpenStreams {
    type SendStream = SendStream;

    type BidiStream = BidiStream;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<BidiStream, StreamError>> {
        let opening = self.opening_bidi.get_or_insert_with(|| {
            let connection = self.connection.clone();
            Box::pin(async move { connection.open_bi().await })
        });
        let result = ready!(opening.as_mut().poll(cx));
        self.opening_bidi = None;
        Poll::Ready(
            result
                .map_err(connection_error)
                .and_then(BidiStream::new)
                .map_err(|connection_error| StreamError::ConnectionErrorIncoming {
                    connection_error,
                }),
        )
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<SendStream, StreamError>> {
        let opening = self.opening_send.get_or_insert_with(|| {
            let connection = self.connection.clone();
            Box::pin(async move { connection.open_uni().await })
        });
        let result = ready!(opening.as_mut().poll(cx));
        self.opening_send = None;
        Poll::Ready(
            result
                .map_err(connection_error)
                .and_then(SendStream::new)
                .map_err(|connection_error| StreamError::ConnectionErrorIncoming {
                    connection_error,
                }),
        )
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        // HTTP/3 codes fit QUIC's varint; invalid caller codes are local misuse.
        let code =
            backend::VarInt::from_u64(code).unwrap_or_else(|_| backend::VarInt::from_u32(0x102));
        self.connection.close(code, reason);
    }
}

// ===== impl SendStream =====

impl SendStream {
    fn new(inner: backend::SendStream) -> Result<Self, ConnectionError> {
        Ok(Self {
            id: stream_id(inner.id())?,
            inner,
        })
    }
}

impl<B: Buf> rt::SendStream<B> for SendStream {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut D,
    ) -> Poll<Result<usize, StreamError>> {
        let written =
            ready!(Pin::new(&mut self.inner).poll_write(cx, data.chunk())).map_err(write_error)?;
        data.advance(written);
        Poll::Ready(Ok(written))
    }

    fn stopped(&self) -> impl Future<Output = Result<Option<u64>, StreamError>> + Send + 'static {
        let stopped = self.inner.stopped();
        async move {
            stopped
                .await
                .map(|code| code.map(backend::VarInt::into_inner))
                .map_err(|error| match error {
                    backend::StoppedError::ConnectionLost(error) => connection_stream_error(error),
                    error @ backend::StoppedError::ZeroRttRejected => {
                        StreamError::Unknown(Box::new(error))
                    }
                })
        }
    }

    fn poll_finish(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        Poll::Ready(
            self.inner
                .finish()
                .map_err(|error| StreamError::Unknown(Box::new(error))),
        )
    }

    fn reset(&mut self, code: u64) {
        let code =
            backend::VarInt::from_u64(code).unwrap_or_else(|_| backend::VarInt::from_u32(0x102));
        let _ = self.inner.reset(code);
    }

    fn send_id(&self) -> StreamId {
        self.id
    }
}

// ===== impl RecvStream =====

impl RecvStream {
    fn new(inner: backend::RecvStream) -> Result<Self, ConnectionError> {
        Ok(Self {
            id: stream_id(inner.id())?,
            inner,
        })
    }
}

impl rt::RecvStream for RecvStream {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
        let result = ready!(pin!(self.inner.read_chunk(usize::MAX, true)).poll(cx));
        Poll::Ready(result.map(|chunk| chunk.map(|chunk| chunk.bytes)).map_err(
            |error| match error {
                backend::ReadError::Reset(code) => StreamError::StreamTerminated {
                    error_code: code.into_inner(),
                },
                backend::ReadError::ConnectionLost(error) => connection_stream_error(error),
                error => StreamError::Unknown(Box::new(error)),
            },
        ))
    }

    fn stop_sending(&mut self, code: u64) {
        let code =
            backend::VarInt::from_u64(code).unwrap_or_else(|_| backend::VarInt::from_u32(0x102));
        let _ = self.inner.stop(code);
    }

    fn recv_id(&self) -> StreamId {
        self.id
    }
}

// ===== impl BidiStream =====

impl BidiStream {
    fn new(
        (send, recv): (backend::SendStream, backend::RecvStream),
    ) -> Result<Self, ConnectionError> {
        Ok(Self {
            send: SendStream::new(send)?,
            recv: RecvStream::new(recv)?,
        })
    }
}

impl<B: Buf> rt::SendStream<B> for BidiStream {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        data: &mut D,
    ) -> Poll<Result<usize, StreamError>> {
        <SendStream as rt::SendStream<B>>::poll_send(&mut self.send, cx, data)
    }

    fn stopped(&self) -> impl Future<Output = Result<Option<u64>, StreamError>> + Send + 'static {
        <SendStream as rt::SendStream<B>>::stopped(&self.send)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        <SendStream as rt::SendStream<B>>::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, code: u64) {
        <SendStream as rt::SendStream<B>>::reset(&mut self.send, code);
    }

    fn send_id(&self) -> StreamId {
        <SendStream as rt::SendStream<B>>::send_id(&self.send)
    }
}

impl rt::RecvStream for BidiStream {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamError>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, code: u64) {
        self.recv.stop_sending(code);
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> rt::BidiStream<B> for BidiStream {
    type SendStream = SendStream;

    type RecvStream = RecvStream;

    fn split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
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

fn connection_stream_error(error: backend::ConnectionError) -> StreamError {
    StreamError::ConnectionErrorIncoming {
        connection_error: connection_error(error),
    }
}

fn write_error(error: backend::WriteError) -> StreamError {
    match error {
        backend::WriteError::Stopped(code) => StreamError::StreamTerminated {
            error_code: code.into_inner(),
        },
        backend::WriteError::ConnectionLost(error) => connection_stream_error(error),
        error => StreamError::Unknown(Box::new(error)),
    }
}

fn stream_id(id: backend::StreamId) -> Result<StreamId, ConnectionError> {
    StreamId::try_from(u64::from(id)).map_err(|_| {
        ConnectionError::InternalError(
            "QUIC backend returned a stream ID outside the 62-bit range".into(),
        )
    })
}
