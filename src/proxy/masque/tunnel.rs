//! UDP payloads over a CONNECT-UDP request stream.

use std::{
    fmt, io, mem,
    pin::Pin,
    task::{Context, Poll, Waker, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncWrite, ReadHalf, WriteHalf};

use super::{MAX_UDP_PAYLOAD, MasqueError, SendError, capsule};
use crate::{
    conn::http3::datagram::{Receiver, SendErrorKind, Sender},
    upgrade::Upgraded,
};

/// Capsule bytes buffered for the control stream before sends report [`SendError::Full`].
const WRITE_LIMIT: usize = 64 * 1024;

/// Read size for the control stream.
const READ_CHUNK: usize = 8 * 1024;

/// A CONNECT-UDP tunnel carrying UDP payloads for one target
/// ([RFC 9298 §5](https://www.rfc-editor.org/rfc/rfc9298.html#section-5)).
///
/// Payloads travel as HTTP Datagrams when the HTTP/3 connection negotiated them, and otherwise
/// as DATAGRAM capsules on the request stream; received capsules are always accepted. Use the
/// tunnel from one task, or [`split`](Self::split) it to send and receive from two.
///
/// Dropping the tunnel, or both its halves, aborts the request stream, which closes the tunnel
/// at the proxy.
#[derive(Debug)]
pub struct UdpTunnel {
    sender: UdpSender,
    receiver: UdpReceiver,
}

/// The sending half of a [`UdpTunnel`].
///
/// HTTP Datagrams go out as they are admitted. A capsule the request stream cannot take at
/// once stays buffered until this half is polled again, so a task that only sends calls
/// [`poll_flush`](Self::poll_flush) before it waits on anything else. Dropping the sender alone
/// sends no FIN; [`poll_close`](Self::poll_close) does.
pub struct UdpSender {
    control: WriteHalf<Upgraded>,
    native: Option<Sender>,
    write_buf: BytesMut,
    /// Whether capsule bytes were written since the last flush.
    unflushed: bool,
    /// Set when `poll_close` starts: sends are refused while buffered capsules drain.
    closing: bool,
    /// Set once the request stream takes no more capsules, after a close or a write error.
    write_closed: bool,
    /// The first write error, reported once by `poll_flush` or `poll_close`.
    write_error: Option<io::Error>,
}

/// The receiving half of a [`UdpTunnel`].
///
/// Dropping the receiver alone discards queued HTTP Datagrams; the request stream stays open
/// until the sender is dropped too.
pub struct UdpReceiver {
    control: ReadHalf<Upgraded>,
    native: Option<Receiver>,
    /// Whether HTTP Datagrams can still arrive.
    native_open: bool,
    decoder: capsule::Decoder,
    read_buf: BytesMut,
    /// Why receiving failed, so later polls report it again.
    error: Option<RecvError>,
    /// Whether the next receive reads the request stream before HTTP Datagrams.
    stream_first: bool,
}

/// A receive failure, kept so later polls report it again.
#[derive(Clone)]
enum RecvError {
    Malformed,
    Io(io::ErrorKind, String),
}

// ===== impl UdpTunnel =====

impl UdpTunnel {
    pub(super) fn new(control: Upgraded, native: Option<(Sender, Receiver)>) -> Self {
        let (read, write) = tokio::io::split(control);
        let (sender, receiver) = native.unzip();
        UdpTunnel {
            sender: UdpSender {
                control: write,
                native: sender,
                write_buf: BytesMut::new(),
                unflushed: false,
                closing: false,
                write_closed: false,
                write_error: None,
            },
            receiver: UdpReceiver {
                control: read,
                native_open: receiver.is_some(),
                native: receiver,
                decoder: capsule::Decoder::default(),
                read_buf: BytesMut::new(),
                error: None,
                stream_first: false,
            },
        }
    }

    /// Splits the tunnel into halves that two tasks can own. Unlike
    /// [`poll_recv`](Self::poll_recv), the receiving half writes no buffered capsules.
    pub fn split(self) -> (UdpSender, UdpReceiver) {
        (self.sender, self.receiver)
    }

    /// See [`UdpSender::max_payload_size`].
    pub fn max_payload_size(&self) -> usize {
        self.sender.max_payload_size()
    }

    /// See [`UdpSender::try_send`].
    pub fn try_send(&mut self, payload: &[u8]) -> Result<(), SendError> {
        self.sender.try_send(payload)
    }

    /// See [`UdpSender::poll_send_ready`].
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SendError>> {
        self.sender.poll_send_ready(cx)
    }

    /// See [`UdpReceiver::poll_recv`]; also writes buffered capsules, so a task that only
    /// receives still sends them.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MasqueError>> {
        let _ = self.sender.poll_write_buf(cx);
        self.receiver.poll_recv(cx)
    }

    /// See [`UdpSender::poll_flush`].
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sender.poll_flush(cx)
    }

    /// See [`UdpSender::poll_close`].
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sender.poll_close(cx)
    }
}

// ===== impl UdpSender =====

impl UdpSender {
    /// Returns the largest UDP payload a send currently accepts, or 0 once sends fail with
    /// [`Closed`](SendError::Closed).
    ///
    /// With HTTP Datagrams this is the QUIC datagram limit less the Quarter Stream ID and
    /// Context ID; larger payloads are rejected rather than moved to capsules, so the path MTU
    /// stays visible ([RFC 9298 §6.1]). A limit too small for any payload also reads as 0, which
    /// [`poll_send_ready`](Self::poll_send_ready) reports as [`TooLarge`](SendError::TooLarge).
    /// Inner QUIC needs at least 1200 bytes ([RFC 9000 §14]).
    ///
    /// [RFC 9298 §6.1]: https://www.rfc-editor.org/rfc/rfc9298.html#section-6.1
    /// [RFC 9000 §14]: https://www.rfc-editor.org/rfc/rfc9000.html#section-14
    pub fn max_payload_size(&self) -> usize {
        // The same order as `try_send`.
        if self.closing || self.native.as_ref().is_some_and(Sender::is_closed) {
            return 0;
        }
        match self.native_limit() {
            Some(limit) => limit,
            None if self.write_closed => 0,
            None => MAX_UDP_PAYLOAD,
        }
    }

    /// Payload limit of HTTP Datagrams, if they are usable.
    fn native_limit(&self) -> Option<usize> {
        let max = self.native.as_ref()?.max_datagram_size()?;
        Some(max.saturating_sub(1).min(MAX_UDP_PAYLOAD))
    }

    /// Queues one UDP payload; success is local admission, not delivery.
    ///
    /// A capsule is written as far as the request stream takes it now; the rest waits for
    /// [`poll_flush`](Self::poll_flush), [`poll_close`](Self::poll_close) or a
    /// [`poll_send_ready`](Self::poll_send_ready) that writes it.
    pub fn try_send(&mut self, payload: &[u8]) -> Result<(), SendError> {
        if self.closing {
            return Err(SendError::Closed);
        }
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(SendError::TooLarge);
        }
        if let Some(native) = &self.native {
            // Context ID 0 carries UDP payloads.
            // https://www.rfc-editor.org/rfc/rfc9298.html#section-4
            match native.try_send_prefixed(&[0], payload) {
                Ok(()) => return Ok(()),
                Err(SendErrorKind::Full) => return Err(SendError::Full),
                Err(SendErrorKind::TooLarge) => return Err(SendError::TooLarge),
                Err(SendErrorKind::Closed) => return Err(SendError::Closed),
                // Datagrams were not negotiated: use capsules.
                // https://www.rfc-editor.org/rfc/rfc9297.html#section-3.5
                Err(SendErrorKind::Unavailable) => {}
            }
        }
        if self.write_closed {
            return Err(SendError::Closed);
        }
        if self.write_buf.len() >= WRITE_LIMIT {
            return Err(SendError::Full);
        }
        capsule::encode_datagram(payload, &mut self.write_buf);
        let _ = self.poll_write_buf(&mut Context::from_waker(Waker::noop()));
        if self.write_closed {
            return Err(SendError::Closed);
        }
        Ok(())
    }

    /// Waits until a payload of [`max_payload_size`](Self::max_payload_size) would be accepted;
    /// fails with [`TooLarge`](SendError::TooLarge) when the limit fits no payload. Capsules
    /// may still be buffered when it is ready.
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SendError>> {
        if self.closing {
            return Poll::Ready(Err(SendError::Closed));
        }
        if let Some(native) = &mut self.native {
            match ready!(native.poll_ready(cx)) {
                // The Context ID alone already exceeds the limit.
                Ok(()) if native.max_datagram_size() == Some(0) => {
                    return Poll::Ready(Err(SendError::TooLarge));
                }
                Ok(()) => return Poll::Ready(Ok(())),
                Err(SendErrorKind::Unavailable) => {}
                Err(SendErrorKind::TooLarge) => return Poll::Ready(Err(SendError::TooLarge)),
                Err(_) => return Poll::Ready(Err(SendError::Closed)),
            }
        }
        let _ = self.poll_write_buf(cx);
        if self.write_closed {
            Poll::Ready(Err(SendError::Closed))
        } else if self.write_buf.len() < WRITE_LIMIT {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// Writes buffered capsules to the request stream; HTTP Datagrams need no flush.
    ///
    /// Returns the first write error once.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_write_buf(cx));
        Poll::Ready(self.write_error.take().map_or(Ok(()), Err))
    }

    /// Writes buffered capsules, then closes the request stream for sending. HTTP Datagrams
    /// still queued are discarded, as no Datagram may follow the FIN
    /// ([RFC 9297 §2.1](https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1)).
    ///
    /// Sends are refused from the first call on. Returns the first write error once, and `Ok`
    /// at once after that or after a close.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closing = true;
        ready!(self.poll_write_buf(cx));
        if !self.write_closed {
            let shutdown = ready!(Pin::new(&mut self.control).poll_shutdown(cx));
            self.write_closed = true;
            self.write_error = shutdown.err();
        }
        Poll::Ready(self.write_error.take().map_or(Ok(()), Err))
    }

    /// Writes buffered capsules, then flushes the request stream if anything was written.
    ///
    /// A write error stops sending and keeps the error for `poll_flush` or `poll_close`.
    fn poll_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.write_closed {
            return Poll::Ready(());
        }
        let result = loop {
            if self.write_buf.is_empty() {
                // Skipping idle flushes spares HTTP/3 a flush round trip on every receive.
                if !self.unflushed {
                    break Ok(());
                }
                let flushed = ready!(Pin::new(&mut self.control).poll_flush(cx));
                self.unflushed = false;
                break flushed;
            }
            match ready!(Pin::new(&mut self.control).poll_write(cx, &self.write_buf)) {
                Ok(0) => break Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.write_buf.advance(n);
                    self.unflushed = true;
                }
                Err(err) => break Err(err),
            }
        };
        if let Err(err) = result {
            self.write_error = Some(err);
            self.write_closed = true;
            self.write_buf.clear();
        }
        Poll::Ready(())
    }
}

impl fmt::Debug for UdpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpSender")
            .field("datagrams", &self.native_limit().is_some())
            .field("max_payload_size", &self.max_payload_size())
            .finish_non_exhaustive()
    }
}

// ===== impl UdpReceiver =====

impl UdpReceiver {
    /// Receives the next UDP payload; `None` once the proxy closed the tunnel.
    ///
    /// An error ends receiving and later calls report it again, with the same kind and
    /// message. A capsule cut short by the end of the stream also resets the request stream
    /// with `H3_MESSAGE_ERROR` ([RFC 9297 §3.3]), and an oversized payload with
    /// `H3_DATAGRAM_ERROR` ([RFC 9298 §5]).
    ///
    /// [RFC 9297 §3.3]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.3
    /// [RFC 9298 §5]: https://www.rfc-editor.org/rfc/rfc9298.html#section-5
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MasqueError>> {
        if let Some(err) = &self.error {
            return Poll::Ready(Err(err.clone().into()));
        }
        let result = ready!(self.poll_payload(cx));
        // Ending inside a capsule breaks the Capsule Protocol, which makes the whole message
        // malformed; the other errors are malformed payloads.
        let truncated = matches!(result, Ok(None)) && self.decoder.is_partial(&self.read_buf);
        let result = if truncated {
            Err(MasqueError::Malformed)
        } else {
            result
        };
        if let Err(err) = &result {
            let failed = match err {
                MasqueError::Io(err) => RecvError::Io(err.kind(), err.to_string()),
                _ => RecvError::Malformed,
            };
            if let (RecvError::Malformed, Some(native)) = (&failed, &self.native) {
                if truncated {
                    native.abort_malformed_message();
                } else {
                    native.abort_malformed();
                }
            }
            self.error = Some(failed);
        }
        Poll::Ready(result)
    }

    /// Polls the next payload from HTTP Datagrams or the request stream; `None` at the end of the
    /// stream, even inside a capsule.
    fn poll_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MasqueError>> {
        // Alternate the first source, so a steady flow on one cannot hold back the other.
        let mut stream_first = self.stream_first;
        self.stream_first = !stream_first;
        // Each round drops at most one payload or reads once, so a proxy flooding unknown
        // contexts or capsule types cannot keep this call from yielding.
        for _ in 0..32 {
            if !stream_first
                && self.native_open
                && let Some(native) = &mut self.native
            {
                match native.poll_recv(cx) {
                    Poll::Ready(Some(datagram)) => match udp_payload(datagram)? {
                        Some(payload) => return Poll::Ready(Ok(Some(payload))),
                        None => continue,
                    },
                    Poll::Ready(None) => self.native_open = false,
                    Poll::Pending => {}
                }
            }

            if let Some(datagram) = self.decoder.decode(&mut self.read_buf)? {
                match udp_payload(datagram)? {
                    Some(payload) => return Poll::Ready(Ok(Some(payload))),
                    None => continue,
                }
            }
            self.read_buf.reserve(READ_CHUNK);
            let read =
                tokio_util::io::poll_read_buf(Pin::new(&mut self.control), cx, &mut self.read_buf);
            // A quiet stream hands this call to the datagrams.
            if read.is_pending() && mem::take(&mut stream_first) {
                continue;
            }
            // The FIN also ends the HTTP Datagrams, so none can follow it.
            if ready!(read).map_err(MasqueError::Io)? == 0 {
                return Poll::Ready(Ok(None));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl fmt::Debug for UdpReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpReceiver")
            .field("datagrams", &self.native.is_some())
            .finish_non_exhaustive()
    }
}

// ===== impl RecvError =====

impl From<RecvError> for MasqueError {
    fn from(err: RecvError) -> Self {
        match err {
            RecvError::Malformed => MasqueError::Malformed,
            RecvError::Io(kind, message) => MasqueError::Io(io::Error::new(kind, message)),
        }
    }
}

/// Strips Context ID 0 from an HTTP Datagram payload ([RFC 9298 §4]).
///
/// Unknown contexts, and payloads too short to carry a Context ID, are dropped: [RFC 9298 §5]
/// aborts only for an oversized Context ID 0 payload, and both encodings share this path
/// ([RFC 9297 §3.5]).
///
/// [RFC 9298 §4]: https://www.rfc-editor.org/rfc/rfc9298.html#section-4
/// [RFC 9298 §5]: https://www.rfc-editor.org/rfc/rfc9298.html#section-5
/// [RFC 9297 §3.5]: https://www.rfc-editor.org/rfc/rfc9297.html#section-3.5
fn udp_payload(mut datagram: Bytes) -> Result<Option<Bytes>, MasqueError> {
    let Some((context, len)) = capsule::varint(&datagram) else {
        return Ok(None);
    };
    if context != 0 {
        return Ok(None);
    }
    datagram.advance(len);
    // A larger Context ID 0 payload MUST abort the stream.
    // https://www.rfc-editor.org/rfc/rfc9298.html#section-5
    if datagram.len() > MAX_UDP_PAYLOAD {
        return Err(MasqueError::Malformed);
    }
    Ok(Some(datagram))
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, time::Duration};

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
        time::timeout,
    };

    use super::*;

    /// A capsule-only tunnel and the proxy's end of its request stream.
    ///
    /// `buffered` puts a write buffer in between, so capsules only reach the proxy if flushed.
    fn capsule_tunnel(capacity: usize, buffered: bool) -> (UdpTunnel, tokio::io::DuplexStream) {
        let (client, proxy) = tokio::io::duplex(capacity);
        let control = if buffered {
            Upgraded::new(tokio::io::BufWriter::new(client), Bytes::new())
        } else {
            Upgraded::new(client, Bytes::new())
        };
        (UdpTunnel::new(control, None), proxy)
    }

    async fn bounded<F: Future>(future: F) -> F::Output {
        timeout(Duration::from_secs(5), future)
            .await
            .expect("tunnel test timed out")
    }

    #[tokio::test]
    async fn split_halves_send_and_receive_from_two_tasks() {
        let (tunnel, mut proxy) = capsule_tunnel(4096, true);
        assert_eq!(tunnel.max_payload_size(), 65527);
        let (mut sender, mut receiver) = tunnel.split();
        assert_eq!(sender.try_send(&[0; 65528]), Err(SendError::TooLarge));
        let (mut limit, _proxy) = capsule_tunnel(4096, true);
        assert_eq!(limit.try_send(&[0; 65527]), Ok(()));

        let recv = tokio::spawn(async move {
            let mut payloads = Vec::new();
            loop {
                match poll_fn(|cx| receiver.poll_recv(cx)).await {
                    Ok(Some(payload)) => payloads.push(payload),
                    result => return (payloads, result),
                }
            }
        });

        // Fill the stream, then the capsule buffer past its limit, so the send task below
        // waits until the proxy drains the stream; its flush then pushes the write buffer.
        let mut sent = 0;
        let full = loop {
            match sender.try_send(&[7; 8000]) {
                Ok(()) => sent += 1,
                Err(err) => break err,
            }
        };
        assert_eq!(full, SendError::Full);
        let send = tokio::spawn(async move {
            poll_fn(|cx| sender.poll_send_ready(cx)).await.unwrap();
            sender.try_send(b"ping").unwrap();
            poll_fn(|cx| sender.poll_flush(cx)).await.unwrap();
            sender
        });
        proxy
            .write_all(&[0, 5, 0, b'p', b'o', b'n', b'g'])
            .await
            .unwrap();
        let mut expected = Vec::new();
        for _ in 0..sent {
            expected.extend_from_slice(&[0, 0x5F, 0x41, 0]);
            expected.extend_from_slice(&[7; 8000]);
        }
        expected.extend_from_slice(&[0, 5, 0, b'p', b'i', b'n', b'g']);
        let mut written = vec![0; expected.len()];
        bounded(proxy.read_exact(&mut written)).await.unwrap();
        assert_eq!(written, expected);
        let _sender = bounded(send).await.unwrap();

        proxy.shutdown().await.unwrap();
        let (payloads, result) = bounded(recv).await.unwrap();
        assert_eq!(payloads, ["pong"]);
        assert!(matches!(result, Ok(None)), "{result:?}");
    }

    #[tokio::test]
    async fn recv_yields_while_dropping_unknown_contexts() {
        let (mut tunnel, mut proxy) = capsule_tunnel(4096, false);
        for _ in 0..64 {
            proxy.write_all(&[0, 2, 1, b'x']).await.unwrap();
        }
        proxy
            .write_all(&[0, 5, 0, b'p', b'o', b'n', b'g'])
            .await
            .unwrap();

        // Dropping 64 payloads takes more than one call, and each yield wakes the task.
        let mut recv = tokio_test::task::spawn(poll_fn(|cx| tunnel.poll_recv(cx)));
        let mut yields = 0;
        let payload = loop {
            match recv.poll() {
                Poll::Ready(result) => break result.unwrap().unwrap(),
                Poll::Pending => {
                    assert!(recv.is_woken(), "yield without a wakeup");
                    yields += 1;
                }
            }
        };
        assert_eq!(payload, "pong");
        assert!(yields > 0, "64 dropped payloads in one call");
    }

    #[tokio::test]
    async fn flush_drives_capsules_and_reports_a_write_error_once() {
        // A task that only receives on the whole tunnel still writes what it sent.
        let (mut tunnel, mut proxy) = capsule_tunnel(4, true);
        tunnel.try_send(b"ping").unwrap();
        let mut written = [0; 7];
        bounded(async {
            tokio::select! {
                read = proxy.read_exact(&mut written) => read.unwrap(),
                result = poll_fn(|cx| tunnel.poll_recv(cx)) => panic!("{result:?}"),
            }
        })
        .await;
        assert_eq!(written, [0, 5, 0, b'p', b'i', b'n', b'g']);

        // A task that only sends drives buffered capsules with `poll_flush`.
        let (mut tunnel, mut proxy) = capsule_tunnel(4096, false);
        tunnel.try_send(&[7; 8000]).unwrap();
        let mut written = vec![0; 8004];
        let (flushed, read) = bounded(async {
            tokio::join!(
                poll_fn(|cx| tunnel.poll_flush(cx)),
                proxy.read_exact(&mut written)
            )
        })
        .await;
        flushed.unwrap();
        read.unwrap();

        // A failed write only stops sending: its error comes back once, receiving goes on.
        proxy.write_all(&[0, 3, 0, b'h', b'i']).await.unwrap();
        drop(proxy);
        assert_eq!(tunnel.try_send(b"x"), Err(SendError::Closed));
        assert_eq!(tunnel.max_payload_size(), 0);
        let recv = bounded(poll_fn(|cx| tunnel.poll_recv(cx))).await;
        assert_eq!(recv.unwrap().unwrap(), "hi");
        let flushed = poll_fn(|cx| tunnel.poll_flush(cx)).await;
        assert_eq!(flushed.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        poll_fn(|cx| tunnel.poll_close(cx)).await.unwrap();
        assert!(matches!(poll_fn(|cx| tunnel.poll_recv(cx)).await, Ok(None)));
    }

    #[tokio::test]
    async fn receive_errors_stick() {
        /// A request stream whose reads fail.
        struct Failing;

        impl AsyncRead for Failing {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Err(io::Error::other("proxy reset")))
            }
        }

        impl AsyncWrite for Failing {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // An I/O error comes back with its kind and message, every time.
        let mut tunnel = UdpTunnel::new(Upgraded::new(Failing, Bytes::new()), None);
        for _ in 0..2 {
            let result = poll_fn(|cx| tunnel.poll_recv(cx)).await;
            let Err(MasqueError::Io(err)) = result else {
                panic!("{result:?}");
            };
            assert_eq!(
                (err.kind(), err.to_string()),
                (io::ErrorKind::Other, "proxy reset".into())
            );
        }
    }

    #[tokio::test]
    async fn close_writes_buffered_capsules_before_fin() {
        // Too small for one capsule, so most of it stays buffered until `poll_close`.
        let (mut tunnel, mut proxy) = capsule_tunnel(2, false);
        tunnel.try_send(b"bye").unwrap();
        // Sends stop as soon as the close starts, before it can finish.
        let closing = poll_fn(|cx| Poll::Ready(tunnel.poll_close(cx))).await;
        assert!(closing.is_pending(), "closed into a full stream");
        assert_eq!(tunnel.try_send(b"late"), Err(SendError::Closed));
        let ready = poll_fn(|cx| tunnel.poll_send_ready(cx)).await;
        assert_eq!(ready, Err(SendError::Closed));
        assert_eq!(tunnel.max_payload_size(), 0);
        let mut written = Vec::new();
        let (closed, read) = bounded(async {
            tokio::join!(
                poll_fn(|cx| tunnel.poll_close(cx)),
                proxy.read_to_end(&mut written)
            )
        })
        .await;
        closed.unwrap();
        read.unwrap();
        assert_eq!(written, [0, 4, 0, b'b', b'y', b'e']);
        assert_eq!(tunnel.try_send(b"late"), Err(SendError::Closed));

        proxy.shutdown().await.unwrap();
        let result = bounded(poll_fn(|cx| tunnel.poll_recv(cx))).await;
        assert!(matches!(result, Ok(None)), "{result:?}");
    }

    #[test]
    fn udp_payload_strips_context_id_zero() {
        let mut max = vec![0; 65528];
        max[1..].fill(7);
        for (datagram, expected) in [
            (vec![0, b'h', b'i'], Some(&b"hi"[..])),
            // An empty UDP payload.
            // https://www.rfc-editor.org/rfc/rfc9298.html#section-5
            (vec![0], Some(&b""[..])),
            // A non-minimal Context ID 0.
            (vec![0x40, 0, b'h', b'i'], Some(&b"hi"[..])),
            (vec![1, b'h', b'i'], None),
            (vec![], None),
            // A Context ID cut short.
            (vec![0x40], None),
            (max.clone(), Some(&max[1..])),
        ] {
            let payload = udp_payload(Bytes::from(datagram)).unwrap();
            assert_eq!(payload.as_deref(), expected);
        }
        max.push(7);
        assert!(matches!(
            udp_payload(Bytes::from(max)),
            Err(MasqueError::Malformed)
        ));
    }
}
