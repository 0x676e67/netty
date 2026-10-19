//! UDP payloads over a CONNECT-UDP request stream.

use std::{
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker, ready},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{MAX_UDP_PAYLOAD, MasqueError, SendError, capsule};
use crate::{
    conn::http3::datagram::{Receiver, SendErrorKind, Sender},
    upgrade::Upgraded,
};

/// Capsule bytes buffered for the control stream before sends report [`SendError::Full`].
const WRITE_LIMIT: usize = 64 * 1024;

/// Read size for the control stream.
const READ_CHUNK: usize = 8 * 1024;

/// A CONNECT-UDP tunnel carrying UDP payloads for one target (RFC 9298 §5).
///
/// Payloads travel as HTTP Datagrams when the HTTP/3 connection negotiated them, and otherwise
/// as DATAGRAM capsules on the request stream; received capsules are always accepted. Methods
/// take `&mut self`: share a tunnel between send and receive tasks behind a mutex.
///
/// Dropping the tunnel aborts the request stream, which closes the tunnel at the proxy.
pub struct UdpTunnel {
    control: Upgraded,
    native: Option<Native>,

    decoder: capsule::Decoder,
    read_buf: BytesMut,
    /// Why receiving failed, so later polls report it again.
    recv_error: Option<RecvError>,

    write_buf: BytesMut,
    /// Whether capsule bytes were written since the last flush.
    unflushed: bool,
    /// Set when `poll_close` starts: sends are refused while buffered capsules drain.
    closing: bool,
    /// Set once the request stream takes no more capsules, after a close or a write error.
    write_closed: bool,
    /// The first write error, reported once by `poll_flush` or `poll_close`.
    write_error: Option<io::Error>,
    /// Tasks waiting to receive, send and close.
    wakers: Arc<Wakers>,
    /// Waker for every control stream write, so its wakeup reaches each waiting task.
    write_waker: Waker,
}

/// HTTP/3 Datagram handles of the request.
struct Native {
    sender: Sender,
    receiver: Receiver,
    recv_open: bool,
}

/// A receive failure, kept so later polls report it again.
#[derive(Clone)]
enum RecvError {
    Malformed,
    Io(io::ErrorKind, String),
}

/// The receive, send and close tasks, woken together when the request stream accepts
/// writes again. Each has its own slot, so one task registering never drops another.
#[derive(Default)]
struct Wakers {
    recv: AtomicWaker,
    send: AtomicWaker,
    close: AtomicWaker,
}

// ===== impl UdpTunnel =====

impl UdpTunnel {
    pub(super) fn new(control: Upgraded, native: Option<(Sender, Receiver)>) -> Self {
        let wakers = Arc::new(Wakers::default());
        UdpTunnel {
            control,
            native: native.map(|(sender, receiver)| Native {
                sender,
                receiver,
                recv_open: true,
            }),
            decoder: capsule::Decoder::default(),
            read_buf: BytesMut::new(),
            recv_error: None,
            write_buf: BytesMut::new(),
            unflushed: false,
            closing: false,
            write_closed: false,
            write_error: None,
            write_waker: Waker::from(wakers.clone()),
            wakers,
        }
    }

    /// Returns the largest UDP payload a send currently accepts.
    ///
    /// With HTTP Datagrams this is the QUIC datagram limit less the Quarter Stream ID and
    /// Context ID; larger payloads are rejected rather than moved to capsules, so the path MTU
    /// stays visible (RFC 9298 §6.1), and a limit too small for any payload reads as 0. Inner
    /// QUIC needs at least 1200 bytes (RFC 9000 §14).
    pub fn max_payload_size(&self) -> usize {
        self.native_limit().unwrap_or(MAX_UDP_PAYLOAD)
    }

    /// Payload limit of HTTP Datagrams, if they are usable.
    fn native_limit(&self) -> Option<usize> {
        let max = self.native.as_ref()?.sender.max_datagram_size()?;
        Some(max.saturating_sub(1).min(MAX_UDP_PAYLOAD))
    }

    /// Queues one UDP payload; success is local admission, not delivery.
    ///
    /// Capsules are written while the tunnel is polled, so a task that only sends drives them
    /// with [`poll_flush`](Self::poll_flush).
    pub fn try_send(&mut self, payload: &[u8]) -> Result<(), SendError> {
        if self.closing {
            return Err(SendError::Closed);
        }
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(SendError::TooLarge);
        }
        if let Some(native) = &self.native {
            let mut datagram = BytesMut::with_capacity(1 + payload.len());
            datagram.extend_from_slice(&[0]);
            datagram.extend_from_slice(payload);
            match native.sender.try_send(datagram.freeze()) {
                Ok(()) => return Ok(()),
                Err(err) => match err.kind() {
                    SendErrorKind::Full => return Err(SendError::Full),
                    SendErrorKind::TooLarge => return Err(SendError::TooLarge),
                    SendErrorKind::Closed => return Err(SendError::Closed),
                    // Datagrams were not negotiated: use capsules (RFC 9297 §3.5).
                    SendErrorKind::Unavailable => {}
                },
            }
        }
        if self.write_closed {
            return Err(SendError::Closed);
        }
        if self.write_buf.len() >= WRITE_LIMIT {
            return Err(SendError::Full);
        }
        capsule::encode_datagram(payload, &mut self.write_buf);
        // Write now; if the stream is full, the waiting tasks finish the write.
        let _ = self.poll_write_buf();
        if self.write_closed {
            return Err(SendError::Closed);
        }
        Ok(())
    }

    /// Waits until a payload of [`max_payload_size`](Self::max_payload_size) would be accepted.
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SendError>> {
        if self.closing {
            return Poll::Ready(Err(SendError::Closed));
        }
        if let Some(native) = &mut self.native {
            match ready!(native.sender.poll_ready(cx)) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(SendErrorKind::Unavailable) => {}
                Err(_) => return Poll::Ready(Err(SendError::Closed)),
            }
        }
        // Register before writing, so the stream's next wakeup reaches this task.
        self.wakers.send.register(cx.waker());
        let _ = self.poll_write_buf();
        if self.write_closed {
            Poll::Ready(Err(SendError::Closed))
        } else if self.write_buf.len() < WRITE_LIMIT {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// Receives the next UDP payload; `None` once the proxy closed the tunnel.
    ///
    /// Also finishes writing buffered capsules. An error ends receiving and later calls report
    /// it again, with the same kind and message; a malformed capsule or payload also resets the
    /// request stream with `H3_DATAGRAM_ERROR`.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MasqueError>> {
        if let Some(err) = &self.recv_error {
            return Poll::Ready(Err(err.clone().into()));
        }
        let result = ready!(self.poll_payload(cx));
        if let Err(err) = &result {
            let failed = match err {
                MasqueError::Io(err) => RecvError::Io(err.kind(), err.to_string()),
                _ => RecvError::Malformed,
            };
            if let (RecvError::Malformed, Some(native)) = (&failed, &self.native) {
                native.receiver.abort_malformed();
            }
            self.recv_error = Some(failed);
        }
        Poll::Ready(result)
    }

    /// Polls the next payload from HTTP Datagrams or the request stream.
    fn poll_payload(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MasqueError>> {
        self.wakers.recv.register(cx.waker());
        // A write error only stops sending; `poll_flush` and `poll_close` report it.
        let _ = self.poll_write_buf();
        // Each round drops at most one payload or reads once, so a proxy flooding unknown
        // contexts or capsule types cannot keep this call from yielding.
        for _ in 0..32 {
            if let Some(native) = self.native.as_mut().filter(|native| native.recv_open) {
                match native.receiver.poll_recv(cx) {
                    Poll::Ready(Some(datagram)) => match udp_payload(datagram)? {
                        Some(payload) => return Poll::Ready(Ok(Some(payload))),
                        None => continue,
                    },
                    Poll::Ready(None) => native.recv_open = false,
                    Poll::Pending => {}
                }
            }

            if let Some(datagram) = self.decoder.decode(&mut self.read_buf)? {
                match udp_payload(datagram)? {
                    Some(payload) => return Poll::Ready(Ok(Some(payload))),
                    None => continue,
                }
            }
            let len = self.read_buf.len();
            self.read_buf.resize(len + READ_CHUNK, 0);
            let mut buf = ReadBuf::new(&mut self.read_buf[len..]);
            let read = Pin::new(&mut self.control).poll_read(cx, &mut buf);
            let n = buf.filled().len();
            self.read_buf.truncate(len + n);
            ready!(read).map_err(MasqueError::Io)?;
            if n == 0 {
                // Datagrams that arrived before the FIN come first; the connection ends their
                // direction once it has routed them.
                if let Some(native) = self.native.as_mut().filter(|native| native.recv_open) {
                    match ready!(native.receiver.poll_recv(cx)) {
                        Some(datagram) => match udp_payload(datagram)? {
                            Some(payload) => return Poll::Ready(Ok(Some(payload))),
                            None => continue,
                        },
                        None => native.recv_open = false,
                    }
                }
                return Poll::Ready(if self.decoder.is_partial(&self.read_buf) {
                    Err(MasqueError::Malformed)
                } else {
                    Ok(None)
                });
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// Writes buffered capsules to the request stream; HTTP Datagrams need no flush.
    ///
    /// Returns the first write error once.
    pub fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.wakers.send.register(cx.waker());
        ready!(self.poll_write_buf());
        Poll::Ready(self.write_error.take().map_or(Ok(()), Err))
    }

    /// Writes buffered capsules, then closes the request stream for sending; HTTP Datagrams
    /// already accepted go to the connection first.
    ///
    /// Sends are refused from the first call on, so a busy sender cannot hold off the FIN.
    /// Returns the first write error once, and `Ok` at once after that or after a close.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closing {
            self.closing = true;
            // A parked sender now sees `Closed`.
            self.wakers.send.wake();
        }
        if !self.write_closed {
            self.wakers.close.register(cx.waker());
            ready!(self.poll_write_buf());
        }
        if !self.write_closed {
            let mut cx = Context::from_waker(&self.write_waker);
            let shutdown = ready!(Pin::new(&mut self.control).poll_shutdown(&mut cx));
            self.write_closed = true;
            self.write_error = shutdown.err();
            // A sender parked on a full buffer now sees `Closed`.
            self.wakers.send.wake();
        }
        Poll::Ready(self.write_error.take().map_or(Ok(()), Err))
    }

    /// Writes buffered capsules, then flushes the request stream if anything was written.
    ///
    /// Polls with `write_waker`, so the tasks registered in `wakers` retry once the stream
    /// drains. A write error stops sending, keeps the error for `poll_flush` or `poll_close`
    /// and wakes the tasks waiting to send or close.
    fn poll_write_buf(&mut self) -> Poll<()> {
        if self.write_closed {
            return Poll::Ready(());
        }
        let mut cx = Context::from_waker(&self.write_waker);
        let result = loop {
            if self.write_buf.is_empty() {
                // Skipping idle flushes spares HTTP/3 a flush round trip on every receive.
                if !self.unflushed {
                    break Ok(());
                }
                let flushed = ready!(Pin::new(&mut self.control).poll_flush(&mut cx));
                self.unflushed = false;
                break flushed;
            }
            match ready!(Pin::new(&mut self.control).poll_write(&mut cx, &self.write_buf)) {
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
            self.wakers.send.wake();
            self.wakers.close.wake();
        }
        Poll::Ready(())
    }
}

impl fmt::Debug for UdpTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpTunnel")
            .field("datagrams", &self.native.is_some())
            .field("max_payload_size", &self.max_payload_size())
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

// ===== impl Wakers =====

impl Wake for Wakers {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.recv.wake();
        self.send.wake();
        self.close.wake();
    }
}

/// Strips Context ID 0 from an HTTP Datagram payload (RFC 9298 §4).
///
/// Unknown contexts, and payloads too short to carry a Context ID, are dropped.
fn udp_payload(mut datagram: Bytes) -> Result<Option<Bytes>, MasqueError> {
    let Some((context, len)) = capsule::varint(&datagram) else {
        return Ok(None);
    };
    if context != 0 {
        return Ok(None);
    }
    datagram.advance(len);
    // RFC 9298 §5: a larger Context ID 0 payload MUST abort the stream.
    if datagram.len() > MAX_UDP_PAYLOAD {
        return Err(MasqueError::Malformed);
    }
    Ok(Some(datagram))
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, sync::Mutex, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
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
    async fn send_and_receive_tasks_share_a_capsule_tunnel() {
        let (tunnel, mut proxy) = capsule_tunnel(4096, true);
        let tunnel = Arc::new(Mutex::new(tunnel));
        let lock = || tunnel.lock().unwrap();
        assert_eq!(lock().max_payload_size(), 65527);
        assert_eq!(lock().try_send(&[0; 65528]), Err(SendError::TooLarge));

        let recv = tokio::spawn({
            let tunnel = tunnel.clone();
            async move {
                let mut payloads = Vec::new();
                loop {
                    match poll_fn(|cx| tunnel.lock().unwrap().poll_recv(cx)).await {
                        Ok(Some(payload)) => payloads.push(payload),
                        result => return (payloads, result),
                    }
                }
            }
        });

        // Fill the stream, then the capsule buffer past its limit, so the send task below
        // waits until the proxy drains the stream.
        let mut sent = 0;
        let full = loop {
            match lock().try_send(&[7; 8000]) {
                Ok(()) => sent += 1,
                Err(err) => break err,
            }
        };
        assert_eq!(full, SendError::Full);

        // The send task waits for room, then the receive task polls the stream again.
        let ready = tokio::spawn({
            let tunnel = tunnel.clone();
            async move { poll_fn(|cx| tunnel.lock().unwrap().poll_send_ready(cx)).await }
        });
        tokio::task::yield_now().await;
        assert!(!ready.is_finished(), "ready over the capsule limit");
        proxy
            .write_all(&[0, 5, 0, b'p', b'o', b'n', b'g'])
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // Draining the stream must wake both tasks, and a capsule queued while the receive
        // task is parked must still be written.
        let mut expected = Vec::new();
        for _ in 0..sent {
            expected.extend_from_slice(&[0, 0x5F, 0x41, 0]);
            expected.extend_from_slice(&[7; 8000]);
        }
        let mut written = vec![0; expected.len()];
        bounded(proxy.read_exact(&mut written)).await.unwrap();
        assert_eq!(written, expected);
        assert_eq!(bounded(ready).await.unwrap(), Ok(()));
        lock().try_send(b"ping").unwrap();
        let mut written = [0; 7];
        bounded(proxy.read_exact(&mut written)).await.unwrap();
        assert_eq!(written, [0, 5, 0, b'p', b'i', b'n', b'g']);

        // Unknown Context IDs are dropped; a capsule cut short by FIN is malformed.
        proxy.write_all(&[0, 2, 1, b'x']).await.unwrap();
        proxy.write_all(&[0, 4, 0, b'e', b'n', b'd']).await.unwrap();
        proxy.write_all(&[0, 5, 0, b'c']).await.unwrap();
        proxy.shutdown().await.unwrap();
        let (payloads, result) = bounded(recv).await.unwrap();
        assert_eq!(payloads, [&b"pong"[..], &b"end"[..]]);
        assert!(matches!(result, Err(MasqueError::Malformed)), "{result:?}");
    }

    #[tokio::test]
    async fn close_and_send_tasks_keep_their_wakeups() {
        // A sender parked on the full capsule buffer still wakes when another task closes.
        let (tunnel, mut proxy) = capsule_tunnel(4096, false);
        let tunnel = Arc::new(Mutex::new(tunnel));
        while tunnel.lock().unwrap().try_send(&[7; 8000]).is_ok() {}
        let ready = tokio::spawn({
            let tunnel = tunnel.clone();
            async move { poll_fn(|cx| tunnel.lock().unwrap().poll_send_ready(cx)).await }
        });
        tokio::task::yield_now().await;
        assert!(!ready.is_finished(), "ready over the capsule limit");
        let mut written = Vec::new();
        let (closed, read) = bounded(async {
            tokio::join!(
                poll_fn(|cx| tunnel.lock().unwrap().poll_close(cx)),
                proxy.read_to_end(&mut written)
            )
        })
        .await;
        closed.unwrap();
        read.unwrap();
        let ready = bounded(ready).await.unwrap();
        assert!(
            matches!(ready, Ok(()) | Err(SendError::Closed)),
            "{ready:?}"
        );

        // A close parked on the stream still finishes after the send slot is registered.
        let (tunnel, mut proxy) = capsule_tunnel(4096, false);
        let tunnel = Arc::new(Mutex::new(tunnel));
        tunnel.lock().unwrap().try_send(&[7; 8000]).unwrap();
        let close = tokio::spawn({
            let tunnel = tunnel.clone();
            async move { poll_fn(|cx| tunnel.lock().unwrap().poll_close(cx)).await }
        });
        tokio::task::yield_now().await;
        assert!(!close.is_finished(), "close before the proxy reads");
        let flushed = poll_fn(|cx| Poll::Ready(tunnel.lock().unwrap().poll_flush(cx))).await;
        assert!(flushed.is_pending(), "flushed into a full stream");
        let mut written = Vec::new();
        bounded(proxy.read_to_end(&mut written)).await.unwrap();
        assert_eq!(written.len(), 8004);
        bounded(close).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn close_stops_a_busy_capsule_sender() {
        let (tunnel, mut proxy) = capsule_tunnel(4096, false);
        let tunnel = Arc::new(Mutex::new(tunnel));
        // A sender that stops only once sending fails, sharing the tunnel with the close.
        let sender = tokio::spawn({
            let tunnel = tunnel.clone();
            async move {
                loop {
                    let sent = poll_fn(|cx| tunnel.lock().unwrap().poll_send_ready(cx))
                        .await
                        .and_then(|()| tunnel.lock().unwrap().try_send(&[1; 100]));
                    if let Err(err) = sent {
                        return err;
                    }
                }
            }
        });
        tokio::task::yield_now().await;
        let mut written = Vec::new();
        let (closed, read) = bounded(async {
            tokio::join!(
                poll_fn(|cx| tunnel.lock().unwrap().poll_close(cx)),
                proxy.read_to_end(&mut written)
            )
        })
        .await;
        closed.unwrap();
        read.unwrap();
        assert_eq!(bounded(sender).await.unwrap(), SendError::Closed);
        // What was accepted before the close went out as whole 104-byte capsules.
        assert!(!written.is_empty() && written.len() % 104 == 0);
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
        let recv = bounded(poll_fn(|cx| tunnel.poll_recv(cx))).await;
        assert_eq!(recv.unwrap().unwrap(), "hi");
        let flushed = poll_fn(|cx| tunnel.poll_flush(cx)).await;
        assert_eq!(flushed.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        poll_fn(|cx| tunnel.poll_close(cx)).await.unwrap();
        assert!(matches!(poll_fn(|cx| tunnel.poll_recv(cx)).await, Ok(None)));
    }

    #[tokio::test]
    async fn receive_errors_stick() {
        // A whole Context ID 0 capsule one byte over the UDP limit, then a valid one.
        let (mut tunnel, mut proxy) = capsule_tunnel(1 << 17, false);
        let mut oversized = BytesMut::new();
        capsule::encode_datagram(&[7; MAX_UDP_PAYLOAD + 1], &mut oversized);
        proxy.write_all(&oversized).await.unwrap();
        proxy.write_all(&[0, 3, 0, b'o', b'k']).await.unwrap();
        for _ in 0..2 {
            let result = bounded(poll_fn(|cx| tunnel.poll_recv(cx))).await;
            assert!(matches!(result, Err(MasqueError::Malformed)), "{result:?}");
        }

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

        // An I/O error comes back with its kind and message.
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
            // A non-minimal Context ID 0.
            (vec![0x40, 0, b'h', b'i'], Some(&b"hi"[..])),
            (vec![1, b'h', b'i'], None),
            (vec![], None),
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
