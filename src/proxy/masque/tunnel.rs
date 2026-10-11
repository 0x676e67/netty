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

    write_buf: BytesMut,
    /// Whether capsule bytes were written since the last flush.
    unflushed: bool,
    /// Set once the request stream takes no more capsules, after a close or a write error.
    write_closed: bool,
    /// Tasks waiting to receive, and to send or close.
    wakers: Arc<Wakers>,
    /// Waker for every control stream write, so its wakeup reaches both tasks.
    write_waker: Waker,
}

/// HTTP/3 Datagram handles of the request.
struct Native {
    sender: Sender,
    receiver: Receiver,
    recv_open: bool,
}

/// The receive task and the send or close task, woken together when the request stream
/// accepts writes again.
#[derive(Default)]
struct Wakers {
    recv: AtomicWaker,
    send: AtomicWaker,
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
            write_buf: BytesMut::new(),
            unflushed: false,
            write_closed: false,
            write_waker: Waker::from(wakers.clone()),
            wakers,
        }
    }

    /// Returns the largest UDP payload a send currently accepts.
    ///
    /// With HTTP Datagrams this is the QUIC datagram limit less the Quarter Stream ID and
    /// Context ID; larger payloads are rejected rather than moved to capsules, so the path MTU
    /// stays visible (RFC 9298 §6.1). Inner QUIC needs at least 1200 bytes (RFC 9000 §14).
    pub fn max_payload_size(&self) -> usize {
        self.native_limit().unwrap_or(MAX_UDP_PAYLOAD)
    }

    /// Payload limit of HTTP Datagrams, if they are usable.
    fn native_limit(&self) -> Option<usize> {
        let max = self.native.as_ref()?.sender.max_datagram_size()?;
        Some(max.checked_sub(1)?.min(MAX_UDP_PAYLOAD))
    }

    /// Queues one UDP payload; success is local admission, not delivery.
    pub fn try_send(&mut self, payload: &[u8]) -> Result<(), SendError> {
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
        match self.poll_write_buf() {
            Poll::Ready(Err(_)) => Err(SendError::Closed),
            _ => Ok(()),
        }
    }

    /// Waits until a payload of [`max_payload_size`](Self::max_payload_size) would be accepted.
    pub fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SendError>> {
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
    /// Also finishes writing buffered capsules, so keep polling it while sending. An error is
    /// fatal to the tunnel: drop it to abort the request stream.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, MasqueError>> {
        self.wakers.recv.register(cx.waker());
        if let Poll::Ready(Err(err)) = self.poll_write_buf() {
            return Poll::Ready(Err(MasqueError::Io(err)));
        }
        loop {
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
                return Poll::Ready(if self.decoder.is_partial(&self.read_buf) {
                    Err(MasqueError::Malformed)
                } else {
                    Ok(None)
                });
            }
        }
    }

    /// Writes buffered capsules, then closes the request stream for sending.
    ///
    /// Returns `Ok` at once if sending already stopped after a close or a write error.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.wakers.send.register(cx.waker());
        ready!(self.poll_write_buf())?;
        let mut cx = Context::from_waker(&self.write_waker);
        ready!(Pin::new(&mut self.control).poll_shutdown(&mut cx))?;
        self.write_closed = true;
        Poll::Ready(Ok(()))
    }

    /// Writes buffered capsules, then flushes the request stream if anything was written.
    ///
    /// Polls with `write_waker`, so the tasks registered in `wakers` retry once the stream
    /// drains. A write error stops sending and wakes a task waiting to send.
    fn poll_write_buf(&mut self) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
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
        if result.is_err() {
            self.write_closed = true;
            self.write_buf.clear();
            self.wakers.send.wake();
        }
        Poll::Ready(result)
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

// ===== impl Wakers =====

impl Wake for Wakers {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.recv.wake();
        self.send.wake();
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

    /// A capsule-only tunnel, as over HTTP/2, and the proxy's end of its request stream.
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
    async fn close_writes_buffered_capsules_before_fin() {
        // Too small for one capsule, so most of it stays buffered until `poll_close`.
        let (mut tunnel, mut proxy) = capsule_tunnel(2, false);
        tunnel.try_send(b"bye").unwrap();
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
