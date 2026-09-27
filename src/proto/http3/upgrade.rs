//! CONNECT tunnels over HTTP/3 request streams.

#[cfg(feature = "http3-datagram")]
use std::sync::Arc;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

use bytes::{Buf, Bytes};
use http::Response;
use http3::quic;
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::{CancellationToken, PollSender, WaitForCancellationFutureOwned};

use super::{
    client::{invalid_datagram_error, H3ClientFuture, RecvGuard, SendGuard, CHUNK},
    shared::Active,
};
use crate::{
    body::{chan, Incoming},
    rt::{self, bounds::Http3ClientConnExec},
    upgrade::{pending, Upgraded},
    Error, Result,
};
#[cfg(feature = "http3-datagram")]
use crate::{
    conn::http3::datagram::Pending,
    proto::http3::datagram::{Registration, RequestState},
};

// pin_project_lite does not support cfg on fields; no registration is
// stored when HTTP Datagrams are disabled.
#[cfg(not(feature = "http3-datagram"))]
type Registration = ();

/// Write commands from the tunnel to its pump task; acknowledgments carry
/// the transport result back.
enum Write {
    Data(Bytes),
    Flush(oneshot::Sender<Result<()>>),
    Finish(oneshot::Sender<Result<()>>),
}

/// Tunnel I/O handed to the application through `Upgraded`. Reads drain the
/// pump task's channel; writes are forwarded to it one chunk at a time.
struct H3Upgraded {
    rx: chan::Receiver,
    data: Bytes,
    sender: PollSender<Write>,
    pending: Option<(bool, oneshot::Receiver<Result<()>>)>,
    shutdown: bool,
    read_closed: bool,
    #[cfg(feature = "http3-datagram")]
    datagrams: Option<Arc<RequestState>>,
}

pin_project! {
    /// Owns a CONNECT transfer and its admission slot until both directions
    /// finish. A failed transfer reports its cause to the tunnel reader. Dropping
    /// the task cancels unfinished directions and releases its admission slot.
    pub struct UpgradeTask<S, R>
    where
        S: quic::SendStream<Bytes>,
        R: quic::RecvStream,
    {
        #[pin]
        transfer: Option<Transfer<S, R>>,
        active: Option<Active>,
        registration: Option<Registration>,
    }
}

// ===== impl UpgradeTask =====

impl<S, R> Future for UpgradeTask<S, R>
where
    S: quic::SendStream<Bytes>,
    R: quic::RecvStream,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        let Some(transfer) = this.transfer.as_mut().as_pin_mut() else {
            return Poll::Ready(());
        };
        let (result, body) = ready!(transfer.poll(cx));
        this.transfer.set(None);
        if let (Err(error), Some(mut body), Some(active)) = (result, body, this.active.as_ref()) {
            body.send_error(active.shared().error_or(error));
        }
        this.registration.take();
        this.active.take();
        Poll::Ready(())
    }
}

/// Datagram semantics and the registration owned by a CONNECT tunnel task.
#[cfg(feature = "http3-datagram")]
pub(super) enum TunnelDatagrams {
    Disabled,
    Ordinary(Registration),
    Datagram(Registration),
}

/// Turns a successful CONNECT into an upgraded tunnel. Both stream directions
/// move to an executor task that reads eagerly, so peer resets surface even
/// while the tunnel is idle.
pub(super) fn tunnel<Q, E>(
    send: SendGuard<super::client::SendStream<Q::BidiStream>>,
    recv: RecvGuard<super::client::RecvStream<Q::BidiStream>>,
    mut headers: Response<()>,
    active: Active,
    #[cfg(feature = "http3-datagram")] datagrams: TunnelDatagrams,
    exec: &E,
) -> Response<Incoming>
where
    Q: rt::quic::Connection<Bytes>,
    <Q::BidiStream as rt::quic::BidiStream<Bytes>>::SendStream: Send + 'static,
    <Q::BidiStream as rt::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
    E: Http3ClientConnExec<Q>,
{
    #[cfg(feature = "http3-datagram")]
    let (registration, datagrams) = match datagrams {
        TunnelDatagrams::Disabled => (None, None),
        TunnelDatagrams::Ordinary(registration) => (Some(registration), None),
        TunnelDatagrams::Datagram(registration) => {
            let state = registration.0.clone();
            (Some(registration), Some(state))
        }
    };

    #[cfg(feature = "http3-datagram")]
    let invalid = registration
        .as_ref()
        .map(|registration| registration.0.invalid.clone());

    #[cfg(not(feature = "http3-datagram"))]
    let invalid: Option<CancellationToken> = None;
    #[cfg(not(feature = "http3-datagram"))]
    let registration = None;
    let (body, rx) = chan::channel(false);
    let (tx, writes) = mpsc::channel(1);
    let io = H3Upgraded {
        rx,
        data: Bytes::new(),
        sender: PollSender::new(tx),
        pending: None,
        shutdown: false,
        read_closed: false,
        #[cfg(feature = "http3-datagram")]
        datagrams: datagrams.clone(),
    };

    let (pending, on_upgrade) = pending();
    let io = Upgraded::new(io, Bytes::new());
    #[cfg(feature = "http3-datagram")]
    let io = if let Some(datagrams) = datagrams {
        headers.extensions_mut().insert(Pending::new(io, datagrams));
        None
    } else {
        Some(io)
    };

    #[cfg(not(feature = "http3-datagram"))]
    let io = Some(io);
    if io.is_some() {
        headers.extensions_mut().insert(on_upgrade);
    }
    *headers.version_mut() = http::Version::HTTP_3;

    exec.execute_h3_future(H3ClientFuture::Upgrade {
        task: UpgradeTask {
            transfer: Some(Transfer {
                send: Some(SendStream::new(send, writes)),
                recv: Some(RecvStream {
                    recv,
                    body: Some(body),
                    data: None,
                    data_done: false,
                }),
                invalid: invalid.map(CancellationToken::cancelled_owned),
            }),
            active: Some(active),
            registration,
        },
    });

    if let Some(io) = io {
        pending.fulfill(io);
    }

    headers.map(|()| Incoming::empty())
}

pin_project! {
    /// Polls both tunnel directions independently until both finish or either
    /// fails. The reader sender is returned so the task can report an error.
    struct Transfer<S, R>
    where
        S: quic::SendStream<Bytes>,
        R: quic::RecvStream,
    {
        send: Option<SendStream<S>>,
        recv: Option<RecvStream<R>>,
        #[pin]
        invalid: Option<WaitForCancellationFutureOwned>,
    }
}

// ===== impl Transfer =====

impl<S, R> Future for Transfer<S, R>
where
    S: quic::SendStream<Bytes>,
    R: quic::RecvStream,
{
    type Output = (Result<()>, Option<chan::Sender>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if this
            .invalid
            .as_pin_mut()
            .is_some_and(|invalid| invalid.poll(cx).is_ready())
        {
            return Poll::Ready((
                Err(invalid_datagram_error()),
                this.recv.as_mut().and_then(|recv| recv.body.take()),
            ));
        }
        if let Some(send) = this.send.as_mut() {
            match Pin::new(send).poll(cx) {
                Poll::Ready(Ok(())) => *this.send = None,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready((
                        Err(error),
                        this.recv.as_mut().and_then(|recv| recv.body.take()),
                    ));
                }
                Poll::Pending => {}
            }
        }
        if let Some(recv) = this.recv.as_mut() {
            match Pin::new(&mut *recv).poll(cx) {
                Poll::Ready(Ok(())) => *this.recv = None,
                Poll::Ready(Err(error)) => {
                    return Poll::Ready((Err(error), recv.body.take()));
                }
                Poll::Pending => {}
            }
        }
        if this.send.is_none() && this.recv.is_none() {
            Poll::Ready((Ok(()), None))
        } else {
            Poll::Pending
        }
    }
}

/// Drives tunnel writes and flush barriers, acknowledging local shutdown before
/// waiting for FIN delivery. The transfer task owns cancellation and admission.
struct SendStream<S>
where
    S: quic::SendStream<Bytes>,
{
    send: SendGuard<S>,
    rx: mpsc::Receiver<Write>,
    finish: Option<oneshot::Sender<Result<()>>>,
}

impl<S> Unpin for SendStream<S> where S: quic::SendStream<Bytes> {}

// ===== impl SendStream =====

impl<S> SendStream<S>
where
    S: quic::SendStream<Bytes>,
{
    fn new(send: SendGuard<S>, rx: mpsc::Receiver<Write>) -> Self {
        Self {
            send,
            rx,
            finish: None,
        }
    }
}

impl<S> Future for SendStream<S>
where
    S: quic::SendStream<Bytes>,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.send.finished {
            return this
                .send
                .stream
                .poll_stopped(cx)
                .map(|result| result.map(|_| ()).map_err(Error::new_h3));
        }
        for _ in 0..32 {
            if this.finish.is_some() {
                ready!(this.send.stream.poll_finish(cx)).map_err(Error::new_h3)?;
                this.send.finished = true;
                if let Some(ack) = this.finish.take() {
                    let _ = ack.send(Ok(()));
                }
                // Shutdown acknowledges local FIN submission; drain still waits for delivery.
                return this
                    .send
                    .stream
                    .poll_stopped(cx)
                    .map(|result| result.map(|_| ()).map_err(Error::new_h3));
            }
            if let Poll::Ready(result) = this.send.stream.poll_stopped(cx) {
                #[cfg(feature = "http3-datagram")]
                if let Some(datagrams) = &this.send.datagrams {
                    datagrams.close_send();
                }
                return Poll::Ready(result.map(|_| ()).map_err(Error::new_h3));
            }
            // Flush accepted DATA before waiting for another command, even when
            // the application never calls flush or sends any more bytes.
            ready!(this.send.stream.poll_ready(cx)).map_err(Error::new_h3)?;
            match ready!(this.rx.poll_recv(cx)) {
                Some(Write::Data(data)) => this
                    .send
                    .stream
                    .start_send_data(data)
                    .map_err(Error::new_h3)?,
                Some(Write::Flush(ack)) => {
                    let _ = ack.send(Ok(()));
                }
                Some(Write::Finish(ack)) => {
                    #[cfg(feature = "http3-datagram")]
                    if let Some(datagrams) = &this.send.datagrams {
                        datagrams.close_send();
                    }
                    this.finish = Some(ack);
                }
                None => return Poll::Ready(Err(Error::new_canceled())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Forwards received DATA with channel backpressure and delivers EOF after
/// trailers. The current QUIC buffer stays here until the reader accepts it.
struct RecvStream<R: quic::RecvStream> {
    recv: RecvGuard<R>,
    body: Option<chan::Sender>,
    data: Option<Bytes>,
    data_done: bool,
}

// ===== impl RecvStream =====

impl<R: quic::RecvStream> Unpin for RecvStream<R> {}

impl<R: quic::RecvStream> Future for RecvStream<R> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(sender) = this.body.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        for _ in 0..32 {
            if sender.poll_closed(cx).is_ready() {
                return Poll::Ready(Err(Error::new_canceled()));
            }
            if let Some(data) = this.data.as_mut() {
                if data.has_remaining() {
                    ready!(sender.poll_ready(cx))?;
                    let size = data.remaining().min(CHUNK);
                    sender
                        .send_data(data.copy_to_bytes(size))
                        .map_err(|_| Error::new_canceled())?;
                    continue;
                }
                this.data = None;
            }
            if !this.data_done {
                match ready!(this.recv.stream.poll_recv_data(cx)).map_err(Error::new_h3)? {
                    Some(mut data) => {
                        this.data = Some(data.copy_to_bytes(data.remaining()));
                        continue;
                    }
                    None => this.data_done = true,
                }
            }
            ready!(this.recv.stream.poll_recv_trailers(cx)).map_err(Error::new_h3)?;
            this.recv.finished = true;
            #[cfg(feature = "http3-datagram")]
            if let Some(datagrams) = &this.recv.datagrams {
                datagrams.close_recv();
            }
            // Dropping the sender delivers EOF to the tunnel reader.
            this.body.take();
            return Poll::Ready(Ok(()));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// The error a closed tunnel reports to the application.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "HTTP/3 tunnel closed")
}

// ===== impl H3Upgraded =====

impl H3Upgraded {
    /// Waits for the pump task to acknowledge the pending flush or finish.
    fn poll_ack(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((finish, ack)) = self.pending.as_mut() {
            let result = ready!(Pin::new(ack).poll(cx));
            let finish = *finish;
            self.pending = None;
            result.map_err(|_| closed())?.map_err(io::Error::other)?;
            self.shutdown |= finish;
        }
        Poll::Ready(Ok(()))
    }

    /// Sends a flush or finish to the pump task and waits for its acknowledgment;
    /// a finish requested behind a pending flush follows once that flush completes.
    fn poll_barrier(&mut self, cx: &mut Context<'_>, finish: bool) -> Poll<io::Result<()>> {
        if self.pending.is_some() {
            let pending_finish = self.pending.as_ref().is_some_and(|(finish, _)| *finish);
            ready!(self.poll_ack(cx))?;
            if !finish || pending_finish {
                return Poll::Ready(Ok(()));
            }
        }
        if self.shutdown {
            return Poll::Ready(Ok(()));
        }
        ready!(self.sender.poll_reserve(cx)).map_err(|_| closed())?;
        let (tx, rx) = oneshot::channel();
        self.sender
            .send_item(if finish {
                Write::Finish(tx)
            } else {
                Write::Flush(tx)
            })
            .map_err(|_| closed())?;
        self.pending = Some((finish, rx));
        self.poll_ack(cx)
    }
}

impl AsyncRead for H3Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.data.is_empty() {
                let size = buf.remaining().min(self.data.len());
                buf.put_slice(&self.data[..size]);
                self.data.advance(size);
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_next(cx)) {
                Some(Ok(data)) => self.data = data,
                Some(Err(error)) => {
                    self.read_closed = true;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                None => {
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H3Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_ack(cx))?;
        if self.shutdown {
            return Poll::Ready(Err(closed()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.sender.poll_reserve(cx)).map_err(|_| closed())?;
        let size = buf.len().min(CHUNK);
        self.sender
            .send_item(Write::Data(Bytes::copy_from_slice(&buf[..size])))
            .map_err(|_| closed())?;
        Poll::Ready(Ok(size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_barrier(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_barrier(cx, true)
    }
}

#[cfg(feature = "http3-datagram")]
impl Drop for H3Upgraded {
    fn drop(&mut self) {
        if let Some(datagrams) = &self.datagrams {
            datagrams.close();
        }
    }
}
