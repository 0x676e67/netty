#[cfg(feature = "http3-datagram")]
use std::sync::Arc;
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{future::try_join, TryFutureExt};
use http::Response;
use http3::quic;
use http_body::Body;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::PollSender;

use super::client::{cooperate, BodyGuard, Failure, RecvGuard, ResponseGuard, SendGuard, CHUNK};
use crate::{body::Incoming, Error, Result};

enum Write {
    Data(Bytes),
    Flush(oneshot::Sender<Result<()>>),
    Finish(oneshot::Sender<Result<()>>),
}

struct Io {
    incoming: Incoming,
    data: Bytes,
    sender: PollSender<Write>,
    pending: Option<(bool, oneshot::Receiver<Result<()>>)>,
    shutdown: bool,
    read_closed: bool,
    #[cfg(feature = "http3-datagram")]
    datagrams: Option<Arc<super::datagram::RequestState>>,
}

pub(super) async fn run<S, R, B>(
    send: SendGuard<S>,
    recv: RecvGuard<R>,
    mut headers: Response<()>,
    response: &mut ResponseGuard<'_, B>,
    failure: &Failure,
    #[cfg(feature = "http3-datagram")] datagrams: Option<Arc<super::datagram::RequestState>>,
) -> Result<()>
where
    S: quic::SendStream<Bytes>,
    R: quic::RecvStream,
{
    let (sender, incoming) = Incoming::h3();
    let (tx, rx) = mpsc::channel(1);
    let io = Io {
        incoming,
        data: Bytes::new(),
        sender: PollSender::new(tx),
        pending: None,
        shutdown: false,
        read_closed: false,
        #[cfg(feature = "http3-datagram")]
        datagrams: datagrams.clone(),
    };
    let (pending, on_upgrade) = crate::upgrade::pending();
    let io = crate::upgrade::Upgraded::new(io, Bytes::new());
    #[cfg(feature = "http3-datagram")]
    let io = if let Some(datagrams) = datagrams {
        headers
            .extensions_mut()
            .insert(crate::conn::http3::datagram::Pending::new(io, datagrams));
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
    let Some(callback) = response.callback.take() else {
        return Err(Error::new_canceled());
    };
    callback
        .try_send(Ok(headers.map(|()| Incoming::empty())))
        .map_err(|_| Error::new_canceled())?;
    if let Some(io) = io {
        pending.fulfill(io);
    }
    let body = BodyGuard {
        sender: Some(sender),
        failure,
    };
    let write = upload(send, rx).map_err(|error| {
        failure.set(error);
        failure.get()
    });
    let read = download(recv, body);
    try_join(write, read).await.map(|_| ())
}

async fn upload<S: quic::SendStream<Bytes>>(
    mut send: SendGuard<S>,
    mut rx: mpsc::Receiver<Write>,
) -> Result<()> {
    let mut budget = 0;
    let mut stopped = false;
    while let Some(write) = poll_fn(|cx| {
        if let Poll::Ready(result) = send.stopped.as_mut().poll(cx) {
            stopped = true;
            return Poll::Ready(result.map(|_| None).map_err(Error::new_h3));
        }
        rx.poll_recv(cx).map(Ok)
    })
    .await?
    {
        match write {
            Write::Data(data) => send.stream.send_data(data).await.map_err(Error::new_h3)?,
            Write::Flush(ack) => {
                let _ = ack.send(Ok(()));
            }
            Write::Finish(ack) => {
                #[cfg(feature = "http3-datagram")]
                if let Some(datagrams) = &send.datagrams {
                    datagrams.close_send();
                }
                send.stream.finish().await.map_err(Error::new_h3)?;
                send.finished = true;
                let _ = ack.send(Ok(()));
                return Ok(());
            }
        }
        cooperate(&mut budget).await;
    }
    if stopped {
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &send.datagrams {
            datagrams.close_send();
        }
        Ok(())
    } else {
        Err(Error::new_canceled())
    }
}

async fn download<R: quic::RecvStream>(
    mut recv: RecvGuard<R>,
    mut body: BodyGuard<'_>,
) -> Result<()> {
    let Some(sender) = body.sender.as_mut() else {
        return Err(Error::new_canceled());
    };
    let transfer = async {
        let mut budget = 0;
        while let Some(mut data) = poll_fn(|cx| {
            if sender.poll_closed(cx).is_ready() {
                return Poll::Ready(Err(Error::new_canceled()));
            }
            recv.stream.poll_recv_data(cx).map_err(Error::new_h3)
        })
        .await?
        {
            while data.has_remaining() {
                poll_fn(|cx| sender.poll_ready(cx)).await?;
                let size = data.remaining().min(CHUNK);
                sender
                    .send_data(data.copy_to_bytes(size))
                    .map_err(|_| Error::new_canceled())?;
                cooperate(&mut budget).await;
            }
            cooperate(&mut budget).await;
        }
        poll_fn(|cx| {
            if sender.poll_closed(cx).is_ready() {
                return Poll::Ready(Err(Error::new_canceled()));
            }
            recv.stream.poll_recv_trailers(cx).map_err(Error::new_h3)
        })
        .await?;
        recv.finished = true;
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &recv.datagrams {
            datagrams.close_recv();
        }
        Ok(())
    };
    let result = transfer.await;
    if let Err(error) = result {
        body.failure.set(error);
        return Err(body.failure.get());
    }
    body.sender.take();
    Ok(())
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "HTTP/3 tunnel closed")
}

// ===== impl Io =====

impl Io {
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

impl AsyncRead for Io {
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
            match ready!(Pin::new(&mut self.incoming).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.data = data;
                    }
                }
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

impl AsyncWrite for Io {
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
impl Drop for Io {
    fn drop(&mut self) {
        if let Some(datagrams) = &self.datagrams {
            datagrams.close();
        }
    }
}
