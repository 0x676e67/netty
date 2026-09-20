// Adapted from Hyper's HTTP/2 CONNECT upgrade implementation.
// Copyright (c) 2014-2026 Sean McArthur
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use std::{
    future::Future,
    io::{self, Cursor},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_channel::{mpsc, oneshot};
use futures_util::{task::AtomicWaker, Stream};
use http2::{Reason, RecvStream, SendStream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{ping::Recorder, SendBuf};

pub(super) fn pair<B>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    ping: Recorder,
) -> (H2Upgraded, UpgradedSendStreamTask<B>) {
    let (tx, rx) = mpsc::channel(1);
    let (error_tx, error_rx) = oneshot::channel();
    let close_notify = Arc::new(UpgradedCloseNotify::new());

    (
        H2Upgraded {
            send_stream: UpgradedSendStreamBridge {
                tx,
                error_rx,
                close_notify: close_notify.clone(),
            },
            recv_stream,
            ping,
            buf: Bytes::new(),
        },
        UpgradedSendStreamTask {
            h2_tx: send_stream,
            rx,
            close_notify,
            error_tx: Some(error_tx),
        },
    )
}

/// The application-facing CONNECT stream; a separate task owns its HTTP/2 sender.
pub(super) struct H2Upgraded {
    ping: Recorder,
    send_stream: UpgradedSendStreamBridge,
    recv_stream: RecvStream,
    buf: Bytes,
}

/// Relays accepted writes and terminal errors while the upgraded stream is alive.
struct UpgradedSendStreamBridge {
    tx: mpsc::Sender<Cursor<Box<[u8]>>>,
    error_rx: oneshot::Receiver<crate::Error>,
    close_notify: Arc<UpgradedCloseNotify>,
}

/// Wakes the send task when the write bridge closes while waiting for capacity.
struct UpgradedCloseNotify {
    closed: AtomicBool,
    task: AtomicWaker,
}

pin_project! {
    /// Drives CONNECT writes until the upgraded stream shuts down or fails.
    #[must_use = "futures do nothing unless polled"]
    pub struct UpgradedSendStreamTask<B> {
        #[pin]
        h2_tx: SendStream<SendBuf<B>>,
        #[pin]
        rx: mpsc::Receiver<Cursor<Box<[u8]>>>,
        close_notify: Arc<UpgradedCloseNotify>,
        error_tx: Option<oneshot::Sender<crate::Error>>,
    }
}

// ===== impl UpgradedSendStreamBridge =====

impl Drop for UpgradedSendStreamBridge {
    fn drop(&mut self) {
        self.close_notify.close();
    }
}

// ===== impl UpgradedCloseNotify =====

impl UpgradedCloseNotify {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            task: AtomicWaker::new(),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.task.wake();
    }

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.closed.load(Ordering::Acquire) {
            return Poll::Ready(());
        }

        self.task.register(cx.waker());

        if self.closed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

// ===== impl UpgradedSendStreamTask =====

impl<B> UpgradedSendStreamTask<B>
where
    B: Buf,
{
    fn tick(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), crate::Error>> {
        let mut me = self.project();

        // this is a manual `select()` over 3 "futures", so we always need
        // to be sure they are ready and/or we are waiting notification of
        // one of the sides hanging up, so the task doesn't live around
        // longer than it's meant to.
        loop {
            // we don't have the next chunk of data yet, so just reserve 1 byte to make
            // sure there's some capacity available. h2 will handle the capacity management
            // for the actual body chunk.
            me.h2_tx.reserve_capacity(1);

            let h2_has_capacity = if me.h2_tx.capacity() == 0 {
                // poll_capacity oddly needs a loop
                loop {
                    match me.h2_tx.poll_capacity(cx) {
                        Poll::Ready(Some(Ok(0))) => {}
                        Poll::Ready(Some(Ok(_))) => break true,
                        Poll::Ready(Some(Err(e))) => {
                            return Poll::Ready(Err(crate::Error::new_body_write(e)))
                        }
                        Poll::Ready(None) => {
                            // None means the stream is no longer in a
                            // streaming state, we either finished it
                            // somehow, or the remote reset us.
                            return Poll::Ready(Err(crate::Error::new_body_write(
                                "send stream capacity unexpectedly closed",
                            )));
                        }
                        Poll::Pending => break false,
                    }
                }
            } else {
                true
            };

            match me.h2_tx.poll_reset(cx) {
                Poll::Ready(Ok(reason)) => {
                    trace!("stream received RST_STREAM: {:?}", reason);
                    return Poll::Ready(Err(crate::Error::new_body_write(::http2::Error::from(
                        reason,
                    ))));
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(crate::Error::new_body_write(err)))
                }
                Poll::Pending => (),
            }

            // Keep accepted writes queued until HTTP/2 capacity returns, so freeing
            // a channel slot cannot let the writer bypass flow-control backpressure.
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-5.2
            if !h2_has_capacity {
                // Empty END_STREAM is allowed without window space; observe the queue
                // without consuming an accepted write that still needs capacity.
                // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.1
                if me.rx.size_hint().0 == 0 && me.close_notify.poll_closed(cx).is_ready() {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    return Poll::Ready(Ok(()));
                }

                return Poll::Pending;
            }

            match me.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(cursor)) => {
                    me.h2_tx
                        .send_data(SendBuf::Cursor(cursor), false)
                        .map_err(crate::Error::new_body_write)?;
                }
                Poll::Ready(None) => {
                    me.h2_tx
                        .send_data(SendBuf::None, true)
                        .map_err(crate::Error::new_body_write)?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<B> Future for UpgradedSendStreamTask<B>
where
    B: Buf,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().tick(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(()),
            Poll::Ready(Err(err)) => {
                if let Some(tx) = self.error_tx.take() {
                    let _oh_well = tx.send(err);
                }
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== impl H2Upgraded =====

impl AsyncRead for H2Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {
                        continue
                    }
                    Some(Ok(buf)) => {
                        self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        })
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        let _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                return match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                };
            }
            Poll::Pending => return Poll::Pending,
        }

        let n = buf.len();
        match self.send_stream.tx.start_send(Cursor::new(buf.into())) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_task_dropped) => {
                // if the task dropped, check if there was an error
                // otherwise i guess its a broken pipe
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => {
                        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.send_stream.tx.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_task_dropped)) => {
                // if the task dropped, check if there was an error
                // otherwise it was a clean close
                match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
                    Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
                    Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send_stream.tx.close_channel();
        self.send_stream.close_notify.close();
        match Pin::new(&mut self.send_stream.error_rx).poll(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(io_error(reason))),
            Poll::Ready(Err(_task_dropped)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn io_error(e: crate::Error) -> std::io::Error {
    io::Error::other(e)
}

fn h2_to_io_error(e: http2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io()
            .expect("[BUG] http2::Error::is_io() is true, but into_io() failed")
    } else {
        io::Error::other(e)
    }
}
