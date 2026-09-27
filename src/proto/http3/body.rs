//! HTTP/3 response bodies that read the QUIC receive half directly.

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{ready, Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use http3::{error::Code, quic};
use http_body::{Body, Frame, SizeHint};

#[cfg(feature = "http3-datagram")]
use super::client::invalid_datagram_error;
#[cfg(feature = "http3-datagram")]
use super::datagram::{Registration, RequestState};
use super::{
    client::{consume_length, RecvGuard},
    shared::Active,
};
use crate::{lock::LockResultExt, Error, Result};

/// Response body handed to the application; [`Incoming`](crate::body::Incoming)
/// boxes it. Dropping it stops receiving without canceling pending sending.
/// Length bookkeeping stays here, so only a poll takes the lock.
pub(super) struct RecvBody<S: quic::RecvStream> {
    link: Arc<Link<S>>,
    /// Declared length still expected.
    remaining: Option<u64>,
    data_done: bool,
    /// A terminal frame was returned: the stream and any error are gone.
    ended: bool,
}

/// Links the body with sending that outlived the response head. The lock
/// guards the receive half so either side can stop the exchange at once; the
/// send task's signals are atomics, so its polling never contends with the
/// body's reads.
struct Link<S: quic::RecvStream> {
    state: Mutex<State<S>>,
    /// The response failed; the send task resets its direction.
    abort: AtomicBool,
    pipe_waker: AtomicWaker,
}

/// The body pipe's side of the link. Dropping it records completion, so a task
/// the executor discards still returns the permit once the response is done.
pub(super) struct PipeGuard<S: quic::RecvStream> {
    link: Arc<Link<S>>,
    error: Option<Error>,
}

/// Receive state; `recv` is taken once the stream is read to FIN, canceled or
/// abandoned by the application.
struct State<S: quic::RecvStream> {
    recv: Option<RecvGuard<S>>,
    /// Released once the response is finished and sending is complete.
    active: Option<Active>,
    #[cfg(feature = "http3-datagram")]
    registration: Option<Registration>,
    /// Body sending or FIN acknowledgment still runs on the executor.
    pipe_pending: bool,
    error: Option<Error>,
    /// The body's waker, for a failure reported by the send task or a Datagram.
    waker: Option<Waker>,
}

// ===== impl RecvBody =====

impl<S: quic::RecvStream> RecvBody<S> {
    /// Wraps the receive half once the head is delivered; `remaining` is the
    /// declared length still expected, `pipe_pending` whether sending or FIN
    /// acknowledgment still needs the executor.
    pub(super) fn new(
        recv: RecvGuard<S>,
        remaining: Option<u64>,
        active: Active,
        #[cfg(feature = "http3-datagram")] registration: Option<Registration>,
        pipe_pending: bool,
    ) -> Self {
        Self {
            link: Arc::new(Link {
                state: Mutex::new(State {
                    recv: Some(recv),
                    active: Some(active),
                    #[cfg(feature = "http3-datagram")]
                    registration,
                    pipe_pending,
                    error: None,
                    waker: None,
                }),
                abort: AtomicBool::new(false),
                pipe_waker: AtomicWaker::new(),
            }),
            remaining,
            data_done: false,
            ended: false,
        }
    }

    /// The send task's handle on the shared state.
    pub(super) fn pipe_guard(&self) -> PipeGuard<S> {
        PipeGuard {
            link: self.link.clone(),
            error: None,
        }
    }

    /// Lets an invalid Datagram stop this body while the application holds it.
    /// One that arrived before the hook existed only cancelled the token, so
    /// the token is checked again once the hook is in place.
    #[cfg(feature = "http3-datagram")]
    pub(super) fn attach(&self, datagrams: &RequestState)
    where
        S: Send + 'static,
    {
        datagrams.attach(Arc::downgrade(&self.link), |link| {
            if let Some(link) = link.downcast_ref::<Link<S>>() {
                link.cancel(invalid_datagram_error());
            }
        });
        if datagrams.invalid.is_cancelled() {
            self.link.cancel(invalid_datagram_error());
        }
    }
}

impl<S> Body for RecvBody<S>
where
    S: quic::RecvStream + Send + 'static,
{
    type Data = Bytes;

    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        let mut state = this.link.state.lock().panic_if_poisoned();
        if !state
            .waker
            .as_ref()
            .is_some_and(|w| w.will_wake(cx.waker()))
        {
            state.waker = Some(cx.waker().clone());
        }
        let frame = ready!(state.poll_frame(cx, &mut this.remaining, &mut this.data_done));
        this.ended = state.recv.is_none() && state.error.is_none();
        drop(state);
        if matches!(frame, Some(Err(_))) {
            // A failed response aborts the exchange: the send task resets
            // its direction on its next poll.
            this.link.abort.store(true, Ordering::Release);
            this.link.pipe_waker.wake();
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        if self.ended {
            SizeHint::with_exact(0)
        } else {
            self.remaining
                .map_or_else(SizeHint::default, SizeHint::with_exact)
        }
    }
}

impl<S: quic::RecvStream> Drop for RecvBody<S> {
    fn drop(&mut self) {
        let mut state = self.link.state.lock().panic_if_poisoned();
        if state.recv.is_some() {
            state.recv = None;
            state.release();
        }
    }
}

// ===== impl PipeGuard =====

impl<S: quic::RecvStream> PipeGuard<S> {
    /// Registers the send task; returns false once a response failure has
    /// aborted the exchange, so the task resets its send direction.
    pub(super) fn watch(&self, cx: &Context<'_>) -> bool {
        self.link.pipe_waker.register(cx.waker());
        !self.link.abort.load(Ordering::Acquire)
    }

    /// Reports a send failure, which cancels a response the application
    /// still holds.
    pub(super) fn fail(&mut self, error: Error) {
        self.error = Some(error);
    }
}

impl<S: quic::RecvStream> Drop for PipeGuard<S> {
    fn drop(&mut self) {
        let mut state = self.link.state.lock().panic_if_poisoned();
        state.pipe_pending = false;
        state.release();
        drop(state);
        if let Some(error) = self.error.take() {
            self.link.cancel(error);
        }
    }
}

// ===== impl Link =====

impl<S: quic::RecvStream> Link<S> {
    /// Stops receiving and reports `error` on the body's next poll. Dropping
    /// the guard sends STOP_SENDING.
    fn cancel(&self, error: Error) {
        let mut state = self.state.lock().panic_if_poisoned();
        if state.recv.is_some() {
            let error = state.finish(error);
            state.error = Some(error);
        }
        let waker = state.waker.take();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

// ===== impl State =====

impl<S: quic::RecvStream> State<S> {
    /// Reads the next frame under the lock; a failure finishes the stream and
    /// reports the error, preferring a published connection error.
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
        remaining: &mut Option<u64>,
        data_done: &mut bool,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        let Some(recv) = self.recv.as_mut() else {
            return Poll::Ready(self.error.take().map(Err));
        };
        let error = loop {
            if *data_done {
                let trailers = match ready!(recv.stream.poll_recv_trailers(cx)) {
                    Ok(trailers) => trailers,
                    Err(error) => break Error::new_h3(error),
                };
                recv.finished = true;
                #[cfg(feature = "http3-datagram")]
                if let Some(datagrams) = &recv.datagrams {
                    datagrams.close_recv();
                }
                self.recv = None;
                self.release();
                return Poll::Ready(trailers.map(|trailers| Ok(Frame::trailers(trailers))));
            }
            match ready!(recv.stream.poll_recv_data(cx)) {
                Ok(Some(mut data)) => {
                    if let Err(reason) = consume_length(remaining, data.remaining()) {
                        recv.code = Code::H3_MESSAGE_ERROR;
                        break Error::new_h3(reason);
                    }
                    let data = data.copy_to_bytes(data.remaining());
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Ok(None) => {
                    if remaining.is_some_and(|n| n != 0) {
                        recv.code = Code::H3_MESSAGE_ERROR;
                        break Error::new_body("HTTP/3 body shorter than content-length");
                    }
                    *data_done = true;
                }
                Err(error) => break Error::new_h3(error),
            }
        };
        Poll::Ready(Some(Err(self.finish(error))))
    }

    /// Releases the stream; prefers a published connection error.
    fn finish(&mut self, error: Error) -> Error {
        let error = match &self.active {
            Some(active) => active.shared().error_or(error),
            None => error,
        };
        self.recv = None;
        self.release();
        error
    }

    /// Returns the permit once the response is done and sending is complete.
    fn release(&mut self) {
        if self.recv.is_none() && !self.pipe_pending {
            #[cfg(feature = "http3-datagram")]
            {
                self.registration = None;
            }
            self.active = None;
        }
    }
}
