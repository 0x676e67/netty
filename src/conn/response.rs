use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{Request, Response};

use crate::{
    Error,
    body::Incoming,
    dispatch::{RetryPromise, TrySendError},
};

type ResponseReceiver<B> = RetryPromise<Request<B>, Response<Incoming>>;

/// Waits for a response to a request submitted to an HTTP/1 or HTTP/2 connection.
///
/// Dropping it while the request is in flight cancels the request.
#[must_use = "poll or await this future to receive the response"]
pub struct ResponseFuture<B> {
    state: State<B>,
}

enum State<B> {
    Waiting(ResponseReceiver<B>),
    // Keep the original request out of the future's inline storage.
    Rejected(Option<Box<TrySendError<Request<B>>>>),
}

impl<B> ResponseFuture<B> {
    pub(super) fn new(sent: Result<ResponseReceiver<B>, TrySendError<Request<B>>>) -> Self {
        let state = match sent {
            Ok(receiver) => State::Waiting(receiver),
            Err(error) => State::Rejected(Some(Box::new(error))),
        };
        Self { state }
    }
}

impl<B> Future for ResponseFuture<B> {
    type Output = Result<Response<Incoming>, TrySendError<Request<B>>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.get_mut().state {
            State::Waiting(receiver) => {
                let response = ready!(Pin::new(receiver).poll(cx));
                Poll::Ready(response.expect("dispatch dropped without returning error"))
            }
            State::Rejected(error) => {
                let error = error
                    .take()
                    .expect("response future polled after completion");
                Poll::Ready(Err(*error))
            }
        }
    }
}

impl<B> fmt::Debug for ResponseFuture<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

pub(super) fn request_not_ready<B>(request: Request<B>) -> TrySendError<Request<B>> {
    TrySendError {
        error: Error::new_canceled().with("connection was not ready"),
        message: Some(request),
    }
}
