//! Lower-level client connection API.
//!
//! The types in this module are to provide a lower-level API based around a
//! single connection. Connecting to a host, pooling connections, and the like
//! are not handled at this level. This module provides the building blocks to
//! customize those things externally.

pub mod http1;
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "http3")]
pub mod http3;

use std::{
    fmt,
    future::{self, Future, Ready},
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{Request, Response};

pub use super::dispatch::TrySendError;
use crate::{Error, body::Incoming, dispatch::RetryPromise};

type ResponseReceiver<B> = RetryPromise<Request<B>, Response<Incoming>>;

/// Waits for a response to a request submitted to an HTTP/1 or HTTP/2 connection.
///
/// Dropping it while the request is in flight cancels the request.
#[must_use = "poll or await this future to receive the response"]
pub struct ResponseFuture<B> {
    sent: Result<ResponseReceiver<B>, Ready<TrySendError<Request<B>>>>,
}

impl<B> ResponseFuture<B> {
    fn new(sent: Result<ResponseReceiver<B>, TrySendError<Request<B>>>) -> Self {
        Self {
            sent: sent.map_err(future::ready),
        }
    }
}

impl<B> Future for ResponseFuture<B> {
    type Output = Result<Response<Incoming>, TrySendError<Request<B>>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.get_mut().sent {
            Ok(receiver) => {
                let response = ready!(Pin::new(receiver).poll(cx));
                Poll::Ready(response.expect("dispatch dropped without returning error"))
            }
            Err(error) => Pin::new(error).poll(cx).map(Err),
        }
    }
}

impl<B> fmt::Debug for ResponseFuture<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

fn request_not_ready<B>(request: Request<B>) -> TrySendError<Request<B>> {
    TrySendError {
        error: Error::new_canceled().with("connection was not ready"),
        message: Some(request),
    }
}
