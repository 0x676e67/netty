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

#[cfg(feature = "http3")]
use futures_util::future::BoxFuture;
use http::{Request, Response};

pub use super::dispatch::TrySendError;
use crate::{body::Incoming, dispatch::RetryPromise};

type ResponseReceiver<B> = RetryPromise<Request<B>, Response<Incoming>>;

/// Waits for a response to a request submitted to an HTTP/1, HTTP/2, or HTTP/3 connection.
///
/// Dropping it while the request is in flight cancels the request.
#[must_use = "poll or await this future to receive the response"]
pub struct ResponseFuture<B>(ResponseFutureInner<B>);

enum ResponseFutureInner<B> {
    Pending(ResponseReceiver<B>),
    /// Boxed so an immediate send failure does not inflate every in-flight future by `Request<B>`.
    Error(Ready<Box<TrySendError<Request<B>>>>),
    #[cfg(feature = "http3")]
    Http3(BoxFuture<'static, Result<Response<Incoming>, TrySendError<Request<B>>>>),
}

impl<B> ResponseFuture<B> {
    /// Creates a new [`ResponseFuture`] from an HTTP/1 or HTTP/2 dispatch attempt.
    fn new(sent: Result<ResponseReceiver<B>, TrySendError<Request<B>>>) -> Self {
        Self(match sent {
            Ok(receiver) => ResponseFutureInner::Pending(receiver),
            Err(error) => ResponseFutureInner::Error(future::ready(Box::new(error))),
        })
    }

    /// Creates a new [`ResponseFuture`] from an HTTP/3 request exchange future.
    #[cfg(feature = "http3")]
    fn http3(
        future: BoxFuture<'static, Result<Response<Incoming>, TrySendError<Request<B>>>>,
    ) -> Self {
        Self(ResponseFutureInner::Http3(future))
    }
}

impl<B> Future for ResponseFuture<B> {
    type Output = Result<Response<Incoming>, TrySendError<Request<B>>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.get_mut().0 {
            ResponseFutureInner::Pending(receiver) => {
                let response = ready!(Pin::new(receiver).poll(cx));
                Poll::Ready(response.expect("dispatch dropped without returning error"))
            }
            ResponseFutureInner::Error(error) => {
                Poll::Ready(Err(*ready!(Pin::new(error).poll(cx))))
            }
            #[cfg(feature = "http3")]
            ResponseFutureInner::Http3(future) => future.as_mut().poll(cx),
        }
    }
}

impl<B> fmt::Debug for ResponseFuture<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseFuture").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_future_size_is_independent_of_request() {
        let size = std::mem::size_of::<ResponseFuture<[u8; 256]>>();
        let limit = std::mem::size_of::<usize>() * if cfg!(feature = "http3") { 3 } else { 2 };
        assert!(
            size <= limit,
            "ResponseFuture<[u8; 256]> is {size} bytes (limit {limit})"
        );
    }
}
