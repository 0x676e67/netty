//! HTTP/3 client connections over a QUIC connection the caller establishes.
//!
//! The caller performs the QUIC and TLS handshakes and hands the connection to
//! [`Builder::handshake`] as an implementation of [`Connection`](crate::rt::quic::Connection)
//! from [`rt::quic`](crate::rt::quic), for example a transport wrapped in
//! [`Compat`](crate::rt::quic::Compat). The handshake returns a [`SendRequest`]
//! handle and a [`Connection`] handle, like HTTP/1 and HTTP/2:
//!
//! - Each request runs inside the future returned by [`SendRequest::try_send_request`]: nothing is
//!   queued and no task is spawned for it. Dropping that future cancels only that request.
//! - The connection task runs on the executor given to [`Builder::new`], which implements
//!   [`Http3ClientConnExec`]. It also drives request body sending that outlives the response head,
//!   including FIN acknowledgment, and CONNECT tunnels.
//! - [`Connection`] resolves once the task finishes. Requests progress without it being polled, but
//!   it must be kept: dropping it closes the QUIC connection and every outstanding exchange.
//! - Dropping the last [`SendRequest`] starts draining: requests created earlier still run, and the
//!   task closes the connection once every exchange, including acknowledgment of its FIN, is done.
//!   [`Connection::graceful_shutdown`] instead returns requests still waiting for SETTINGS or
//!   admission, then waits for admitted exchanges to finish.
//!
//! Admission is limited locally by [`Http3Options::max_concurrent_requests`]. Extended CONNECT with
//! HTTP Datagram sessions lives in the `datagram` submodule with the `http3-datagram` feature.
//!
//! ```ignore
//! let (mut tx, connection) = Builder::new(exec).handshake::<_, Full<Bytes>>(quic).await?;
//! let connection = tokio::spawn(connection);
//! let response = tx
//!     .try_send_request(Request::get("https://example.com/").body(Full::new(Bytes::new()))?)
//!     .await?;
//! ```

#[cfg(feature = "http3-datagram")]
pub mod datagram;

use std::{
    future::{poll_fn, Future},
    marker::PhantomData,
    pin::Pin,
    sync::{atomic::Ordering, Arc, Mutex, PoisonError},
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::{Request, Response};
use http3::error::Code;
use http_body::Body;
use tokio::sync::oneshot;

#[cfg(feature = "http3-datagram")]
use crate::proto::http3::datagram::{Drive, Registry};
use crate::{
    body::Incoming,
    dispatch::TrySendError,
    error::BoxError,
    proto::http3::{
        client::{self, ConnTask, H3ClientFuture},
        shared::{Active, Shared},
        transport::Transport,
        Http3Options,
    },
    rt::{bounds::Http3ClientConnExec, quic},
    Error, Result,
};

/// The boxed request future a handle returns.
type ExchangeFuture<B> = BoxFuture<'static, Result<Response<Incoming>, TrySendError<Request<B>>>>;

/// Starts requests on the connection. Erasing the QUIC backend and executor
/// here keeps handles at `SendRequest<B>`, like the HTTP/1 and HTTP/2 ones.
trait Exchange<B>: Send {
    /// Starts a request with its reservation.
    fn call(&mut self, request: Request<B>, reservation: Option<Active>) -> ExchangeFuture<B>;

    /// Clones the exchange for a cloned handle.
    fn clone_box(&self) -> Box<dyn Exchange<B>>;
}

/// The sender side of an established connection.
///
/// Each request runs inside the future returned by [`Self::try_send_request`].
/// Request body sending that outlives the response head, including FIN
/// acknowledgment, and CONNECT tunnels are handed to the executor.
pub struct SendRequest<B> {
    /// The lock only makes the handle `Sync` without requiring that of the
    /// QUIC backend; requests reach the exchange through `get_mut` and never
    /// lock.
    exchange: Mutex<Box<dyn Exchange<B>>>,
    shared: Arc<Shared>,
}

/// Handle to the connection task, which the executor runs like the HTTP/2
/// connection. It resolves once the task finishes; dropping it closes the
/// QUIC connection and every outstanding exchange. The body and executor
/// types are fixed by the handshake.
#[must_use = "dropping the connection handle closes the connection"]
pub struct Connection<Q, B, E>
where
    Q: quic::Connection<Bytes>,
    B: Body + 'static,
    E: Http3ClientConnExec<Q>,
    B::Error: Into<BoxError>,
{
    opener: Q::OpenStreams,
    shared: Arc<Shared>,
    done: oneshot::Receiver<Result<()>>,
    completed: bool,
    _marker: PhantomData<fn(B, E)>,
}

/// The opener is only used through `&mut self`, so the handle is `Unpin`
/// whatever the backend is.
impl<Q, B, E> Unpin for Connection<Q, B, E>
where
    Q: quic::Connection<Bytes>,
    B: Body + 'static,
    E: Http3ClientConnExec<Q>,
    B::Error: Into<BoxError>,
{
}

/// Configures a single HTTP/3 connection and its executor.
#[derive(Clone)]
pub struct Builder<E> {
    exec: E,
    options: Http3Options,
}

/// Closes the QUIC connection if the handshake is abandoned before the opener
/// moves into the connection task.
struct HandshakeGuard<O>(Option<O>)
where
    O: quic::OpenStreams<Bytes>;

// ===== impl SendRequest =====

impl<B> Clone for SendRequest<B> {
    fn clone(&self) -> Self {
        let exchange = self
            .exchange
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone_box();
        self.shared.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            exchange: Mutex::new(exchange),
            shared: self.shared.clone(),
        }
    }
}

impl<B> Drop for SendRequest<B> {
    fn drop(&mut self) {
        // Closing the last sender drains previously created requests, like
        // the HTTP/1 and HTTP/2 dispatch queues.
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.shared.drain();
        }
    }
}

impl<B> SendRequest<B> {
    /// Checks whether the connection accepts requests.
    /// This does not reserve a QUIC stream or wait for peer stream credit.
    pub fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.is_closed() {
            Poll::Ready(Err(Error::new_closed()))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Waits until the connection accepts requests; see [`Self::poll_ready`].
    pub async fn ready(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_ready(cx)).await
    }

    /// Returns a readiness hint; the connection may close before a request is sent.
    pub fn is_ready(&self) -> bool {
        !self.shared.is_draining()
    }

    /// Whether the connection no longer accepts new requests.
    pub fn is_closed(&self) -> bool {
        self.shared.is_draining()
    }
}

impl<B> SendRequest<B>
where
    B: Body + 'static,
{
    /// Sends a `Request` on the associated connection.
    ///
    /// Returns a future that if successful, yields the `Response`.
    /// The request progresses when the returned future is polled.
    ///
    /// # Errors
    ///
    /// If there was an error before trying to open the request stream, the message
    /// will be returned as part of this error.
    ///
    /// # Cancel safety
    ///
    /// Drop the returned future to cancel an in-flight request. If a stream has
    /// been opened, cancellation aborts its unfinished send and receive directions
    /// with `H3_REQUEST_CANCELLED`
    /// ([RFC 9114 §4.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1)).
    /// The connection remains usable for other current and subsequent requests.
    /// Keep the executor and QUIC transport running so cancellation can reach the peer.
    ///
    /// After the response is delivered, dropping its body only cancels receiving;
    /// unfinished request body sending can continue independently.
    #[allow(clippy::result_large_err)]
    pub fn try_send_request(
        &mut self,
        request: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, TrySendError<Request<B>>>> {
        // Reserve before returning the future so dropping the last sender
        // cannot close the connection before this request is polled.
        let reservation = (!self.shared.is_draining()).then(|| Active::reserve(&self.shared));
        self.exchange
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .call(request, reservation)
    }
}

// ===== impl Exchange =====

impl<B, F> Exchange<B> for F
where
    F: FnMut(Request<B>, Option<Active>) -> ExchangeFuture<B> + Clone + Send + 'static,
{
    fn call(&mut self, request: Request<B>, reservation: Option<Active>) -> ExchangeFuture<B> {
        self(request, reservation)
    }

    fn clone_box(&self) -> Box<dyn Exchange<B>> {
        Box::new(self.clone())
    }
}

// ===== impl Builder =====

impl<E> Builder<E> {
    /// Creates a builder. The executor drives the connection, CONNECT tunnels,
    /// and request body sending or FIN acknowledgment after the response head.
    pub fn new(exec: E) -> Self {
        Self {
            exec,
            options: Http3Options::default(),
        }
    }

    /// Replaces protocol settings and local admission limits.
    pub fn options(mut self, options: Http3Options) -> Self {
        self.options = options;
        self
    }

    /// Initializes HTTP/3 over a QUIC connection whose TLS handshake is complete.
    /// The connection task is handed to the executor; the returned handle
    /// resolves when it finishes.
    pub async fn handshake<Q, B>(self, quic: Q) -> Result<(SendRequest<B>, Connection<Q, B, E>)>
    where
        Q: quic::Connection<Bytes>,
        Q::OpenStreams: Clone + Send + 'static,
        Q::BidiStream: quic::BidiStream<Bytes> + Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
        <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        E: Http3ClientConnExec<Q> + Send + 'static,
    {
        self.handshake_inner(
            quic,
            #[cfg(feature = "http3-datagram")]
            None,
        )
        .await
    }

    /// Initializes HTTP/3 with a single raw Datagram reader and bounded routing.
    /// Advertises H3_DATAGRAM; native sends still require peer negotiation.
    /// The supplied QUIC transport must advertise support for receiving Datagram
    /// frames in its transport parameters, as required by RFC 9297 Section 2.1.1.
    #[cfg(feature = "http3-datagram")]
    pub async fn handshake_with_datagrams<Q, B>(
        self,
        mut quic: Q,
    ) -> Result<(SendRequest<B>, Connection<Q, B, E>)>
    where
        Q: quic::Connection<Bytes> + quic::DatagramConnection,
        Q::Sender: Send + 'static,
        Q::Receiver: Send + 'static,
        Q::OpenStreams: Clone + Send + 'static,
        Q::BidiStream: quic::BidiStream<Bytes> + Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
        <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        E: Http3ClientConnExec<Q> + Send + 'static,
    {
        let Some((sender, receiver)) = quic.take_datagrams() else {
            return Err(Error::new_h3("QUIC Datagram reader already taken"));
        };
        let datagrams = Registry::new(sender, receiver);
        self.handshake_inner(quic, Some(datagrams)).await
    }

    /// Builds the protocol layer, spawns the connection task and returns the handles.
    async fn handshake_inner<Q, B>(
        self,
        quic: Q,
        #[cfg(feature = "http3-datagram")] datagrams: Option<(Arc<Registry>, Drive)>,
    ) -> Result<(SendRequest<B>, Connection<Q, B, E>)>
    where
        Q: quic::Connection<Bytes>,
        Q::OpenStreams: Clone + Send + 'static,
        Q::BidiStream: quic::BidiStream<Bytes> + Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
        <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        E: Http3ClientConnExec<Q> + Send + 'static,
    {
        let opts = self.options;
        if opts.max_concurrent_requests == 0 {
            return Err(Error::new_h3("invalid HTTP/3 request capacity"));
        }

        #[cfg(feature = "http3-datagram")]
        if datagrams.is_some()
            && opts
                .settings_order
                .as_ref()
                .is_some_and(|order| !order.contains(&http3::SettingId::H3_DATAGRAM))
        {
            return Err(Error::new_h3(
                "HTTP Datagram settings order omits H3_DATAGRAM",
            ));
        }

        let mut handshake_guard = HandshakeGuard(Some(quic.opener()));
        let mut builder = http3::client::builder();
        builder
            .max_field_section_size(opts.max_field_section_size)
            .max_qpack_decode_buffer_size(opts.max_qpack_decode_buffer_size)
            .qpack_encoder_table_capacity(opts.qpack_encoder_table_capacity)
            .qpack_max_table_capacity(opts.qpack_max_table_capacity)
            .qpack_blocked_streams(opts.qpack_blocked_streams)
            .send_grease(opts.send_grease)
            .enable_extended_connect(opts.enable_extended_connect);
        if let Some(order) = opts.settings_order {
            builder.settings_order(order);
        }
        #[cfg(feature = "http3-datagram")]
        builder.enable_datagram(datagrams.is_some());
        let (driver, sender) = builder
            .build(Transport(quic))
            .await
            .map_err(Error::new_h3)?;

        #[cfg(feature = "http3-datagram")]
        let (registry, datagrams) = datagrams.map_or((None, None), |(r, d)| (Some(r), Some(d)));
        let shared = Shared::new(
            opts.max_concurrent_requests,
            #[cfg(feature = "http3-datagram")]
            registry,
        );

        let opener = handshake_guard.0.take().ok_or_else(Error::new_canceled)?;
        let (done, completion) = oneshot::channel();
        let task = ConnTask::new(
            driver,
            opener.clone(),
            #[cfg(feature = "http3-datagram")]
            datagrams,
            shared.clone(),
            done,
        );

        self.exec.execute_h3_future(H3ClientFuture::Task { task });

        let exchange: Box<dyn Exchange<B>> = {
            let shared = shared.clone();
            let exec = self.exec;
            Box::new(move |request, reservation| {
                client::request::<Q, _, _>(
                    sender.clone(),
                    exec.clone(),
                    shared.clone(),
                    request,
                    reservation,
                )
            })
        };

        Ok((
            SendRequest {
                exchange: Mutex::new(exchange),
                shared: shared.clone(),
            },
            Connection {
                opener,
                shared,
                done: completion,
                completed: false,
                _marker: PhantomData,
            },
        ))
    }
}

// ===== impl Connection =====

impl<Q, B, E> Connection<Q, B, E>
where
    Q: quic::Connection<Bytes>,
    B: Body + 'static,
    E: Http3ClientConnExec<Q>,
    B::Error: Into<BoxError>,
{
    /// Stops admitting requests and waits for existing exchanges to finish.
    /// Accepted request body bytes and FIN must be acknowledged or stopped by the peer.
    /// This only initiates shutdown; await the handle, with a deadline applied
    /// outside, to observe completion.
    pub fn graceful_shutdown(self: Pin<&mut Self>) {
        self.get_mut().shared.shutdown();
    }
}

impl<Q, B, E> Future for Connection<Q, B, E>
where
    Q: quic::Connection<Bytes>,
    B: Body + 'static,
    E: Http3ClientConnExec<Q>,
    B::Error: Into<BoxError>,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Ok(()));
        }
        let result = ready!(Pin::new(&mut this.done).poll(cx));
        this.completed = true;
        Poll::Ready(
            result.unwrap_or_else(|_| {
                Err(Error::new_canceled().with("HTTP/3 connection task dropped"))
            }),
        )
    }
}

impl<Q, B, E> Drop for Connection<Q, B, E>
where
    Q: quic::Connection<Bytes>,
    B: Body + 'static,
    E: Http3ClientConnExec<Q>,
    B::Error: Into<BoxError>,
{
    fn drop(&mut self) {
        if !self.completed {
            self.shared
                .terminate(Error::new_canceled().with("HTTP/3 connection dropped"));
            quic::OpenStreams::close(
                &mut self.opener,
                Code::H3_NO_ERROR.value(),
                b"client connection dropped",
            );
        }
    }
}

// ===== impl HandshakeGuard =====

impl<O> Drop for HandshakeGuard<O>
where
    O: quic::OpenStreams<Bytes>,
{
    fn drop(&mut self) {
        if let Some(opener) = self.0.as_mut() {
            opener.close(Code::H3_NO_ERROR.value(), b"HTTP/3 handshake canceled");
        }
    }
}
