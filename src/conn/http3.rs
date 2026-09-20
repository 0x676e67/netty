//! HTTP/3 client connections.

#[cfg(feature = "http3-datagram")]
pub mod datagram;

use std::{
    borrow::Cow,
    future::{poll_fn, Future},
    pin::Pin,
    sync::{atomic::Ordering, Arc},
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use http::{Request, Response};
use http3::{error::Code, ConnectionState};
use http_body::Body;

use crate::{
    body::Incoming,
    dispatch::{self, TrySendError},
    error::BoxError,
    proto::http3::{
        client,
        dispatch::{Active, Shared},
        transport::{Stops, Transport},
        Http3Options,
    },
    rt::{quic, Executor},
    Error, Result,
};

/// The sender side of an established connection.
pub struct SendRequest<B> {
    dispatch: dispatch::UnboundedSender<Request<B>, Response<Incoming>>,
}

/// Drives control streams and request dispatch until the connection closes.
/// Dropping it terminates the QUIC connection and all outstanding exchanges.
#[must_use = "connections must be polled to make progress"]
pub struct Connection<Q: quic::Connection<Bytes>, B, E> {
    #[cfg(feature = "http3-datagram")]
    datagrams: Option<Box<dyn crate::proto::http3::datagram::Drive>>,
    driver: Box<http3::client::Connection<Transport<Q>, Bytes>>,
    sender: http3::client::SendRequest<Transport<Q::OpenStreams>, Bytes>,
    opener: Q::OpenStreams,
    stops: Stops,
    rx: dispatch::Receiver<Request<B>, Response<Incoming>>,
    shared: Arc<Shared>,
    exec: E,
    active_limit: usize,
    completed: bool,
}

/// Configures a single HTTP/3 connection and its request executor.
#[derive(Clone)]
pub struct Builder<E> {
    exec: E,
    options: Http3Options,
}

struct Opening<O: quic::OpenStreams<Bytes>>(Option<O>);

// ===== impl SendRequest =====

impl<B> Clone for SendRequest<B> {
    fn clone(&self) -> Self {
        Self {
            dispatch: self.dispatch.clone(),
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

    /// Waits until the dispatcher is ready; see [`Self::poll_ready`].
    pub async fn ready(&mut self) -> Result<()> {
        poll_fn(|cx| self.poll_ready(cx)).await
    }

    /// Returns a readiness hint; the connection may close before a request is sent.
    pub fn is_ready(&self) -> bool {
        self.dispatch.is_ready()
    }

    /// Whether the connection no longer accepts new requests.
    pub fn is_closed(&self) -> bool {
        self.dispatch.is_closed()
    }

    /// Queues a request, returning it on failures before dispatch starts.
    /// Dropping the returned future cancels only this request. Keep driving the
    /// connection and executor to deliver QUIC reset/stop signals to the peer.
    /// After response handoff, dropping its body stops receiving while an
    /// unfinished upload can continue.
    #[allow(clippy::result_large_err)]
    pub fn try_send_request(
        &mut self,
        request: Request<B>,
    ) -> impl Future<Output = Result<Response<Incoming>, TrySendError<Request<B>>>> {
        let sent = self.dispatch.try_send_cancelable(request);
        async move {
            match sent {
                Ok((response, consumed)) => {
                    let result = response.await.unwrap_or_else(|_| {
                        Err(TrySendError {
                            error: Error::new_canceled(),
                            message: None,
                        })
                    });
                    // Keep cancellation alive until the caller receives the response,
                    // even if its body has already reached FIN in the callback.
                    let _ = consumed.send(());
                    result
                }
                Err(request) => Err(TrySendError {
                    error: Error::new_canceled().with("connection was not ready"),
                    message: Some(request),
                }),
            }
        }
    }
}

// ===== impl Builder =====

impl<E> Builder<E> {
    /// Creates a builder using the supplied executor for request exchanges.
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
    /// The returned driver must run for requests, SETTINGS and QPACK to progress.
    pub async fn handshake<Q, B>(self, quic: Q) -> Result<(SendRequest<B>, Connection<Q, B, E>)>
    where
        Q: quic::Connection<Bytes>,
        Q::OpenStreams: Clone + Send + 'static,
        Q::BidiStream: quic::BidiStream<Bytes> + Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send,
        <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send,
        <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        E: Executor<Pin<Box<dyn Future<Output = ()> + Send>>>,
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
        <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send,
        <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send,
        <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        E: Executor<Pin<Box<dyn Future<Output = ()> + Send>>>,
    {
        let Some((sender, receiver)) = quic.take_datagrams() else {
            return Err(Error::new_h3("QUIC Datagram reader already taken"));
        };
        let datagrams = crate::proto::http3::datagram::Registry::new(sender, receiver);
        self.handshake_inner(quic, Some(datagrams)).await
    }

    async fn handshake_inner<Q, B>(
        self,
        quic: Q,
        #[cfg(feature = "http3-datagram")] datagrams: Option<(
            Arc<crate::proto::http3::datagram::Registry>,
            Box<dyn crate::proto::http3::datagram::Drive>,
        )>,
    ) -> Result<(SendRequest<B>, Connection<Q, B, E>)>
    where
        Q: quic::Connection<Bytes>,
        Q::OpenStreams: Clone + Send + 'static,
        Q::BidiStream: quic::BidiStream<Bytes> + Send + 'static,
        <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send,
        <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send,
        <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
        E: Executor<Pin<Box<dyn Future<Output = ()> + Send>>>,
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
        let mut opening = Opening(Some(quic.opener()));
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
        let stops = Stops::default();
        let (driver, sender) = builder
            .build(Transport(quic, stops.clone()))
            .await
            .map_err(Error::new_h3)?;
        #[cfg(feature = "http3-datagram")]
        let (registry, datagrams) = datagrams.map_or((None, None), |(r, d)| (Some(r), Some(d)));
        let shared = Shared::new(
            #[cfg(feature = "http3-datagram")]
            registry,
        );
        let (tx, rx) = dispatch::channel();
        Ok((
            SendRequest {
                dispatch: tx.unbound(),
            },
            Connection {
                driver: Box::new(driver),
                sender,
                stops,
                opener: opening.0.take().ok_or_else(Error::new_canceled)?,
                #[cfg(feature = "http3-datagram")]
                datagrams,
                rx,
                shared,
                exec: self.exec,
                active_limit: opts.max_concurrent_requests,
                completed: false,
            },
        ))
    }
}

// ===== impl Connection =====

impl<Q: quic::Connection<Bytes>, B, E> Connection<Q, B, E> {
    /// Stops admitting requests and waits for existing exchanges to finish.
    /// This only initiates shutdown. Continue polling; apply a deadline outside.
    pub fn graceful_shutdown(self: Pin<&mut Self>)
    where
        Self: Unpin,
    {
        let this = self.get_mut();
        this.shared.drain();
        this.cancel_queued();
    }

    fn cancel_queued(&mut self) {
        self.rx.close();
        while let Some((request, callback)) = self.rx.try_recv() {
            callback.send(Err(TrySendError {
                error: Error::new_canceled().with("connection closed"),
                message: Some(request),
            }));
        }
    }
}

impl<Q, B, E> Future for Connection<Q, B, E>
where
    Q: quic::Connection<Bytes>,
    Q::OpenStreams: Clone + Send + Unpin + 'static,
    Q::BidiStream: quic::BidiStream<Bytes> + Send + 'static,
    <Q::BidiStream as quic::BidiStream<Bytes>>::SendStream: Send,
    <Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream: Send,
    <<Q::BidiStream as quic::BidiStream<Bytes>>::RecvStream as quic::RecvStream>::Buf: Send,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Executor<Pin<Box<dyn Future<Output = ()> + Send>>> + Unpin,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Ok(()));
        }
        this.shared.register(cx);
        if let Poll::Ready(error) = this.driver.poll_close(cx) {
            let normal = error.is_h3_no_error();
            this.shared.terminate(Error::new_h3(error));
            this.completed = true;
            this.cancel_queued();
            return Poll::Ready(if normal {
                Ok(())
            } else {
                Err(this.shared.error())
            });
        }
        if this.shared.peer_extended_connect.get().is_none() {
            // Borrowed settings come from the received SETTINGS frame; Owned
            // values are protocol defaults before peer negotiation completes.
            if let Cow::Borrowed(settings) = this.driver.settings() {
                #[cfg(feature = "http3-datagram")]
                if let Some(datagrams) = &this.shared.datagrams {
                    datagrams.negotiated(settings.enable_datagram());
                }
                let _ = this
                    .shared
                    .peer_extended_connect
                    .set(settings.enable_extended_connect());
                this.shared.settings_ready.cancel();
            }
        }
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &mut this.datagrams {
            if let Poll::Ready(result) = datagrams.poll(cx) {
                this.datagrams = None;
                if let Err((code, error)) = result {
                    // Publish the cause before transport close wakes exchanges.
                    this.shared.terminate(error);
                    quic::OpenStreams::close(
                        &mut this.opener,
                        code.value(),
                        b"HTTP Datagram driver failed",
                    );
                    this.completed = true;
                    this.cancel_queued();
                    return Poll::Ready(Err(this.shared.error()));
                }
                if let Some(registry) = &this.shared.datagrams {
                    registry.close();
                }
            }
        }
        if ConnectionState::is_closing(this.driver.as_ref()) || this.rx.is_closed() {
            this.shared.drain();
        }
        if this.shared.draining.load(Ordering::Acquire) {
            this.cancel_queued();
            this.shared.active_waker.register(cx.waker());
            if this.shared.active.load(Ordering::Acquire) == 0 {
                quic::OpenStreams::close(&mut this.opener, Code::H3_NO_ERROR.value(), b"");
                this.shared.terminate(Error::new_closed());
                this.completed = true;
                return Poll::Ready(Ok(()));
            }
            return Poll::Pending;
        }
        for _ in 0..32 {
            if this.shared.active.load(Ordering::Acquire) >= this.active_limit {
                // Register only while admission needs a completion, then check
                // again so a completion racing registration cannot be missed.
                this.shared.active_waker.register(cx.waker());
                if this.shared.active.load(Ordering::Acquire) >= this.active_limit {
                    return Poll::Pending;
                }
            }
            match ready!(this.rx.poll_recv(cx)) {
                Some((request, callback)) => {
                    if callback.is_canceled() {
                        continue;
                    }
                    this.shared.active.fetch_add(1, Ordering::AcqRel);
                    let active = Active(this.shared.clone());
                    this.exec.execute(Box::pin(client::exchange(
                        this.sender.clone(),
                        this.stops.clone(),
                        dispatch::Envelope::new(request, callback),
                        active,
                    )));
                }
                None => {
                    this.shared.drain();
                    return Poll::Pending;
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<Q: quic::Connection<Bytes>, B, E> Drop for Connection<Q, B, E> {
    fn drop(&mut self) {
        if !self.completed {
            self.shared
                .terminate(Error::new_canceled().with("HTTP/3 driver dropped"));
            quic::OpenStreams::close(
                &mut self.opener,
                Code::H3_NO_ERROR.value(),
                b"client driver dropped",
            );
        }
    }
}

// ===== impl Opening =====

impl<O: quic::OpenStreams<Bytes>> Drop for Opening<O> {
    fn drop(&mut self) {
        if let Some(opener) = self.0.as_mut() {
            opener.close(Code::H3_NO_ERROR.value(), b"HTTP/3 handshake canceled");
        }
    }
}
