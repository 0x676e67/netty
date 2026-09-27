//! HTTP/3 client connections and request exchanges. The connection task drives
//! control streams, SETTINGS, Datagram routing and graceful shutdown. Requests
//! run in the caller's future; body pipes that outlive the response head and
//! CONNECT tunnels move to the executor.

use std::{
    borrow::Cow,
    future::{pending, poll_fn, Future},
    pin::{pin, Pin},
    sync::Arc,
    task::{ready, Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use futures_util::future::BoxFuture;
use http::{header, HeaderMap, Method, Request, Response, StatusCode};
use http3::{
    client::{RequestStream, SendRequest},
    error::{Code, StreamError},
    ext::Protocol,
    quic, ConnectionState,
};
use http_body::Body;
use http_body_util::combinators::BoxBody;
use pin_project_lite::pin_project;
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use super::{
    body::{PipeGuard, RecvBody},
    shared::{Active, Shared},
    transport::{Stream, Transport},
    upgrade::{self, UpgradeTask},
};
use crate::{
    body::Incoming,
    dispatch::TrySendError,
    error::BoxError,
    ext::OnPreserveHeader,
    proto::headers,
    rt::{self, bounds::Http3ClientConnExec},
    Error, Result,
};
#[cfg(feature = "http3-datagram")]
use crate::{
    conn::http3::datagram::DatagramRequest,
    proto::http3::datagram::{Drive, RequestState},
};

/// Protocol adapter for the send half of a bidirectional QUIC stream.
pub(super) type SendStream<S> = Stream<<S as rt::quic::BidiStream<Bytes>>::SendStream, Bytes>;

/// Protocol adapter for the receive half of a bidirectional QUIC stream.
pub(super) type RecvStream<S> = Stream<<S as rt::quic::BidiStream<Bytes>>::RecvStream, Bytes>;

/// Largest chunk handed to the QUIC send half at once.
pub(super) const CHUNK: usize = 16 * 1024;

/// Send half of a request stream. Dropping it before `finished` resets the
/// send direction, so a completed FIN must set the flag first.
pub(super) struct SendGuard<S>
where
    S: quic::SendStream<Bytes>,
{
    #[cfg(feature = "http3-datagram")]
    pub(super) datagrams: Option<Arc<RequestState>>,
    pub(super) stream: RequestStream<S, Bytes>,
    pub(super) finished: bool,
}

/// Receive half of a request stream. Dropping it before `finished` sends
/// STOP_SENDING with `code`, which defaults to a local cancellation.
pub(super) struct RecvGuard<S>
where
    S: quic::RecvStream,
{
    #[cfg(feature = "http3-datagram")]
    pub(super) datagrams: Option<Arc<RequestState>>,
    pub(super) stream: RequestStream<S, Bytes>,
    pub(super) finished: bool,
    pub(super) code: Code,
}

/// The connection task the executor runs: drives control streams until the
/// connection closes, then reports the outcome to the handle. Dropping it
/// unfinished terminates the connection, so an executor that discards it
/// cannot leave requests waiting.
pub struct ConnTask<Q>
where
    Q: rt::quic::Connection<Bytes>,
{
    #[cfg(feature = "http3-datagram")]
    datagrams: Option<Drive>,
    driver: http3::client::Connection<Transport<Q>, Bytes>,
    opener: Q::OpenStreams,
    shared: Arc<Shared>,
    done: Option<oneshot::Sender<Result<()>>>,
}

impl<Q> Unpin for ConnTask<Q> where Q: rt::quic::Connection<Bytes> {}

pin_project! {
    /// Background work accepted by the HTTP/3 client executor. Requests and
    /// response heads remain in the caller's future.
    #[project = H3ClientFutureProject]
    pub enum H3ClientFuture<Q>
    where
        Q: rt::quic::Connection<Bytes>,
    {
        Task {
            #[pin]
            task: ConnTask<Q>,
        },
        Pipe {
            #[pin]
            pipe: PipeMap<RecvStream<Q::BidiStream>>,
        },
        Upgrade {
            #[pin]
            task: UpgradeTask<SendStream<Q::BidiStream>, RecvStream<Q::BidiStream>>,
        },
    }
}

pin_project! {
    /// Completes a body pipe after response handoff, propagating errors to the
    /// receive half. Dropping it releases sending's share of the admission slot.
    pub struct PipeMap<S>
    where
        S: quic::RecvStream,
    {
        pipe: Option<BoxFuture<'static, Result<()>>>,
        guard: Option<PipeGuard<S>>,
        #[pin]
        invalid: Option<WaitForCancellationFutureOwned>,
    }
}

// ===== impl H3ClientFuture =====

impl<Q> Future for H3ClientFuture<Q>
where
    Q: rt::quic::Connection<Bytes>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.project() {
            H3ClientFutureProject::Task { task } => task.poll(cx),
            H3ClientFutureProject::Pipe { pipe } => pipe.poll(cx),
            H3ClientFutureProject::Upgrade { task } => task.poll(cx),
        }
    }
}

// ===== impl PipeMap =====

impl<S: quic::RecvStream> PipeMap<S> {
    fn new(
        pipe: BoxFuture<'static, Result<()>>,
        guard: PipeGuard<S>,
        invalid: Option<CancellationToken>,
    ) -> Self {
        Self {
            pipe: Some(pipe),
            guard: Some(guard),
            invalid: invalid.map(CancellationToken::cancelled_owned),
        }
    }
}

impl<S: quic::RecvStream> Future for PipeMap<S> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut this = self.project();
        let (Some(pipe), Some(guard)) = (this.pipe.as_mut(), this.guard.as_mut()) else {
            return Poll::Ready(());
        };

        let result = if this
            .invalid
            .as_mut()
            .as_pin_mut()
            .is_some_and(|invalid| invalid.poll(cx).is_ready())
        {
            Err(invalid_datagram_error())
        } else if !guard.watch(cx) {
            Err(Error::new_canceled())
        } else {
            ready!(pipe.as_mut().poll(cx))
        };

        this.invalid.set(None);

        // Reset unfinished sending before the response learns why it failed.
        this.pipe.take();
        if let Err(error) = result {
            guard.fail(error);
        }

        this.guard.take();
        Poll::Ready(())
    }
}

// ===== impl ConnTask =====

impl<Q> ConnTask<Q>
where
    Q: rt::quic::Connection<Bytes>,
{
    /// Wraps the protocol driver and the Datagram driver; `done` reports the
    /// outcome to the handle.
    pub(crate) fn new(
        driver: http3::client::Connection<Transport<Q>, Bytes>,
        opener: Q::OpenStreams,
        #[cfg(feature = "http3-datagram")] datagrams: Option<Drive>,
        shared: Arc<Shared>,
        done: oneshot::Sender<Result<()>>,
    ) -> Self {
        Self {
            #[cfg(feature = "http3-datagram")]
            datagrams,
            driver,
            opener,
            shared,
            done: Some(done),
        }
    }

    /// Reports the outcome; the handle may already be gone.
    fn finish(&mut self, result: Result<()>) -> Poll<()> {
        if let Some(done) = self.done.take() {
            let _ = done.send(result);
        }
        Poll::Ready(())
    }
}

impl<Q> Future for ConnTask<Q>
where
    Q: rt::quic::Connection<Bytes>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.done.is_none() {
            return Poll::Ready(());
        }

        this.shared.register(cx);
        if let Poll::Ready(error) = this.driver.poll_close(cx) {
            let normal = error.is_h3_no_error();
            this.shared.terminate(Error::new_h3(error));
            let result = if normal {
                Ok(())
            } else {
                Err(this.shared.error())
            };
            return this.finish(result);
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
            if let Poll::Ready(result) = datagrams.as_mut().poll(cx) {
                this.datagrams = None;
                if let Err((code, error)) = result {
                    // Publish the cause before transport close wakes exchanges.
                    this.shared.terminate(error);
                    rt::quic::OpenStreams::close(
                        &mut this.opener,
                        code.value(),
                        b"HTTP Datagram driver failed",
                    );
                    let error = this.shared.error();
                    return this.finish(Err(error));
                }
                if let Some(registry) = &this.shared.datagrams {
                    registry.close();
                }
            }
        }

        if ConnectionState::is_closing(&this.driver) {
            this.shared.shutdown();
        }

        // The waker is registered above, so a completion racing this check
        // still wakes the task.
        if this.shared.is_draining() && this.shared.is_idle() {
            rt::quic::OpenStreams::close(&mut this.opener, Code::H3_NO_ERROR.value(), b"");
            this.shared.terminate(Error::new_closed());
            return this.finish(Ok(()));
        }
        Poll::Pending
    }
}

impl<Q> Drop for ConnTask<Q>
where
    Q: rt::quic::Connection<Bytes>,
{
    fn drop(&mut self) {
        if self.done.is_some() {
            self.shared
                .terminate(Error::new_canceled().with("HTTP/3 connection task dropped"));
            rt::quic::OpenStreams::close(
                &mut self.opener,
                Code::H3_NO_ERROR.value(),
                b"connection task dropped",
            );
            let error = self.shared.error();
            let _ = self.finish(Err(error));
        }
    }
}

// ===== impl SendGuard =====

impl<S> Drop for SendGuard<S>
where
    S: quic::SendStream<Bytes>,
{
    fn drop(&mut self) {
        if !self.finished {
            let code = Code::H3_REQUEST_CANCELLED;
            #[cfg(feature = "http3-datagram")]
            let code = if self
                .datagrams
                .as_ref()
                .is_some_and(|d| d.invalid.is_cancelled())
            {
                Code::H3_DATAGRAM_ERROR
            } else {
                code
            };
            self.stream.stop_stream(code);
        }
    }
}

// ===== impl RecvGuard =====

impl<S: quic::RecvStream> Drop for RecvGuard<S> {
    fn drop(&mut self) {
        if !self.finished {
            // Late Datagrams after receive cancellation must be discarded,
            // without canceling the task that still owns the send direction.
            // https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
            #[cfg(feature = "http3-datagram")]
            if let Some(datagrams) = &self.datagrams {
                datagrams.close_recv();
            }
            let code = self.code;
            #[cfg(feature = "http3-datagram")]
            let code = if self
                .datagrams
                .as_ref()
                .is_some_and(|d| d.invalid.is_cancelled())
            {
                Code::H3_DATAGRAM_ERROR
            } else {
                code
            };
            self.stream.stop_sending(code);
        }
    }
}

/// Runs one request. Errors before stream opening is attempted return it;
/// dropping the future before it resolves cancels both directions. `exec`
/// runs body sending that outlives the response head or a CONNECT tunnel.
#[allow(clippy::result_large_err)]
pub(crate) fn request<Q, B, E>(
    mut sender: SendRequest<Transport<Q::OpenStreams>, Bytes>,
    exec: E,
    shared: Arc<Shared>,
    mut request: Request<B>,
    reservation: Option<Active>,
) -> BoxFuture<'static, Result<Response<Incoming>, TrySendError<Request<B>>>>
where
    Q: rt::quic::Connection<Bytes>,
    Q::OpenStreams: Send + 'static,
    Q::BidiStream: rt::quic::BidiStream<Bytes> + Send + 'static,
    <Q::BidiStream as rt::quic::BidiStream<Bytes>>::SendStream: Send + 'static,
    <Q::BidiStream as rt::quic::BidiStream<Bytes>>::RecvStream: Send + 'static,
    <<Q::BidiStream as rt::quic::BidiStream<Bytes>>::RecvStream as rt::quic::RecvStream>::Buf: Send,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http3ClientConnExec<Q> + Send + 'static,
{
    Box::pin(async move {
        let Some(reservation) = reservation else {
            return Err(rejected(
                Error::new_canceled().with("connection closed"),
                request,
            ));
        };

        let connect = request.method() == Method::CONNECT;
        let head = request.method() == Method::HEAD;

        #[cfg(feature = "http3-datagram")]
        let datagram_request = request.extensions().get::<DatagramRequest>().is_some();
        #[cfg(feature = "http3-datagram")]
        if datagram_request
            && (shared.datagrams.is_none()
                || !connect
                || request.extensions().get::<Protocol>().is_none())
        {
            return Err(rejected(
            Error::new_user_invalid_request(
                "Datagram requests require an Extended CONNECT and a Datagram-enabled connection",
            ),
            request,
        ));
        }

        if connect && !request.body().is_end_stream() {
            return Err(rejected(Error::new_user_invalid_connect(), request));
        }

        headers::strip_connection_headers(request.headers_mut(), true);
        let length = match validate_request(&request) {
            Ok(length) => length,
            Err(error) => return Err(rejected(Error::new_user_invalid_request(error), request)),
        };

        if request.extensions().get::<Protocol>().is_some() {
            shared.settings_ready.cancelled().await;
            if !shared
                .peer_extended_connect
                .get()
                .is_some_and(|enabled| *enabled)
            {
                let error = if shared.permits.is_closed() {
                    shared.error()
                } else {
                    Error::new_user_invalid_request("peer did not enable Extended CONNECT")
                };
                return Err(rejected(error, request));
            }
        }

        let length = if length.is_none() && !connect {
            let size = request.body().size_hint().exact();
            if let Some(size) = size {
                if size != 0 || headers::method_has_defined_payload_semantics(request.method()) {
                    headers::set_content_length_if_missing(request.headers_mut(), size);
                }
            }
            size
        } else {
            length
        };

        if request.body().is_end_stream() && length.is_some_and(|n| n != 0) {
            return Err(rejected(
                Error::new_user_body("body shorter than content-length"),
                request,
            ));
        }

        let active = match reservation.admit().await {
            Ok(active) => active,
            Err(error) => return Err(rejected(error, request)),
        };

        let (mut parts, body) = request.into_parts();
        if let Some(header_sort) = parts.extensions.remove::<OnPreserveHeader>() {
            header_sort.call(&mut parts.headers);
        }

        // From here on the request has left the caller, so failures cannot return it.
        let stream = sender
            .send_request(Request::from_parts(parts, ()))
            .await
            .map_err(|error| lost(shared.error_or(Error::new_h3(error))))?;
        if stream.id().into_inner() % 4 != 0 {
            return Err(lost(Error::new_h3(
                "QUIC backend returned a non-client request stream ID",
            )));
        }

        #[cfg(feature = "http3-datagram")]
        let registration = shared.datagrams.as_ref().map(|registry| {
            registry.register(stream.id(), datagram_request, CancellationToken::new())
        });

        #[cfg(feature = "http3-datagram")]
        let datagrams = registration.as_ref().map(|registration| &registration.0);

        #[cfg(feature = "http3-datagram")]
        let invalid = datagrams.as_ref().map(|state| state.invalid.clone());

        #[cfg(not(feature = "http3-datagram"))]
        let invalid: Option<CancellationToken> = None;

        let (send, recv) = stream.split();
        let mut send = SendGuard {
            #[cfg(feature = "http3-datagram")]
            datagrams: datagrams.cloned(),
            stream: send,
            finished: false,
        };

        let mut recv = RecvGuard {
            #[cfg(feature = "http3-datagram")]
            datagrams: datagrams.cloned(),
            stream: recv,
            finished: false,
            code: Code::H3_REQUEST_CANCELLED,
        };

        let mut invalid_watch = pin!(invalid_datagram(invalid.clone()));

        // CONNECT keeps its send direction open for the tunnel, so its head is
        // read before anything is finished.
        let initial_response = if connect {
            let headers = {
                let mut response = pin!(ResponseFutMap { recv: &mut recv });
                poll_fn(|cx| {
                    if let Poll::Ready(error) = invalid_watch.as_mut().poll(cx) {
                        return Poll::Ready(Err(error));
                    }
                    response.as_mut().poll(cx)
                })
                .await
            }
            .map_err(|error| lost(shared.error_or(error)))?;
            if headers.status().is_success() {
                #[cfg(feature = "http3-datagram")]
                let datagrams = match registration {
                    None => upgrade::TunnelDatagrams::Disabled,
                    Some(registration) if datagram_request => {
                        upgrade::TunnelDatagrams::Datagram(registration)
                    }
                    Some(registration) => upgrade::TunnelDatagrams::Ordinary(registration),
                };
                return Ok(upgrade::tunnel::<Q, _>(
                    send,
                    recv,
                    headers,
                    active,
                    #[cfg(feature = "http3-datagram")]
                    datagrams,
                    &exec,
                ));
            }
            Some(headers)
        } else {
            None
        };

        // An empty body finishes inline; its FIN acknowledgment is checked once
        // the head is in, so a drain cannot discard an unacknowledged FIN.
        let mut finished = None;
        let mut pipe = if body.is_end_stream() {
            Finish { send: &mut send }
                .await
                .map_err(|error| lost(shared.error_or(error)))?;
            finished = Some(send);
            None
        } else {
            Some(Box::pin(PipeToSendStream::new(send, body, length))
                as BoxFuture<'static, Result<()>>)
        };

        let mut headers = match initial_response {
            Some(headers) => headers,
            None => {
                let mut response = pin!(ResponseFutMap { recv: &mut recv });
                poll_fn(|cx| {
                    if let Some(pending) = pipe.as_mut() {
                        match pending.as_mut().poll(cx) {
                            Poll::Ready(Ok(())) => pipe = None,
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Pending => {}
                        }
                    }
                    if let Poll::Ready(error) = invalid_watch.as_mut().poll(cx) {
                        return Poll::Ready(Err(error));
                    }
                    response.as_mut().poll(cx)
                })
                .await
                .map_err(|error| lost(shared.error_or(error)))?
            }
        };

        let mut remaining = content_length(headers.headers()).map_err(|error| {
            // A malformed response is a stream error, not a local cancellation.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.2
            recv.code = Code::H3_MESSAGE_ERROR;
            lost(error)
        })?;
        if head
            || matches!(
                headers.status(),
                StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
            )
        {
            remaining = Some(0);
        }
        *headers.version_mut() = http::Version::HTTP_3;

        // The peer's response packet normally carries the acknowledgment of the
        // packet that held HEADERS and FIN; only a late one needs a task.
        if let Some(mut send) = finished.take() {
            if send.finished {
                match send
                    .stream
                    .poll_stopped(&mut Context::from_waker(Waker::noop()))
                {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(error)) => {
                        return Err(lost(shared.error_or(Error::new_h3(error))));
                    }
                    Poll::Pending => {
                        pipe = Some(Box::pin(async move {
                            poll_fn(|cx| send.stream.poll_stopped(cx))
                                .await
                                .map(|_| ())
                                .map_err(Error::new_h3)
                        }));
                    }
                }
            }
        }

        #[cfg(feature = "http3-datagram")]
        let datagrams = datagrams.cloned();
        let body = RecvBody::new(
            recv,
            remaining,
            active,
            #[cfg(feature = "http3-datagram")]
            registration,
            pipe.is_some(),
        );

        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &datagrams {
            body.attach(datagrams);
        }

        if let Some(pipe) = pipe {
            exec.execute_h3_future(H3ClientFuture::Pipe {
                pipe: PipeMap::new(pipe, body.pipe_guard(), invalid),
            });
        }

        Ok(headers.map(|()| Incoming::h3(BoxBody::new(body))))
    })
}

/// Resolves when a Datagram arrives for a request without Datagram semantics.
pub(super) async fn invalid_datagram(invalid: Option<CancellationToken>) -> Error {
    match invalid {
        Some(invalid) => invalid.cancelled().await,
        None => pending().await,
    }
    invalid_datagram_error()
}

/// A Datagram on a request without Datagram semantics is a stream error.
/// https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
pub(super) fn invalid_datagram_error() -> Error {
    Error::new_h3("HTTP Datagram on a request without Datagram semantics")
}

/// Closes the send direction of an empty request body. After a peer STOP_SENDING
/// the guard stays unfinished so dropping it answers with a reset.
struct Finish<'a, S>
where
    S: quic::SendStream<Bytes>,
{
    send: &'a mut SendGuard<S>,
}

// ===== impl Finish =====

impl<S> Future for Finish<'_, S>
where
    S: quic::SendStream<Bytes>,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let send = &mut self.get_mut().send;
        match ready!(send.stream.poll_finish(cx)) {
            Ok(()) => {}
            Err(StreamError::RemoteTerminate { .. }) => return Poll::Ready(Ok(())),
            Err(error) => return Poll::Ready(Err(Error::new_h3(error))),
        }
        send.finished = true;
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &send.datagrams {
            datagrams.close_send();
        }
        Poll::Ready(Ok(()))
    }
}

/// Failure before the request left the caller; the request is returned.
fn rejected<B>(error: Error, request: Request<B>) -> TrySendError<Request<B>> {
    TrySendError {
        error,
        message: Some(request),
    }
}

/// Failure once stream opening has been attempted; the request cannot be returned.
fn lost<B>(error: Error) -> TrySendError<Request<B>> {
    TrySendError {
        error,
        message: None,
    }
}

pin_project! {
    /// Sends a Body through the native HTTP/3 stream, retaining only its current
    /// chunk across polls. Completion includes FIN acknowledgment or peer STOP.
    struct PipeToSendStream<S, B>
    where
        S: quic::SendStream<Bytes>,
        B: Body,
    {
        send: SendGuard<S>,
        #[pin]
        body: B,
        data: Option<B::Data>,
        remaining: Option<u64>,
        trailers_sent: bool,
        finishing: bool,
    }
}

// ===== impl PipeToSendStream =====

impl<S, B> PipeToSendStream<S, B>
where
    S: quic::SendStream<Bytes>,
    B: Body,
{
    fn new(send: SendGuard<S>, body: B, remaining: Option<u64>) -> Self {
        Self {
            send,
            body,
            data: None,
            remaining,
            trailers_sent: false,
            finishing: false,
        }
    }
}

impl<S, B> Future for PipeToSendStream<S, B>
where
    S: quic::SendStream<Bytes>,
    B: Body,
    B::Error: Into<BoxError>,
{
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        if this.send.finished {
            return this
                .send
                .stream
                .poll_stopped(cx)
                .map(|result| result.map(|_| ()).map_err(Error::new_h3));
        }
        for _ in 0..32 {
            if *this.finishing {
                match ready!(this.send.stream.poll_finish(cx)) {
                    Ok(()) => {}
                    Err(StreamError::RemoteTerminate { .. }) => return Poll::Ready(Ok(())),
                    Err(error) => return Poll::Ready(Err(Error::new_h3(error))),
                }
                // FIN is submitted, but admission remains held until it is acknowledged.
                this.send.finished = true;
                #[cfg(feature = "http3-datagram")]
                if let Some(datagrams) = &this.send.datagrams {
                    datagrams.close_send();
                }
                return this
                    .send
                    .stream
                    .poll_stopped(cx)
                    .map(|result| result.map(|_| ()).map_err(Error::new_h3));
            }
            // Check STOP even for an endlessly ready sequence of empty Body frames.
            if let Poll::Ready(result) = this.send.stream.poll_stopped(cx) {
                return Poll::Ready(result.map(|_| ()).map_err(Error::new_h3));
            }
            match ready!(this.send.stream.poll_ready(cx)) {
                Ok(()) => {}
                Err(StreamError::RemoteTerminate { .. }) => return Poll::Ready(Ok(())),
                Err(error) => return Poll::Ready(Err(Error::new_h3(error))),
            }
            if let Some(data) = this.data.as_mut() {
                if data.has_remaining() {
                    let size = data.remaining().min(CHUNK);
                    match this.send.stream.start_send_data(data.copy_to_bytes(size)) {
                        Ok(()) => {}
                        Err(StreamError::RemoteTerminate { .. }) => return Poll::Ready(Ok(())),
                        Err(error) => return Poll::Ready(Err(Error::new_h3(error))),
                    }
                    continue;
                }
                *this.data = None;
            }
            let frame = match ready!(this.body.as_mut().poll_frame(cx)) {
                Some(frame) => frame.map_err(Error::new_user_body)?,
                None => {
                    if this.remaining.is_some_and(|n| n != 0) {
                        return Poll::Ready(Err(Error::new_user_body(
                            "body shorter than content-length",
                        )));
                    }
                    *this.finishing = true;
                    continue;
                }
            };
            if *this.trailers_sent {
                return Poll::Ready(Err(Error::new_user_body("body frame after trailers")));
            }
            match frame.into_data() {
                Ok(data) => {
                    consume_length(this.remaining, data.remaining())
                        .map_err(Error::new_user_body)?;
                    *this.data = Some(data);
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        if this.remaining.is_some_and(|n| n != 0) {
                            return Poll::Ready(Err(Error::new_user_body(
                                "body shorter than content-length",
                            )));
                        }
                        match this.send.stream.start_send_trailers(trailers) {
                            Ok(()) => {}
                            Err(StreamError::RemoteTerminate { .. }) => return Poll::Ready(Ok(())),
                            Err(error) => return Poll::Ready(Err(Error::new_h3(error))),
                        }
                        *this.trailers_sent = true;
                    }
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Reads the final response head, skipping informational responses.
struct ResponseFutMap<'a, S>
where
    S: quic::RecvStream,
{
    recv: &'a mut RecvGuard<S>,
}

// ===== impl ResponseFutMap =====

impl<S> Future for ResponseFutMap<'_, S>
where
    S: quic::RecvStream,
{
    type Output = Result<Response<()>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let recv = &mut self.get_mut().recv;
        for _ in 0..32 {
            let headers = ready!(recv.stream.poll_recv_response(cx)).map_err(Error::new_h3)?;
            if headers.status() == StatusCode::SWITCHING_PROTOCOLS {
                recv.code = Code::H3_MESSAGE_ERROR;
                return Poll::Ready(Err(Error::new_h3("HTTP/3 response cannot use status 101")));
            }
            if !headers.status().is_informational() {
                return Poll::Ready(Ok(headers));
            }
            // Ignore the length on a response without content, but still validate
            // the field syntax. RFC 9114, Section 4.1.2.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.2
            content_length(headers.headers()).inspect_err(|_| {
                recv.code = Code::H3_MESSAGE_ERROR;
            })?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Validates the request and returns its declared Content-Length.
fn validate_request<B>(request: &Request<B>) -> Result<Option<u64>> {
    if request.extensions().get::<Protocol>().is_some() && request.method() != Method::CONNECT {
        return Err(Error::new_h3("Extended CONNECT protocol requires CONNECT"));
    }
    let ordinary_connect =
        request.method() == Method::CONNECT && request.extensions().get::<Protocol>().is_none();
    if request.uri().authority().is_none()
        || (!ordinary_connect && request.uri().scheme().is_none())
    {
        return Err(Error::new_h3(
            "HTTP/3 request requires scheme and authority",
        ));
    }
    // Reject this before the lower layer consumes the request and turns a local
    // header construction error into a connection failure.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1
    if request
        .uri()
        .authority()
        .zip(request.headers().get(header::HOST))
        .is_some_and(|(authority, host)| authority.as_str() != host)
    {
        return Err(Error::new_h3("Host conflicts with HTTP/3 authority"));
    }
    if request
        .headers()
        .get_all(header::TE)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"trailers"))
    {
        return Err(Error::new_h3("HTTP/3 TE must be trailers"));
    }
    content_length(request.headers())
}

/// Parses every Content-Length field, rejecting malformed or conflicting values.
fn content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut length = None;
    for value in headers.get_all(header::CONTENT_LENGTH) {
        let value = value.to_str().map_err(Error::new_h3)?;
        for item in value.split(',') {
            let item = item.trim_matches([' ', '\t']);
            if item.is_empty() || !item.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::new_h3("invalid content-length"));
            }
            let parsed = item.parse::<u64>().map_err(Error::new_h3)?;
            if length.is_some_and(|n| n != parsed) {
                return Err(Error::new_h3("conflicting content-length"));
            }
            length = Some(parsed);
        }
    }
    Ok(length)
}

/// Counts `size` against the declared length.
pub(super) fn consume_length(remaining: &mut Option<u64>, size: usize) -> Result<(), &'static str> {
    if let Some(left) = remaining {
        *left = left
            .checked_sub(u64::try_from(size).map_err(|_| "body size overflow")?)
            .ok_or("body exceeds content-length")?;
    }
    Ok(())
}
