use std::{
    future::poll_fn,
    pin::pin,
    sync::{Arc, OnceLock},
    task::Poll,
};

use bytes::{Buf, Bytes};
use futures_util::{
    future::{select, try_join, Either},
    TryFutureExt,
};
use http::{header, HeaderMap, Method, Request, Response, StatusCode};
use http3::{
    client::{RequestStream, SendRequest},
    error::Code,
    quic,
};
use http_body::Body;

use super::dispatch::{Active, Callback, Shared};
use crate::{
    body::{Incoming, Sender},
    dispatch::{Envelope, TrySendError},
    error::BoxError,
    Error, Result,
};

pub(super) const CHUNK: usize = 16 * 1024;

pub(super) struct Failure {
    error: OnceLock<Arc<Error>>,
    connection: Arc<Shared>,
}

pub(super) struct ResponseGuard<'a, B> {
    pub(super) callback: Option<Callback<B>>,
    pub(super) failure: &'a Failure,
}

pub(super) struct BodyGuard<'a> {
    pub(super) sender: Option<Sender>,
    pub(super) failure: &'a Failure,
}

pub(super) struct SendGuard<S: quic::SendStream<Bytes>> {
    #[cfg(feature = "http3-datagram")]
    pub(super) datagrams: Option<Arc<super::datagram::RequestState>>,
    pub(super) stream: RequestStream<S, Bytes>,
    pub(super) stopped: super::transport::Stopped,
    pub(super) finished: bool,
}

pub(super) struct RecvGuard<S: quic::RecvStream> {
    #[cfg(feature = "http3-datagram")]
    pub(super) datagrams: Option<Arc<super::datagram::RequestState>>,
    pub(super) stream: RequestStream<S, Bytes>,
    pub(super) finished: bool,
    pub(super) code: Code,
}

pub(crate) async fn exchange<O, B>(
    mut sender: SendRequest<O, Bytes>,
    stops: super::transport::Stops,
    envelope: Envelope<Request<B>, Response<Incoming>>,
    active: Active,
) where
    O: quic::OpenStreams<Bytes>,
    O::BidiStream: quic::BidiStream<Bytes>,
    B: Body,
    B::Error: Into<BoxError>,
{
    let (mut request, mut callback) = envelope.into_parts();
    let shared = active.0.clone();
    let failure = Failure {
        error: OnceLock::new(),
        connection: shared.clone(),
    };
    let cancel = callback.take_cancellation();
    let mut response = ResponseGuard {
        callback: Some(callback),
        failure: &failure,
    };
    #[cfg(feature = "http3-datagram")]
    let datagram_cancellation = shared
        .datagrams
        .as_ref()
        .map(|registry| (registry, tokio_util::sync::CancellationToken::new()));
    let work = async {
        let connect = request.method() == Method::CONNECT;
        #[cfg(feature = "http3-datagram")]
        let datagram_request = request
            .extensions()
            .get::<crate::conn::http3::datagram::DatagramRequest>()
            .is_some();
        #[cfg(feature = "http3-datagram")]
        if datagram_request
            && (shared.datagrams.is_none()
                || !connect
                || request.extensions().get::<http3::ext::Protocol>().is_none())
        {
            if let Some(callback) = response.callback.take() {
                callback.send(Err(TrySendError {
                    error: Error::new_user_invalid_request("Datagram requests require an Extended CONNECT and a Datagram-enabled connection"),
                    message: Some(request),
                }));
            }
            return Ok(());
        }
        if connect && !request.body().is_end_stream() {
            if let Some(callback) = response.callback.take() {
                callback.send(Err(TrySendError {
                    error: Error::new_user_invalid_connect(),
                    message: Some(request),
                }));
            }
            return Ok(());
        }
        if let Err(error) = validate_request(&request) {
            if let Some(callback) = response.callback.take() {
                callback.send(Err(TrySendError {
                    error: Error::new_user_invalid_request(error),
                    message: Some(request),
                }));
            }
            return Ok(());
        }
        if request.extensions().get::<http3::ext::Protocol>().is_some() {
            shared.settings_ready.cancelled().await;
            if !shared
                .peer_extended_connect
                .get()
                .is_some_and(|enabled| *enabled)
            {
                if let Some(callback) = response.callback.take() {
                    callback.send(Err(TrySendError {
                        error: Error::new_user_invalid_request(
                            "peer did not enable Extended CONNECT",
                        ),
                        message: Some(request),
                    }));
                }
                return Ok(());
            }
        }
        let length = content_length(request.headers())?;
        let length = if length.is_none() && !connect {
            let size = request.body().size_hint().exact();
            if let Some(size) = size {
                request
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, size.into());
            }
            size
        } else {
            length
        };
        let head = request.method() == Method::HEAD;
        let (parts, body) = request.into_parts();
        let stream = sender
            .send_request(Request::from_parts(parts, ()))
            .await
            .map_err(Error::new_h3)?;
        if stream.id().into_inner() % 4 != 0 {
            return Err(Error::new_h3(
                "QUIC backend returned a non-client request stream ID",
            ));
        }
        let stopped = stops
            .take(stream.id())
            .ok_or_else(|| Error::new_h3("QUIC stop observer missing"))?;
        let transfer = async {
            #[cfg(feature = "http3-datagram")]
            let registration =
                datagram_cancellation
                    .as_ref()
                    .map(|(registry, invalid_datagram)| {
                        registry.register(stream.id(), datagram_request, invalid_datagram.clone())
                    });
            let (send, recv) = stream.split();
            let send = SendGuard {
                #[cfg(feature = "http3-datagram")]
                datagrams: registration.as_ref().map(|r| r.0.clone()),
                stream: send,
                stopped,
                finished: false,
            };
            let mut recv = RecvGuard {
                #[cfg(feature = "http3-datagram")]
                datagrams: registration.as_ref().map(|r| r.0.clone()),
                stream: recv,
                finished: false,
                code: Code::H3_REQUEST_CANCELLED,
            };
            let initial_response = if connect {
                let headers = response_headers(&mut recv).await?;
                if headers.status().is_success() {
                    return super::upgrade::run(
                        send,
                        recv,
                        headers,
                        &mut response,
                        &failure,
                        #[cfg(feature = "http3-datagram")]
                        if datagram_request {
                            registration.as_ref().map(|r| r.0.clone())
                        } else {
                            None
                        },
                    )
                    .await;
                }
                Some(headers)
            } else {
                None
            };
            let upload = upload(send, body, length).map_err(|error| {
                failure.set(error);
                failure.get()
            });
            let download =
                download(recv, &mut response, head, initial_response, &failure).map_err(|error| {
                    failure.set(error);
                    failure.get()
                });
            try_join(upload, download).await.map(|_| ())
        };
        transfer.await
    };
    let stop = async {
        let connection = pin!(shared.closed.cancelled());
        let request = pin!(async {
            if let Some(cancel) = cancel {
                if cancel.await.is_err() {
                    return;
                }
            }
            // Successful response handoff disarms future-drop cancellation.
            // Body and tunnel ownership now govern the remaining exchange.
            std::future::pending::<()>().await;
        });
        let canceled = select(connection, request);
        #[cfg(feature = "http3-datagram")]
        {
            if let Some((_, invalid_datagram)) = &datagram_cancellation {
                let canceled = pin!(canceled);
                let invalid = pin!(invalid_datagram.cancelled());
                let _ = select(canceled, invalid).await;
            } else {
                let _ = canceled.await;
            }
        }
        #[cfg(not(feature = "http3-datagram"))]
        let _ = canceled.await;
    };
    let result = {
        let work = pin!(work);
        let stop = pin!(stop);
        match select(work, stop).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                #[cfg(feature = "http3-datagram")]
                if datagram_cancellation
                    .as_ref()
                    .is_some_and(|(_, invalid_datagram)| invalid_datagram.is_cancelled())
                {
                    failure.set(Error::new_h3(
                        "HTTP Datagram on a request without Datagram semantics",
                    ));
                }
                Err(failure.get())
            }
        }
    };
    if let Err(error) = result {
        failure.set(error);
    }
    // Envelope returns unstarted requests; ResponseGuard covers started tasks.
    drop(response);
    drop(active);
}

async fn upload<S, B>(mut send: SendGuard<S>, body: B, mut remaining: Option<u64>) -> Result<()>
where
    S: quic::SendStream<Bytes>,
    B: Body,
    B::Error: Into<BoxError>,
{
    let mut body = pin!(body);
    let mut trailers_sent = false;
    let mut budget = 0;
    let mut stopped = false;
    while let Some(frame) = poll_fn(|cx| {
        // Check cancellation before Body: continuously ready empty frames never
        // reach the QUIC writer, so checking only on Pending would miss STOP.
        // A complete early response remains valid: RFC 9114, Section 4.1.
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
        if let Poll::Ready(result) = send.stopped.as_mut().poll(cx) {
            stopped = true;
            return Poll::Ready(result.err().map(|error| Err(Error::new_h3(error))));
        }
        body.as_mut()
            .poll_frame(cx)
            .map(|frame| frame.map(|result| result.map_err(Error::new_user_body)))
    })
    .await
    {
        let frame = frame?;
        if trailers_sent {
            return Err(Error::new_user_body("body frame after trailers"));
        }
        match frame.into_data() {
            Ok(mut data) => {
                consume_length(&mut remaining, data.remaining()).map_err(Error::new_user_body)?;
                while data.has_remaining() {
                    let size = data.remaining().min(CHUNK);
                    match send.stream.send_data(data.copy_to_bytes(size)).await {
                        Ok(()) => {}
                        Err(http3::error::StreamError::RemoteTerminate { .. }) => return Ok(()),
                        Err(error) => return Err(Error::new_h3(error)),
                    }
                    cooperate(&mut budget).await;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    if remaining.is_some_and(|n| n != 0) {
                        return Err(Error::new_user_body("body shorter than content-length"));
                    }
                    match send.stream.send_trailers(trailers).await {
                        Ok(()) => {}
                        Err(http3::error::StreamError::RemoteTerminate { .. }) => return Ok(()),
                        Err(error) => return Err(Error::new_h3(error)),
                    }
                    trailers_sent = true;
                }
            }
        }
        cooperate(&mut budget).await;
    }
    if stopped {
        return Ok(());
    }
    if remaining.is_some_and(|n| n != 0) {
        return Err(Error::new_user_body("body shorter than content-length"));
    }
    match send.stream.finish().await {
        Ok(()) => {}
        Err(http3::error::StreamError::RemoteTerminate { .. }) => return Ok(()),
        Err(error) => return Err(Error::new_h3(error)),
    }
    send.finished = true;
    #[cfg(feature = "http3-datagram")]
    if let Some(datagrams) = &send.datagrams {
        datagrams.close_send();
    }
    Ok(())
}

async fn response_headers<S: quic::RecvStream>(recv: &mut RecvGuard<S>) -> Result<Response<()>> {
    let mut budget = 0;
    let headers = loop {
        let headers = recv.stream.recv_response().await.map_err(Error::new_h3)?;
        if headers.status() == StatusCode::SWITCHING_PROTOCOLS {
            recv.code = Code::H3_MESSAGE_ERROR;
            return Err(Error::new_h3("HTTP/3 response cannot use status 101"));
        }
        if !headers.status().is_informational() {
            break headers;
        }
        // Informational responses cannot contain Content-Length, even zero.
        // https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6
        if headers.headers().contains_key(header::CONTENT_LENGTH) {
            recv.code = Code::H3_MESSAGE_ERROR;
            return Err(Error::new_h3(
                "informational response contains content-length",
            ));
        }
        cooperate(&mut budget).await;
    };
    Ok(headers)
}

async fn download<S: quic::RecvStream, B>(
    mut recv: RecvGuard<S>,
    response: &mut ResponseGuard<'_, B>,
    head: bool,
    initial_response: Option<Response<()>>,
    failure: &Failure,
) -> Result<()> {
    let mut budget = 0;
    let mut headers = match initial_response {
        Some(headers) => headers,
        None => response_headers(&mut recv).await?,
    };
    let mut remaining = content_length(headers.headers()).inspect_err(|_| {
        // A malformed response is a stream error, not a local cancellation.
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.2
        recv.code = Code::H3_MESSAGE_ERROR;
    })?;
    if headers.status() == StatusCode::NO_CONTENT && remaining.is_some() {
        recv.code = Code::H3_MESSAGE_ERROR;
        return Err(Error::new_h3("204 response contains content-length"));
    }
    if head
        || matches!(
            headers.status(),
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        )
    {
        remaining = Some(0);
    }
    *headers.version_mut() = http::Version::HTTP_3;
    let (sender, incoming) = Incoming::h3();
    let mut body = BodyGuard {
        sender: Some(sender),
        failure,
    };
    let Some(callback) = response.callback.take() else {
        return Err(Error::new_canceled());
    };
    callback
        .try_send(Ok(headers.map(|()| incoming)))
        .map_err(|_| Error::new_canceled())?;
    let Some(sender) = body.sender.as_mut() else {
        return Err(Error::new_canceled());
    };
    let transfer = async {
        while let Some(mut data) = poll_fn(|cx| {
            if sender.poll_closed(cx).is_ready() {
                return Poll::Ready(Err(Error::new_closed()));
            }
            recv.stream.poll_recv_data(cx).map_err(Error::new_h3)
        })
        .await?
        {
            consume_length(&mut remaining, data.remaining()).map_err(|reason| {
                recv.code = Code::H3_MESSAGE_ERROR;
                Error::new_h3(reason)
            })?;
            while data.has_remaining() {
                poll_fn(|cx| sender.poll_ready(cx)).await?;
                let size = data.remaining().min(CHUNK);
                sender
                    .send_data(data.copy_to_bytes(size))
                    .map_err(|_| Error::new_closed())?;
                cooperate(&mut budget).await;
            }
            cooperate(&mut budget).await;
        }
        if remaining.is_some_and(|n| n != 0) {
            recv.code = Code::H3_MESSAGE_ERROR;
            return Err(Error::new_body("HTTP/3 body shorter than content-length"));
        }
        if let Some(trailers) = poll_fn(|cx| {
            if sender.poll_closed(cx).is_ready() {
                return Poll::Ready(Err(Error::new_closed()));
            }
            recv.stream.poll_recv_trailers(cx).map_err(Error::new_h3)
        })
        .await?
        {
            sender
                .send_trailers(trailers)
                .map_err(|_| Error::new_closed())?;
        }
        recv.finished = true;
        #[cfg(feature = "http3-datagram")]
        if let Some(datagrams) = &recv.datagrams {
            datagrams.close_recv();
        }
        Ok(())
    };
    match transfer.await {
        Err(error) if !error.is_closed() => {
            body.failure.set(error);
            return Err(body.failure.get());
        }
        // Body drop only abandons receiving; request-future cancellation
        // separately stops both directions before response handoff.
        _ => {}
    }
    body.sender.take();
    Ok(())
}

fn validate_request<B>(request: &Request<B>) -> Result<()> {
    if request.extensions().get::<http3::ext::Protocol>().is_some()
        && request.method() != Method::CONNECT
    {
        return Err(Error::new_h3("Extended CONNECT protocol requires CONNECT"));
    }
    let ordinary_connect = request.method() == Method::CONNECT
        && request.extensions().get::<http3::ext::Protocol>().is_none();
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
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ] {
        if request.headers().contains_key(name) {
            return Err(Error::new_h3("connection-specific HTTP/3 header"));
        }
    }
    if request
        .headers()
        .get_all(header::TE)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"trailers"))
    {
        return Err(Error::new_h3("HTTP/3 TE must be trailers"));
    }
    content_length(request.headers())?;
    Ok(())
}

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

fn consume_length(remaining: &mut Option<u64>, size: usize) -> Result<(), &'static str> {
    if let Some(left) = remaining {
        *left = left
            .checked_sub(u64::try_from(size).map_err(|_| "body size overflow")?)
            .ok_or("body exceeds content-length")?;
    }
    Ok(())
}

pub(super) async fn cooperate(budget: &mut usize) {
    *budget += 1;
    if *budget < 32 {
        return;
    }
    *budget = 0;
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

// ===== impl Failure =====

impl Failure {
    pub(super) fn set(&self, error: Error) {
        self.error.get_or_init(|| {
            // Closing QUIC can wake this exchange with a secondary transport
            // error after the driver has already published the actual cause.
            self.connection
                .error
                .get()
                .cloned()
                .unwrap_or_else(|| Arc::new(error))
        });
    }

    pub(super) fn get(&self) -> Error {
        self.error.get().map_or_else(
            || self.connection.error(),
            |e| Error::from_shared(e.clone()),
        )
    }
}

// ===== impl ResponseGuard =====

impl<B> Drop for ResponseGuard<'_, B> {
    fn drop(&mut self) {
        if let Some(callback) = self.callback.take() {
            callback.send(Err(TrySendError {
                error: self.failure.get(),
                message: None,
            }));
        }
    }
}

// ===== impl BodyGuard =====

impl Drop for BodyGuard<'_> {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.as_mut() {
            sender.send_error(self.failure.get());
        }
    }
}

// ===== impl SendGuard =====

impl<S: quic::SendStream<Bytes>> Drop for SendGuard<S> {
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
            // without canceling an upload that still owns the send direction.
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
