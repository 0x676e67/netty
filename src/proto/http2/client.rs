use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures_channel::{
    mpsc,
    mpsc::{Receiver, Sender},
    oneshot,
};
use futures_util::{
    future::{Either, FusedFuture},
    stream::{FusedStream, Stream},
    task::AtomicWaker,
};
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use http2::{
    SendStream,
    client::{Builder, Connection, ResponseFuture, SendRequest},
    ext::Protocol,
};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    PipeToSendStream, SendBuf, ping,
    ping::{Ponger, Recorder},
};
use crate::{
    Error, Result,
    body::{self, Incoming},
    dispatch::{self, Callback, Envelope, SendWhen, TrySendError},
    error::BoxError,
    ext::OnPreserveHeader,
    proto::{Dispatched, headers},
    rt::{
        Time,
        bounds::{Http2ClientConnExec, Http2UpgradedExec},
    },
    upgrade::{self, Upgraded},
};

/// Receiver for HTTP/2 client requests
type ClientRx<B> = dispatch::Receiver<Request<B>, Response<Incoming>>;

///// An mpsc channel is used to help notify the `Connection` task when *all*
///// other handles to it have been dropped, so that it can shutdown.
type ConnDropRef = mpsc::Sender<Infallible>;

///// A oneshot channel watches the `Connection` task, and when it completes,
///// the "dispatch" task will be notified and can shutdown sooner.
type ConnEof = oneshot::Receiver<Infallible>;

pub(crate) async fn handshake<T, B, E>(
    io: T,
    req_rx: ClientRx<B>,
    builder: Builder,
    ping_config: ping::Config,
    mut exec: E,
    timer: Time,
) -> Result<ClientTask<B, E, T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Body + 'static,
    B::Data: Send + 'static,
    E: Http2ClientConnExec<B, T> + Unpin,
    B::Error: Into<BoxError>,
{
    let (h2_tx, mut conn) = builder
        .handshake::<_, SendBuf<B::Data>>(io)
        .await
        .map_err(Error::new_h2)?;

    // An mpsc channel is used entirely to detect when the
    // 'Client' has been dropped. This is to get around a bug
    // in h2 where dropping all SendRequests won't notify a
    // parked Connection.
    let (conn_drop_ref, conn_drop_rx) = mpsc::channel(1);
    let (cancel_tx, conn_eof) = oneshot::channel();

    let (conn, ping) = if ping_config.is_enabled() {
        let pp = conn.ping_pong().expect("conn.ping_pong");
        let (recorder, ponger) = ping::channel(pp, ping_config, timer);

        let conn: Conn<_, B> = Conn { ponger, conn };
        (Either::Left(conn), recorder)
    } else {
        (Either::Right(conn), ping::Recorder::disabled())
    };
    let conn: ConnMapErr<T, B> = ConnMapErr {
        conn,
        is_terminated: false,
    };
    let peer = Arc::new(PeerSettings::new());

    exec.execute_h2_future(H2ClientFuture::Task {
        task: ConnTask::new(conn, conn_drop_rx, cancel_tx, peer.clone()),
    });

    Ok(ClientTask {
        ping,
        conn_drop_ref,
        conn_eof,
        executor: exec,
        gate: ConnectGate::new(peer),
        h2_tx,
        req_rx,
        fut_ctx: None,
        marker: PhantomData,
    })
}

pin_project! {
    struct Conn<T, B>
    where
        B: Body,
    {
        #[pin]
        ponger: Ponger,
        #[pin]
        conn: Connection<T, SendBuf<<B as Body>::Data>>,
    }
}

impl<T, B> Future for Conn<T, B>
where
    B: Body,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), http2::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        match this.ponger.poll(cx) {
            Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                this.conn.set_target_window_size(wnd);
                this.conn.set_initial_window_size(wnd)?;
            }
            Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                debug!("connection keep-alive timed out");
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }

        Pin::new(&mut this.conn).poll(cx)
    }
}

pin_project! {
    struct ConnMapErr<T, B>
    where
        B: Body,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
    {
        #[pin]
        conn: Either<Conn<T, B>, Connection<T, SendBuf<<B as Body>::Data>>>,
        #[pin]
        is_terminated: bool,
    }
}

impl<T, B> Future for ConnMapErr<T, B>
where
    B: Body,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if *this.is_terminated {
            return Poll::Pending;
        }
        let polled = this.conn.poll(cx);
        if polled.is_ready() {
            *this.is_terminated = true;
        }
        polled.map_err(|_e| {
            debug!(error = %_e, "connection error");
        })
    }
}

impl<T, B> ConnMapErr<T, B>
where
    B: Body,
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn extended_connect_protocol(&self) -> Option<bool> {
        match &self.conn {
            Either::Left(conn) => conn.conn.extended_connect_protocol(),
            Either::Right(conn) => conn.extended_connect_protocol(),
        }
    }
}

impl<T, B> FusedFuture for ConnMapErr<T, B>
where
    B: Body,
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn is_terminated(&self) -> bool {
        self.is_terminated
    }
}

/// Server SETTINGS published by the connection task, the only writer.
///
/// The dispatcher is the only waiter, and senders read it without locking.
pub(crate) struct PeerSettings {
    extended_connect: AtomicU8,
    waker: AtomicWaker,
}

// ===== impl PeerSettings =====

impl PeerSettings {
    const UNKNOWN: u8 = 0;
    const DISABLED: u8 = 1;
    const ENABLED: u8 = 2;

    fn new() -> Self {
        Self {
            extended_connect: AtomicU8::new(Self::UNKNOWN),
            waker: AtomicWaker::new(),
        }
    }

    /// Returns whether the server enabled extended CONNECT, or `None` before its SETTINGS.
    pub(crate) fn extended_connect(&self) -> Option<bool> {
        match self.extended_connect.load(Ordering::Acquire) {
            Self::ENABLED => Some(true),
            Self::DISABLED => Some(false),
            _ => None,
        }
    }

    fn publish(&self, enabled: bool) {
        let state = if enabled {
            Self::ENABLED
        } else {
            Self::DISABLED
        };
        self.extended_connect.store(state, Ordering::Release);
        self.waker.wake();
    }

    /// Polls until the server's SETTINGS are known, registering the dispatcher.
    fn poll_extended_connect(&self, cx: &mut Context<'_>) -> Poll<bool> {
        if let Some(enabled) = self.extended_connect() {
            return Poll::Ready(enabled);
        }
        self.waker.register(cx.waker());
        // Recheck so a publish between the load and the registration is not missed.
        match self.extended_connect() {
            Some(enabled) => Poll::Ready(enabled),
            None => Poll::Pending,
        }
    }
}

/// A request and the callback that completes it.
type Pending<B> = (Request<B>, Callback<Request<B>, Response<Incoming>>);

/// Holds extended CONNECT requests until the server's SETTINGS allow or refuse them
/// ([RFC 8441 §3](https://www.rfc-editor.org/rfc/rfc8441#section-3)).
///
/// Only the dispatcher uses it. Refusing needs no stream capacity, so it settles before
/// the dispatcher waits to open a stream; admitted requests take the normal send path.
struct ConnectGate<B> {
    peer: Arc<PeerSettings>,
    parked: VecDeque<Envelope<Request<B>, Response<Incoming>>>,
}

// ===== impl ConnectGate =====

impl<B> ConnectGate<B> {
    fn new(peer: Arc<PeerSettings>) -> Self {
        Self {
            peer,
            parked: VecDeque::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.parked.is_empty()
    }

    /// Lets a request through, or parks or refuses an extended CONNECT.
    fn admit(
        &mut self,
        req: Request<B>,
        cb: Callback<Request<B>, Response<Incoming>>,
        cx: &mut Context<'_>,
    ) -> Option<Pending<B>> {
        if req.extensions().get::<Protocol>().is_none() {
            return Some((req, cb));
        }
        match self.peer.poll_extended_connect(cx) {
            Poll::Ready(true) => Some((req, cb)),
            Poll::Ready(false) => {
                cb.send(Err(refused(req)));
                None
            }
            // A connection that ends first returns parked requests unsent.
            Poll::Pending => {
                trace!("extended CONNECT waits for peer SETTINGS");
                self.parked.push_back(Envelope::new(req, cb));
                None
            }
        }
    }

    /// Refuses parked requests once the server is known not to support the protocol,
    /// and drops callers that stopped waiting while that is still unknown.
    fn poll_settle(&mut self, cx: &mut Context<'_>) {
        if self.parked.is_empty() {
            return;
        }
        match self.peer.poll_extended_connect(cx) {
            Poll::Ready(true) => {}
            Poll::Ready(false) => {
                for mut parked in self.parked.drain(..) {
                    if let Some((req, cb)) = parked.take() {
                        cb.send(Err(refused(req)));
                    }
                }
            }
            Poll::Pending => self
                .parked
                .retain_mut(|parked| parked.poll_canceled(cx).is_pending()),
        }
    }

    /// Takes the oldest parked request once the server enabled the protocol.
    fn pop_enabled(&mut self) -> Option<Pending<B>> {
        if self.peer.extended_connect() != Some(true) {
            return None;
        }
        self.parked.pop_front().and_then(|mut parked| parked.take())
    }

    /// Returns parked requests unsent, keeping the connection failure as their cause.
    fn release(&mut self, err: &::http2::Error) {
        for mut parked in self.parked.drain(..) {
            let Some((req, cb)) = parked.take() else {
                continue;
            };
            // `http2::Error` is not `Clone`; rebuild the protocol reason or I/O kind.
            let error = match (err.reason(), err.get_io()) {
                (Some(reason), _) => Error::new_canceled().with(::http2::Error::from(reason)),
                (None, Some(io)) => {
                    Error::new_canceled().with(std::io::Error::new(io.kind(), io.to_string()))
                }
                (None, None) => Error::new_canceled().with(err.to_string()),
            };
            cb.send(Err(TrySendError {
                error,
                message: Some(req),
            }));
        }
    }
}

/// Rejects extended CONNECT to a server that did not enable it.
fn refused<B>(req: Request<B>) -> TrySendError<Request<B>> {
    debug!("peer did not enable extended CONNECT");
    TrySendError {
        error: Error::new_user_invalid_request("peer did not enable Extended CONNECT"),
        message: Some(req),
    }
}

pin_project! {
    pub struct ConnTask<T, B>
    where
        B: Body,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
    {
        #[pin]
        drop_rx: Receiver<Infallible>,
        #[pin]
        cancel_tx: Option<oneshot::Sender<Infallible>>,
        #[pin]
        conn: ConnMapErr<T, B>,
        peer: Arc<PeerSettings>,
    }
}

impl<T, B> ConnTask<T, B>
where
    B: Body,
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn new(
        conn: ConnMapErr<T, B>,
        drop_rx: Receiver<Infallible>,
        cancel_tx: oneshot::Sender<Infallible>,
        peer: Arc<PeerSettings>,
    ) -> Self {
        Self {
            drop_rx,
            cancel_tx: Some(cancel_tx),
            conn,
            peer,
        }
    }
}

impl<T, B> Future for ConnTask<T, B>
where
    B: Body,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        let finished = !this.conn.is_terminated() && Pin::new(&mut this.conn).poll(cx).is_ready();

        // The driver applies the server's SETTINGS while polled, possibly in its final poll;
        // this task is the only writer, so only changes are published.
        if let Some(enabled) = this.conn.extended_connect_protocol()
            && this.peer.extended_connect() != Some(enabled)
        {
            this.peer.publish(enabled);
        }

        if finished {
            // ok or err, the `conn` has finished.
            return Poll::Ready(());
        }

        if !this.drop_rx.is_terminated() && Pin::new(&mut this.drop_rx).poll_next(cx).is_ready() {
            // mpsc has been dropped, hopefully polling
            // the connection some more should start shutdown
            // and then close.
            trace!("send_request dropped, starting conn shutdown");
            drop(this.cancel_tx.take().expect("ConnTask Future polled twice"));
        }

        Poll::Pending
    }
}

pin_project! {
    #[project = H2ClientFutureProject]
    pub enum H2ClientFuture<B, T, E>
    where
        B: http_body::Body,
        B: 'static,
        B::Error: Into<BoxError>,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
    {
        Pipe {
            #[pin]
            pipe: PipeMap<B>,
        },
        Send {
            #[pin]
            send_when: SendWhen<B, E>,
        },
        Task {
            #[pin]
            task: ConnTask<T, B>,
        },
    }
}

impl<B, T, E> Future for H2ClientFuture<B, T, E>
where
    B: Body + 'static,
    B::Error: Into<BoxError>,
    E: Http2UpgradedExec<B::Data>,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this {
            H2ClientFutureProject::Pipe { pipe } => pipe.poll(cx),
            H2ClientFutureProject::Send { send_when } => send_when.poll(cx),
            H2ClientFutureProject::Task { task } => task.poll(cx),
        }
    }
}

struct FutCtx<B>
where
    B: Body,
{
    is_connect: bool,
    eos: bool,
    fut: ResponseFuture,
    body_tx: SendStream<SendBuf<B::Data>>,
    body: B,
    cb: Callback<Request<B>, Response<Incoming>>,
}

impl<B: Body> Unpin for FutCtx<B> {}

pub(crate) struct ClientTask<B, E, T>
where
    B: Body,
    E: Unpin,
{
    ping: ping::Recorder,
    conn_drop_ref: ConnDropRef,
    conn_eof: ConnEof,
    executor: E,
    /// Extended CONNECT requests waiting on the server's SETTINGS.
    gate: ConnectGate<B>,
    h2_tx: SendRequest<SendBuf<B::Data>>,
    req_rx: ClientRx<B>,
    fut_ctx: Option<FutCtx<B>>,
    marker: PhantomData<T>,
}

pin_project! {
    pub struct PipeMap<S>
    where
        S: Body,
    {
        #[pin]
        pipe: PipeToSendStream<S>,
        #[pin]
        conn_drop_ref: Option<Sender<Infallible>>,
        #[pin]
        ping: Option<Recorder>,
        cancel_rx: Option<oneshot::Receiver<()>>,
    }
}

impl<B> Future for PipeMap<B>
where
    B: http_body::Body,
    B::Error: Into<BoxError>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        const EXPECT_TAKEN_ONCE_MSG: &str = "Future polled twice";

        let mut this = self.project();

        // Check if the client cancelled the request (e.g. dropped the
        // response future due to a timeout). If so, reset the h2 stream
        // so that a RST_STREAM is sent and flow-control capacity is freed.
        match this.cancel_rx.as_mut().map(|rx| Pin::new(rx).poll(cx)) {
            Some(Poll::Ready(Ok(()))) => {
                debug!("client request body send cancelled, resetting stream");
                this.pipe.as_mut().send_reset(http2::Reason::CANCEL);
                this.conn_drop_ref.take().expect(EXPECT_TAKEN_ONCE_MSG);
                this.ping.take().expect(EXPECT_TAKEN_ONCE_MSG);
                return Poll::Ready(());
            }
            Some(Poll::Ready(Err(_))) => {
                // Sender dropped without cancelling (normal response or error).
                // Stop polling the receiver.
                *this.cancel_rx = None;
            }
            Some(Poll::Pending) | None => {}
        }

        match Pin::new(&mut this.pipe).poll(cx) {
            Poll::Ready(result) => {
                if let Err(_e) = result {
                    debug!("client request body error: {}", _e);
                }
                drop(this.conn_drop_ref.take().expect(EXPECT_TAKEN_ONCE_MSG));
                drop(this.ping.take().expect(EXPECT_TAKEN_ONCE_MSG));
                return Poll::Ready(());
            }
            Poll::Pending => (),
        };
        Poll::Pending
    }
}

impl<B, E, T> ClientTask<B, E, T>
where
    B: Body + 'static + Unpin,
    B::Data: Send,
    E: Http2ClientConnExec<B, T> + Unpin,
    B::Error: Into<BoxError>,
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_pipe(&mut self, f: FutCtx<B>, cx: &mut Context<'_>) {
        let ping = self.ping.clone();

        // A one-shot channel so that send_task can tell pipe_task to
        // reset the stream when the client cancels the request.
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        let send_stream = if !f.is_connect {
            if !f.eos {
                let mut pipe = PipeToSendStream::new(f.body, f.body_tx);

                // eagerly see if the body pipe is ready and
                // can thus skip allocating in the executor
                match Pin::new(&mut pipe).poll(cx) {
                    Poll::Ready(_) => (),
                    Poll::Pending => {
                        let conn_drop_ref = self.conn_drop_ref.clone();
                        // keep the ping recorder's knowledge of an
                        // "open stream" alive while this body is
                        // still sending...
                        let ping = ping.clone();

                        let pipe = PipeMap {
                            pipe,
                            conn_drop_ref: Some(conn_drop_ref),
                            ping: Some(ping),
                            cancel_rx: Some(cancel_rx),
                        };
                        // Clear send task
                        self.executor
                            .execute_h2_future(H2ClientFuture::Pipe { pipe });
                    }
                }
            }

            None
        } else {
            Some(f.body_tx)
        };

        self.executor.execute_h2_future(H2ClientFuture::Send {
            send_when: SendWhen {
                when: ResponseFutMap {
                    fut: f.fut,
                    ping: Some(ping),
                    send_stream: Some(send_stream),
                    cancel_tx: Some(cancel_tx),
                    exec: self.executor.clone(),
                },
                call_back: Some(f.cb),
            },
        });
    }
}

impl<B, E, T> ClientTask<B, E, T>
where
    B: Body + 'static,
    E: Http2ClientConnExec<B, T> + Unpin,
    B::Error: Into<BoxError>,
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.gate.peer.extended_connect() == Some(true)
    }

    pub(crate) fn peer_settings(&self) -> Arc<PeerSettings> {
        self.gate.peer.clone()
    }

    pub(crate) fn current_max_send_streams(&self) -> usize {
        self.h2_tx.current_max_send_streams()
    }

    pub(crate) fn current_max_recv_streams(&self) -> usize {
        self.h2_tx.current_max_recv_streams()
    }
}

pin_project! {
    pub(crate) struct ResponseFutMap<B, E>
    where
        B: Body,
        B: 'static,
    {
        #[pin]
        fut: ResponseFuture,
        #[pin]
        ping: Option<Recorder>,
        #[pin]
        send_stream: Option<Option<SendStream<SendBuf<<B as Body>::Data>>>>,
        cancel_tx: Option<oneshot::Sender<()>>,
        exec: E,
    }
}

impl<B: Body + 'static, E> ResponseFutMap<B, E> {
    /// Signal the pipe_task to reset the stream (e.g. on client cancellation).
    pub(crate) fn cancel(self: Pin<&mut Self>) {
        if let Some(cancel_tx) = self.project().cancel_tx.take() {
            let _ = cancel_tx.send(());
        }
    }
}

impl<B, E> Future for ResponseFutMap<B, E>
where
    B: Body + 'static,
    E: Http2UpgradedExec<B::Data>,
{
    type Output = Result<Response<body::Incoming>, (Error, Option<Request<B>>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        let result = ready!(this.fut.poll(cx));

        let ping = this.ping.take().expect("Future polled twice");
        let send_stream = this.send_stream.take().expect("Future polled twice");

        match result {
            Ok(res) => {
                // record that we got the response headers
                ping.record_non_data();

                let content_length = headers::content_length_parse_all(res.headers());
                if let (Some(mut send_stream), StatusCode::OK) = (send_stream, res.status()) {
                    if content_length.is_some_and(|len| len != 0) {
                        warn!("h2 connect response with non-zero body not supported");

                        send_stream.send_reset(http2::Reason::INTERNAL_ERROR);
                        return Poll::Ready(Err((
                            Error::new_h2(http2::Reason::INTERNAL_ERROR.into()),
                            None::<Request<B>>,
                        )));
                    }
                    let (parts, recv_stream) = res.into_parts();
                    let mut res = Response::from_parts(parts, Incoming::empty());

                    let (pending, on_upgrade) = upgrade::pending();
                    let (io, task) = super::upgrade::pair(send_stream, recv_stream, ping);
                    this.exec.execute_upgrade(task);
                    let upgraded = Upgraded::new(io, Bytes::new());

                    pending.fulfill(upgraded);
                    res.extensions_mut().insert(on_upgrade);

                    Poll::Ready(Ok(res))
                } else {
                    let res = res.map(|stream| {
                        let ping = ping.for_stream(&stream);
                        Incoming::h2(stream, content_length.into(), ping)
                    });
                    Poll::Ready(Ok(res))
                }
            }
            Err(err) => {
                ping.ensure_not_timed_out().map_err(|e| (e, None))?;

                debug!("client response error: {}", err);
                Poll::Ready(Err((Error::new_h2(err), None::<Request<B>>)))
            }
        }
    }
}

impl<B, E, T> Future for ClientTask<B, E, T>
where
    B: Body + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http2ClientConnExec<B, T> + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Refusals need no stream capacity, so they must not wait behind open backpressure.
            self.gate.poll_settle(cx);

            match ready!(self.h2_tx.poll_ready(cx)) {
                Ok(()) => (),
                Err(err) => {
                    self.ping.ensure_not_timed_out()?;
                    self.gate.release(&err);
                    return if err.reason() == Some(::http2::Reason::NO_ERROR) {
                        trace!("connection gracefully shutdown");
                        Poll::Ready(Ok(Dispatched::Shutdown))
                    } else {
                        Poll::Ready(Err(Error::new_h2(err)))
                    };
                }
            };

            // If we were waiting on pending open
            // continue where we left off.
            if let Some(f) = self.fut_ctx.take() {
                self.poll_pipe(f, cx);
                continue;
            }

            let next = match self.gate.pop_enabled() {
                Some(parked) => Poll::Ready(Some(parked)),
                // Parked requests keep dispatch alive after every sender is dropped.
                None => match self.req_rx.poll_recv(cx) {
                    Poll::Ready(None) if !self.gate.is_empty() => Poll::Pending,
                    next => next,
                },
            };
            match next {
                Poll::Ready(Some((req, cb))) => {
                    // Check that future hasn't been canceled already
                    if cb.is_canceled() {
                        trace!("request callback is canceled");
                        continue;
                    }
                    let Some((req, cb)) = self.gate.admit(req, cb, cx) else {
                        continue;
                    };
                    let (head, body) = req.into_parts();
                    let mut req = ::http::Request::from_parts(head, ());
                    headers::strip_connection_headers(req.headers_mut(), true);
                    if let Some(len) = body.size_hint().exact()
                        && (len != 0 || headers::method_has_defined_payload_semantics(req.method()))
                    {
                        headers::set_content_length_if_missing(req.headers_mut(), len);
                    }

                    // Sort headers
                    if let Some(header_sort) = req.extensions_mut().remove::<OnPreserveHeader>() {
                        header_sort.call(req.headers_mut());
                    }

                    let is_connect = req.method() == Method::CONNECT;
                    let eos = body.is_end_stream();

                    if is_connect
                        && headers::content_length_parse_all(req.headers())
                            .is_some_and(|len| len != 0)
                    {
                        debug!("h2 connect request with non-zero body not supported");
                        cb.send(Err(TrySendError {
                            error: Error::new_user_invalid_connect(),
                            message: None,
                        }));
                        continue;
                    }

                    let (fut, body_tx) = match self.h2_tx.send_request(req, !is_connect && eos) {
                        Ok(ok) => ok,
                        Err(err) => {
                            debug!("client send request error: {}", err);
                            cb.send(Err(TrySendError {
                                error: Error::new_h2(err),
                                message: None,
                            }));
                            continue;
                        }
                    };

                    let f = FutCtx {
                        is_connect,
                        eos,
                        fut,
                        body_tx,
                        body,
                        cb,
                    };

                    // Check poll_ready() again.
                    // If the call to send_request() resulted in the new stream being pending open
                    // we have to wait for the open to complete before accepting new requests.
                    match self.h2_tx.poll_ready(cx) {
                        Poll::Pending => {
                            // Save Context
                            self.fut_ctx = Some(f);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => (),
                        Poll::Ready(Err(err)) => {
                            f.cb.send(Err(TrySendError {
                                error: Error::new_h2(err),
                                message: None,
                            }));
                            continue;
                        }
                    }
                    self.poll_pipe(f, cx);
                    continue;
                }

                Poll::Ready(None) => {
                    trace!("client::dispatch::Sender dropped");
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }

                Poll::Pending => match ready!(Pin::new(&mut self.conn_eof).poll(cx)) {
                    // As of Rust 1.82, this pattern is no longer needed, and emits a warning.
                    // But we cannot remove it as long as MSRV is less than that.
                    Ok(never) => match never {},
                    Err(_conn_is_eof) => {
                        trace!("connection task is closed, closing dispatch task");
                        return Poll::Ready(Ok(Dispatched::Shutdown));
                    }
                },
            }
        }
    }
}
