mod task_waker;

use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    mem,
    ops::ControlFlow,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::Instant,
};

use bytes::Bytes;
use futures_channel::{mpsc, oneshot};
use futures_util::{
    future::{Either, FusedFuture},
    stream::{FusedStream, FuturesUnordered, Stream},
    task::AtomicWaker,
};
use http::{Method, Request, Response};
use http_body::Body;
use http2::{
    Reason, SendStream,
    client::{Builder, Connection, ResponseFuture, SendRequest},
    ext::Protocol,
};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};

use self::task_waker::TaskWaker;
use super::{
    PipeToSendStream, SendBuf, ping,
    ping::{Ponger, Recorder},
    upgrade::CONNECT_UDP,
};
use crate::{
    Error, Result,
    body::{self, Incoming},
    dispatch::{self, Callback, Envelope, TrySendError},
    error::BoxError,
    ext::OnPreserveHeader,
    proto::{Dispatched, headers},
    rt::{
        Sleep, Time, Timer,
        bounds::{Http2ClientConnExec, Http2UpgradedExec},
    },
    upgrade::{self, Upgraded},
};

/// Receiver for HTTP/2 client requests
type ClientRx<B> = dispatch::Receiver<Request<B>, Response<Incoming>>;

/// Held by each handle to the connection, so the connection task is woken to shut
/// down once all are dropped.
type ConnDropRef = mpsc::Sender<Infallible>;

/// Ends once every [`ConnDropRef`] is dropped.
type ConnDropRx = mpsc::Receiver<Infallible>;

/// Dropped with the `Connection` future, which stops dispatch.
type StopTx = oneshot::Sender<Infallible>;

/// Closes once the `Connection` future is dropped.
type StopRx = oneshot::Receiver<Infallible>;

/// Reports to the `Connection` future how dispatch ended.
type DoneTx = oneshot::Sender<Result<Dispatched>>;

/// Settles with how dispatch ended.
type DoneRx = oneshot::Receiver<Result<Dispatched>>;

/// Tells a spawned body pipe to reset its stream when the caller cancels the request.
type PipeCancelTx = oneshot::Sender<()>;

/// Settles once the caller cancels the request, or closes once its response settled.
type PipeCancelRx = oneshot::Receiver<()>;

pub(crate) async fn handshake<T, B, E>(
    io: T,
    req_rx: ClientRx<B>,
    builder: Builder,
    ping_config: ping::Config,
    mut exec: E,
    timer: Time,
) -> Result<ClientTask<B>>
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

    let preface_ping = match &timer {
        Time::Timer(timer) => Some(PrefacePingTimer::new(timer.clone())),
        Time::Empty => None,
    };
    let peer = Arc::new(PeerSettings::new());
    let (conn, ping) = if ping_config.is_enabled() {
        let pp = conn.ping_pong().expect("conn.ping_pong");
        let (recorder, ponger) = ping::channel(pp, ping_config, timer);

        let conn: Conn<_, B> = Conn {
            ponger,
            conn,
            peer: peer.clone(),
            pending_window: None,
        };
        (Either::Left(conn), recorder)
    } else {
        (Either::Right(conn), ping::Recorder::disabled())
    };
    let conn: ConnMapErr<T, B> = ConnMapErr {
        conn,
        preface_ping,
        is_terminated: false,
    };

    let (stop_tx, stop) = oneshot::channel();
    let (done, done_rx) = oneshot::channel();
    let dispatch = Dispatch {
        ping,
        conn_drop_ref: conn_drop_ref.clone(),
        executor: exec.clone(),
        spawn_pipe: |exec, pipe| exec.execute_h2_future(H2ClientFuture::Pipe { pipe }),
        gate: ConnectGate::new(peer.clone()),
        h2_tx: h2_tx.clone(),
        req_rx,
        fut_ctx: None,
        stop,
        done: Some(done),
    };
    exec.execute_h2_future(H2ClientFuture::Task {
        task: Box::pin(ConnTask::new(conn, conn_drop_rx, peer.clone(), dispatch)),
    });

    Ok(ClientTask {
        _conn_drop_ref: conn_drop_ref,
        _stop: stop_tx,
        done: done_rx,
        peer,
        h2_tx,
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
        // Tells whether the dispatcher parks requests until the server's SETTINGS.
        peer: Arc<PeerSettings>,
        // A BDP stream window waiting for the previous SETTINGS to be acknowledged.
        pending_window: Option<u32>,
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
        match this.ponger.as_mut().poll(cx) {
            Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                this.conn.set_target_window_size(wnd);
                // http2 lets one SETTINGS await its ACK at a time, so the
                // newest window waits for it instead of failing the connection.
                *this.pending_window = this
                    .conn
                    .set_initial_window_size(wnd)
                    .is_err()
                    .then_some(wnd);
            }
            Poll::Pending => {}
        }

        let mut poll = Pin::new(&mut this.conn).poll(cx);
        // An ACK read by this poll lets the waiting window go out now.
        if poll.is_pending()
            && let Some(wnd) = *this.pending_window
            && this.conn.set_initial_window_size(wnd).is_ok()
        {
            *this.pending_window = None;
            poll = Pin::new(&mut this.conn).poll(cx);
        }
        // Any bytes count as read activity for keep-alive, including control
        // frames the connection handles itself.
        if this.conn.take_read_activity() {
            this.ponger.record_read();
        }
        // Checked once the connection has read what it received and registered its
        // wakeups, so a request sent later wakes this task. Parked requests wait on the
        // server too.
        if poll.is_pending() {
            let is_idle =
                this.ponger.tracks_idle() && !this.conn.has_streams() && !this.peer.poll_parked(cx);
            if this
                .ponger
                .as_mut()
                .get_mut()
                .poll_keep_alive(cx, is_idle)
                .is_ready()
            {
                debug!("connection keep-alive timed out");
                // Write GOAWAY if the socket takes it now, but don't wait on an
                // unresponsive peer to close.
                this.conn.abrupt_shutdown(Reason::INTERNAL_ERROR);
                let _ = Pin::new(&mut this.conn).poll(cx);
                return Poll::Ready(Ok(()));
            }
        }
        poll
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
        preface_ping: Option<PrefacePingTimer>,
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
        let polled = this.conn.as_mut().poll(cx);
        if polled.is_ready() {
            *this.is_terminated = true;
        } else if let Some(preface_ping) = this.preface_ping {
            // Reads move the deadline, so it is read after every poll.
            let deadline = match this.conn.as_ref().get_ref() {
                Either::Left(conn) => conn.conn.preface_ping_deadline(),
                Either::Right(conn) => conn.preface_ping_deadline(),
            };
            if preface_ping.poll(cx, deadline).is_ready() {
                cx.waker().wake_by_ref();
            }
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

/// Wakes the connection task when its preface PING times out, since `http2` has no timer.
struct PrefacePingTimer {
    timer: Arc<dyn Timer + Send + Sync>,
    sleep: Option<Pin<Box<dyn Sleep>>>,
    /// The deadline `sleep` was last set to, kept after it fires.
    deadline: Option<Instant>,
}

// ===== impl PrefacePingTimer =====

impl PrefacePingTimer {
    fn new(timer: Arc<dyn Timer + Send + Sync>) -> Self {
        Self {
            timer,
            sleep: None,
            deadline: None,
        }
    }

    /// Polls the sleep for `deadline`, moving it when the deadline moves.
    ///
    /// Each deadline fires once, so a timer clock ahead of the connection's, such as a paused
    /// one, cannot make the task spin.
    fn poll(&mut self, cx: &mut Context<'_>, deadline: Option<Instant>) -> Poll<()> {
        let Some(deadline) = deadline else {
            return Poll::Pending;
        };
        if self.deadline != Some(deadline) {
            self.deadline = Some(deadline);
            match self.sleep {
                Some(ref mut sleep) => self.timer.reset(sleep, deadline),
                None => self.sleep = Some(self.timer.sleep_until(deadline)),
            }
        }
        let Some(sleep) = self.sleep.as_mut() else {
            return Poll::Pending;
        };
        ready!(sleep.as_mut().poll(cx));
        self.sleep = None;
        Poll::Ready(())
    }
}

/// Server SETTINGS published by the connection task, the only writer, and whether the
/// dispatcher parks requests until they arrive.
///
/// The dispatcher waits for the SETTINGS, the connection task for parked requests, and
/// senders read it without locking.
pub(crate) struct PeerSettings {
    extended_connect: AtomicU8,
    waker: AtomicWaker,
    parked: AtomicBool,
    conn_waker: AtomicWaker,
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
            parked: AtomicBool::new(false),
            conn_waker: AtomicWaker::new(),
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

    /// Records whether requests are parked, waking the connection task when the first is.
    fn set_parked(&self, parked: bool) {
        if !self.parked.swap(parked, Ordering::AcqRel) && parked {
            self.conn_waker.wake();
        }
    }

    /// Returns whether requests are parked, registering the connection task first.
    fn poll_parked(&self, cx: &mut Context<'_>) -> bool {
        self.conn_waker.register(cx.waker());
        self.parked.load(Ordering::Acquire)
    }
}

/// A request and the callback that completes it.
type Queued<B> = (Request<B>, Callback<Request<B>, Response<Incoming>>);

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
    fn admit(&mut self, (req, cb): Queued<B>, cx: &mut Context<'_>) -> Option<Queued<B>> {
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
                self.peer.set_parked(true);
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
        self.peer.set_parked(!self.parked.is_empty());
    }

    /// Takes the oldest parked request once the server enabled the protocol.
    fn pop_enabled(&mut self) -> Option<Queued<B>> {
        if self.peer.extended_connect() != Some(true) {
            return None;
        }
        let parked = self.parked.pop_front();
        self.peer.set_parked(!self.parked.is_empty());
        parked.and_then(|mut parked| parked.take())
    }

    /// Returns parked requests unsent, each with an error from `error`.
    fn release(&mut self, error: impl Fn() -> Error) {
        for mut parked in self.parked.drain(..) {
            let Some((req, cb)) = parked.take() else {
                continue;
            };
            cb.send(Err(TrySendError {
                error: error(),
                message: Some(req),
            }));
        }
        self.peer.set_parked(false);
    }
}

impl<B> Drop for ConnectGate<B> {
    fn drop(&mut self) {
        // Requests dropped with the dispatcher no longer wait on the server.
        self.peer.set_parked(false);
    }
}

/// A canceled request's error caused by the connection failing with `err`.
fn canceled_by(err: &::http2::Error) -> Error {
    // `http2::Error` is not `Clone`; rebuild the protocol reason or I/O kind.
    match (err.reason(), err.get_io()) {
        (Some(reason), _) => Error::new_canceled().with(::http2::Error::from(reason)),
        (None, Some(io)) => {
            Error::new_canceled().with(std::io::Error::new(io.kind(), io.to_string()))
        }
        (None, None) => Error::new_canceled().with(err.to_string()),
    }
}

/// A canceled request's error caused by the keep-alive timeout, which also
/// reports [`is_timeout`](Error::is_timeout).
fn canceled_by_timeout() -> Error {
    Error::new_canceled().with(ping::KeepAliveTimedOut)
}

/// Rejects extended CONNECT to a server that did not enable it.
fn refused<B>(req: Request<B>) -> TrySendError<Request<B>> {
    debug!("peer did not enable extended CONNECT");
    TrySendError {
        error: Error::new_user_invalid_request("peer did not enable Extended CONNECT"),
        message: Some(req),
    }
}

/// A part of the connection task, in the order a pass polls them.
///
/// Dispatch wakes the connection to write a request, and the connection's reads wake the
/// responses they complete, so one pass takes a request or a response all the way.
#[derive(Clone, Copy)]
enum Part {
    Dispatch,
    Conn,
    Responses,
}

pin_project! {
    /// Drives the connection, its request dispatch and the responses of dispatched requests.
    ///
    /// One task does it all, so a request wakes this task only and its response its caller
    /// only, without a hop between tasks that the scheduler may move to another worker.
    #[project = ConnTaskProj]
    pub struct ConnTask<T, B, E>
    where
        B: Body,
        B: 'static,
        T: AsyncRead,
        T: AsyncWrite,
        T: Unpin,
    {
        #[pin]
        drop_rx: ConnDropRx,
        // `None` once finished, dropped so its streams resolve.
        #[pin]
        conn: Option<ConnMapErr<T, B>>,
        peer: Arc<PeerSettings>,
        // `None` once dispatch ended and reported how.
        dispatch: Option<Dispatch<B, E>>,
        // Responses of dispatched requests, completed by the connection's reads.
        responses: FuturesUnordered<SendWhen<B, E>>,
        waker: Arc<TaskWaker<Part, 3>>,
        // Whether the last pass yielded before writing new requests.
        yielded: bool,
    }
}

// ===== impl ConnTask =====

impl<T, B, E> ConnTask<T, B, E>
where
    B: Body + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[inline]
    fn new(
        conn: ConnMapErr<T, B>,
        drop_rx: ConnDropRx,
        peer: Arc<PeerSettings>,
        dispatch: Dispatch<B, E>,
    ) -> Self {
        Self {
            drop_rx,
            conn: Some(conn),
            peer,
            dispatch: Some(dispatch),
            responses: FuturesUnordered::new(),
            waker: TaskWaker::new([Part::Dispatch, Part::Conn, Part::Responses]),
            yielded: false,
        }
    }
}

impl<T, B, E> ConnTask<T, B, E>
where
    B: Body + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http2UpgradedExec<B::Data> + Clone,
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Hands queued requests to the connection, which writes them in this pass. Each adds a
    /// response.
    ///
    /// Continues when the task should yield so more requests can join new ones before the
    /// connection writes them.
    fn poll_dispatch(
        this: &mut ConnTaskProj<'_, T, B, E>,
        cx: &mut Context<'_>,
    ) -> Poll<ControlFlow<()>> {
        let in_flight = this.responses.len();
        while let Some(dispatch) = this.dispatch.as_mut() {
            match Pin::new(dispatch).poll_next(cx) {
                Poll::Ready(Some(response)) => this.responses.push(response),
                Poll::Ready(None) => *this.dispatch = None,
                Poll::Pending => break,
            }
        }

        // With other responses in flight, their callers may send more requests soon:
        // yield once so one write takes them all.
        let sent = this.responses.len() > in_flight;
        if sent && in_flight > 0 && !mem::replace(this.yielded, true) {
            return Poll::Ready(ControlFlow::Continue(()));
        }
        *this.yielded = false;
        Poll::Pending
    }

    /// Drives the connection, ending dispatch with it.
    fn poll_conn(this: &mut ConnTaskProj<'_, T, B, E>, cx: &mut Context<'_>) {
        // http2 does not wake the connection when its last handle drops; the senders that go
        // with the handles do.
        if !this.drop_rx.is_terminated() {
            let _ = this.drop_rx.as_mut().poll_next(cx);
        }

        let Some(mut conn) = this.conn.as_mut().as_pin_mut() else {
            return;
        };
        let finished = conn.as_mut().poll(cx).is_ready();

        // The driver applies the server's SETTINGS while polled, possibly in its final poll;
        // this task is the only writer, so only changes are published.
        if let Some(enabled) = conn.extended_connect_protocol()
            && this.peer.extended_connect() != Some(enabled)
        {
            this.peer.publish(enabled);
        }

        if finished {
            // ok or err, the `conn` has finished. Dropping it ends its streams, so their
            // responses report how it ended, and dispatch ends with it.
            this.conn.set(None);
            if let Some(mut dispatch) = this.dispatch.take() {
                while let Poll::Ready(Some(response)) = Pin::new(&mut dispatch).poll_next(cx) {
                    this.responses.push(response);
                }
                dispatch.conn_closed();
            }
        }
    }

    /// Completes responses, breaking once the connection has finished and none is left.
    fn poll_responses(
        this: &mut ConnTaskProj<'_, T, B, E>,
        cx: &mut Context<'_>,
    ) -> Poll<ControlFlow<()>> {
        while let Poll::Ready(Some(())) = Pin::new(&mut *this.responses).poll_next(cx) {}

        if this.conn.is_none() && this.responses.is_empty() {
            return Poll::Ready(ControlFlow::Break(()));
        }
        Poll::Pending
    }
}

impl<T, B, E> Future for ConnTask<T, B, E>
where
    B: Body + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http2UpgradedExec<B::Data> + Clone,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let waker = this.waker.clone();
        let turn = |part, cx: &mut Context<'_>| match part {
            Part::Dispatch => Self::poll_dispatch(&mut this, cx),
            Part::Conn => {
                Self::poll_conn(&mut this, cx);
                Poll::Pending
            }
            Part::Responses => Self::poll_responses(&mut this, cx),
        };
        match ready!(waker.poll(cx, turn)) {
            ControlFlow::Break(()) => Poll::Ready(()),
            ControlFlow::Continue(()) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
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
        Task {
            task: Pin<Box<ConnTask<T, B, E>>>,
        },
    }
}

impl<B, T, E> Future for H2ClientFuture<B, T, E>
where
    B: Body + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http2UpgradedExec<B::Data> + Clone,
    T: AsyncRead + AsyncWrite + Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this {
            H2ClientFutureProject::Pipe { pipe } => pipe.poll(cx),
            H2ClientFutureProject::Task { task } => task.as_mut().poll(cx),
        }
    }
}

struct FutCtx<B>
where
    B: Body,
{
    is_connect: bool,
    connect_udp: bool,
    eos: bool,
    fut: ResponseFuture,
    body_tx: SendStream<SendBuf<B::Data>>,
    body: B,
    cb: Callback<Request<B>, Response<Incoming>>,
}

impl<B: Body> Unpin for FutCtx<B> {}

/// The `Connection` future's end of dispatch: settles once the connection task stops
/// dispatching, and dropping it stops dispatch.
pub(crate) struct ClientTask<B>
where
    B: Body + 'static,
{
    // Wakes the connection task once dropped with the last handle, which http2 does not.
    _conn_drop_ref: ConnDropRef,
    _stop: StopTx,
    done: DoneRx,
    peer: Arc<PeerSettings>,
    h2_tx: SendRequest<SendBuf<B::Data>>,
}

/// Hands requests to the connection, in the connection task.
///
/// Yields the response of each request it hands over, and ends after reporting how dispatch
/// ended.
struct Dispatch<B, E>
where
    B: Body + 'static,
{
    ping: ping::Recorder,
    conn_drop_ref: ConnDropRef,
    executor: E,
    // Spawns a request body pipe; set where the executor is known to spawn it.
    spawn_pipe: fn(&mut E, PipeMap<B>),
    /// Extended CONNECT requests waiting on the server's SETTINGS.
    gate: ConnectGate<B>,
    h2_tx: SendRequest<SendBuf<B::Data>>,
    req_rx: ClientRx<B>,
    fut_ctx: Option<FutCtx<B>>,
    stop: StopRx,
    // `None` once dispatch reported how it ended.
    done: Option<DoneTx>,
}

// Dispatch never pins its fields, so it is `Unpin` whatever the executor is.
impl<B: Body + 'static, E> Unpin for Dispatch<B, E> {}

pin_project! {
    pub struct PipeMap<S>
    where
        S: Body,
    {
        #[pin]
        pipe: PipeToSendStream<S>,
        #[pin]
        conn_drop_ref: Option<ConnDropRef>,
        cancel_rx: Option<PipeCancelRx>,
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
                return Poll::Ready(());
            }
            Poll::Pending => (),
        };
        Poll::Pending
    }
}

pin_project! {
    /// Drives an HTTP/2 response future and delivers its result through the callback.
    /// Resets the request stream if its caller cancels while the response is pending.
    struct SendWhen<B, E>
    where
        B: Body,
        B: 'static,
    {
        #[pin]
        when: ResponseFutMap<B, E>,
        #[pin]
        call_back: Option<Callback<Request<B>, Response<Incoming>>>,
    }
}

impl<B, E> Future for SendWhen<B, E>
where
    B: Body + 'static,
    E: Http2UpgradedExec<B::Data>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut call_back = this.call_back.take().expect("polled after complete");

        match Pin::new(&mut this.when).poll(cx) {
            Poll::Ready(Ok(res)) => {
                call_back.send(Ok(res));
                Poll::Ready(())
            }
            Poll::Pending => {
                // check if the callback is canceled
                match call_back.poll_canceled(cx) {
                    Poll::Ready(v) => v,
                    Poll::Pending => {
                        // Move call_back back to struct before return
                        this.call_back.set(Some(call_back));
                        return Poll::Pending;
                    }
                };
                trace!("send_when canceled");
                // Tell pipe_task to reset the h2 stream so that
                // RST_STREAM is sent and flow-control capacity freed.
                this.when.as_mut().cancel();
                Poll::Ready(())
            }
            Poll::Ready(Err((error, message))) => {
                call_back.send(Err(TrySendError { error, message }));
                Poll::Ready(())
            }
        }
    }
}

pin_project! {
    struct ResponseFutMap<B, E>
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
        cancel_tx: Option<PipeCancelTx>,
        connect_udp: bool,
        exec: E,
    }
}

impl<B: Body + 'static, E> ResponseFutMap<B, E> {
    /// Signal the pipe_task to reset the stream (e.g. on client cancellation).
    fn cancel(self: Pin<&mut Self>) {
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
                // A CONNECT-UDP success that breaks the Capsule Protocol is malformed, a stream
                // error of type PROTOCOL_ERROR.
                // https://www.rfc-editor.org/rfc/rfc9297.html#section-3.2
                // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1
                if *this.connect_udp
                    && res.status().is_success()
                    && headers::breaks_capsule_protocol(res.status(), res.headers())
                {
                    if let Some(mut send_stream) = send_stream {
                        send_stream.send_reset(http2::Reason::PROTOCOL_ERROR);
                    }
                    return Poll::Ready(Err((
                        Error::new_h2(http2::Reason::PROTOCOL_ERROR.into()),
                        None::<Request<B>>,
                    )));
                }

                // Any 2xx opens the tunnel, and its content-length is ignored: the response has
                // no content, and what follows is tunneled data.
                // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5
                // https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6
                if res.status().is_success()
                    && let Some(send_stream) = send_stream
                {
                    let (parts, recv_stream) = res.into_parts();
                    let mut res = Response::from_parts(parts, Incoming::empty());

                    let (pending, on_upgrade) = upgrade::pending();
                    let (io, task) = super::upgrade::pair(
                        send_stream,
                        recv_stream,
                        ping,
                        // Only MASQUE resets the stream.
                        (cfg!(feature = "masque") && *this.connect_udp)
                            .then_some(res.extensions_mut()),
                    );
                    this.exec.execute_upgrade(task);
                    let upgraded = Upgraded::new(io, Bytes::new());

                    pending.fulfill(upgraded);
                    res.extensions_mut().insert(on_upgrade);

                    Poll::Ready(Ok(res))
                } else {
                    // A refused CONNECT tunnels nothing, so its request half ends here and the
                    // stream closes with the response rather than when the body drops.
                    if let Some(mut send_stream) = send_stream {
                        let _ = send_stream.send_data(SendBuf::None, true);
                    }
                    let content_length = headers::content_length_parse_all(res.headers());
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

// ===== impl ClientTask =====

impl<B> ClientTask<B>
where
    B: Body + 'static,
{
    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.peer.extended_connect() == Some(true)
    }

    pub(crate) fn peer_settings(&self) -> Arc<PeerSettings> {
        self.peer.clone()
    }

    pub(crate) fn current_max_send_streams(&self) -> usize {
        self.h2_tx.current_max_send_streams()
    }

    pub(crate) fn current_max_recv_streams(&self) -> usize {
        self.h2_tx.current_max_recv_streams()
    }
}

impl<B> Future for ClientTask<B>
where
    B: Body + 'static,
{
    type Output = Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // The connection task ends without a report only if its executor drops it.
        let done = ready!(Pin::new(&mut self.done).poll(cx));
        Poll::Ready(done.unwrap_or(Ok(Dispatched::Shutdown)))
    }
}

// ===== impl Dispatch =====

impl<B, E> Dispatch<B, E>
where
    B: Body + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http2UpgradedExec<B::Data> + Clone,
{
    /// Reports how dispatch ended to the `Connection` future, if it is still there.
    fn end(&mut self, dispatched: Result<Dispatched>) {
        if let Some(done) = self.done.take() {
            let _ = done.send(dispatched);
        }
    }

    /// Ends dispatch with the connection, unless it already ended.
    fn conn_closed(mut self) {
        if self.done.is_none() {
            return;
        }
        trace!("connection task is closed, closing dispatch task");
        // The connection may have closed on a keep-alive timeout since `poll_ready`, which
        // dispatch reports too.
        let dispatched = match self.ping.ensure_not_timed_out() {
            Ok(()) => Ok(Dispatched::Shutdown),
            Err(err) => {
                self.gate.release(canceled_by_timeout);
                Err(err)
            }
        };
        self.end(dispatched);
    }

    fn poll_pipe(&mut self, f: FutCtx<B>) -> SendWhen<B, E> {
        let ping = self.ping.clone();

        // Lets the response tell a spawned body pipe to reset the stream when the client
        // cancels the request.
        let mut pipe_cancel_tx = None;

        let send_stream = if !f.is_connect {
            if !f.eos {
                let mut pipe = PipeToSendStream::new(f.body, f.body_tx);

                // A body that is already done needs no task of its own. This poll registers
                // no waker: one left on the stream would wake dispatch as the connection
                // writes the request, and a pending pipe registers its own task's.
                match Pin::new(&mut pipe).poll(&mut Context::from_waker(Waker::noop())) {
                    Poll::Ready(_) => (),
                    Poll::Pending => {
                        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
                        pipe_cancel_tx = Some(cancel_tx);
                        let conn_drop_ref = self.conn_drop_ref.clone();

                        let pipe = PipeMap {
                            pipe,
                            conn_drop_ref: Some(conn_drop_ref),
                            cancel_rx: Some(cancel_rx),
                        };
                        // The rest of the body is piped on a task of its own.
                        (self.spawn_pipe)(&mut self.executor, pipe);
                    }
                }
            }

            None
        } else {
            Some(f.body_tx)
        };

        // The connection's reads complete the response, in this task.
        SendWhen {
            when: ResponseFutMap {
                fut: f.fut,
                ping: Some(ping),
                send_stream: Some(send_stream),
                cancel_tx: pipe_cancel_tx,
                connect_udp: f.connect_udp,
                exec: self.executor.clone(),
            },
            call_back: Some(f.cb),
        }
    }

    /// Hands the next queued request to the connection, continuing with its response, or
    /// breaks with how dispatch ended.
    ///
    /// Dispatch ends once every sender is gone or the connection fails.
    fn poll_request(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ControlFlow<Result<Dispatched>, SendWhen<B, E>>> {
        loop {
            // Refusals need no stream capacity, so they must not wait behind open backpressure.
            self.gate.poll_settle(cx);

            match ready!(self.h2_tx.poll_ready(cx)) {
                Ok(()) => (),
                Err(err) => {
                    // `poll_ready` reports connection errors before pending-open state, so
                    // the parked stream may already be on the wire. Let h2 resolve it.
                    if let Some(f) = self.fut_ctx.take() {
                        return Poll::Ready(ControlFlow::Continue(self.poll_pipe(f)));
                    }
                    let timed_out = self.ping.ensure_not_timed_out();
                    if timed_out.is_err() {
                        self.gate.release(canceled_by_timeout);
                    } else {
                        self.gate.release(|| canceled_by(&err));
                    }
                    if let Err(err) = timed_out {
                        return Poll::Ready(ControlFlow::Break(Err(err)));
                    }
                    return Poll::Ready(ControlFlow::Break(
                        if err.reason() == Some(::http2::Reason::NO_ERROR) {
                            trace!("connection gracefully shutdown");
                            Ok(Dispatched::Shutdown)
                        } else {
                            Err(Error::new_h2(err))
                        },
                    ));
                }
            };

            // If we were waiting on pending open
            // continue where we left off.
            if let Some(f) = self.fut_ctx.take() {
                return Poll::Ready(ControlFlow::Continue(self.poll_pipe(f)));
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
                    let Some((req, cb)) = self.gate.admit((req, cb), cx) else {
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
                    // `send_request` takes the `:protocol` extension.
                    let connect_udp = is_connect
                        && req
                            .extensions()
                            .get::<Protocol>()
                            .is_some_and(|protocol| protocol.as_str() == CONNECT_UDP);

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
                        connect_udp,
                        eos,
                        fut,
                        body_tx,
                        body,
                        cb,
                    };

                    // Check poll_ready() again.
                    // If the call to send_request() resulted in the new stream being pending open
                    // we have to wait for the open to complete before accepting new requests.
                    // On error the stream still belongs to h2; the next iteration reports it.
                    if self.h2_tx.poll_ready(cx).is_pending() {
                        // Save Context
                        self.fut_ctx = Some(f);
                        return Poll::Pending;
                    }
                    return Poll::Ready(ControlFlow::Continue(self.poll_pipe(f)));
                }

                Poll::Ready(None) => {
                    trace!("client::dispatch::Sender dropped");
                    return Poll::Ready(ControlFlow::Break(Ok(Dispatched::Shutdown)));
                }

                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<B, E> Stream for Dispatch<B, E>
where
    B: Body + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
    E: Http2UpgradedExec<B::Data> + Clone,
{
    type Item = SendWhen<B, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // A dropped `Connection` future stops dispatch. `stop` registers the waker only when
        // dispatch would wait, so each request costs just an atomic load.
        let step = if this.stop.try_recv().is_err() {
            ControlFlow::Break(Ok(Dispatched::Shutdown))
        } else {
            match this.poll_request(cx) {
                Poll::Ready(step) => step,
                Poll::Pending => match Pin::new(&mut this.stop).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => ControlFlow::Break(Ok(Dispatched::Shutdown)),
                },
            }
        };
        match step {
            ControlFlow::Continue(response) => Poll::Ready(Some(response)),
            ControlFlow::Break(dispatched) => {
                this.end(dispatched);
                Poll::Ready(None)
            }
        }
    }
}
