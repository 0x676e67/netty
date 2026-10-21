use std::{
    convert::Infallible,
    future::Future,
    io,
    sync::{Arc, Mutex, mpsc},
    task::Poll,
};

use bytes::Bytes;
use futures_channel::oneshot;
use futures_util::{StreamExt as _, future::BoxFuture};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use netty::{
    conn::{TrySendError, http2},
    rt::Executor as _,
    upgrade::Upgraded,
};
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream};
use tokio_test::{assert_pending, assert_ready, task};

use crate::support::TokioIo;

const CHUNK: &[u8; 1024] = &[b'x'; 1024];
const CHUNKS: usize = 8;

#[derive(Clone)]
struct Executor(mpsc::Sender<BoxFuture<'static, ()>>);

// Every protocol task is polled to quiescence before asserting Pending. This
// distinguishes flow control from a sender task that simply hasn't run yet.
struct Driver {
    executor: Executor,
    rx: mpsc::Receiver<BoxFuture<'static, ()>>,
    tasks: Vec<task::Spawn<BoxFuture<'static, ()>>>,
}

/// A request the proxy received, the sender of its response, and its upgrade.
type Accepted = (
    Request<hyper::body::Incoming>,
    oneshot::Sender<Response<Full<Bytes>>>,
    hyper::upgrade::OnUpgrade,
);

/// A Hyper HTTP/2 server playing the proxy at the far end of a driver's pipe; the test answers
/// each request it receives.
struct HyperProxy(futures_channel::mpsc::UnboundedReceiver<Accepted>);

// ===== impl Executor =====

impl<F> netty::rt::Executor<F> for Executor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        self.0.send(Box::pin(future)).unwrap();
    }
}

impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        self.0.send(Box::pin(future)).unwrap();
    }
}

// ===== impl Driver =====

impl Driver {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            executor: Executor(tx),
            rx,
            tasks: Vec::new(),
        }
    }

    /// Completes a client handshake over a new pipe, returning its server end.
    fn handshake(
        &mut self,
        options: netty::http2::Http2Options,
    ) -> (
        http2::SendRequest<Empty<Bytes>>,
        http2::Connection<DuplexStream, Empty<Bytes>, Executor>,
        DuplexStream,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client, conn) = self
            .finish(
                http2::Builder::new(self.executor.clone())
                    .options(options)
                    .handshake(client_io),
            )
            .unwrap();
        (client, conn, server_io)
    }

    fn run(&mut self) {
        loop {
            let mut progressed = false;
            while let Ok(future) = self.rx.try_recv() {
                let mut task = task::spawn(future);
                if task.poll().is_pending() {
                    self.tasks.push(task);
                }
                progressed = true;
            }
            let mut i = 0;
            while i < self.tasks.len() {
                if self.tasks[i].is_woken() {
                    progressed = true;
                    if self.tasks[i].poll().is_ready() {
                        self.tasks.swap_remove(i);
                        continue;
                    }
                }
                i += 1;
            }
            if !progressed {
                return;
            }
        }
    }

    fn poll<F: Future>(&mut self, future: &mut task::Spawn<F>) -> Poll<F::Output> {
        loop {
            let result = future.poll();
            self.run();
            if result.is_ready() || !future.is_woken() {
                return result;
            }
        }
    }

    fn finish<F: Future>(&mut self, future: F) -> F::Output {
        assert_ready!(self.poll(&mut task::spawn(future)))
    }

    fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.executor.execute(future);
    }
}

// ===== impl HyperProxy =====

impl HyperProxy {
    /// Serves `io` on `driver`, with `configure` setting up the Hyper builder.
    fn spawn(
        driver: &Driver,
        io: DuplexStream,
        configure: impl FnOnce(&mut hyper::server::conn::http2::Builder<Executor>),
    ) -> Self {
        let (tx, rx) = futures_channel::mpsc::unbounded();
        let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
            let upgrade = hyper::upgrade::on(&mut request);
            let (respond, response) = oneshot::channel();
            tx.unbounded_send((request, respond, upgrade)).unwrap();
            async move { Ok::<_, Infallible>(response.await.unwrap()) }
        });
        let mut builder = hyper::server::conn::http2::Builder::new(driver.executor.clone());
        configure(&mut builder);
        driver.spawn(async move {
            builder
                .serve_connection(TokioIo::new(io), service)
                .await
                .unwrap();
        });
        Self(rx)
    }

    /// Sends `request` and answers it with `response`. Returns the client's result, the request
    /// as the proxy saw it, and the proxy's end of a successful upgrade.
    fn exchange(
        &mut self,
        driver: &mut Driver,
        client: &mut http2::SendRequest<Empty<Bytes>>,
        request: Request<Empty<Bytes>>,
        response: Response<Full<Bytes>>,
    ) -> (
        Result<Response<netty::body::Incoming>, TrySendError<Request<Empty<Bytes>>>>,
        Request<hyper::body::Incoming>,
        Option<TokioIo<hyper::upgrade::Upgraded>>,
    ) {
        let success = response.status().is_success();
        let mut sending = task::spawn(client.try_send_request(request));
        assert_pending!(driver.poll(&mut sending));
        let (request, respond, upgrade) = driver.finish(self.0.next()).unwrap();
        respond.send(response).unwrap();
        let server = success.then(|| TokioIo::new(driver.finish(upgrade).unwrap()));
        (assert_ready!(driver.poll(&mut sending)), request, server)
    }
}

/// The code the client reset the proxy's upgraded stream with. Hyper's reader maps `CANCEL` to
/// EOF, so this reads the code from a write's error.
fn proxy_reset(driver: &mut Driver, server: &mut TokioIo<hyper::upgrade::Upgraded>) -> h2::Reason {
    driver.run();
    let error = driver.finish(server.write_all(b"after-reset")).unwrap_err();
    let mut source = std::error::Error::source(&error);
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<h2::Error>() {
            return error.reason().unwrap();
        }
        source = error.source();
    }
    panic!("reset without an h2 reason: {error:?}");
}

fn extended_connect(path: &str) -> Request<Empty<Bytes>> {
    let mut request = Request::connect(format!("https://localhost:443{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(::http2::ext::Protocol::from_static("websocket"));
    request
}

/// A CONNECT-UDP request to 192.0.2.1:53 through the test proxy.
#[cfg(feature = "masque")]
fn connect_udp_request() -> Request<Empty<Bytes>> {
    use netty::proxy::masque::{self, Template};

    let template = Template::new("https://localhost:443/masque/{target_host}/{target_port}/");
    masque::http2_request(template.unwrap().expand("192.0.2.1", 53).unwrap())
}

fn connect() -> (
    Driver,
    Upgraded,
    TokioIo<hyper::upgrade::Upgraded>,
    http2::SendRequest<Empty<Bytes>>,
) {
    connect_request(
        Request::connect("localhost:443")
            .body(Empty::<Bytes>::new())
            .unwrap(),
        false,
    )
}

fn connect_request(
    request: Request<Empty<Bytes>>,
    enable_connect_protocol: bool,
) -> (
    Driver,
    Upgraded,
    TokioIo<hyper::upgrade::Upgraded>,
    http2::SendRequest<Empty<Bytes>>,
) {
    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(
        netty::http2::Http2Options::builder()
            .initial_window_size(1024)
            .build(),
    );
    assert!(!conn.is_extended_connect_protocol_enabled());
    let mut proxy = HyperProxy::spawn(&driver, server_io, |builder| {
        builder.initial_stream_window_size(1024);
        if enable_connect_protocol {
            builder.enable_connect_protocol();
        }
    });
    driver.run();
    assert_eq!(
        conn.is_extended_connect_protocol_enabled(),
        enable_connect_protocol
    );
    driver.spawn(async move {
        conn.await.unwrap();
    });
    let empty = Response::new(Full::new(Bytes::new()));
    let (response, request, server) = proxy.exchange(&mut driver, &mut client, request, empty);
    assert_eq!(request.method(), Method::CONNECT);
    if enable_connect_protocol {
        let protocol = request.extensions().get::<hyper::ext::Protocol>().unwrap();
        assert_eq!(protocol.as_str(), "websocket");
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().authority().unwrap(), "localhost:443");
        assert_eq!(request.uri().path_and_query().unwrap(), "/chat?room=1");
    }
    let response = response.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let upgraded = driver.finish(netty::upgrade::on(response)).unwrap();
    (driver, upgraded, server.unwrap(), client)
}

#[tokio::test]
async fn h2_extended_connect_peer_support() {
    let mut request = Request::connect("https://localhost:443/chat?room=1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(::http2::ext::Protocol::from_static("websocket"));
    let (mut driver, mut upgraded, mut server, _client) = connect_request(request, true);
    driver.finish(upgraded.write_all(b"ping")).unwrap();
    let mut received = [0; 4];
    driver.finish(server.read_exact(&mut received)).unwrap();
    assert_eq!(&received, b"ping");
    driver.finish(server.write_all(b"pong")).unwrap();
    driver.finish(upgraded.read_exact(&mut received)).unwrap();
    assert_eq!(&received, b"pong");
    driver.finish(upgraded.shutdown()).unwrap();
    driver.finish(server.shutdown()).unwrap();
}

#[tokio::test]
async fn h2_extended_connect_waits_for_peer_settings() {
    /// How the server answers while extended CONNECT requests are parked.
    #[derive(Clone, Copy)]
    enum Peer {
        /// Writes bytes that are not an HTTP/2 frame (FRAME_SIZE_ERROR).
        Garbage,
        /// Closes the transport before sending SETTINGS.
        Eof,
        /// Sends SETTINGS with or without extended CONNECT.
        Settings(bool),
    }
    // The last case drops every sender while the requests are parked.
    let cases = [
        (Peer::Garbage, true),
        (Peer::Eof, true),
        (Peer::Settings(false), true),
        (Peer::Settings(true), true),
        (Peer::Settings(true), false),
    ];
    for (peer, keep_sender) in cases {
        let settings = match peer {
            Peer::Settings(enabled) => Some(enabled),
            Peer::Garbage | Peer::Eof => None,
        };
        let mut driver = Driver::new();
        let (mut client, conn, server_io) = driver.handshake(Default::default());
        assert_eq!(client.is_extended_connect_protocol_enabled(), None);
        driver.spawn(async move {
            let _ = conn.await;
        });

        // The server has not sent SETTINGS, so these wait; one caller gives up.
        let mut connects = ["/a", "/canceled", "/b"]
            .map(|path| task::spawn(client.try_send_request(extended_connect(path))));
        for connect in &mut connects {
            assert_pending!(driver.poll(connect));
        }
        let [first, canceled, last] = connects;
        drop(canceled);
        // A parked extended CONNECT must not hold back other requests.
        let get = Request::get("https://localhost/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut get = task::spawn(client.try_send_request(get));
        let client = keep_sender.then_some(client);
        assert_pending!(driver.poll(&mut get));

        let paths = Arc::new(Mutex::new(Vec::new()));
        match peer {
            Peer::Settings(enabled) => {
                let seen = paths.clone();
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    seen.lock().unwrap().push(request.uri().path().to_owned());
                    async { Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new())) }
                });
                let mut builder = hyper::server::conn::http2::Builder::new(driver.executor.clone());
                if enabled {
                    builder.enable_connect_protocol();
                }
                driver.spawn(async move {
                    let _ = builder
                        .serve_connection(TokioIo::new(server_io), service)
                        .await;
                });
            }
            Peer::Garbage => driver.spawn(async move {
                let mut server_io = server_io;
                let _ = server_io
                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await;
            }),
            Peer::Eof => drop(server_io),
        }

        // Parked requests leave in order, each caller getting its own request back.
        for (mut connect, path) in [(first, "/a"), (last, "/b")] {
            let result = assert_ready!(driver.poll(&mut connect));
            if settings == Some(true) {
                assert_eq!(result.unwrap().status(), StatusCode::OK);
                continue;
            }
            let mut error = result.unwrap_err();
            assert_eq!(error.error().is_user(), settings.is_some());
            assert_eq!(error.error().is_canceled(), settings.is_none());
            assert_eq!(error.take_message().unwrap().uri().path(), path);
            let cause = std::error::Error::source(error.error());
            match peer {
                Peer::Garbage => assert_eq!(
                    cause
                        .and_then(|cause| cause.downcast_ref::<::http2::Error>())
                        .and_then(::http2::Error::reason),
                    Some(::http2::Reason::FRAME_SIZE_ERROR)
                ),
                Peer::Eof => assert!(cause.is_some_and(|cause| cause.is::<io::Error>())),
                Peer::Settings(_) => {}
            }
        }
        if let Some(client) = &client {
            assert_eq!(client.is_extended_connect_protocol_enabled(), settings);
        }
        assert_eq!(
            assert_ready!(driver.poll(&mut get)).is_ok(),
            settings.is_some()
        );
        let expected: &[&str] = match settings {
            None => &[],
            Some(false) => &["/"],
            Some(true) => &["/", "/a", "/b"],
        };
        assert_eq!(*paths.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn h2_extended_connect_published_when_connection_ends() {
    let mut driver = Driver::new();
    let (client, conn, mut server_io) = driver.handshake(Default::default());
    let (done_tx, mut done) = oneshot::channel();
    driver.spawn(async move {
        let _ = conn.await;
        let _ = done_tx.send(());
    });

    // Hyper serves on its own pipe, so its SETTINGS can be relayed with the EOF at once.
    let (hyper_io, mut relay_io) = tokio::io::duplex(64 * 1024);
    let mut builder = hyper::server::conn::http2::Builder::new(driver.executor.clone());
    builder.enable_connect_protocol();
    driver.spawn(async move {
        let service = service_fn(|_: Request<hyper::body::Incoming>| async {
            Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
        });
        let _ = builder
            .serve_connection(TokioIo::new(hyper_io), service)
            .await;
    });
    driver.run();
    let mut settings = vec![0; 1024];
    let read = assert_ready!(task::spawn(relay_io.read(&mut settings)).poll()).unwrap();
    assert!(read > 0);

    // Without running the client in between, it applies SETTINGS in its final poll.
    assert_ready!(task::spawn(server_io.write_all(&settings[..read])).poll()).unwrap();
    drop(server_io);
    driver.run();
    assert!(done.try_recv().unwrap().is_some());
    assert_eq!(client.is_extended_connect_protocol_enabled(), Some(true));
}

#[tokio::test]
async fn h2_extended_connect_follows_later_settings() {
    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(Default::default());
    driver.spawn(async move {
        let _ = conn.await;
    });
    let mut server = driver.finish(h2::server::handshake(server_io)).unwrap();
    let drive = |driver: &mut Driver, server: &mut h2::server::Connection<_, Bytes>| {
        let mut closed = task::spawn(std::future::poll_fn(|cx| server.poll_closed(cx)));
        assert_pending!(driver.poll(&mut closed));
    };

    drive(&mut driver, &mut server);
    assert_eq!(client.is_extended_connect_protocol_enabled(), Some(false));
    let error = driver
        .finish(client.try_send_request(extended_connect("/chat")))
        .unwrap_err();
    assert!(error.error().is_user());

    // RFC 8441 §3 only forbids withdrawing the setting; a later SETTINGS may enable it.
    server.enable_connect_protocol().unwrap();
    drive(&mut driver, &mut server);
    assert_eq!(client.is_extended_connect_protocol_enabled(), Some(true));
    let mut connect = task::spawn(client.try_send_request(extended_connect("/chat")));
    assert_pending!(driver.poll(&mut connect));
    let (request, _respond) = driver.finish(server.accept()).unwrap().unwrap();
    assert_eq!(request.method(), Method::CONNECT);
    assert!(request.extensions().get::<h2::ext::Protocol>().is_some());
}

#[tokio::test]
async fn h2_extended_connect_refusal_ignores_open_backpressure() {
    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(
        netty::http2::Http2Options::builder()
            .initial_max_send_streams(1)
            .build(),
    );
    driver.spawn(async move {
        let _ = conn.await;
    });

    let mut connect = task::spawn(client.try_send_request(extended_connect("/chat")));
    assert_pending!(driver.poll(&mut connect));
    // One stream is held open, so the next GET waits to open.
    let get = |path: &str| {
        Request::get(format!("https://localhost{path}"))
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    let mut held = task::spawn(client.try_send_request(get("/held")));
    assert_pending!(driver.poll(&mut held));
    let mut queued = task::spawn(client.try_send_request(get("/queued")));
    assert_pending!(driver.poll(&mut queued));

    let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
        if request.uri().path() == "/held" {
            std::future::pending::<()>().await;
        }
        Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
    });
    let mut builder = hyper::server::conn::http2::Builder::new(driver.executor.clone());
    builder.max_concurrent_streams(1);
    driver.spawn(async move {
        let _ = builder
            .serve_connection(TokioIo::new(server_io), service)
            .await;
    });

    // The refusal needs no stream capacity, so it is not held behind the queued GET.
    let mut error = assert_ready!(driver.poll(&mut connect)).unwrap_err();
    assert!(error.error().is_user());
    assert_eq!(error.take_message().unwrap().uri().path(), "/chat");
    assert_eq!(client.is_extended_connect_protocol_enabled(), Some(false));
    assert_pending!(driver.poll(&mut queued));
}

#[tokio::test]
async fn h2_extended_connect_cancel_while_parked_releases_connection() {
    let mut driver = Driver::new();
    let (mut client, conn, _server_io) = driver.handshake(Default::default());
    let (done_tx, mut done) = oneshot::channel();
    driver.spawn(async move {
        let _ = conn.await;
        let _ = done_tx.send(());
    });

    let mut connect = task::spawn(client.try_send_request(extended_connect("/chat")));
    assert_pending!(driver.poll(&mut connect));
    drop(client);
    driver.run();
    assert!(done.try_recv().unwrap().is_none());

    // The server never sends SETTINGS; the canceled caller must not keep the task alive.
    drop(connect);
    driver.run();
    assert!(done.try_recv().unwrap().is_some());
    assert!(driver.tasks.is_empty());
}

// https://github.com/hyperium/hyper/issues/4003, for HTTP/2 CONNECT
//
// Like `h2_idle_stream_does_not_pin_connection_window`, but the idle
// stream is the send side of an `Upgraded` tunnel. It must not reserve
// connection-level flow control capacity while it has nothing to write.
#[tokio::test]
async fn h2_idle_upgraded_does_not_pin_connection_window() {
    // One byte short of the initial connection-level window.
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.2
    const STREAM_A_LEN: usize = 65534;

    let mut driver = Driver::new();
    let executor = driver.executor.clone();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_tx, server_rx) = oneshot::channel();
    let server_tx = std::sync::Mutex::new(Some(server_tx));
    let upgrade_executor = executor.clone();
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let tx = (request.method() == http::Method::CONNECT)
            .then(|| server_tx.lock().unwrap().take().unwrap());
        let executor = upgrade_executor.clone();
        async move {
            if let Some(tx) = tx {
                let upgrade = hyper::upgrade::on(request);
                executor.execute(async move {
                    tx.send(upgrade.await.unwrap()).unwrap();
                });
            } else {
                let body = request.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body, Bytes::from_static(b"b"));
            }
            Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
        }
    });
    let server_executor = executor.clone();
    let (mut client, conn) = driver
        .finish(http2::Builder::new(executor).handshake::<_, Full<Bytes>>(client_io))
        .unwrap();
    driver.spawn(async move {
        hyper::server::conn::http2::Builder::new(server_executor)
            .initial_stream_window_size(65535)
            .initial_connection_window_size(65535)
            .serve_connection(TokioIo::new(server_io), service)
            .await
            .unwrap();
    });
    driver.spawn(async move {
        conn.await.unwrap();
    });
    let request = Request::connect("localhost:443")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = driver.finish(client.try_send_request(request)).unwrap();
    let mut upgraded = driver.finish(netty::upgrade::on(response)).unwrap();
    let mut server = TokioIo::new(driver.finish(server_rx).unwrap());

    // Keep the Hyper server's upgraded receive side alive without reading it,
    // so it cannot release capacity and send WINDOW_UPDATE for the tunnel.
    let data = vec![b'a'; STREAM_A_LEN];
    driver.finish(upgraded.write_all(&data)).unwrap();

    // Driver::finish polls every task to quiescence. The idle tunnel must leave
    // the final connection-window byte available for the second request.
    let request = Request::post("https://localhost/b")
        .body(Full::new(Bytes::from_static(b"b")))
        .unwrap();
    let mut response = task::spawn(client.try_send_request(request));
    let response = assert_ready!(driver.poll(&mut response)).unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut received = vec![0; STREAM_A_LEN];
    driver.finish(server.read_exact(&mut received)).unwrap();
    assert_eq!(received, data);
    driver.finish(upgraded.shutdown()).unwrap();
    driver.finish(server.shutdown()).unwrap();
}

async fn write_chunks(writer: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
    for _ in 0..CHUNKS {
        writer.write_all(CHUNK).await?;
    }
    Ok(())
}

#[tokio::test]
async fn h2_connect_backpressure_bidirectional() {
    let (mut driver, upgraded, server, _client) = connect();
    let (mut reader, mut writer) = tokio::io::split(upgraded);
    let (mut server_reader, mut server_writer) = tokio::io::split(server);
    let (written_tx, written_rx) = oneshot::channel();
    driver.spawn(async move {
        write_chunks(&mut writer).await.unwrap();
        written_tx.send(()).unwrap();
        writer.shutdown().await.unwrap();
    });
    let (server_written_tx, server_written_rx) = oneshot::channel();
    driver.spawn(async move {
        write_chunks(&mut server_writer).await.unwrap();
        server_written_tx.send(()).unwrap();
        server_writer.shutdown().await.unwrap();
    });
    let mut written = task::spawn(written_rx);
    let mut server_written = task::spawn(server_written_rx);
    assert_pending!(driver.poll(&mut written));
    assert_pending!(driver.poll(&mut server_written));

    // Both stream windows are exhausted. Reading must release the receive
    // window even while the upgraded write side waits for send capacity.
    let mut response = Vec::new();
    driver.finish(reader.read_to_end(&mut response)).unwrap();
    assert_eq!(response, CHUNK.repeat(CHUNKS));
    assert_ready!(driver.poll(&mut server_written)).unwrap();
    assert_pending!(driver.poll(&mut written));

    let mut request = Vec::new();
    driver
        .finish(server_reader.read_to_end(&mut request))
        .unwrap();
    assert_eq!(request, CHUNK.repeat(CHUNKS));
    assert_ready!(driver.poll(&mut written)).unwrap();
}

#[tokio::test]
async fn h2_connect_zero_window_preserves_queued_shutdown_data() {
    let (mut driver, mut upgraded, mut server, _client) = connect();
    driver.finish(upgraded.write_all(CHUNK)).unwrap();
    driver.finish(upgraded.write_all(b"queued data")).unwrap();
    let mut shutdown = task::spawn(upgraded.shutdown());
    assert_pending!(driver.poll(&mut shutdown));

    // Reading the exhausted stream releases capacity and sends WINDOW_UPDATE;
    // the already accepted write must survive until that capacity arrives.
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9
    let mut first = [0; 1024];
    driver.finish(server.read_exact(&mut first)).unwrap();
    assert_eq!(&first, CHUNK);
    assert_ready!(driver.poll(&mut shutdown)).unwrap();
    let mut rest = Vec::new();
    driver.finish(server.read_to_end(&mut rest)).unwrap();
    assert_eq!(rest, b"queued data");
}

#[tokio::test]
async fn h2_connect_zero_window_empty_shutdown_wakes_sender() {
    let (mut driver, mut upgraded, mut server, _client) = connect();
    driver.finish(upgraded.write_all(CHUNK)).unwrap();
    // The peer has received a full window but has not read or released it.
    driver.finish(upgraded.shutdown()).unwrap();
    let mut received = Vec::new();
    driver.finish(server.read_to_end(&mut received)).unwrap();
    assert_eq!(received, CHUNK);
}

#[tokio::test]
async fn h2_connect_reset_during_backpressure() {
    let (mut driver, mut upgraded, server, _client) = connect();
    let mut write = task::spawn(write_chunks(&mut upgraded));
    assert_pending!(driver.poll(&mut write));
    // Dropping both halves of Hyper's open tunnel cancels the stream without
    // granting send capacity to the blocked client.
    drop(server);
    let error = assert_ready!(driver.poll(&mut write)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<netty::Error>()
            .is_some()
    );
}

// Any 2xx to CONNECT opens the tunnel, not only 200.
// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5
#[test]
fn h2_connect_any_2xx_opens_tunnel() {
    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(Default::default());
    let mut proxy = HyperProxy::spawn(&driver, server_io, |_| {});
    driver.spawn(async move {
        let _ = conn.await;
    });
    driver.run();

    let request = Request::connect("localhost:443")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let accepted = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (response, _request, server) = proxy.exchange(&mut driver, &mut client, request, accepted);
    let response = response.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let mut upgraded = driver.finish(netty::upgrade::on(response)).unwrap();
    let mut server = server.unwrap();

    driver.finish(upgraded.write_all(b"ping")).unwrap();
    let mut received = [0; 4];
    driver.finish(server.read_exact(&mut received)).unwrap();
    assert_eq!(&received, b"ping");
    driver.finish(server.write_all(b"pong")).unwrap();
    driver.finish(upgraded.read_exact(&mut received)).unwrap();
    assert_eq!(&received, b"pong");
}

// Use only the low-level API so this also checks CONNECT-UDP without the masque feature.
#[test]
fn h2_connect_udp_rejects_capsule_headers() {
    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(Default::default());
    let mut proxy = HyperProxy::spawn(&driver, server_io, |builder| {
        builder.enable_connect_protocol();
    });
    driver.spawn(async move {
        let _ = conn.await;
    });
    driver.run();

    let mut request = Request::connect("https://localhost:443/masque/192.0.2.1/53/")
        .header("capsule-protocol", "?1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(::http2::ext::Protocol::from_static("connect-udp"));
    let response = Response::builder()
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (result, request, server) = proxy.exchange(&mut driver, &mut client, request, response);
    assert_eq!(request.method(), Method::CONNECT);
    let protocol = request.extensions().get::<hyper::ext::Protocol>().unwrap();
    assert_eq!(protocol.as_str(), "connect-udp");
    assert!(result.is_err(), "{result:?}");
    let reason = proxy_reset(&mut driver, &mut server.unwrap());
    assert_eq!(reason, h2::Reason::PROTOCOL_ERROR);
}

#[cfg(feature = "masque")]
#[tokio::test]
async fn h2_connect_udp_carries_capsules() {
    use netty::proxy::masque::UdpTunnel;

    let mut driver = Driver::new();
    let (mut client, conn, server_io) =
        driver.handshake(netty::http2::Http2Options::builder().build());
    let mut proxy = HyperProxy::spawn(&driver, server_io, |builder| {
        builder.enable_connect_protocol();
    });
    driver.run();
    driver.spawn(async move {
        conn.await.unwrap();
    });

    // Any 2xx opens the tunnel, not just 200 (RFC 9298 §3.5).
    let accepted = Response::builder()
        .status(StatusCode::ACCEPTED)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (response, request, server) =
        proxy.exchange(&mut driver, &mut client, connect_udp_request(), accepted);
    assert_eq!(request.method(), Method::CONNECT);
    let protocol = request.extensions().get::<hyper::ext::Protocol>().unwrap();
    assert_eq!(protocol.as_str(), "connect-udp");
    assert_eq!(request.uri(), "https://localhost:443/masque/192.0.2.1/53/");
    assert_eq!(request.headers()["capsule-protocol"], "?1");
    let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
    let mut server = server.unwrap();
    assert_eq!(tunnel.max_payload_size(), 65527);
    tunnel.try_send(b"ping").unwrap();
    let mut capsule = [0; 7];
    driver.finish(server.read_exact(&mut capsule)).unwrap();
    assert_eq!(&capsule, b"\0\x05\0ping");
    driver.finish(server.write_all(b"\0\x05\0pong")).unwrap();
    driver.finish(server.shutdown()).unwrap();
    let mut recv = || driver.finish(std::future::poll_fn(|cx| tunnel.poll_recv(cx)));
    assert_eq!(recv().unwrap().unwrap(), "pong");
    assert!(recv().unwrap().is_none());
}

// A plain test: every future is polled by hand, and in a tokio task that never yields, tokio's
// cooperative budget runs out and the wakeups it defers never run.
#[cfg(feature = "masque")]
#[test]
fn h2_connect_udp_resets_malformed_input_with_protocol_error() {
    use std::{future::poll_fn, pin::Pin};

    use netty::proxy::masque::{self, MasqueError, UdpTunnel};

    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(Default::default());
    driver.spawn(async move {
        let _ = conn.await;
    });
    let mut proxy = HyperProxy::spawn(&driver, server_io, |builder| {
        builder
            .enable_connect_protocol()
            .initial_stream_window_size(16);
    });
    driver.run();
    let idle = driver.tasks.len();

    // Sends a CONNECT-UDP request that the proxy answers with `response`.
    let mut connect = |driver: &mut Driver, response: Response<Bytes>| {
        let request = connect_udp_request();
        let (result, request, server) =
            proxy.exchange(driver, &mut client, request, response.map(Full::new));
        assert_eq!(request.method(), Method::CONNECT);
        let protocol = request.extensions().get::<hyper::ext::Protocol>().unwrap();
        assert_eq!(protocol.as_str(), "connect-udp");
        (result, server)
    };

    // A success that breaks the Capsule Protocol is malformed (RFC 9297 §3.2).
    for (status, header) in [
        (200, Some(("content-type", "application/octet-stream"))),
        (204, None),
    ] {
        let mut response = Response::builder().status(status);
        if let Some((name, value)) = header {
            response = response.header(name, value);
        }
        let (result, server) = connect(&mut driver, response.body(Bytes::new()).unwrap());
        let mut server = server.unwrap();
        assert!(result.is_err(), "{status} {header:?}");
        assert_eq!(
            proxy_reset(&mut driver, &mut server),
            h2::Reason::PROTOCOL_ERROR,
            "{status} {header:?}"
        );
    }

    // A refusal is not malformed, even with a body.
    let response = Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-length", "4")
        .body(Bytes::from_static(b"nope"))
        .unwrap();
    let (response, server) = connect(&mut driver, response);
    assert!(server.is_none());
    let mut response = response.unwrap();
    let result = UdpTunnel::from_http2(&mut response);
    assert!(
        matches!(
            result,
            Err(MasqueError::Unsuccessful(StatusCode::FORBIDDEN))
        ),
        "{result:?}"
    );
    // The refusal stays with the caller.
    let body = driver.finish(response.into_body().collect()).unwrap();
    assert_eq!(body.to_bytes(), "nope");

    // A malformed capsule, while the tunnel is open and after the client closed it.
    let malformed = [0, 0x80, 1, 0, 0, 0];
    for close in [false, true] {
        let (response, server) = connect(&mut driver, Response::new(Bytes::new()));
        let mut server = server.unwrap();
        let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
        if close {
            // Sending a capsule queued ahead of END_STREAM wakes the send task again while it
            // waits for a reset; the proxy's 16-byte window spreads that over window updates.
            tunnel.try_send(&[7; 64]).unwrap();
            driver.finish(poll_fn(|cx| tunnel.poll_close(cx))).unwrap();
            let mut received = Vec::new();
            driver.finish(server.read_to_end(&mut received)).unwrap();
            assert_eq!(received.len(), 68);
        }
        driver.finish(server.write_all(&malformed)).unwrap();
        let result = assert_ready!(task::spawn(poll_fn(|cx| tunnel.poll_recv(cx))).poll());
        assert!(matches!(result, Err(MasqueError::Malformed)), "{result:?}");
        if !close {
            // Dropped before the send task runs, the tunnel still leaves its reset behind.
            drop(tunnel);
        }
        assert_eq!(
            proxy_reset(&mut driver, &mut server),
            h2::Reason::PROTOCOL_ERROR,
            "{close}"
        );
    }

    // A send task waiting for a reset after END_STREAM ends once the tunnel drops.
    let (response, _server) = connect(&mut driver, Response::new(Bytes::new()));
    let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
    driver.finish(poll_fn(|cx| tunnel.poll_close(cx))).unwrap();
    drop(tunnel);
    driver.run();
    assert_eq!(driver.tasks.len(), idle, "a send task outlived its tunnel");

    // After a close, dropping the tunnel lets the stream end as usual.
    let (response, server) = connect(&mut driver, Response::new(Bytes::new()));
    let mut server = server.unwrap();
    let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
    driver.finish(server.shutdown()).unwrap();
    tunnel.try_send(&[7; 64]).unwrap();
    driver.finish(poll_fn(|cx| tunnel.poll_close(cx))).unwrap();
    drop(tunnel);
    let mut received = Vec::new();
    driver.finish(server.read_to_end(&mut received)).unwrap();
    assert_eq!(received.len(), 68, "capsule cut short");

    // Dropped before its close, the tunnel aborts the stream even while a capsule waits on the
    // proxy's flow control.
    let (response, server) = connect(&mut driver, Response::new(Bytes::new()));
    let mut server = server.unwrap();
    let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
    for _ in 0..2 {
        tunnel.try_send(&[7; 64]).unwrap();
        driver.run();
    }
    drop(tunnel);
    assert_eq!(proxy_reset(&mut driver, &mut server), h2::Reason::CANCEL);
    assert_eq!(driver.tasks.len(), idle, "a send task outlived its tunnel");

    // Hyper ends its side before it abandons the request and resets with NO_ERROR. The client
    // reads the END_STREAM, so the capsule it cuts short is malformed, and sees the reset on its
    // send side.
    let (response, server) = connect(&mut driver, Response::new(Bytes::new()));
    let mut server = server.unwrap();
    let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
    driver.finish(server.write_all(&[0, 5, 0, b'p'])).unwrap();
    drop(server);
    driver.run();
    assert_eq!(
        tunnel.try_send(b"after-reset"),
        Err(masque::SendError::Closed)
    );
    let error = driver
        .finish(poll_fn(|cx| tunnel.poll_flush(cx)))
        .unwrap_err();
    let error = error
        .get_ref()
        .unwrap()
        .downcast_ref::<netty::Error>()
        .unwrap();
    let cause = std::error::Error::source(error).unwrap();
    assert_eq!(
        cause.downcast_ref::<::http2::Error>().unwrap().reason(),
        Some(::http2::Reason::NO_ERROR)
    );
    let result = driver.finish(poll_fn(|cx| tunnel.poll_recv(cx)));
    assert!(matches!(result, Err(MasqueError::Malformed)), "{result:?}");

    // Without `UdpTunnel`, a kept response does not hold the stream open past its IO.
    let (response, server) = connect(&mut driver, Response::new(Bytes::new()));
    let mut server = server.unwrap();
    let mut response = response.unwrap();
    let mut io = driver.finish(netty::upgrade::on(&mut response)).unwrap();
    driver
        .finish(poll_fn(|cx| Pin::new(&mut io).poll_shutdown(cx)))
        .unwrap();
    drop(io);
    assert_eq!(proxy_reset(&mut driver, &mut server), h2::Reason::CANCEL);
    assert_eq!(driver.tasks.len(), idle, "a send task outlived its IO");
    drop(response);

    // Other Extended CONNECT protocols keep their rules: Content-Type is no reason to reset.
    let response = Response::builder()
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (response, _request, _server) = proxy.exchange(
        &mut driver,
        &mut client,
        extended_connect("/chat"),
        response,
    );
    let mut response = response.unwrap();
    // Even with valid framing, `UdpTunnel` refuses it and leaves the upgrade to the caller.
    response.headers_mut().remove("content-type");
    let result = UdpTunnel::from_http2(&mut response);
    assert!(
        matches!(result, Err(MasqueError::InvalidResponse)),
        "{result:?}"
    );
    assert!(driver.finish(netty::upgrade::on(&mut response)).is_ok());
}

// Plain for the same reason. A bare h2 server plays the proxy, because Hyper cannot send these
// frames: it drops or refuses Content-Length on a successful CONNECT, and it ends its side before
// any reset.
#[cfg(feature = "masque")]
#[test]
fn h2_connect_udp_treats_raw_proxy_framing_as_malformed() {
    use std::future::poll_fn;

    use netty::proxy::masque::{MasqueError, UdpTunnel};

    let mut driver = Driver::new();
    let (mut client, conn, server_io) = driver.handshake(Default::default());
    driver.spawn(async move {
        let _ = conn.await;
    });
    let (requests_tx, mut requests) = futures_channel::mpsc::unbounded();
    driver.spawn(async move {
        let mut builder = h2::server::Builder::new();
        builder.enable_connect_protocol();
        let mut server = builder.handshake::<_, Bytes>(server_io).await.unwrap();
        while let Some(Ok(request)) = server.accept().await {
            requests_tx.unbounded_send(request).unwrap();
        }
    });
    driver.run();

    let mut connect = |driver: &mut Driver, response: Response<()>| {
        let mut sending = task::spawn(client.try_send_request(connect_udp_request()));
        assert_pending!(driver.poll(&mut sending));
        let (_request, mut respond) = driver.finish(requests.next()).unwrap();
        let send = respond.send_response(response, false).unwrap();
        (assert_ready!(driver.poll(&mut sending)), send)
    };

    // Content-Length breaks the Capsule Protocol even at zero (RFC 9297 §3.2), and a nonzero one
    // gets this reset rather than the plain CONNECT `INTERNAL_ERROR`.
    for length in ["0", "5"] {
        let response = Response::builder()
            .header("content-length", length)
            .body(())
            .unwrap();
        let (result, mut send) = connect(&mut driver, response);
        assert!(result.is_err(), "{length}");
        let reason = driver.finish(poll_fn(|cx| send.poll_reset(cx))).unwrap();
        assert_eq!(reason, h2::Reason::PROTOCOL_ERROR, "{length}");
    }

    // A proxy reset with NO_ERROR or CANCEL reads as the end of the stream, so one inside a
    // capsule is malformed.
    for reason in [h2::Reason::NO_ERROR, h2::Reason::CANCEL] {
        let (response, mut send) = connect(&mut driver, Response::new(()));
        let mut tunnel = UdpTunnel::from_http2(&mut response.unwrap()).unwrap();
        send.send_data(Bytes::from_static(&[0, 5, 0, b'p']), false)
            .unwrap();
        driver.run();
        send.send_reset(reason);
        let result = driver.finish(poll_fn(|cx| tunnel.poll_recv(cx)));
        assert!(
            matches!(result, Err(MasqueError::Malformed)),
            "{reason:?}: {result:?}"
        );
    }
}
