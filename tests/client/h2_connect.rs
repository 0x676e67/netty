use std::{
    convert::Infallible,
    future::Future,
    io,
    sync::{Arc, Mutex, mpsc},
    task::Poll,
};

use bytes::Bytes;
use futures_channel::oneshot;
use futures_util::future::BoxFuture;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use netty::{conn::http2, rt::Executor as _, upgrade::Upgraded};
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
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

fn extended_connect(path: &str) -> Request<Empty<Bytes>> {
    let mut request = Request::connect(format!("https://localhost:443{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    request
        .extensions_mut()
        .insert(::http2::ext::Protocol::from_static("websocket"));
    request
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
    let (tx, rx) = mpsc::channel();
    let executor = Executor(tx);
    let mut driver = Driver {
        executor: executor.clone(),
        rx,
        tasks: Vec::new(),
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_tx, server_rx) = oneshot::channel();
    let server_tx = std::sync::Mutex::new(Some(server_tx));
    let upgrade_executor = executor.clone();
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        assert_eq!(request.method(), http::Method::CONNECT);
        if enable_connect_protocol {
            assert_eq!(
                request
                    .extensions()
                    .get::<hyper::ext::Protocol>()
                    .unwrap()
                    .as_str(),
                "websocket"
            );
            assert_eq!(request.uri().scheme_str(), Some("https"));
            assert_eq!(request.uri().authority().unwrap(), "localhost:443");
            assert_eq!(request.uri().path_and_query().unwrap(), "/chat?room=1");
        }
        let upgrade = hyper::upgrade::on(request);
        let tx = server_tx.lock().unwrap().take().unwrap();
        upgrade_executor.execute(async move {
            tx.send(upgrade.await.unwrap()).unwrap();
        });
        async { Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new())) }
    });
    let server_executor = executor.clone();
    let (mut client, conn) = driver
        .finish(
            http2::Builder::new(executor)
                .options(
                    netty::http2::Http2Options::builder()
                        .initial_window_size(1024)
                        .build(),
                )
                .handshake::<_, Empty<Bytes>>(client_io),
        )
        .unwrap();
    assert!(!conn.is_extended_connect_protocol_enabled());
    driver.spawn(async move {
        let mut builder = hyper::server::conn::http2::Builder::new(server_executor);
        builder.initial_stream_window_size(1024);
        if enable_connect_protocol {
            builder.enable_connect_protocol();
        }
        builder
            .serve_connection(TokioIo::new(server_io), service)
            .await
            .unwrap();
    });
    driver.run();
    assert_eq!(
        conn.is_extended_connect_protocol_enabled(),
        enable_connect_protocol
    );
    driver.spawn(async move {
        conn.await.unwrap();
    });
    let response = driver.finish(client.try_send_request(request)).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let upgraded = driver.finish(netty::upgrade::on(response)).unwrap();
    let server = TokioIo::new(driver.finish(server_rx).unwrap());
    (driver, upgraded, server, client)
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
        let (tx, rx) = mpsc::channel();
        let executor = Executor(tx);
        let mut driver = Driver {
            executor: executor.clone(),
            rx,
            tasks: Vec::new(),
        };
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (mut client, conn) = driver
            .finish(http2::Builder::new(executor.clone()).handshake::<_, Empty<Bytes>>(client_io))
            .unwrap();
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
                let mut builder = hyper::server::conn::http2::Builder::new(executor.clone());
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
async fn h2_extended_connect_follows_later_settings() {
    let (tx, rx) = mpsc::channel();
    let executor = Executor(tx);
    let mut driver = Driver {
        executor: executor.clone(),
        rx,
        tasks: Vec::new(),
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (mut client, conn) = driver
        .finish(http2::Builder::new(executor).handshake::<_, Empty<Bytes>>(client_io))
        .unwrap();
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
async fn h2_extended_connect_cancel_while_parked_releases_connection() {
    let (tx, rx) = mpsc::channel();
    let executor = Executor(tx);
    let mut driver = Driver {
        executor: executor.clone(),
        rx,
        tasks: Vec::new(),
    };
    let (client_io, _server_io) = tokio::io::duplex(64 * 1024);
    let (mut client, conn) = driver
        .finish(http2::Builder::new(executor).handshake::<_, Empty<Bytes>>(client_io))
        .unwrap();
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

    let (tx, rx) = mpsc::channel();
    let executor = Executor(tx);
    let mut driver = Driver {
        executor: executor.clone(),
        rx,
        tasks: Vec::new(),
    };
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
