use std::{future::Future, io, sync::mpsc, task::Poll};

use bytes::Bytes;
use futures_channel::oneshot;
use futures_util::future::BoxFuture;
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::service::service_fn;
use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_test::{assert_pending, assert_ready, task};
use wreq_proto::{conn::http2, rt::Executor as _, upgrade::Upgraded};

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

impl<F> wreq_proto::rt::Executor<F> for Executor
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
                    wreq_proto::http2::Http2Options::builder()
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
    let upgraded = driver.finish(wreq_proto::upgrade::on(response)).unwrap();
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
    assert!(error
        .get_ref()
        .unwrap()
        .downcast_ref::<wreq_proto::Error>()
        .is_some());
}
