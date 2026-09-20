#[path = "support/quic.rs"]
mod native;

#[path = "http3/body.rs"]
mod body;
#[path = "http3/capture.rs"]
mod capture;
#[path = "http3/credit.rs"]
mod credit;
#[cfg(feature = "http3-datagram")]
#[path = "http3/datagram.rs"]
mod datagram;
#[cfg(feature = "http3-datagram")]
#[path = "http3/datagram_close.rs"]
mod datagram_close;
#[path = "http3/goaway.rs"]
mod goaway;
#[path = "http3/pause.rs"]
mod pause;
#[path = "http3/request_drop.rs"]
mod request_drop;
#[path = "http3/soak.rs"]
mod soak;
#[path = "http3/tls.rs"]
mod tls;

use std::{future::Future, time::Duration};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Request, Response, Version};
use http_body_util::{BodyExt, Full};
use tokio::{sync::oneshot, time::timeout};
use wreq_proto::{
    conn::http3::{Builder, Connection, SendRequest},
    http3::Http3Options,
    rt::Executor,
};

#[derive(Clone, Copy)]
struct Exec;

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Exec {
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

type ClientBody = Full<Bytes>;

type Server = h3::server::Connection<h3_quinn::Connection, Bytes>;

struct Pair<B = ClientBody, E = Exec> {
    tx: SendRequest<B>,
    driver: Connection<crate::native::Connection, B, E>,
    server: Server,
    _endpoints: (quic::Endpoint, quinn::Endpoint),
    server_quic: quinn::Connection,
}

async fn pair(options: Http3Options) -> Pair {
    pair_with(options, Exec).await
}

async fn pair_with<B, E>(options: Http3Options, exec: E) -> Pair<B, E>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    E: Executor<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>,
{
    pair_config(options, exec, false, false, false, None).await
}

async fn pair_config<B, E>(
    options: Http3Options,
    exec: E,
    _datagrams: bool,
    peer_datagrams: bool,
    extended: bool,
    bidi: Option<u32>,
) -> Pair<B, E>
where
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    E: Executor<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>,
{
    let (_, mut server_config, client_config) = tls::config();
    if let Some(bidi) = bidi {
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(bidi.into());
        server_config.transport_config(std::sync::Arc::new(transport));
    }
    let (client, server, endpoints) = quic_pair(server_config, client_config).await;
    let server_quic = server.clone();
    let ((tx, driver), server) = tokio::join!(
        async {
            let builder = Builder::new(exec).options(options);
            let transport = crate::native::Connection::new(client);
            #[cfg(feature = "http3-datagram")]
            if _datagrams {
                return builder.handshake_with_datagrams(transport).await.unwrap();
            }
            builder.handshake(transport).await.unwrap()
        },
        async {
            h3::server::builder()
                .enable_datagram(peer_datagrams)
                .enable_extended_connect(extended)
                .build(h3_quinn::Connection::new(server))
                .await
                .unwrap()
        }
    );
    Pair {
        tx,
        driver,
        server,
        _endpoints: endpoints,
        server_quic,
    }
}

async fn quic_pair(
    server_config: quinn::ServerConfig,
    client_config: quic::ClientConfig,
) -> (
    quic::Connection,
    quinn::Connection,
    (quic::Endpoint, quinn::Endpoint),
) {
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let client_endpoint = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, server) = tokio::join!(client, async {
        server_endpoint.accept().await.unwrap().await.unwrap()
    });
    (client.unwrap(), server, (client_endpoint, server_endpoint))
}

async fn bounded<F: Future>(future: F) -> F::Output {
    timeout(Duration::from_secs(10), future)
        .await
        .expect("HTTP/3 test timed out")
}

#[tokio::test]
async fn canceling_partially_written_headers_resets_stream_and_releases_slot() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let pause = pause::Pause::default();
        let (mut tx, driver) = Builder::new(Exec)
            .options(Http3Options::builder().max_concurrent_requests(1).build())
            .handshake::<_, ClientBody>(pause.wrap(crate::native::Connection::new(client)))
            .await
            .unwrap();
        let client_driver = tokio::spawn(driver);
        let mut server = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let request = tx.try_send_request(
            Request::get("https://localhost/canceled")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        );
        pause.blocked().await;
        assert_eq!(pause.observers(), 1);
        // Accept while the stream is still open so the reset cannot race the
        // server's initial stream discovery.
        let resolver = server.accept().await.unwrap().unwrap();
        drop(request);
        let error = resolver.resolve_request().await.err().unwrap();
        assert!(
            matches!(
                error,
                h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == h3::error::Code::H3_REQUEST_CANCELLED
            ),
            "{error}"
        );
        assert_eq!(
            pause.observers(),
            0,
            "canceled HEADERS retained stop observer"
        );
        pause.resume();
        let response = tx.try_send_request(
            Request::get("https://localhost/survivor")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        );
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.uri().path(), "/survivor");
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            drop(stream);
            match server.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                _ => panic!("unexpected request or connection failure"),
            }
        });
        assert!(response
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn response_header_budgets_have_distinct_failure_scopes() {
    bounded(async {
        for compressed in [false, true] {
            // Omit the advertised field limit so the upstream server can send
            // a section exceeding our local receive budget.
            let options = Http3Options::builder()
                .send_grease(false)
                .settings_order(Vec::new());
            let options = if compressed {
                options.max_qpack_decode_buffer_size(128)
            } else {
                options.max_field_section_size(128)
            };
            let Pair {
                mut tx,
                driver,
                mut server,
                server_quic,
                _endpoints,
            } = pair(options.build()).await;
            let client_driver = tokio::spawn(driver);
            let (rejected, notified) = oneshot::channel();
            let server_task = tokio::spawn(async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                while stream.recv_data().await.unwrap().is_some() {}
                stream
                    .send_response(
                        Response::builder()
                            .header("large", "a".repeat(4096))
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                notified.await.unwrap();
                if compressed {
                    let error = server_quic.closed().await;
                    assert!(matches!(error, quinn::ConnectionError::ApplicationClosed(ref close)
                        if close.error_code.into_inner() == h3::error::Code::H3_EXCESSIVE_LOAD.value()), "{error}");
                } else {
                    loop {
                        match stream.send_data(Bytes::from_static(b"probe")).await {
                            Ok(()) => tokio::task::yield_now().await,
                            Err(error) => {
                                assert!(matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                                    if code == h3::error::Code::H3_REQUEST_CANCELLED), "{error}");
                                break;
                            }
                        }
                    }
                    drop(stream);
                    let resolver = server.accept().await.unwrap().unwrap();
                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                    stream.send_response(Response::new(())).await.unwrap();
                    stream.finish().await.unwrap();
                    drop(stream);
                    match server.accept().await {
                        Ok(None) => {}
                        Err(error) if error.is_h3_no_error() => {}
                        _ => panic!("unexpected request or connection failure"),
                    }
                }
            });
            let error = tx
                .try_send_request(
                    Request::get("https://localhost/large")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap_err();
            assert!(!error.error().is_user());
            rejected.send(()).unwrap();
            if compressed {
                assert!(client_driver.await.unwrap().is_err());
                assert!(tx.ready().await.is_err());
            } else {
                let response = tx
                    .try_send_request(
                        Request::get("https://localhost/survivor")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
                drop(tx);
                client_driver.await.unwrap().unwrap();
            }
            server_task.await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn streaming_post_trailers_and_last_sender_drop() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let (received, ready) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), http::Method::POST);
                let mut body = BytesMut::new();
                while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                    let size = chunk.remaining();
                    body.extend_from_slice(&chunk.copy_to_bytes(size));
                }
                assert_eq!(body.len(), 128 * 1024);
                assert!(body.iter().all(|b| *b == 7));
                stream
                    .send_response(
                        Response::builder()
                            .header("content-length", "5")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                ready.await.unwrap();
                stream
                    .send_data(Bytes::from_static(b"hello"))
                    .await
                    .unwrap();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-complete", "yes".parse().unwrap());
                stream.send_trailers(trailers).await.unwrap();
                stream.finish().await.unwrap();
            });
            let _ = server.accept().await;
            stream_task.await.unwrap();
        });
        let response = tx
            .try_send_request(
                Request::post("https://localhost/")
                    .body(Full::new(Bytes::from(vec![7; 128 * 1024])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.version(), Version::HTTP_3);
        drop(tx);
        received.send(()).unwrap();
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["x-complete"], "yes");
        assert_eq!(body.to_bytes(), "hello");
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn conflicting_host_returns_request_without_closing_connection() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::builder().max_concurrent_requests(1).build()).await;
        let drive = tokio::spawn(driver);
        let peer = tokio::spawn(async move {
            let (request, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.uri().path(), "/unchanged");
            assert_eq!(request.headers()["host"], "localhost");
            let mut uploaded = BytesMut::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                uploaded.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            assert_eq!(uploaded, "unconsumed");
            stream.send_response(Response::new(())).await.unwrap();
            stream.send_data(uploaded.freeze()).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let request = Request::post("https://localhost/unchanged")
            .header("host", "other.local")
            .extension(42_usize)
            .body(Full::new(Bytes::from_static(b"unconsumed")))
            .unwrap();
        let mut error = tx.try_send_request(request).await.unwrap_err();
        assert!(error.error().is_user(), "{error:?}");
        assert!(!tx.is_closed());
        let mut request = error
            .take_message()
            .expect("local rejection consumed the request");
        assert_eq!(request.extensions().get::<usize>(), Some(&42));
        assert_eq!(request.headers()["host"], "other.local");
        request
            .headers_mut()
            .insert("host", "localhost".parse().unwrap());
        let response = tx.try_send_request(request).await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "unconsumed"
        );
        drop(tx);
        drive.await.unwrap().unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn unbounded_queue_returns_unattempted_requests_on_close() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        tx.ready().await.unwrap();
        let mut other = tx.clone();
        assert!(other.is_ready());
        let mut pending = Vec::new();
        // Exceed the former queue limit without polling the driver. Cloned
        // senders remain ready and every unsent request must be recoverable.
        for index in 0..64 {
            let sender = if index % 2 == 0 { &mut tx } else { &mut other };
            sender.ready().await.unwrap();
            pending.push(
                sender.try_send_request(
                    Request::get(format!("https://localhost/queued/{index}"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                ),
            );
        }
        drop(tx);
        assert!(other.is_ready());
        drop(driver);
        for (index, request) in pending.into_iter().enumerate() {
            let request = request.await.unwrap_err().take_message().unwrap();
            assert_eq!(request.uri().path(), format!("/queued/{index}"));
        }
        assert!(other.is_closed());
        assert!(other.ready().await.is_err());
        let request = other
            .try_send_request(
                Request::get("https://localhost/after-close")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap_err()
            .take_message()
            .unwrap();
        assert_eq!(request.uri().path(), "/after-close");
        drop(server);
    })
    .await;
}

#[tokio::test]
async fn dropped_response_body_cancels_a_pending_receive() {
    bounded(async {
        let Pair { mut tx, driver, mut server, _endpoints, .. } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let (dropped, wait_drop) = oneshot::channel();
        let (observed, wait_observed) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                while stream.recv_data().await.unwrap().is_some() {}
                stream.send_response(Response::new(())).await.unwrap();
                wait_drop.await.unwrap();
                let chunk = Bytes::from(vec![1; 64 * 1024]);
                loop {
                    if let Err(error) = stream.send_data(chunk.clone()).await {
                        assert!(matches!(error, h3::error::StreamError::RemoteTerminate { code, .. } if code == h3::error::Code::H3_REQUEST_CANCELLED));
                        observed.send(()).unwrap();
                        break;
                    }
                }
            });
            let second = server.accept().await.unwrap().unwrap();
            let second_task = tokio::spawn(async move {
                let (_, mut stream) = second.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            });
            let _ = server.accept().await;
            stream_task.await.unwrap();
            second_task.await.unwrap();
        });
        let response = tx.try_send_request(Request::get("https://localhost/").body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        drop(response);
        dropped.send(()).unwrap();
        wait_observed.await.unwrap();
        let next = tx.try_send_request(Request::get("https://localhost/after-cancel").body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        next.into_body().collect().await.unwrap();
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    }).await;
}

#[tokio::test]
async fn dropping_driver_reports_body_error_instead_of_eof() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                while stream.recv_data().await.is_ok_and(|data| data.is_some()) {}
                std::future::pending::<()>().await;
            });
            let _ = server.accept().await;
            stream_task.abort();
            let _ = stream_task.await;
        });
        let mut response = tx
            .try_send_request(
                Request::get("https://localhost/")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        client_driver.abort();
        assert!(client_driver.await.unwrap_err().is_cancelled());
        assert!(response.body_mut().frame().await.unwrap().is_err());
        assert!(response.body_mut().frame().await.is_none());
        assert!(tx.is_closed());
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn short_response_is_an_error_and_informationals_are_skipped() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream
                    .send_response(Response::builder().status(103).body(()).unwrap())
                    .await
                    .unwrap();
                stream
                    .send_response(
                        Response::builder()
                            .header("content-length", "10")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                stream
                    .send_data(Bytes::from_static(b"short"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            });
            let _ = server.accept().await;
            stream_task.await.unwrap();
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut received = BytesMut::new();
        let error = loop {
            match body
                .frame()
                .await
                .expect("truncated response ended without an error")
            {
                Ok(frame) => received.extend_from_slice(&frame.into_data().unwrap()),
                Err(error) => break error,
            }
        };
        assert_eq!(received, "short");
        assert!(!error.is_user());
        assert!(body.frame().await.is_none());
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn connect_flush_and_half_close_preserve_incoming_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), http::Method::CONNECT);
                stream.send_response(Response::new(())).await.unwrap();
                let mut size = 0;
                while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                    size += chunk.remaining();
                    while chunk.has_remaining() {
                        assert_eq!(chunk.get_u8(), 9);
                    }
                }
                assert_eq!(size, 128 * 1024);
                stream
                    .send_data(Bytes::from_static(b"received FIN"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            });
            let _ = server.accept().await;
            stream_task.await.unwrap();
        });
        let mut response = tx
            .try_send_request(
                Request::connect("localhost:443")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let mut tunnel = wreq_proto::upgrade::on(&mut response).await.unwrap();
        drop(tx);
        tunnel.write_all(&vec![9; 128 * 1024]).await.unwrap();
        tunnel.flush().await.unwrap();
        tunnel.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        tunnel.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"received FIN");
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn extended_connect_requires_peer_permission() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            match server.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                _ => panic!("Extended CONNECT was sent without permission"),
            }
        });
        let mut request = Request::connect("https://localhost/websocket")
            .body(Full::new(Bytes::new()))
            .unwrap();
        request
            .extensions_mut()
            .insert(http3::ext::Protocol::WEBSOCKET);
        let error = tx.try_send_request(request).await.unwrap_err();
        assert!(error.error().is_user());
        assert!(error.message().is_some());
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[derive(Clone, Copy)]
struct Discard;

impl<F> Executor<F> for Discard {
    fn execute(&self, future: F) {
        drop(future);
    }
}

#[tokio::test]
async fn executor_discard_returns_request_and_releases_active_slot() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_with::<ClientBody, _>(
            Http3Options::builder().max_concurrent_requests(1).build(),
            Discard,
        )
        .await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let _ = server.accept().await;
        });
        for _ in 0..2 {
            let error = tx
                .try_send_request(
                    Request::get("https://localhost/discard")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap_err();
            assert!(error.message().is_some());
        }
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn user_body_error_keeps_its_classification() {
    assert_user_body_error(std::io::Error::other("upload failed").into()).await;
}

async fn assert_user_body_error(cause: Box<dyn std::error::Error + Send + Sync>) {
    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    type Body = http_body_util::combinators::BoxBody<Bytes, BoxError>;
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_with::<Body, _>(Http3Options::default(), Exec).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            while let Ok(Some(resolver)) = server.accept().await {
                tasks.spawn(async move {
                    let _ = resolver.resolve_request().await;
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let frames =
            futures_util::stream::iter(vec![Err::<http_body::Frame<Bytes>, BoxError>(cause)]);
        let body = http_body_util::StreamBody::new(frames).boxed();
        let error = tx
            .try_send_request(
                Request::post("https://localhost/failure")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(error.error().is_user());
        assert!(!error.error().is_h3_request_rejected());
        assert!(error.message().is_none());
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[cfg(feature = "http3-datagram")]
fn datagram_request() -> Request<ClientBody> {
    let mut request = Request::connect("https://localhost/.well-known/masque/udp/localhost/443/")
        .body(Full::new(Bytes::new()))
        .unwrap();
    request
        .extensions_mut()
        .insert(http3::ext::Protocol::CONNECT_UDP);
    request
        .extensions_mut()
        .insert(wreq_proto::conn::http3::datagram::DatagramRequest);
    request
}

#[cfg(feature = "http3-datagram")]
#[tokio::test]
async fn datagram_sessions_route_by_stream_and_close_with_control() {
    use tokio::io::AsyncWriteExt;
    use wreq_proto::conn::http3::datagram::{self, SendErrorKind};
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            server_quic,
            _endpoints,
        } = pair_config::<ClientBody, _>(Http3Options::default(), Exec, true, true, true, None)
            .await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let resolver = server.accept().await.unwrap().unwrap();
                tasks.spawn(async move {
                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                    assert_eq!(
                        request
                            .extensions()
                            .get::<h3::ext::Protocol>()
                            .unwrap()
                            .as_str(),
                        "connect-udp"
                    );
                    stream.send_response(Response::new(())).await.unwrap();
                    assert!(stream.recv_data().await.unwrap().is_none());
                    stream.finish().await.unwrap();
                });
            }
            let _ = server.accept().await;
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let mut first = tx.try_send_request(datagram_request()).await.unwrap();
        let mut second = tx.try_send_request(datagram_request()).await.unwrap();
        let (mut first_io, first_tx, mut first_rx) = datagram::on(&mut first).unwrap().into_parts();
        let (mut second_io, second_tx, mut second_rx) =
            datagram::on(&mut second).unwrap().into_parts();
        assert_ne!(first_tx.stream_id(), second_tx.stream_id());
        let limit = first_tx.max_datagram_size().unwrap();
        let oversized = Bytes::from(vec![0; limit + 1]);
        let error = first_tx.try_send(oversized.clone()).unwrap_err();
        assert_eq!(error.kind(), SendErrorKind::TooLarge);
        assert_eq!(error.into_payload(), oversized);
        first_tx.try_send(Bytes::from_static(b"first")).unwrap();
        second_tx.try_send(Bytes::new()).unwrap();
        let packet1 = server_quic.read_datagram().await.unwrap();
        let packet2 = server_quic.read_datagram().await.unwrap();
        assert_eq!(packet1[0] as u64 * 4, first_tx.stream_id().into_inner());
        assert_eq!(&packet1[1..], b"first");
        assert_eq!(packet2.len(), 1);
        assert_eq!(packet2[0] as u64 * 4, second_tx.stream_id().into_inner());
        // Reversing delivery must not exchange the two sessions' receive queues.
        server_quic.send_datagram(packet2).unwrap();
        server_quic.send_datagram(packet1).unwrap();
        assert_eq!(second_rx.recv().await.unwrap(), Bytes::new());
        assert_eq!(first_rx.recv().await.unwrap(), b"first"[..]);
        first_io.shutdown().await.unwrap();
        assert_eq!(
            first_tx.try_send(Bytes::new()).unwrap_err().kind(),
            SendErrorKind::Closed
        );
        drop(first_io);
        assert!(first_rx.recv().await.is_none());
        second_io.shutdown().await.unwrap();
        drop(second_io);
        assert_eq!(
            second_tx.try_send(Bytes::new()).unwrap_err().kind(),
            SendErrorKind::Closed
        );
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[cfg(feature = "http3-datagram")]
#[tokio::test]
async fn datagram_on_ordinary_request_resets_only_that_stream() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            server_quic,
            _endpoints,
        } = pair_config::<ClientBody, _>(
            Http3Options::builder().max_concurrent_requests(1).build(),
            Exec,
            true,
            true,
            false,
            None,
        )
        .await;
        let client_driver = tokio::spawn(driver);
        let (send_packet, ready) = oneshot::channel();
        let (reset, reset_seen) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let first = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                let id = stream.id().into_inner();
                stream.send_response(Response::new(())).await.unwrap();
                ready.await.unwrap();
                server_quic
                    .send_datagram(Bytes::from(vec![(id / 4) as u8, 7]))
                    .unwrap();
                // The response write half observes STOP_SENDING, not a connection close.
                let mut stopped = false;
                for _ in 0..1024 {
                    match stream.send_data(Bytes::from(vec![1; 16384])).await {
                        Err(h3::error::StreamError::RemoteTerminate { code, .. }) => {
                            assert_eq!(code.value(), 0x33);
                            stopped = true;
                            break;
                        }
                        result => result.unwrap(),
                    }
                    tokio::task::yield_now().await;
                }
                assert!(stopped);
                reset.send(()).unwrap();
            });
            let resolver = server.accept().await.unwrap().unwrap();
            let second = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            });
            let _ = server.accept().await;
            first.await.unwrap();
            second.await.unwrap();
        });
        let canceled_response = tx
            .try_send_request(
                Request::get("https://localhost/ordinary")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        send_packet.send(()).unwrap();
        // Cancellation must reach the peer and release admission even when
        // the application retains the response without ever polling its Body.
        reset_seen.await.unwrap();
        let response = tx
            .try_send_request(
                Request::get("https://localhost/healthy")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
        assert!(canceled_response.into_body().collect().await.is_err());
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[cfg(feature = "http3-datagram")]
#[tokio::test]
async fn datagram_unavailable_preserves_reliable_control_stream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wreq_proto::conn::http3::datagram::{self, SendErrorKind};
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_config::<ClientBody, _>(Http3Options::default(), Exec, true, false, true, None)
            .await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                while let Some(mut bytes) = stream.recv_data().await.unwrap() {
                    let size = bytes.remaining();
                    stream.send_data(bytes.copy_to_bytes(size)).await.unwrap();
                }
                stream.finish().await.unwrap();
            });
            let _ = server.accept().await;
            stream_task.await.unwrap();
        });
        let mut response = tx.try_send_request(datagram_request()).await.unwrap();
        let (mut control, sender, _) = datagram::on(&mut response).unwrap().into_parts();
        assert_eq!(sender.max_datagram_size(), None);
        assert_eq!(
            sender.try_send(Bytes::new()).unwrap_err().kind(),
            SendErrorKind::Unavailable
        );
        // RFC 9297 DATAGRAM Capsule: type=0, length=2, opaque bytes=[0,42].
        control.write_all(&[0, 2, 0, 42]).await.unwrap();
        control.shutdown().await.unwrap();
        let mut echo = Vec::new();
        control.read_to_end(&mut echo).await.unwrap();
        assert_eq!(echo, [0, 2, 0, 42]);
        drop(control);
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn forbidden_response_fields_fail_the_request_without_closing_connection() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for header in [
                Some("connection"),
                Some("transfer-encoding"),
                Some("te"),
                None,
            ] {
                let resolver = server.accept().await.unwrap().unwrap();
                tasks.spawn(async move {
                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                    let mut response = Response::new(());
                    if let Some(header) = header {
                        response
                            .headers_mut()
                            .insert(header, "trailers".parse().unwrap());
                    }
                    stream.send_response(response).await.unwrap();
                    let _ = stream.finish().await;
                });
            }
            let _ = server.accept().await;
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        for _ in 0..3 {
            let error = tx
                .try_send_request(
                    Request::get("https://localhost/invalid")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap_err();
            assert!(!error.error().is_user());
            assert!(error.message().is_none());
        }
        let response = tx
            .try_send_request(
                Request::get("https://localhost/valid")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.into_body().collect().await.unwrap();
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[derive(Debug)]
struct UnfinishedBody {
    ready_empty: bool,
    polled: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}

impl http_body::Body for UnfinishedBody {
    type Data = Bytes;

    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if let Some(polled) = self.polled.take() {
            let _ = polled.send(());
        }
        if self.ready_empty {
            std::task::Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::new()))))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl Drop for UnfinishedBody {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

#[tokio::test]
async fn peer_stop_cancels_pending_upload_without_losing_response() {
    peer_stop_cancels_upload(false).await;
}

#[tokio::test]
async fn peer_stop_cancels_ready_empty_upload_without_losing_response() {
    peer_stop_cancels_upload(true).await;
}

async fn peer_stop_cancels_upload(ready_empty: bool) {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_with::<UnfinishedBody, _>(
            Http3Options::builder().max_concurrent_requests(1).build(),
            Exec,
        )
        .await;
        let client_driver = tokio::spawn(driver);
        let (polled, body_polled) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut first_body = Some(body_polled);
            let mut streams = Vec::new();
            loop {
                let resolver = match server.accept().await {
                    Ok(Some(resolver)) => resolver,
                    Ok(None) => break,
                    Err(error) if error.is_h3_no_error() => break,
                    Err(error) => panic!("unexpected connection error: {error}"),
                };
                let body_polled = first_body.take();
                streams.push(tokio::spawn(async move {
                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                    if let Some(body_polled) = body_polled {
                        body_polled.await.unwrap();
                    }
                    stream.send_response(Response::new(())).await.unwrap();
                    stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                    stream
                        .send_data(Bytes::from_static(b"early response"))
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }));
            }
            assert_eq!(streams.len(), 2);
            for stream in streams {
                stream.await.unwrap();
            }
        });
        let mut polled = Some(polled);
        // With one active slot, the second request proves cancellation releases
        // admission credit without discarding either complete early response.
        for _ in 0..2 {
            let (dropped, body_dropped) = oneshot::channel();
            let response = tx
                .try_send_request(
                    Request::post("https://localhost/early")
                        .header("content-length", 1024)
                        .body(UnfinishedBody {
                            ready_empty,
                            polled: polled.take(),
                            dropped: Some(dropped),
                        })
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                b"early response"[..]
            );
            timeout(Duration::from_secs(1), body_dropped)
                .await
                .expect("peer STOP_SENDING must cancel the unfinished upload")
                .unwrap();
        }
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn dropped_unpolled_response_after_fin_cancels_pending_upload() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let pause = pause::Pause::default();
        pause.resume();
        let (mut tx, driver) = Builder::new(Exec)
            .options(Http3Options::builder().max_concurrent_requests(1).build())
            .handshake::<_, UnfinishedBody>(pause.wrap(crate::native::Connection::new(client)))
            .await
            .unwrap();
        let client_driver = tokio::spawn(driver);
        let mut server = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let (polled, body_pending) = oneshot::channel();
        let (dropped, body_dropped) = oneshot::channel();
        let (reset_seen, reset_observed) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let stream_task = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                body_pending.await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
                let result = stream.recv_data().await;
                assert!(matches!(result,
                    Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED));
                let _ = reset_seen.send(());
            });
            let _ = server.accept().await;
            stream_task.await.unwrap();
        });
        let response = tx.try_send_request(
            Request::post("https://localhost/response-before-upload")
                .body(UnfinishedBody {
                    ready_empty: false,
                    polled: Some(polled),
                    dropped: Some(dropped),
                })
                .unwrap(),
        );
        // The response has entered the callback and its receive side reached
        // FIN, but the caller has never polled the response future. Dropping
        // that future must still cancel the independently pending upload.
        pause.received_fin().await;
        drop(response);
        body_dropped.await.unwrap();
        reset_observed.await.unwrap();
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
        assert_eq!(pause.observers(), 0);
    })
    .await;
}

#[tokio::test]
async fn canceled_request_waiting_for_quic_credit_releases_active_slot() {
    bounded(async {
        let (_, mut server_config, client_config) = tls::config();
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(0_u32.into());
        server_config.transport_config(std::sync::Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let server_quic = server.clone();
        let pause = pause::Pause::default();
        pause.resume();
        let (mut tx, driver) = Builder::new(Exec)
            .options(Http3Options::builder().max_concurrent_requests(1).build())
            .handshake::<_, ClientBody>(pause.wrap(crate::native::Connection::new(client)))
            .await
            .unwrap();
        let mut server = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let client_driver = tokio::spawn(driver);
        let canceled = tx.try_send_request(
            Request::get("https://localhost/canceled")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        );
        // Observe the actual open attempt: readiness no longer reserves a slot
        // or implies that the queued request has entered the active set.
        pause.waiting_for_credit().await;
        drop(canceled);
        let response = tx.try_send_request(
            Request::get("https://localhost/survivor")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        );
        pause.waiting_for_credit().await;
        server_quic.set_max_concurrent_bi_streams(1_u32.into());
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.uri().path(), "/survivor");
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            drop(stream);
            match server.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                _ => panic!("unexpected request or connection failure"),
            }
        });
        assert!(response
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn goaway_wakes_requests_waiting_for_stream_credit() {
    bounded(async {
        let (_, mut server_config, client_config) = tls::config();
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(0_u32.into());
        server_config.transport_config(std::sync::Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let pause = pause::Pause::default();
        let (mut tx, driver) = Builder::new(Exec)
            .handshake::<_, ClientBody>(pause.wrap(crate::native::Connection::new(client)))
            .await
            .unwrap();
        let client_driver = tokio::spawn(driver);
        let mut server = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let mut requests = Vec::new();
        for _ in 0..3 {
            requests.push(
                tx.try_send_request(
                    Request::get("https://localhost/not-opened")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                ),
            );
            pause.waiting_for_credit().await;
        }
        tx.ready().await.unwrap();
        let mut observer = tx.clone();
        assert!(observer.is_ready());
        server.shutdown(0).await.unwrap();
        let server_task = tokio::spawn(async move {
            match server.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                _ => panic!("a request was opened after GOAWAY"),
            }
        });
        // The peer grants no new credit and keeps the connection open. Only
        // GOAWAY may release this request; an idle timeout is not the result.
        for request in requests {
            let error = request.await.unwrap_err();
            assert!(!error.error().is_timeout());
        }
        client_driver.await.unwrap().unwrap();
        assert!(observer.ready().await.is_err());
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn goaway_rejects_new_requests_but_drains_existing_response() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let observer = tx.clone();
        let (draining, drained) = oneshot::channel();
        let client_driver = tokio::spawn(async move {
            let mut driver = Box::pin(driver);
            let mut draining = Some(draining);
            std::future::poll_fn(|cx| {
                let result = driver.as_mut().poll(cx);
                if observer.is_closed() {
                    if let Some(draining) = draining.take() {
                        draining.send(()).unwrap();
                    }
                }
                result
            })
            .await
        });
        let (goaway, requested) = oneshot::channel();
        let (finish, permitted) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream
                .send_response(
                    Response::builder()
                        .header("content-length", 5)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            requested.await.unwrap();
            server.shutdown(1).await.unwrap();
            let body = tokio::spawn(async move {
                permitted.await.unwrap();
                stream
                    .send_data(Bytes::from_static(b"drain"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            });
            match server.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                _ => panic!("unexpected request or connection failure"),
            }
            body.await.unwrap();
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        tx.ready().await.unwrap();
        let mut blocked = tx.clone();
        assert!(blocked.is_ready());
        goaway.send(()).unwrap();
        drained.await.unwrap();
        assert!(blocked.ready().await.is_err());
        assert!(tx.is_closed());
        let rejected = tx
            .try_send_request(
                Request::get("https://localhost/not-sent")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap_err()
            .take_message()
            .unwrap();
        assert_eq!(rejected.uri().path(), "/not-sent");
        finish.send(()).unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "drain"
        );
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn canceling_handshake_waiting_for_control_stream_closes_quic() {
    bounded(async {
        let (_, mut server_config, client_config) = tls::config();
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(0_u32.into());
        server_config.transport_config(std::sync::Arc::new(transport));
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let client_endpoint = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let client = client_endpoint
            .connect(server_endpoint.local_addr().unwrap(), "localhost")
            .unwrap();
        let (client, server) = tokio::join!(client, async {
            server_endpoint.accept().await.unwrap().await.unwrap()
        });
        // Keep an independent handle alive: dropping the last QUIC handle alone
        // must not be what makes the remote close observable.
        let client = client.unwrap();
        let mut handshake = Box::pin(
            Builder::new(Exec)
                .handshake::<_, ClientBody>(crate::native::Connection::new(client.clone())),
        );
        assert!(futures_util::poll!(&mut handshake).is_pending());
        drop(handshake);
        match server.closed().await {
            quinn::ConnectionError::ApplicationClosed(error) => {
                assert_eq!(
                    error.error_code.into_inner(),
                    http3::error::Code::H3_NO_ERROR.value()
                );
            }
            error => panic!("unexpected handshake cancellation: {error}"),
        }
    })
    .await;
}

#[tokio::test]
async fn settings_order_and_configured_values_reach_upstream_server() {
    use wreq_proto::http3::SettingId;
    bounded(async {
        for &native in &[
            false,
            #[cfg(feature = "http3-datagram")]
            true,
        ] {
            let (_, server_config, client_config) = tls::config();
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let capture = capture::Capture::default();
            let options = Http3Options::builder()
                .send_grease(false)
                .max_field_section_size(32100)
                .qpack_blocked_streams(Some(0))
                .settings_order(vec![
                    SettingId::QPACK_MAX_BLOCKED_STREAMS,
                    SettingId(0xfafa),
                    SettingId::MAX_HEADER_LIST_SIZE,
                    SettingId::QPACK_MAX_TABLE_CAPACITY,
                    SettingId::H3_DATAGRAM,
                ])
                .build();
            let builder = Builder::new(Exec).options(options);
            let transport = crate::native::Connection::new(client);
            #[cfg(feature = "http3-datagram")]
            let (mut tx, driver) = if native {
                builder
                    .handshake_with_datagrams::<_, ClientBody>(transport)
                    .await
            } else {
                builder.handshake::<_, ClientBody>(transport).await
            }
            .unwrap();
            #[cfg(not(feature = "http3-datagram"))]
            let (mut tx, driver) = builder.handshake::<_, ClientBody>(transport).await.unwrap();
            let mut server = h3::server::builder()
                .enable_datagram(native)
                .build::<_, Bytes>(capture.connection(server))
                .await
                .unwrap();
            let client_driver = tokio::spawn(driver);
            let server_task = tokio::spawn(async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
                drop(stream);
                let _ = server.accept().await;
            });
            let response = tx
                .try_send_request(
                    Request::get("https://localhost/")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            response.into_body().collect().await.unwrap();
            assert_eq!(
                capture.settings().await,
                vec![(7, 0), (6, 32100), (0x33, u64::from(native))]
            );
            drop(tx);
            client_driver.await.unwrap().unwrap();
            server_task.await.unwrap();
        }
    })
    .await;
}

#[cfg(feature = "http3-datagram")]
#[tokio::test]
async fn datagram_handshake_rejects_order_omitting_its_setting() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, _server, _endpoints) = quic_pair(server_config, client_config).await;
        let result = Builder::new(Exec)
            .options(Http3Options::builder().settings_order(vec![]).build())
            .handshake_with_datagrams::<_, ClientBody>(crate::native::Connection::new(client))
            .await;
        assert!(result.is_err());
    })
    .await;
}

#[tokio::test]
async fn invalid_response_lengths_signal_message_error_and_preserve_connection() {
    bounded(async {
        let Pair { mut tx, driver, mut server, _endpoints, .. } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let (rejected, mut notified) = tokio::sync::mpsc::channel(1);
        let (observed, mut confirmed) = tokio::sync::mpsc::channel(1);
        let server_task = tokio::spawn(async move {
            for (status, length) in [(200, "invalid"), (200, "1, 2"), (103, "0"), (204, "0")] {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                while stream.recv_data().await.unwrap().is_some() {}
                stream.send_response(Response::builder().status(status).header("content-length", length).body(()).unwrap()).await.unwrap();
                if status == 103 {
                    // A valid final response must not hide a malformed 1xx.
                    let _ = stream.send_response(Response::new(())).await;
                }
                notified.recv().await.unwrap();
                loop {
                    match stream.send_data(Bytes::from_static(b"probe")).await {
                        Ok(()) => tokio::task::yield_now().await,
                        Err(error) => {
                            assert!(matches!(error, h3::error::StreamError::RemoteTerminate { code, .. } if code == h3::error::Code::H3_MESSAGE_ERROR), "{status} {length}: {error}");
                            break;
                        }
                    }
                }
                observed.send(()).await.unwrap();
            }
            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            drop(stream);
            let _ = server.accept().await;
        });
        for _ in 0..4 {
            let error = tx.try_send_request(Request::get("https://localhost/invalid")
                .body(Full::new(Bytes::new())).unwrap()).await.unwrap_err();
            assert!(!error.error().is_user());
            rejected.send(()).await.unwrap();
            confirmed.recv().await.unwrap();
        }
        let response = tx.try_send_request(Request::get("https://localhost/survivor")
            .body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        response.into_body().collect().await.unwrap();
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    }).await;
}

#[tokio::test]
async fn head_204_and_304_end_without_content() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            for (status, length) in [(200, Some("123")), (204, None), (304, Some("123"))] {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                let mut response = Response::builder().status(status);
                if let Some(length) = length {
                    response = response.header("content-length", length);
                }
                stream
                    .send_response(response.body(()).unwrap())
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
            let _ = server.accept().await;
        });
        for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 304)] {
            let response = tx
                .try_send_request(
                    Request::builder()
                        .method(method)
                        .uri("https://localhost/")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
            let mut body = response.into_body();
            assert!(body.frame().await.is_none());
            assert!(http_body::Body::is_end_stream(&body));
        }
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn unknown_length_upload_and_response_preserve_trailers() {
    bounded(async {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-upload-complete", "yes".parse().unwrap());
        let frames = vec![
            Ok::<_, std::convert::Infallible>(http_body::Frame::data(Bytes::from_static(b"one"))),
            Ok(http_body::Frame::data(Bytes::from_static(b"two"))),
            Ok(http_body::Frame::trailers(trailers)),
        ];
        let body = http_body_util::StreamBody::new(futures_util::stream::iter(frames));
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_with(Http3Options::default(), Exec).await;
        let client_driver = tokio::spawn(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            let mut uploaded = BytesMut::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let len = data.remaining();
                uploaded.extend_from_slice(&data.copy_to_bytes(len));
            }
            assert_eq!(uploaded.as_ref(), b"onetwo");
            let trailers = stream.recv_trailers().await.unwrap().unwrap();
            assert_eq!(trailers["x-upload-complete"], "yes");
            stream.send_response(Response::new(())).await.unwrap();
            stream.send_data(uploaded.freeze()).await.unwrap();
            stream.send_trailers(trailers).await.unwrap();
            stream.finish().await.unwrap();
            drop(stream);
            let _ = server.accept().await;
        });
        let response = tx
            .try_send_request(Request::post("https://localhost/").body(body).unwrap())
            .await
            .unwrap();
        assert!(!response.headers().contains_key("content-length"));
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["x-upload-complete"], "yes");
        assert_eq!(body.to_bytes(), "onetwo");
        drop(tx);
        client_driver.await.unwrap().unwrap();
        server_task.await.unwrap();
    })
    .await;
}
