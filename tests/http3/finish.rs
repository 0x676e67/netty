use std::convert::Infallible;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[tokio::test]
async fn early_response_drain_waits_for_upload_fin_ack() {
    check_drain(false).await;
}

#[tokio::test]
async fn tunnel_drain_waits_for_upload_fin_ack() {
    check_drain(true).await;
}

async fn check_drain(connect: bool) {
    for drop_sender in [false, true] {
        bounded(async {
            let (_, server_config, client_config) = tls::config();
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let pause = pause::Pause::default();
            pause.hold_finish_ack();
            let ((mut tx, driver), mut server) = tokio::join!(
                async {
                    Builder::new(Exec).handshake(pause.wrap(native::Connection::new(client))).await.unwrap()
                },
                async {
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)).await.unwrap()
                },
            );
            let (shutdown, requested) = oneshot::channel();
            let mut drive = tokio::spawn(async move {
                let mut driver = std::pin::pin!(driver);
                tokio::select! {
                    result = &mut driver => return result,
                    _ = requested => {
                        driver.as_mut().graceful_shutdown();
                    }
                }
                driver.await
            });
            let (read, received) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let transfer = tokio::spawn(async move {
                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                    // Complete the response before the client starts its upload.
                    stream.send_response(Response::new(())).await.unwrap();
                    stream.finish().await.unwrap();
                    let mut total = 0;
                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                        total += data.remaining();
                        while data.has_remaining() { assert_eq!(data.get_u8(), 9); }
                    }
                    assert_eq!(total, 128 * 1024);
                    read.send(()).unwrap();
                });
                let _ = server.accept().await;
                transfer.await.unwrap();
            });
            let (upload, allowed) = oneshot::channel();
            let body = if connect {
                Full::new(Bytes::new()).boxed()
            } else {
                http_body_util::StreamBody::new(futures_util::stream::once(async move {
                    allowed.await.unwrap();
                    Ok::<_, Infallible>(http_body::Frame::data(Bytes::from(vec![9; 128 * 1024])))
                })).boxed()
            };
            let request = if connect { Request::connect("localhost:443") } else { Request::post("https://localhost/") };
            let mut response = tx.try_send_request(request.body(body).unwrap()).await.unwrap();
            if drop_sender {
                drop(tx);
            } else {
                shutdown.send(()).unwrap();
            }
            if connect {
                let mut tunnel = netty::upgrade::on(&mut response).await.unwrap();
                let mut incoming = Vec::new();
                tunnel.read_to_end(&mut incoming).await.unwrap();
                assert!(incoming.is_empty());
                tunnel.write_all(&vec![9; 128 * 1024]).await.unwrap();
                tunnel.shutdown().await.unwrap();
            } else {
                assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
                upload.send(()).unwrap();
            }
            tokio::select! {
                _ = pause.waiting_for_finish_ack() => {},
                result = &mut drive => panic!("driver closed before FIN acknowledgment: {result:?}"),
            }
            assert!(!drive.is_finished());
            received.await.unwrap();
            pause.release_finish_ack();
            drive.await.unwrap().unwrap();
            peer.await.unwrap();
        }).await;
    }
}

#[tokio::test]
async fn empty_request_drain_waits_for_fin_ack() {
    for drop_sender in [false, true] {
        bounded(async {
            let (_, server_config, client_config) = tls::config();
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let pause = pause::Pause::default();
            pause.hold_finish_ack();
            let ((mut tx, driver), mut server) = tokio::join!(
                async {
                    Builder::new(Exec)
                        .handshake::<_, ClientBody>(pause.wrap(native::Connection::new(client)))
                        .await
                        .unwrap()
                },
                async {
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server))
                        .await
                        .unwrap()
                },
            );
            let (shutdown, requested) = oneshot::channel();
            let mut drive = tokio::spawn(async move {
                let mut driver = std::pin::pin!(driver);
                tokio::select! {
                    result = &mut driver => return result,
                    _ = requested => {
                        driver.as_mut().graceful_shutdown();
                    }
                }
                driver.await
            });
            let peer = tokio::spawn(async move {
                let (_, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
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
            assert!(response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
            if drop_sender {
                drop(tx);
            } else {
                shutdown.send(()).unwrap();
            }
            // The request FIN is sent but not yet acknowledged; the drain must
            // wait for it even though no upload task exists.
            tokio::select! {
                _ = pause.waiting_for_finish_ack() => {},
                result = &mut drive => panic!("driver closed before FIN acknowledgment: {result:?}"),
            }
            assert!(!drive.is_finished());
            pause.release_finish_ack();
            drive.await.unwrap().unwrap();
            peer.await.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn empty_request_fails_when_its_fin_reports_a_stream_error() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let pause = pause::Pause::default();
        pause.fail_finish_ack();
        let ((mut tx, driver), mut server) = tokio::join!(
            async {
                Builder::new(Exec)
                    .handshake::<_, ClientBody>(pause.wrap(native::Connection::new(client)))
                    .await
                    .unwrap()
            },
            async {
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server))
                    .await
                    .unwrap()
            },
        );
        let mut drive = Box::pin(driver);
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        // The head is in, but the FIN acknowledgment reports a stream error:
        // the request fails instead of yielding a response on a broken stream.
        let error = tx
            .try_send_request(
                Request::get("https://localhost/")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(!error.error().is_user());
        assert!(error.message().is_none());
        drop(tx);
        drive.as_mut().graceful_shutdown();
        drive.await.unwrap();
        peer.await.unwrap();
    })
    .await;
}
