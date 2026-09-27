use netty::conn::http3::datagram::{self, SendErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[tokio::test]
async fn dropping_rejected_connect_body_preserves_next_datagram_session() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            server_quic,
            _endpoints,
        } = pair_config(
            Http3Options::builder().max_concurrent_requests(1).build(),
            Exec,
            true,
            true,
            true,
            None,
        )
        .await;
        let mut client_driver = Box::pin(driver);
        let (reset_old, reset) = oneshot::channel();
        let (old_reset, reset_seen) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (_, mut rejected) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            let rejected_id = rejected.id().into_inner();
            rejected
                .send_response(
                    Response::builder()
                        .status(407)
                        .header("content-length", 65536)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            rejected
                .send_data(Bytes::from_static(b"denied"))
                .await
                .unwrap();
            // Retain the unfinished response while the client drops its Body.
            // With active=1, accepting the next request proves slot reclamation.
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_ne!(stream.id(), rejected.id());
            stream.send_response(Response::new(())).await.unwrap();
            reset.await.unwrap();
            rejected.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            rejected.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            // Late Datagrams for the rejected request must not be delivered to
            // its successor, even when that successor uses the only active slot.
            assert!(rejected_id / 4 < 64);
            server_quic
                .send_datagram(Bytes::from(vec![(rejected_id / 4) as u8, 99]))
                .unwrap();
            old_reset.send(()).unwrap();
            let packet = server_quic.read_datagram().await.unwrap();
            assert_eq!(u64::from(packet[0]) * 4, stream.id().into_inner());
            assert_eq!(&packet[1..], b"still alive");
            server_quic.send_datagram(packet).unwrap();
            assert!(stream.recv_data().await.unwrap().is_none());
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let mut rejected = tx.try_send_request(datagram_request()).await.unwrap();
        assert_eq!(rejected.status(), 407);
        assert!(datagram::on(&mut rejected).is_none());
        assert!(netty::upgrade::on(&mut rejected).await.is_err());
        drop(rejected);

        let mut response = tx.try_send_request(datagram_request()).await.unwrap();
        let (mut control, sender, mut receiver) = datagram::on(&mut response).unwrap().into_parts();
        reset_old.send(()).unwrap();
        reset_seen.await.unwrap();
        sender.try_send(Bytes::from_static(b"still alive")).unwrap();
        assert_eq!(receiver.recv().await.unwrap(), b"still alive"[..]);
        control.shutdown().await.unwrap();
        let mut body = Vec::new();
        control.read_to_end(&mut body).await.unwrap();
        assert!(body.is_empty());
        assert!(receiver.recv().await.is_none());
        drop(control);
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn control_fin_closes_only_its_datagram_direction() {
    for peer_first in [false, true] {
        bounded(async {
            let Pair {
                mut tx,
                driver,
                mut server,
                server_quic,
                _endpoints,
            } = pair_config(
                Http3Options::builder().max_concurrent_requests(1).build(),
                Exec,
                true,
                true,
                true,
                None,
            )
            .await;
            let mut client_driver = Box::pin(driver);
            let (finish_peer, finish) = oneshot::channel();
            let server_task = tokio::spawn(async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let tunnel = tokio::spawn(async move {
                    let (_, mut stream) = resolver.resolve_request().await.unwrap();
                    stream.send_response(Response::new(())).await.unwrap();
                    finish.await.unwrap();
                    stream.finish().await.unwrap();
                    let mut received = BytesMut::new();
                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                        let len = data.remaining();
                        received.extend_from_slice(&data.copy_to_bytes(len));
                    }
                    assert_eq!(received, "control");
                });
                // With active=1 this request can start only after the tunnel ends.
                let (_, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                tunnel.await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
                let _ = server.accept().await;
            });
            let mut response = tx.try_send_request(datagram_request()).await.unwrap();
            let (mut control, sender, mut receiver) =
                datagram::on(&mut response).unwrap().into_parts();
            // RFC 9297 §2.1 ties each Datagram direction to its stream half.
            // https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
            if !peer_first {
                control.write_all(b"control").await.unwrap();
                control.shutdown().await.unwrap();
                assert_eq!(
                    sender.try_send(Bytes::new()).unwrap_err().kind(),
                    SendErrorKind::Closed
                );
                let id = sender.stream_id().into_inner();
                assert!(id / 4 < 64);
                server_quic
                    .send_datagram(Bytes::from(vec![(id / 4) as u8, 42]))
                    .unwrap();
                assert_eq!(receiver.recv().await.unwrap(), [42][..]);
            }
            {
                let mut received = std::pin::pin!(receiver.recv());
                futures_util::future::poll_fn(|cx| {
                    assert!(received.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                finish_peer.send(()).unwrap();
                // FIN must wake a receiver even if nobody is reading control.
                assert!(received.await.is_none());
            }
            let mut bytes = Vec::new();
            control.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty());
            if peer_first {
                sender.try_send(Bytes::from_static(b"after FIN")).unwrap();
                let wire = server_quic.read_datagram().await.unwrap();
                assert_eq!(wire[0] as u64 * 4, sender.stream_id().into_inner());
                assert_eq!(&wire[1..], b"after FIN");
                control.write_all(b"control").await.unwrap();
                control.shutdown().await.unwrap();
            }
            assert_eq!(
                sender.try_send(Bytes::new()).unwrap_err().kind(),
                SendErrorKind::Closed
            );
            assert!(receiver.recv().await.is_none());
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
            drop(control);
            drop(tx);
            client_driver.as_mut().graceful_shutdown();
            client_driver.await.unwrap();
            server_task.await.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn control_reset_wakes_datagrams_and_releases_request() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_config(
            Http3Options::builder().max_concurrent_requests(1).build(),
            Exec,
            true,
            true,
            true,
            None,
        )
        .await;
        let mut client_driver = Box::pin(driver);
        let (reset_peer, reset) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let tunnel = tokio::spawn(async move {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                reset.await.unwrap();
                stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                let error = stream
                    .recv_data()
                    .await
                    .err()
                    .expect("expected client reset");
                assert!(
                    matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == h3::error::Code::H3_REQUEST_CANCELLED)
                );
            });
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            tunnel.await.unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let mut response = tx.try_send_request(datagram_request()).await.unwrap();
        let (mut control, sender, mut receiver) = datagram::on(&mut response).unwrap().into_parts();
        {
            let mut received = std::pin::pin!(receiver.recv());
            futures_util::future::poll_fn(|cx| {
                assert!(received.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            reset_peer.send(()).unwrap();
            assert!(received.await.is_none());
        }
        assert_eq!(
            sender.try_send(Bytes::new()).unwrap_err().kind(),
            SendErrorKind::Closed
        );
        // Datagram EOF alone cannot distinguish FIN from a reset. The reliable
        // control stream must retain the error even if its consumer reads later.
        assert!(control.read(&mut [0; 1]).await.is_err());
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
        drop(control);
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        server_task.await.unwrap();
    })
    .await;
}
