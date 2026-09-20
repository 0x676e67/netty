//! Dependency cancellation contracts against an upstream h3 server.
use std::sync::Arc;

use futures_util::FutureExt;

use super::*;

#[tokio::test]
async fn dropping_request_or_send_half_resets_upload() {
    bounded(async {
        for split in [false, true] {
            let (_, server_config, client_config) = tls::config();
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let (client, server) = tokio::join!(
                http3::client::new(http3_quic::Connection::new(client)),
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)),
            );
            let (mut driver, mut sender) = client.unwrap();
            let mut server = server.unwrap();
            let drive = tokio::spawn(async move { driver.wait_idle().await });
            let (accepted_tx, accepted_rx) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let (_, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                accepted_tx.send(()).unwrap();
                let error = stream
                    .recv_data()
                    .await
                    .err()
                    .expect("upload must be reset");
                assert!(
                    matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == h3::error::Code::H3_REQUEST_CANCELLED.value())
                );
                if split {
                    stream.send_response(Response::new(())).await.unwrap();
                    stream
                        .send_data(Bytes::from_static(b"still receiving"))
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }
                server
            });
            let stream = sender
                .send_request(Request::post("https://localhost/drop").body(()).unwrap())
                .await
                .unwrap();
            accepted_rx.await.unwrap();
            if split {
                let (send, mut recv) = stream.split();
                drop(send);
                assert_eq!(recv.recv_response().await.unwrap().status(), 200);
                let mut body = BytesMut::new();
                while let Some(mut data) = recv.recv_data().await.unwrap() {
                    body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                assert_eq!(&body[..], b"still receiving");
                assert!(recv.recv_trailers().await.unwrap().is_none());
            } else {
                drop(stream);
            }
            let _server = peer.await.unwrap();
            drop(sender);
            assert!(drive.await.unwrap().is_h3_no_error());
        }
    })
    .await;
}

#[tokio::test]
async fn dropping_receive_half_stops_download_without_canceling_upload() {
    bounded(async {
        let (_, server_config, mut client_config) = tls::config();
        const RECEIVE_WINDOW: u32 = 64 * 1024;
        let mut transport = quic::TransportConfig::default();
        transport.stream_receive_window(RECEIVE_WINDOW.into());
        client_config.transport_config(Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let (client, server) = tokio::join!(
            http3::client::new(http3_quic::Connection::new(client)),
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)),
        );
        let (mut driver, mut sender) = client.unwrap();
        let mut server = server.unwrap();
        let drive = tokio::spawn(async move { driver.wait_idle().await });
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
            let (mut send, mut recv) = stream.split();
            let ((), ()) = tokio::join!(
                async {
                    // Leave room for a prefetched chunk while reading headers,
                    // but keep this write blocked until STOP_SENDING arrives.
                    // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
                    let error = send
                        .send_data(Bytes::from(vec![0; 4 * RECEIVE_WINDOW as usize]))
                        .await
                        .expect_err("download must be stopped");
                    assert!(
                        matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == h3::error::Code::H3_REQUEST_CANCELLED.value())
                    );
                },
                async {
                    let mut body = BytesMut::new();
                    while let Some(mut data) = recv.recv_data().await.unwrap() {
                        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                    }
                    assert_eq!(&body[..], b"still sending");
                }
            );
            server
        });
        let mut stream = sender
            .send_request(
                Request::post("https://localhost/drop-recv")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.recv_response().await.unwrap();
        let (mut send, recv) = stream.split();
        drop(recv);
        send.send_data(Bytes::from_static(b"still sending"))
            .await
            .unwrap();
        send.finish().await.unwrap();
        drop(send);
        let _server = peer.await.unwrap();
        drop(sender);
        assert!(drive.await.unwrap().is_h3_no_error());
    })
    .await;
}

#[tokio::test]
async fn finish_after_cancelled_write_delivers_complete_body() {
    bounded(async {
        let (_, mut server_config, client_config) = tls::config();
        const RECEIVE_WINDOW: u32 = 64 * 1024;
        const BODY_LEN: usize = 4 * RECEIVE_WINDOW as usize;
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(RECEIVE_WINDOW.into());
        server_config.transport_config(Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let (client, server) = tokio::join!(
            http3::client::new(http3_quic::Connection::new(client)),
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)),
        );
        let (mut driver, mut sender) = client.unwrap();
        let mut server = server.unwrap();
        let drive = tokio::spawn(async move { driver.wait_idle().await });
        let (read_tx, read_rx) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            // Keep the upload flow-controlled until the client cancels its write
            // future. FIN must follow the entire DATA frame, not truncate it.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
            read_rx.await.unwrap();
            let mut body = BytesMut::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            assert_eq!(body.len(), BODY_LEN);
            assert!(body.iter().all(|byte| *byte == b'x'));
            assert!(stream.recv_trailers().await.unwrap().is_none());
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            server
        });
        let mut stream = sender
            .send_request(
                Request::post("https://localhost/finish-pending")
                    .header("content-length", BODY_LEN)
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(stream
            .send_data(Bytes::from(vec![b'x'; BODY_LEN]))
            .now_or_never()
            .is_none());
        read_tx.send(()).unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        assert!(stream.recv_data().await.unwrap().is_none());
        assert!(stream.recv_trailers().await.unwrap().is_none());
        drop(stream);
        let _server = peer.await.unwrap();
        drop(sender);
        assert!(drive.await.unwrap().is_h3_no_error());
    })
    .await;
}
