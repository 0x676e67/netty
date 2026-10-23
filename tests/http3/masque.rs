//! MASQUE CONNECT-UDP over HTTP/3.

use std::{
    convert::Infallible,
    future::{Ready, poll_fn, ready},
    sync::Mutex,
    task::{Context, Poll},
};

use h3::error::Code;
use http::{HeaderValue, Method, StatusCode, Uri};
use netty::proxy::masque::{self, ConnectUdp, MasqueError, SendError, Template, UdpTunnel};
use tower_service::Service;

use super::*;

/// Hands out the shared connection to the template's proxy.
struct Proxy(SendRequest<ClientBody>);

impl Service<Uri> for Proxy {
    type Response = SendRequest<ClientBody>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, proxy: Uri) -> Self::Future {
        assert_eq!(proxy, "https://localhost:4433/");
        ready(Ok(self.0.clone()))
    }
}

async fn recv(tunnel: &mut UdpTunnel) -> Result<Option<Bytes>, MasqueError> {
    poll_fn(|cx| tunnel.poll_recv(cx)).await
}

/// Reads `len` bytes of the request stream.
async fn read_stream(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    len: usize,
) -> Vec<u8> {
    let mut data = Vec::new();
    while data.len() < len {
        let mut chunk = stream
            .recv_data()
            .await
            .unwrap()
            .expect("request stream ended");
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    data
}

#[tokio::test]
async fn connect_udp_carries_payloads_as_http_datagrams() {
    bounded(async {
        let Pair {
            tx,
            driver,
            mut server,
            server_quic,
            _endpoints,
        } = pair_config(Http3Options::default(), Exec, true, true, true, None).await;
        let mut client_driver = Box::pin(driver);
        // Datagrams and stream data may arrive in either order, so the capsule waits.
        let (datagram_seen, wait_datagram) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut refused) = resolver.resolve_request().await.unwrap();
            let response = Response::builder().status(403).body(()).unwrap();
            refused.send_response(response).await.unwrap();
            refused.finish().await.unwrap();
            // A refusal aborts the request (RFC 9298 §3.1) rather than marking it malformed.
            assert_eq!(reset_code(&mut refused).await, Code::H3_REQUEST_CANCELLED);

            let resolver = server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), Method::CONNECT);
            let protocol = request.extensions().get::<h3::ext::Protocol>().unwrap();
            assert_eq!(protocol.as_str(), "connect-udp");
            assert_eq!(
                request.uri(),
                "https://localhost:4433/masque/2001%3Adb8%3A%3A1/53/"
            );
            assert_eq!(request.headers()["capsule-protocol"], "?1");
            assert_eq!(
                request.headers()["proxy-authorization"],
                "Basic dXNlcjpwYXNz"
            );
            stream.send_response(Response::new(())).await.unwrap();

            // Quarter Stream ID 1 (stream 4), then Context ID 0.
            assert_eq!(
                server_quic.read_datagram().await.unwrap(),
                [1, 0, b'h', b'i'][..]
            );
            let max = server_quic.read_datagram().await.unwrap();
            assert_eq!(max[..2], [1, 0]);
            server_quic
                .send_datagram(Bytes::from_static(&[1, 1, b'x']))
                .unwrap();
            server_quic
                .send_datagram(Bytes::from_static(&[1, 0, b'n']))
                .unwrap();
            wait_datagram.await.unwrap();
            stream
                .send_data(Bytes::from_static(&[0, 2, 0, b'c']))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            // A full queue of datagrams sent right before the client's FIN still arrives.
            for i in 0..64 {
                assert_eq!(server_quic.read_datagram().await.unwrap(), [1, 0, i][..]);
            }
            assert!(stream.recv_data().await.unwrap().is_none(), "client FIN");
            let _ = server.accept().await;
            max.len() - 2
        });

        let template = Template::new("https://localhost:4433/masque/{target_host}/{target_port}/");
        let mut connector = ConnectUdp::new(template.unwrap(), Proxy(tx))
            .with_auth(HeaderValue::from_static("Basic dXNlcjpwYXNz"));
        let target: Uri = "udp://[2001:db8::1]:53".parse().unwrap();
        poll_fn(|cx| connector.poll_ready(cx)).await.unwrap();
        let refused = connector.call(target.clone()).await.unwrap_err();
        assert!(
            matches!(refused, MasqueError::Unsuccessful(StatusCode::FORBIDDEN)),
            "{refused:?}"
        );

        let mut tunnel = connector.call(target).await.unwrap();
        let max = tunnel.max_payload_size();
        tunnel.try_send(b"hi").unwrap();
        tunnel.try_send(&vec![7; max]).unwrap();
        // Oversized payloads are rejected rather than moved to capsules.
        assert_eq!(tunnel.try_send(&vec![7; max + 1]), Err(SendError::TooLarge));
        assert_eq!(poll_fn(|cx| tunnel.poll_send_ready(cx)).await, Ok(()));
        // The unknown Context ID is dropped; capsules are accepted alongside datagrams.
        assert_eq!(recv(&mut tunnel).await.unwrap().unwrap(), "n");
        datagram_seen.send(()).unwrap();
        assert_eq!(recv(&mut tunnel).await.unwrap().unwrap(), "c");
        assert!(recv(&mut tunnel).await.unwrap().is_none());
        // The driver sends 32 per turn, so a queue of 64 outlasts the FIN unless drained first.
        for i in 0..64 {
            tunnel.try_send(&[i]).unwrap();
        }
        poll_fn(|cx| tunnel.poll_close(cx)).await.unwrap();
        assert_eq!(tunnel.max_payload_size(), 0);
        drop(tunnel);
        drop(connector);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        assert_eq!(server_task.await.unwrap(), max);
    })
    .await;
}

#[tokio::test]
async fn connect_udp_falls_back_to_capsules() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        }: Pair = pair_config(Http3Options::default(), Exec, true, false, true, None).await;
        let mut client_driver = Box::pin(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.uri(), "https://localhost/masque/192.0.2.1/443/");
            stream.send_response(Response::new(())).await.unwrap();
            assert_eq!(read_stream(&mut stream, 7).await, b"\0\x05\0ping");
            stream
                .send_data(Bytes::from_static(b"\0\x04\0end"))
                .await
                .unwrap();
            // `poll_close` writes the buffered capsule, then FIN.
            assert_eq!(read_stream(&mut stream, 4).await, b"\0\x02\0x");
            assert!(stream.recv_data().await.unwrap().is_none());
            // A capsule cut short by FIN.
            stream
                .send_data(Bytes::from_static(b"\0\x05\0"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });

        let template = Template::new("https://localhost/masque/{target_host}/{target_port}/");
        let uri = template.unwrap().expand("192.0.2.1", 443).unwrap();
        let mut response = tx
            .try_send_request(masque::http3_request(uri))
            .await
            .unwrap();
        let mut tunnel = UdpTunnel::from_http3(&mut response).unwrap();
        assert_eq!(tunnel.max_payload_size(), 65527);
        assert_eq!(poll_fn(|cx| tunnel.poll_send_ready(cx)).await, Ok(()));
        tunnel.try_send(b"ping").unwrap();
        assert_eq!(recv(&mut tunnel).await.unwrap().unwrap(), "end");
        tunnel.try_send(b"x").unwrap();
        poll_fn(|cx| tunnel.poll_close(cx)).await.unwrap();
        assert_eq!(tunnel.try_send(b"late"), Err(SendError::Closed));
        let result = recv(&mut tunnel).await;
        assert!(matches!(result, Err(MasqueError::Malformed)), "{result:?}");
        drop(tunnel);
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn close_stops_a_busy_sender() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        }: Pair = pair_config(Http3Options::default(), Exec, true, true, true, None).await;
        let mut client_driver = Box::pin(driver);
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            assert!(stream.recv_data().await.unwrap().is_none(), "client FIN");
            let _ = server.accept().await;
        });

        let template = Template::new("https://localhost/masque/{target_host}/{target_port}/");
        let uri = template.unwrap().expand("192.0.2.1", 443).unwrap();
        let mut response = tx
            .try_send_request(masque::http3_request(uri))
            .await
            .unwrap();
        let mut tunnel = UdpTunnel::from_http3(&mut response).unwrap();
        // With the queue full, readiness waits until the connection sends some of it.
        while tunnel.try_send(&[1; 100]).is_ok() {}
        assert_eq!(tunnel.try_send(&[1; 100]), Err(SendError::Full));
        let mut ready = tokio_test::task::spawn(poll_fn(|cx| tunnel.poll_send_ready(cx)));
        assert!(ready.poll().is_pending(), "ready with a full queue");
        while !ready.is_woken() {
            tokio::task::yield_now().await;
        }
        assert_eq!(ready.poll(), Poll::Ready(Ok(())));
        drop(ready);

        let tunnel = Arc::new(Mutex::new(tunnel));
        // A sender that stops only once sending fails, sharing the tunnel with the close.
        let sender = tokio::spawn({
            let tunnel = tunnel.clone();
            async move {
                loop {
                    let sent = poll_fn(|cx| tunnel.lock().unwrap().poll_send_ready(cx))
                        .await
                        .and_then(|()| tunnel.lock().unwrap().try_send(&[1; 100]));
                    if let Err(err) = sent {
                        return err;
                    }
                }
            }
        });
        tokio::task::yield_now().await;
        poll_fn(|cx| tunnel.lock().unwrap().poll_close(cx))
            .await
            .unwrap();
        assert_eq!(sender.await.unwrap(), SendError::Closed);
        // Reading to the end keeps the exchange open until the proxy has the FIN.
        let end = poll_fn(|cx| tunnel.lock().unwrap().poll_recv(cx)).await;
        assert!(end.unwrap().is_none());
        drop(tunnel);
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn malformed_response_or_capsule_resets_the_stream() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        }: Pair = pair_config(Http3Options::default(), Exec, true, false, true, None).await;
        let mut client_driver = Box::pin(driver);
        let server_task = tokio::spawn(async move {
            // The Capsule Protocol forbids a 206 success (RFC 9297 §3.2); HTTP/3 forbids
            // Transfer-Encoding and status 101 (RFC 9114 §4.2, §4.5), and a refusal can still be
            // malformed. A malformed response is a stream error in both directions
            // (RFC 9114 §4.1.2).
            for response in [
                Response::builder().status(StatusCode::PARTIAL_CONTENT),
                Response::builder().header("transfer-encoding", "chunked"),
                Response::builder().status(StatusCode::SWITCHING_PROTOCOLS),
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("content-length", "x"),
            ] {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                let response = response.body(()).unwrap();
                stream.send_response(response).await.unwrap();
                assert_eq!(reset_code(&mut stream).await, Code::H3_MESSAGE_ERROR);
                assert_eq!(stop_code(&mut stream).await, Code::H3_MESSAGE_ERROR);
            }

            // A Context ID 0 capsule longer than any UDP payload breaks RFC 9298 §5, while a
            // capsule cut short by FIN breaks the Capsule Protocol, so the message is
            // malformed (RFC 9297 §3.3).
            for (data, fin, code) in [
                (&[0, 0x80, 1, 0, 0, 0][..], false, Code::H3_DATAGRAM_ERROR),
                (&[0, 5, 0][..], true, Code::H3_MESSAGE_ERROR),
            ] {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                stream.send_data(Bytes::from_static(data)).await.unwrap();
                if fin {
                    stream.finish().await.unwrap();
                }
                assert_eq!(reset_code(&mut stream).await, code);
            }

            // A refusal whose body overruns its Content-Length is malformed as well; the client
            // stops reading and cancels its unfinished request, as for any failed response body.
            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("content-length", "1")
                .body(())
                .unwrap();
            stream.send_response(response).await.unwrap();
            stream.send_data(Bytes::from_static(b"nope")).await.unwrap();
            assert_eq!(stop_code(&mut stream).await, Code::H3_MESSAGE_ERROR);
            assert_eq!(reset_code(&mut stream).await, Code::H3_REQUEST_CANCELLED);
        });

        let template = Template::new("https://localhost/masque/{target_host}/{target_port}/");
        let uri = template.unwrap().expand("192.0.2.1", 443).unwrap();
        // The client rejects these heads itself.
        for _ in 0..4 {
            let request = masque::http3_request(uri.clone());
            assert!(tx.try_send_request(request).await.is_err());
        }

        // The error sticks, and the stream resets while the tunnel lives.
        let mut tunnels = Vec::new();
        for _ in 0..2 {
            let mut response = tx
                .try_send_request(masque::http3_request(uri.clone()))
                .await
                .unwrap();
            let mut tunnel = UdpTunnel::from_http3(&mut response).unwrap();
            for _ in 0..2 {
                let result = recv(&mut tunnel).await;
                assert!(matches!(result, Err(MasqueError::Malformed)), "{result:?}");
            }
            assert_eq!(tunnel.max_payload_size(), 0);
            assert_eq!(tunnel.try_send(b"x"), Err(SendError::Closed));
            tunnels.push(tunnel);
        }
        let response = tx
            .try_send_request(masque::http3_request(uri))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.into_body().collect().await.is_err());
        server_task.await.unwrap();
        drop(tunnels);
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn refusal_stays_readable_until_the_request_aborts() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        }: Pair = pair_config(Http3Options::default(), Exec, true, false, true, None).await;
        let mut client_driver = Box::pin(driver);
        let (head_seen, wait_head) = oneshot::channel();
        let (reset_seen, wait_reset) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            // Other CONNECT and Extended CONNECT refusals still end the request normally.
            for _ in 0..2 {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                let response = Response::builder().status(403).body(()).unwrap();
                stream.send_response(response).await.unwrap();
                stream.finish().await.unwrap();
                assert!(stream.recv_data().await.unwrap().is_none(), "client FIN");
            }

            let resolver = server.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            let response = Response::builder().status(407).body(()).unwrap();
            stream.send_response(response).await.unwrap();
            wait_head.await.unwrap();
            // The request stays open while the caller holds the refusal.
            assert!(
                timeout(Duration::from_millis(50), stream.recv_data())
                    .await
                    .is_err()
            );
            stream.send_data(Bytes::from_static(b"nope")).await.unwrap();
            stream.finish().await.unwrap();
            // Reading the refusal to its end aborts the request (RFC 9298 §3.1).
            assert_eq!(reset_code(&mut stream).await, Code::H3_REQUEST_CANCELLED);
            reset_seen.send(()).unwrap();
            let _ = server.accept().await;
        });

        let mut extended = Request::connect("https://localhost/webtransport")
            .body(Full::new(Bytes::new()))
            .unwrap();
        extended
            .extensions_mut()
            .insert(netty::http3::Protocol::WEB_TRANSPORT);
        for request in [
            Request::connect("localhost:443")
                .body(Full::new(Bytes::new()))
                .unwrap(),
            extended,
        ] {
            let response = tx.try_send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            response.into_body().collect().await.unwrap();
        }

        let template = Template::new("https://localhost/masque/{target_host}/{target_port}/");
        let uri = template.unwrap().expand("192.0.2.1", 443).unwrap();
        let mut response = tx
            .try_send_request(masque::http3_request(uri))
            .await
            .unwrap();
        let result = UdpTunnel::from_http3(&mut response);
        assert!(
            matches!(
                result,
                Err(MasqueError::Unsuccessful(
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED
                ))
            ),
            "{result:?}"
        );
        head_seen.send(()).unwrap();
        // The abort follows the end of the body, not its drop.
        let mut body = response.into_body();
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(data, "nope");
        assert!(body.frame().await.is_none());
        wait_reset.await.unwrap();
        drop(body);
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        server_task.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn tiny_datagram_limits_report_what_fits() {
    bounded(async {
        // A QUIC DATAGRAM frame takes up to 9 bytes of framing, so a 9-byte peer limit fits
        // nothing, 10 bytes fit only the Quarter Stream ID and 11 bytes also fit Context ID 0.
        // quinn charges 32 bytes of overhead per received datagram, so buffers this small take
        // none and nothing is sent.
        for (buffer, fits) in [(9, false), (10, false), (11, true)] {
            let (_, mut server_config, client_config) = tls::config();
            let mut transport = quinn::TransportConfig::default();
            transport.datagram_receive_buffer_size(Some(buffer));
            server_config.transport_config(std::sync::Arc::new(transport));
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let ((mut tx, driver), mut server) = tokio::join!(
                async {
                    Builder::new(Exec)
                        .handshake_with_datagrams::<_, ClientBody>(crate::native::Connection::new(
                            client,
                        ))
                        .await
                        .unwrap()
                },
                async {
                    h3::server::builder()
                        .enable_datagram(true)
                        .enable_extended_connect(true)
                        .build::<_, Bytes>(h3_quinn::Connection::new(server))
                        .await
                        .unwrap()
                }
            );
            let mut client_driver = Box::pin(driver);
            let (fin_seen, wait_fin) = oneshot::channel();
            let server_task = tokio::spawn(async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream.send_response(Response::new(())).await.unwrap();
                assert!(stream.recv_data().await.unwrap().is_none(), "client FIN");
                fin_seen.send(()).unwrap();
                let _ = server.accept().await;
            });

            let template = Template::new("https://localhost/masque/{target_host}/{target_port}/");
            let uri = template.unwrap().expand("192.0.2.1", 443).unwrap();
            let mut response = tx
                .try_send_request(masque::http3_request(uri))
                .await
                .unwrap();
            let mut tunnel = UdpTunnel::from_http3(&mut response).unwrap();
            assert_eq!(tunnel.max_payload_size(), 0, "buffer {buffer}");
            let ready = poll_fn(|cx| tunnel.poll_send_ready(cx)).await;
            if fits {
                assert_eq!(ready, Ok(()));
            } else {
                assert_eq!(ready, Err(SendError::TooLarge), "buffer {buffer}");
                assert_eq!(tunnel.try_send(b""), Err(SendError::TooLarge));
            }
            poll_fn(|cx| tunnel.poll_close(cx)).await.unwrap();
            // The close only submits the FIN; dropping the tunnel lets the connection close
            // before QUIC sends it.
            wait_fin.await.unwrap();
            drop(tunnel);
            drop(tx);
            client_driver.as_mut().graceful_shutdown();
            client_driver.await.unwrap();
            server_task.await.unwrap();
        }
    })
    .await;
}
