//! MASQUE CONNECT-UDP over HTTP/3, including QUIC through the tunnel.
//!
//! `MasqueUdpSocket` is a reference for wiring `UdpTunnel` into quinn.

use std::{
    convert::Infallible,
    future::{Ready, poll_fn, ready},
    io::{self, IoSliceMut},
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Mutex,
    task::{self, Context, Poll},
};

use http::{HeaderValue, Method, StatusCode, Uri};
use netty::proxy::masque::{self, ConnectUdp, MasqueError, SendError, Template, UdpTunnel};
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
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

/// A quinn socket that carries every datagram through one CONNECT-UDP tunnel.
///
/// The tunnel reaches a single target, so it suits one QUIC connection to that target.
#[derive(Debug)]
struct MasqueUdpSocket {
    tunnel: Mutex<UdpTunnel>,
    target: SocketAddr,
}

/// Waits for room in the tunnel; one connection driver means one waiting task.
#[derive(Debug)]
struct MasquePoller(Arc<MasqueUdpSocket>);

impl UdpPoller for MasquePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let ready = self.0.tunnel.lock().unwrap().poll_send_ready(cx);
        ready.map_err(io::Error::other)
    }
}

impl AsyncUdpSocket for MasqueUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(MasquePoller(self))
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // `max_transmit_segments` is 1, so `contents` is a single datagram.
        assert_eq!(
            transmit.destination, self.target,
            "the tunnel's only target"
        );
        match self.tunnel.lock().unwrap().try_send(transmit.contents) {
            Ok(()) => Ok(()),
            Err(SendError::Full) => Err(io::ErrorKind::WouldBlock.into()),
            // Lost like an oversized UDP datagram; any other error would end the connection.
            Err(SendError::TooLarge) => Ok(()),
            Err(err) => Err(io::Error::other(err)),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let payload = match task::ready!(self.tunnel.lock().unwrap().poll_recv(cx)) {
            Ok(Some(payload)) => payload,
            Ok(None) => return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            Err(err) => return Poll::Ready(Err(io::Error::other(err))),
        };
        let len = payload.len().min(bufs[0].len());
        bufs[0][..len].copy_from_slice(&payload[..len]);
        meta[0] = RecvMeta {
            addr: self.target,
            len,
            stride: len,
            ..RecvMeta::default()
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok((Ipv4Addr::UNSPECIFIED, 0).into())
    }
}

/// Inner QUIC stays at its 1200-byte minimum, which the outer datagrams must carry.
fn inner_transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1200).mtu_discovery_config(None);
    Arc::new(transport)
}

#[tokio::test]
async fn quic_over_connect_udp() {
    // The target: a QUIC echo server.
    let (cert, mut server_config, _) = tls::config();
    server_config.transport_config(inner_transport());
    let target = Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let conn = target.accept().await.unwrap().await.unwrap();
        let peer = conn.remote_address();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let body = recv.read_to_end(1 << 20).await.unwrap();
        send.write_all(&body).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
        peer
    });

    bounded(async {
        let Pair {
            tx,
            driver,
            mut server,
            server_quic,
            _endpoints,
        } = pair_config(Http3Options::default(), Exec, true, true, true, None).await;
        let mut client_driver = Box::pin(driver);

        // The proxy relays HTTP Datagrams of the first request to the target over UDP.
        let relayed = Arc::new(AtomicUsize::new(0));
        let (relay_addr, relay_bound) = oneshot::channel();
        let proxy = tokio::spawn({
            let relayed = relayed.clone();
            async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                let path = request.uri().path().trim_end_matches('/');
                let mut segments = path.rsplit('/');
                let port: u16 = segments.next().unwrap().parse().unwrap();
                let host: Ipv4Addr = segments.next().unwrap().parse().unwrap();
                stream.send_response(Response::new(())).await.unwrap();

                let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                udp.connect((host, port)).await.unwrap();
                relay_addr.send(udp.local_addr().unwrap()).unwrap();
                let mut buf = vec![0; 65535];
                loop {
                    tokio::select! {
                        datagram = server_quic.read_datagram() => {
                            let Ok(datagram) = datagram else { break };
                            // Quarter Stream ID 0, then Context ID 0.
                            assert_eq!(datagram[..2], [0, 0]);
                            udp.send(&datagram[2..]).await.unwrap();
                            relayed.fetch_add(1, Ordering::Relaxed);
                        }
                        len = udp.recv(&mut buf) => {
                            let mut datagram = BytesMut::from(&[0, 0][..]);
                            datagram.extend_from_slice(&buf[..len.unwrap()]);
                            server_quic.send_datagram(datagram.freeze()).unwrap();
                        }
                    }
                }
                drop(stream);
            }
        });

        let template = Template::new("https://localhost:4433/masque/{target_host}/{target_port}/");
        let mut connector = ConnectUdp::new(template.unwrap(), Proxy(tx));
        let uri = format!("udp://{target_addr}").parse().unwrap();
        let tunnel = connector.call(uri).await.unwrap();
        assert!(tunnel.max_payload_size() >= 1200, "{tunnel:?}");
        let socket = Arc::new(MasqueUdpSocket {
            tunnel: Mutex::new(tunnel),
            target: target_addr,
        });
        let mut client = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls::client_crypto(&cert));
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto.unwrap()));
        client_config.transport_config(inner_transport());
        client.set_default_client_config(client_config);

        let conn = client
            .connect(target_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let body: Vec<u8> = (0..256 * 1024).map(|i| i as u8).collect();
        send.write_all(&body).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(1 << 20).await.unwrap(), body);
        conn.close(0u32.into(), b"done");
        // Drain while the tunnel still carries the close: a closed tunnel fails the driver.
        client.wait_idle().await;

        // The target only ever talked to the proxy, and more than a handshake went through.
        let peer = echo.await.unwrap();
        assert_eq!(peer, relay_bound.await.unwrap());
        assert!(relayed.load(Ordering::Relaxed) > 100);
        // Dropping the endpoint drops the tunnel, which aborts its request stream.
        drop(client);
        proxy.abort();
        drop(connector);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
    })
    .await;
}
