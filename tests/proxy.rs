//! QUIC through a SOCKS5 UDP relay, end to end.
//!
//! `Socks5UdpSocket` is a reference for wiring `netty::proxy::socks::udp` into quinn: it wraps
//! the runtime's UDP socket, framing every datagram for the relay and unframing replies.

use std::{
    io::{self, IoSliceMut},
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use netty::proxy::socks::udp::{self, UdpAssociation};
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime, UdpPoller,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    udp::{RecvMeta, Transmit},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

/// A quinn socket that tunnels every datagram through a SOCKS5 UDP association.
#[derive(Debug)]
struct Socks5UdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    relay: SocketAddr,
    control: Mutex<UdpAssociation<TcpStream>>,
}

impl AsyncUdpSocket for Socks5UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // `max_transmit_segments` is 1, so `contents` is a single datagram.
        let mut datagram =
            Vec::with_capacity(udp::header_len(transmit.destination) + transmit.contents.len());
        udp::encode_header(transmit.destination, &mut datagram);
        datagram.extend_from_slice(transmit.contents);
        self.inner.try_send(&Transmit {
            destination: self.relay,
            ecn: None,
            contents: &datagram,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // The association ends with its control connection.
        if self.control.lock().unwrap().poll_closed(cx).is_ready() {
            return Poll::Ready(Err(io::Error::other("SOCKS5 UDP association closed")));
        }
        loop {
            let n = ready!(self.inner.poll_recv(cx, bufs, meta))?;
            let mut kept = 0;
            for i in 0..n {
                let received = &mut bufs[i][..meta[i].len];
                let Some(unframed) =
                    udp::unframe(self.relay, meta[i].addr, received, meta[i].stride)
                else {
                    continue;
                };
                // A dual-stack inner socket would map the source back to IPv6 here.
                meta[i].addr = unframed.source;
                meta[i].len = unframed.len;
                meta[i].stride = unframed.stride;
                if kept != i {
                    let (front, back) = bufs.split_at_mut(i);
                    front[kept][..meta[i].len].copy_from_slice(&back[0][..meta[i].len]);
                    meta[kept] = meta[i];
                }
                kept += 1;
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

/// Minimal IPv4 SOCKS5 proxy: username/password auth, then UDP ASSOCIATE relaying for `client`.
async fn socks5_relay(listener: TcpListener, client: SocketAddr, relayed: Arc<AtomicUsize>) {
    // IPv4 ADDR(4) PORT(2), as in requests and datagram headers.
    let ipv4 = |b: &[u8]| {
        SocketAddr::from((
            Ipv4Addr::new(b[0], b[1], b[2], b[3]),
            u16::from_be_bytes([b[4], b[5]]),
        ))
    };

    let (mut control, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 4];
    control.read_exact(&mut greeting).await.unwrap();
    assert_eq!(
        greeting,
        [5, 2, 0, 2],
        "offers no-auth and username/password"
    );
    control.write_all(&[5, 2]).await.unwrap();
    let mut auth = [0; 13];
    control.read_exact(&mut auth).await.unwrap();
    assert_eq!(&auth, b"\x01\x04user\x06secret");
    control.write_all(&[1, 0]).await.unwrap();
    let mut request = [0; 10];
    control.read_exact(&mut request).await.unwrap();
    assert_eq!(
        &request[..4],
        &[5, 3, 0, 1],
        "UDP ASSOCIATE with an IPv4 address"
    );
    assert_eq!(ipv4(&request[4..]), client, "declares the client's address");

    // Bind loopback but report 0.0.0.0, as many proxies do, so the client must substitute.
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = relay.local_addr().unwrap().port().to_be_bytes();
    control
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]])
        .await
        .unwrap();

    let mut buf = vec![0; 65536];
    loop {
        let (len, from) = relay.recv_from(&mut buf).await.unwrap();
        if from == client {
            // From the client: RSV(2) FRAG(1) ATYP(1)=IPv4 ADDR(4) PORT(2) DATA.
            assert_eq!(&buf[..4], &[0, 0, 0, 1], "unfragmented IPv4 datagram");
            relay.send_to(&buf[10..len], ipv4(&buf[4..])).await.unwrap();
            relayed.fetch_add(1, Ordering::Relaxed);
        } else {
            // From the target: wrap with its address and pass to the client.
            let SocketAddr::V4(from) = from else {
                unreachable!("IPv4 only")
            };
            let mut datagram = vec![0, 0, 0, 1];
            datagram.extend_from_slice(&from.ip().octets());
            datagram.extend_from_slice(&from.port().to_be_bytes());
            datagram.extend_from_slice(&buf[..len]);
            relay.send_to(&datagram, client).await.unwrap();
        }
    }
}

fn tls() -> (quinn::ServerConfig, quinn::ClientConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"echo".to_vec()];

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"echo".to_vec()];

    (
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap())),
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client).unwrap())),
    )
}

#[tokio::test]
async fn quic_over_socks5_udp() {
    let (server_config, client_config) = tls();
    let server = Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let peer = conn.remote_address();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let body = recv.read_to_end(1 << 20).await.unwrap();
        send.write_all(&body).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
        peer
    });

    let socks = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let socks_addr = socks.local_addr().unwrap();
    // Bound first so the association can declare where datagrams come from.
    let inner = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client_addr = inner.local_addr().unwrap();
    let relayed = Arc::new(AtomicUsize::new(0));
    tokio::spawn(socks5_relay(socks, client_addr, relayed.clone()));

    let exchange = async {
        let control = TcpStream::connect(socks_addr).await.unwrap();
        let proxy_ip = control.peer_addr().unwrap().ip();
        let association = udp::associate(control, Some(("user", "secret")), client_addr)
            .await
            .unwrap();
        let relay = association.relay_addr(proxy_ip);
        assert_eq!(relay.ip(), proxy_ip, "unspecified bound address replaced");

        let runtime = Arc::new(TokioRuntime);
        let socket = Arc::new(Socks5UdpSocket {
            inner: runtime.wrap_udp_socket(inner).unwrap(),
            relay,
            control: Mutex::new(association),
        });
        let mut client =
            Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)
                .unwrap();
        client.set_default_client_config(client_config);

        let conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        // Enough data for many datagrams in both directions.
        let body: Vec<u8> = (0..256 * 1024).map(|i| i as u8).collect();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&body).await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(1 << 20).await.unwrap();
        assert_eq!(echoed, body);
        conn.close(0u32.into(), b"done");
        // The server finishes once the close arrives through the relay.
        (relay, echo.await.unwrap())
    };
    let (relay, peer) = tokio::time::timeout(Duration::from_secs(20), exchange)
        .await
        .expect("QUIC exchange through the relay timed out");

    assert_eq!(
        peer.port(),
        relay.port(),
        "server saw the relay, not the client"
    );
    assert!(
        relayed.load(Ordering::Relaxed) > 100,
        "datagrams went through the relay"
    );
}
