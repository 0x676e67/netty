// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
//       conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
//       conditions and the following disclaimer in the documentation and/or other materials
//       provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Local public-API interop against Cloudflare's tokio-quiche server.
//! Server setup follows the Cloudflare example; see CLOUDFLARE-COPYING.
#[path = "../../tests/support/quic.rs"]
mod native;
#[path = "../../tests/http3/tls.rs"]
mod tls;
use std::{collections::HashSet, future::Future, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::Request;
use http_body_util::{BodyExt, Full};
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};
use tokio_quiche::{
    http3::{
        driver::{H3Event, OutboundFrame, ServerH3Event},
        settings::Http3Settings,
    },
    listen,
    metrics::DefaultMetrics,
    quiche::h3::{Header, NameValue},
    settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths},
    ConnectionParams, ServerH3Driver,
};
use wreq_proto::{conn::http3::Builder, http3::Http3Options, rt::Executor};
#[derive(Clone, Copy)]
struct Exec;

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Exec {
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiche_server_empty_large_and_concurrent_responses_with_grease() {
    for grease in [false, true] {
        timeout(Duration::from_secs(20), run(grease, false))
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quiche_server_canceled_responses_release_streams_before_close() {
    timeout(Duration::from_secs(20), run(false, true))
        .await
        .unwrap();
}

async fn run(grease: bool, cancel: bool) {
    let callers = if cancel { 32 } else { 8 };
    let rounds = if cancel { 4 } else { 1 };
    let expected = callers * rounds;
    let (cert, _, mut config) = tls::config();
    if cancel {
        let mut transport = quic::TransportConfig::default();
        transport.receive_window(32_768_u32.into());
        transport.stream_receive_window(16_384_u32.into());
        config.transport_config(Arc::new(transport));
    }
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let mut settings = QuicSettings::default();
    settings.max_idle_timeout = Some(Duration::from_secs(10));
    settings.initial_max_data = 10_000_000;
    settings.initial_max_stream_data_bidi_local = 1_000_000;
    settings.initial_max_stream_data_bidi_remote = 1_000_000;
    settings.initial_max_stream_data_uni = 1_000_000;
    settings.initial_max_streams_bidi = 32;
    settings.initial_max_streams_uni = 16;
    settings.grease = grease;
    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            settings,
            TlsCertificatePaths {
                cert: cert_path.to_str().unwrap(),
                private_key: key_path.to_str().unwrap(),
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        ),
        DefaultMetrics,
    )
    .unwrap();
    let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = listeners[0].next().await.unwrap().unwrap();
        // quiche 0.29.3 has a stateless QPACK encoder and no dynamic decoder.
        let (driver, mut controller) = ServerH3Driver::new(Http3Settings {
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            ..Default::default()
        });
        connection.start(driver);
        let mut tasks = JoinSet::new();
        let mut accepted = 0;
        let mut active = HashSet::new();
        let mut stopped = 0;
        let mut drained_tx = Some(drained_tx);
        loop {
            if accepted == expected && active.is_empty() && tasks.is_empty() {
                if let Some(tx) = drained_tx.take() {
                    tx.send((accepted, stopped)).unwrap();
                }
            }
            let event = tokio::select! {
                event = controller.event_receiver_mut().recv() => {
                    let Some(event) = event else { break };
                    event
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if result.unwrap().unwrap() {
                        stopped += 1;
                    }
                    continue;
                }
            };
            match event {
                ServerH3Event::Headers {
                    incoming_headers, ..
                } => {
                    accepted += 1;
                    assert!(active.insert(incoming_headers.stream_id));
                    tasks.spawn(async move {
                        let path = incoming_headers
                            .headers
                            .iter()
                            .find(|h| h.name() == b":path")
                            .unwrap()
                            .value();
                        let length = std::str::from_utf8(path)
                            .unwrap()
                            .trim_start_matches('/')
                            .parse::<usize>()
                            .unwrap();
                        assert!(
                            length == 0
                                || length == 128 * 1024
                                || (cancel && length == 4 * 1024 * 1024)
                        );
                        let mut send = incoming_headers.send;
                        send.send(OutboundFrame::Headers(
                            vec![
                                Header::new(b":status", b"200"),
                                Header::new(b"content-length", length.to_string().as_bytes()),
                                Header::new(b"x-peer", b"quiche"),
                            ],
                            None,
                        ))
                        .await
                        .unwrap();
                        for _ in 0..length / (16 * 1024) {
                            if send
                                .send(OutboundFrame::Body(Bytes::from(vec![7; 16 * 1024]), false))
                                .await
                                .is_err()
                            {
                                assert!(cancel && length == 4 * 1024 * 1024);
                                return true;
                            }
                        }
                        assert!(
                            length < 4 * 1024 * 1024,
                            "canceled response unexpectedly sent in full"
                        );
                        send.send(OutboundFrame::Body(Bytes::new(), true))
                            .await
                            .unwrap();
                        false
                    });
                }
                ServerH3Event::Core(H3Event::StreamClosed { stream_id }) => {
                    assert!(active.remove(&stream_id));
                }
                ServerH3Event::Core(H3Event::ConnectionShutdown(error)) => {
                    assert!(error.is_none(), "quiche shutdown: {error:?}");
                    break;
                }
                ServerH3Event::Core(H3Event::ConnectionError(error)) => {
                    panic!("quiche peer error: {error:?}")
                }
                _ => {}
            }
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert_eq!(accepted, expected);
        assert!(active.is_empty());
    });
    let endpoint = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let stats = connection.clone();
    let (sender, driver) = Builder::new(Exec)
        .options(
            Http3Options::builder()
                .send_grease(grease)
                .max_concurrent_requests(if cancel { 32 } else { 4 })
                .qpack_max_table_capacity(Some(0))
                .qpack_blocked_streams(Some(0))
                .build(),
        )
        .handshake(crate::native::Connection::new(connection))
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let mut clients = JoinSet::new();
    for i in 0..callers {
        let mut sender = sender.clone();
        clients.spawn(async move {
            for _ in 0..rounds {
                let canceled = cancel && i % 2 == 0;
                let length = if canceled {
                    4 * 1024 * 1024
                } else if !cancel && i % 2 == 0 {
                    0
                } else {
                    128 * 1024
                };
                sender.ready().await.unwrap();
                let response = sender
                    .try_send_request(
                        Request::get(format!("https://localhost/{length}"))
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.version(), http::Version::HTTP_3);
                assert_eq!(response.status(), 200);
                assert_eq!(response.headers()["x-peer"], "quiche");
                let mut body = response.into_body();
                if canceled {
                    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
                    assert!(!first.is_empty());
                    assert!(first.iter().all(|b| *b == 7));
                    drop(body);
                    continue;
                }
                let body = body.collect().await.unwrap().to_bytes();
                assert_eq!(body.len(), length);
                assert!(body.iter().all(|b| *b == 7));
            }
        });
    }
    while let Some(result) = clients.join_next().await {
        result.unwrap();
    }
    let (accepted, stopped) = timeout(Duration::from_secs(5), drained_rx)
        .await
        .expect("quiche streams and send tasks must drain before connection close")
        .unwrap();
    assert_eq!(accepted, expected);
    assert_eq!(stopped, if cancel { expected / 2 } else { 0 });
    if cancel {
        assert!(stats.stats().frame_tx.stop_sending >= (expected / 2) as u64);
        assert!(stats.stats().frame_rx.max_streams_bidi > 0);
    }
    println!("quiche pre-close: requests={accepted} canceled_senders={stopped} active_streams=0 send_tasks=0");
    drop(sender);
    driver.await.unwrap().unwrap();
    endpoint.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    peer.await.unwrap();
    println!("quiche server grease={grease} cancel={cancel}: {expected} requests complete with connection/task cleanup");
}
