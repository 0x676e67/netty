//! Explicit long-running cancellation and resource-lifetime validation.
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use tokio::{task::JoinSet, time::timeout};
use wreq_proto::{http3::Http3Options, rt::Executor};

#[derive(Clone, Default)]
struct CountingExec(Arc<AtomicUsize>);

struct Active(Arc<AtomicUsize>);

// ===== impl Active =====

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

// ===== impl CountingExec =====

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for CountingExec {
    fn execute(&self, future: F) {
        self.0.fetch_add(1, Ordering::AcqRel);
        let active = Active(self.0.clone());
        tokio::spawn(async move {
            let _active = active;
            future.await;
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "30-minute resource soak; H3_SOAK_SECONDS overrides duration"]
async fn cancellation_and_close() {
    let seconds = std::env::var("H3_SOAK_SECONDS").map_or(1800, |v| v.parse::<u64>().unwrap());
    assert!(seconds > 0);
    let exec = CountingExec::default();
    let buffer = std::env::var("H3_SOAK_UDP_BUFFER")
        .ok()
        .map(|value| value.parse::<usize>().unwrap());
    let socket = || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let reference = socket2::SockRef::from(&socket);
        let original = reference.recv_buffer_size().unwrap();
        if let Some(buffer) = buffer {
            reference.set_recv_buffer_size(buffer).unwrap();
        }
        println!(
            "soak UDP receive buffer: original={original} actual={}",
            reference.recv_buffer_size().unwrap()
        );
        socket
    };
    let (_, server_config, client_config) = super::tls::config();
    let endpoints = (
        quic::Endpoint::new(
            quic::EndpointConfig::default(),
            None,
            socket(),
            Arc::new(quic::TokioRuntime),
        )
        .unwrap(),
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap(),
    );
    endpoints.0.set_default_client_config(client_config);
    let (client_quic, server_quic) = tokio::join!(
        endpoints
            .0
            .connect(endpoints.1.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { endpoints.1.accept().await.unwrap().await.unwrap() }
    );
    let client_quic = client_quic.unwrap();
    let ((tx, driver), mut server) = tokio::join!(
        async {
            wreq_proto::conn::http3::Builder::new(exec.clone())
                .options(Http3Options::builder().send_grease(false).build())
                .handshake::<_, super::ClientBody>(crate::native::Connection::new(
                    client_quic.clone(),
                ))
                .await
                .unwrap()
        },
        async {
            h3::server::builder()
                .build::<_, Bytes>(h3_quinn::Connection::new(server_quic.clone()))
                .await
                .unwrap()
        }
    );
    let client_driver = tokio::spawn(driver);
    let completed = Arc::new(AtomicUsize::new(0));
    let reset = Arc::new(AtomicUsize::new(0));
    let closing = Arc::new(AtomicBool::new(false));
    let server_completed = completed.clone();
    let server_reset = reset.clone();
    let server_closing = closing.clone();
    let server_task = tokio::spawn(async move {
        let chunk = Bytes::from(vec![7; 16 * 1024]);
        let mut streams = JoinSet::new();
        loop {
            match server.accept().await {
                Ok(Some(resolver)) => {
                    let chunk = chunk.clone();
                    let completed = server_completed.clone();
                    let reset = server_reset.clone();
                    let closing = server_closing.clone();
                    streams.spawn(async move {
                        let result = async {
                            let (request, mut stream) = resolver.resolve_request().await?;
                            let cancel = request.uri().path() == "/cancel";
                            while let Some(data) = stream.recv_data().await? {
                                assert_eq!(data.remaining(), 0);
                            }
                            let count = if cancel { 256 } else { 8 };
                            stream
                                .send_response(
                                    Response::builder()
                                        .header("content-length", count * chunk.len())
                                        .body(())
                                        .unwrap(),
                                )
                                .await?;
                            for _ in 0..count {
                                stream.send_data(chunk.clone()).await?;
                            }
                            stream.finish().await?;
                            completed.fetch_add(1, Ordering::Relaxed);
                            Ok::<(), h3::error::StreamError>(())
                        }
                        .await;
                        if let Err(error) = result {
                            // Once all clients finish, connection close can
                            // reach the server before the last stream resets.
                            if closing.load(Ordering::Acquire) && error.is_h3_no_error() {
                                return;
                            }
                            assert!(
                                matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                                if code == h3::error::Code::H3_REQUEST_CANCELLED),
                                "{error}"
                            );
                            reset.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                    while let Some(result) = streams.try_join_next() {
                        result.unwrap();
                    }
                }
                Ok(None) => break,
                Err(error) if error.is_h3_no_error() => break,
                Err(error) => panic!("server connection failed: {error}"),
            }
        }
        while let Some(result) = streams.join_next().await {
            result.unwrap();
        }
    });
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    println!(
        "soak pid={} seconds={seconds} concurrency=32",
        std::process::id()
    );
    let mut clients = JoinSet::new();
    for worker in 0..32 {
        let mut sender = tx.clone();
        let peer = server_quic.clone();
        let client = client_quic.clone();
        clients.spawn(async move {
            let mut counts = [0_u64; 3];
            let mut iteration = worker;
            while Instant::now() < deadline {
                let kind = iteration % 10;
                iteration += 1;
                let mut phase = "readiness";
                let mut received = 0;
                timeout(Duration::from_secs(10), async {
                    sender.ready().await.unwrap();
                    let request = Request::get(if kind < 2 {
                        "https://localhost/cancel"
                    } else {
                        "https://localhost/complete"
                    })
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                    let response = sender.try_send_request(request);
                    if kind == 0 {
                        drop(response);
                        counts[0] += 1;
                        return;
                    }
                    phase = "response headers";
                    let response = response.await.unwrap();
                    assert_eq!(response.status(), 200);
                    let mut body = response.into_body();
                    phase = "response body";
                    while let Some(frame) = body.frame().await {
                        let data = frame.unwrap().into_data().unwrap();
                        assert!(data.iter().all(|&byte| byte == 7));
                        received += data.len();
                        if kind == 1 && received > 0 {
                            counts[1] += 1;
                            return;
                        }
                    }
                    assert!(kind >= 2, "canceled response had no body");
                    assert_eq!(received, 128 * 1024);
                    counts[2] += 1;
                })
                .await
                .unwrap_or_else(|error| panic!(
                    "request stalled during soak: {error}; worker={worker} iteration={iteration} kind={kind} phase={phase} received={received}; client_closed={:?}; client_stats={:?}; peer_closed={:?}; peer_stats={:?}",
                    client.close_reason(), client.stats(), peer.close_reason(), peer.stats()
                ));
            }
            counts
        });
    }
    let mut totals = [0_u64; 3];
    let mut progress = tokio::time::interval(Duration::from_secs(30));
    progress.tick().await;
    while !clients.is_empty() {
        tokio::select! {
            result = clients.join_next() => {
                for (total, count) in totals.iter_mut().zip(result.unwrap().unwrap()) {
                    *total += count;
                }
            }
            _ = progress.tick() => {
                println!("soak elapsed={:.3} server_complete={} server_reset={} active={} client_lost={} server_lost={} client_blackholes={} server_blackholes={}",
                    started.elapsed().as_secs_f64(), completed.load(Ordering::Relaxed),
                    reset.load(Ordering::Relaxed), exec.0.load(Ordering::Acquire),
                    client_quic.stats().path.lost_packets, server_quic.stats().path.lost_packets,
                    client_quic.stats().path.black_holes_detected, server_quic.stats().path.black_holes_detected);
            }
        }
    }
    closing.store(true, Ordering::Release);
    drop(tx);
    timeout(Duration::from_secs(20), client_driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(20), server_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), async {
        while exec.0.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exchange tasks leaked");
    assert!(totals.iter().all(|&count| count > 0));
    assert!(completed.load(Ordering::Relaxed) as u64 >= totals[2]);
    assert!(reset.load(Ordering::Relaxed) > 0);
    drop(server_quic);
    endpoints.0.close(0_u32.into(), b"soak complete");
    endpoints.1.close(0_u32.into(), b"soak complete");
    timeout(Duration::from_secs(10), async {
        endpoints.0.wait_idle().await;
        endpoints.1.wait_idle().await;
    })
    .await
    .unwrap();
    println!("soak elapsed={:.3} queued_cancel={} body_cancel={} complete={} server_complete={} server_reset={} active=0",
        started.elapsed().as_secs_f64(), totals[0], totals[1], totals[2],
        completed.load(Ordering::Relaxed), reset.load(Ordering::Relaxed));
}
