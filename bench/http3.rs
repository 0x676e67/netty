//! Localhost comparison with the same upstream h3 server and QUIC configuration.
//! H3_BENCH_SECONDS and H3_BENCH_ROUNDS control the bounded measurement runs.
//! H3_BENCH_DIRECT_TASKS=1 adds a task hop to the direct client for diagnosis only.
//! H3_BENCH_DIRECT_CLONE=1 adds a per-request clone arm alongside both defaults.
//! H3_BENCH_PROFILE=1 observes worker/exchange polls; it perturbs performance.
#[path = "../tests/support/quic.rs"]
mod native;
#[path = "http3/profile.rs"]
mod profile;
#[path = "../tests/http3/tls.rs"]
mod tls;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use netty::{conn::http3::Builder, http3::Http3Options, rt::Executor};
use tokio::{task::JoinSet, time::timeout};

#[derive(Clone, Default)]
struct Exec {
    active: Arc<AtomicUsize>,
    profile: Option<Arc<profile::Stats>>,
}

struct Active(Arc<AtomicUsize>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Exec {
    fn execute(&self, future: F) {
        self.active.fetch_add(1, Ordering::AcqRel);
        let active = Active(self.active.clone());
        if let Some(stats) = &self.profile {
            let stats = stats.clone();
            tokio::spawn(async move {
                let _active = active;
                profile::observe(future, stats).await;
            });
        } else {
            tokio::spawn(async move {
                let _active = active;
                future.await;
            });
        }
    }
}

#[derive(Clone)]
enum Sender {
    Proto(netty::conn::http3::SendRequest<Full<Bytes>>),
    Direct(http3::client::SendRequest<http3_quic::OpenStreams, Bytes>),
    Cloned(http3::client::SendRequest<http3_quic::OpenStreams, Bytes>),
    Task(http3::client::SendRequest<http3_quic::OpenStreams, Bytes>),
}

impl Sender {
    async fn request(&mut self, payload: Bytes) {
        let len = payload.len();
        match self {
            Self::Proto(sender) => {
                let request =
                    Request::post("https://localhost/bench").header("content-length", len);
                sender.ready().await.unwrap();
                let response = sender
                    .try_send_request(request.body(Full::new(payload)).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                let mut body = response.into_body();
                let mut received = 0;
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame.unwrap().into_data() {
                        assert!(data.iter().all(|&byte| byte == 7));
                        received += data.len();
                    }
                }
                assert_eq!(received, len);
            }
            Self::Direct(sender) => direct_request(sender, payload).await,
            Self::Cloned(sender) => direct_request(&mut sender.clone(), payload).await,
            Self::Task(sender) => {
                let mut sender = sender.clone();
                tokio::spawn(async move { direct_request(&mut sender, payload).await })
                    .await
                    .unwrap();
            }
        }
    }
}

async fn direct_request(
    sender: &mut http3::client::SendRequest<http3_quic::OpenStreams, Bytes>,
    payload: Bytes,
) {
    let len = payload.len();
    let request = Request::post("https://localhost/bench").header("content-length", len);
    let stream = sender
        .send_request(request.body(()).unwrap())
        .await
        .unwrap();
    let (mut send, mut recv) = stream.split();
    let upload = async {
        let mut payload = payload;
        while payload.has_remaining() {
            let len = payload.remaining().min(16 * 1024);
            send.send_data(payload.copy_to_bytes(len)).await.unwrap();
        }
        send.finish().await.unwrap();
    };
    let download = async {
        assert_eq!(recv.recv_response().await.unwrap().status(), 200);
        let mut received = 0;
        while let Some(mut data) = recv.recv_data().await.unwrap() {
            while data.has_remaining() {
                let chunk = data.chunk();
                assert!(chunk.iter().all(|&byte| byte == 7));
                let len = chunk.len();
                received += len;
                data.advance(len);
            }
        }
        assert!(recv.recv_trailers().await.unwrap().is_none());
        assert_eq!(received, len);
    };
    tokio::join!(upload, download);
}

// A bounded histogram with at least five significant binary bits per bucket.
// Recording is local to each worker; there is no measurement lock in the loop.
struct Samples {
    counts: [u64; 1920],
    total: u64,
}

impl Samples {
    fn new() -> Self {
        Self {
            counts: [0; 1920],
            total: 0,
        }
    }

    fn record(&mut self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let index = if micros < 64 {
            micros as usize
        } else {
            let shift = 63 - micros.leading_zeros() - 5;
            64 + (shift as usize - 1) * 32 + ((micros >> shift) as usize - 32)
        };
        self.counts[index] += 1;
        self.total += 1;
    }

    fn merge(&mut self, other: Self) {
        for (count, added) in self.counts.iter_mut().zip(other.counts) {
            *count += added;
        }
        self.total += other.total;
    }

    fn percentile(&self, percent: u64) -> u64 {
        let rank = (u128::from(self.total) * u128::from(percent)).div_ceil(100) as u64;
        let mut count = 0;
        for (index, &samples) in self.counts.iter().enumerate() {
            count += samples;
            if count >= rank {
                if index < 64 {
                    return index as u64;
                }
                let shift = (index - 64) / 32 + 1;
                let mantissa = (index - 64) % 32 + 32;
                let upper = (((mantissa + 1) as u128) << shift) - 1;
                return u64::try_from(upper).unwrap_or(u64::MAX);
            }
        }
        u64::MAX
    }
}

async fn run(
    sender: &Sender,
    payload: &Bytes,
    concurrency: usize,
    seconds: u64,
    profile: Option<&Arc<profile::Stats>>,
) -> (Samples, f64) {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut workers = JoinSet::new();
    for _ in 0..concurrency {
        let mut sender = sender.clone();
        let payload = payload.clone();
        let worker = async move {
            let mut samples = Samples::new();
            while Instant::now() < deadline {
                let started = Instant::now();
                timeout(Duration::from_secs(10), sender.request(payload.clone()))
                    .await
                    .unwrap();
                samples.record(started.elapsed());
            }
            samples
        };
        if let Some(stats) = profile {
            workers.spawn(profile::observe(worker, stats.clone()));
        } else {
            workers.spawn(worker);
        }
    }
    let mut samples = Samples::new();
    while let Some(result) = workers.join_next().await {
        samples.merge(result.unwrap());
    }
    (samples, started.elapsed().as_secs_f64())
}

fn endpoint(config: Option<quinn::ServerConfig>) -> quinn::Endpoint {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(1024 * 1024)
        .unwrap();
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        config,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap()
}

async fn measure(
    proto: bool,
    direct_clone: bool,
    concurrency: usize,
    bytes: usize,
    seconds: u64,
    round: u64,
) {
    let direct_tasks = std::env::var("H3_BENCH_DIRECT_TASKS").is_ok_and(|s| s == "1");
    let (_, mut server_config, mut client_config) = tls::config();
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(256_u32.into());
    let transport = Arc::new(transport);
    server_config.transport_config(transport.clone());
    let mut client_transport = quic::TransportConfig::default();
    client_transport.max_concurrent_bidi_streams(256_u32.into());
    client_config.transport_config(Arc::new(client_transport));
    let server_endpoint = endpoint(Some(server_config));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(1024 * 1024)
        .unwrap();
    let client_endpoint = quic::Endpoint::new(
        quic::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quic::TokioRuntime),
    )
    .unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connecting = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, server) = tokio::join!(connecting, async {
        server_endpoint.accept().await.unwrap().await.unwrap()
    });
    let profiling = std::env::var("H3_BENCH_PROFILE").is_ok_and(|s| s == "1");
    let worker_profile = profiling.then(|| Arc::new(profile::Stats::default()));
    let exec = Exec {
        profile: profiling.then(|| Arc::new(profile::Stats::default())),
        ..Exec::default()
    };
    let client = client.unwrap();
    let (sender, driver) = if proto {
        let (sender, driver) = Builder::new(exec.clone())
            .options(Http3Options::builder().send_grease(false).build())
            .handshake(crate::native::Connection::new(client))
            .await
            .unwrap();
        (
            Sender::Proto(sender),
            tokio::spawn(async move {
                driver.await.unwrap();
            }),
        )
    } else {
        let (mut driver, sender) = http3::client::builder()
            .send_grease(false)
            .max_field_section_size(64 * 1024)
            .max_qpack_decode_buffer_size(256 * 1024)
            .build(http3_quic::Connection::new(client))
            .await
            .unwrap();
        (
            if direct_tasks {
                Sender::Task(sender)
            } else if direct_clone {
                Sender::Cloned(sender)
            } else {
                Sender::Direct(sender)
            },
            tokio::spawn(async move {
                let error = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                assert!(error.is_h3_no_error(), "{error}");
            }),
        )
    };
    let payload = Bytes::from(vec![7; bytes]);
    let expected = payload.clone();
    let server_task = tokio::spawn(async move {
        let mut server = h3::server::builder()
            .send_grease(false)
            .build::<_, Bytes>(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let mut tasks = JoinSet::new();
        let mut completed = 0_u64;
        loop {
            match server.accept().await {
                Ok(Some(resolver)) => {
                    let payload = expected.clone();
                    tasks.spawn(async move {
                        let (_, mut stream) = resolver.resolve_request().await.unwrap();
                        let mut received = 0;
                        while let Some(mut data) = stream.recv_data().await.unwrap() {
                            while data.has_remaining() {
                                let chunk = data.chunk();
                                assert!(chunk.iter().all(|&byte| byte == 7));
                                let len = chunk.len();
                                received += len;
                                data.advance(len);
                            }
                        }
                        assert_eq!(received, payload.len());
                        stream
                            .send_response(
                                Response::builder()
                                    .header("content-length", payload.len())
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        if !payload.is_empty() {
                            stream.send_data(payload).await.unwrap();
                        }
                        stream.finish().await.unwrap();
                    });
                    while let Some(result) = tasks.try_join_next() {
                        result.unwrap();
                        completed += 1;
                    }
                }
                Ok(None) => break,
                Err(error) if error.is_h3_no_error() => break,
                Err(error) => panic!("server failed: {error}"),
            }
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
            completed += 1;
        }
        completed
    });
    let (warmup, _) = run(&sender, &payload, concurrency, 1, worker_profile.as_ref()).await;
    let (samples, elapsed) = run(
        &sender,
        &payload,
        concurrency,
        seconds,
        worker_profile.as_ref(),
    )
    .await;
    drop(sender);
    // All requests and timing are complete. Both clients keep the connection
    // alive until its driver or connection handle is dropped.
    driver.abort();
    match timeout(Duration::from_secs(10), driver)
        .await
        .expect("client driver shutdown timed out")
    {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {}
        Err(error) => panic!("client driver failed: {error}"),
    }
    assert_eq!(
        timeout(Duration::from_secs(10), server_task)
            .await
            .unwrap()
            .unwrap(),
        warmup.total + samples.total
    );
    // The connection can finish before the executor wrapper drops its guard.
    timeout(Duration::from_secs(10), async {
        while exec.active.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("exchange tasks leaked");
    client_endpoint.close(0_u32.into(), b"complete");
    server_endpoint.close(0_u32.into(), b"complete");
    client_endpoint.wait_idle().await;
    server_endpoint.wait_idle().await;
    let implementation = if proto {
        "netty"
    } else if direct_tasks {
        "http3-task"
    } else if direct_clone {
        "http3-clone"
    } else {
        "http3"
    };
    if let Some(stats) = worker_profile {
        let context = format!("{round},{implementation},{concurrency},{bytes}");
        stats.report(&context, "worker", warmup.total + samples.total);
        exec.profile
            .as_ref()
            .unwrap()
            .report(&context, "exchange", warmup.total + samples.total);
    }
    println!(
        "{round},{implementation}{},{concurrency},{bytes},{},{elapsed:.6},{:.2},{},{}",
        if profiling { "-profile" } else { "" },
        samples.total,
        samples.total as f64 / elapsed,
        samples.percentile(50),
        samples.percentile(99)
    );
}

fn main() {
    let direct_tasks = std::env::var("H3_BENCH_DIRECT_TASKS").is_ok_and(|s| s == "1");
    let direct_clone = std::env::var("H3_BENCH_DIRECT_CLONE").is_ok_and(|s| s == "1");
    let profiling = std::env::var("H3_BENCH_PROFILE").is_ok_and(|s| s == "1");
    assert!(
        !(direct_tasks && direct_clone),
        "select one diagnostic mode"
    );
    assert!(
        !(profiling && (direct_tasks || direct_clone)),
        "task profiling requires the default comparison"
    );
    let seconds: u64 = std::env::var("H3_BENCH_SECONDS").map_or(3, |s| s.parse().unwrap());
    let rounds: u64 = std::env::var("H3_BENCH_ROUNDS").map_or(3, |s| s.parse().unwrap());
    assert!(seconds > 0 && rounds > 0);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    println!("round,implementation,concurrency,body_bytes,requests,seconds,requests_per_second,p50_us_upper,p99_us_upper");
    runtime.block_on(async {
        for round in 0..rounds {
            for bytes in [0, 128 * 1024] {
                for concurrency in [1, 32, 128] {
                    let mut clients = vec![(false, false)];
                    if direct_clone {
                        clients.push((false, true));
                    }
                    clients.push((true, false));
                    if round % 2 != 0 {
                        clients.reverse();
                    }
                    for (proto, cloned) in clients {
                        measure(proto, cloned, concurrency, bytes, seconds, round).await;
                    }
                }
            }
        }
    });
}
