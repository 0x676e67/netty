//! Single-connection QPACK turnover against the native independent peer.
#[path = "../../tests/support/quic.rs"]
mod native;
#[path = "../../tests/http3/tls.rs"]
mod tls;
use std::{
    future::Future,
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    time::timeout,
};
use wreq_proto::{conn::http3::Builder, http3::Http3Options, rt::Executor};
#[derive(Clone, Copy)]
struct Exec;
impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Exec {
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_table_churn() {
    let seconds = std::env::var("H3_QPACK_SECONDS").map_or(300, |s| s.parse::<u64>().unwrap());
    assert!(seconds > 0);
    timeout(Duration::from_secs(seconds + 30), run(seconds))
        .await
        .unwrap();
}
async fn run(seconds: u64) {
    // Fail if the fixed fixture port is already owned; never stop another server.
    let port = std::net::UdpSocket::bind("127.0.0.1:4433").unwrap();
    let (cert, _, config) = tls::config();
    let dir = tempfile::tempdir().unwrap();
    let examples = dir.path().join("examples");
    std::fs::create_dir(&examples).unwrap();
    std::fs::write(examples.join("server.cert"), cert.cert.der()).unwrap();
    std::fs::write(
        examples.join("server.key"),
        cert.signing_key.serialize_der(),
    )
    .unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_native-peer"));
    command
        .args(["0", "none", "both"])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    drop(port);
    let mut peer = command.spawn().unwrap();
    let input = peer.stdin.take().unwrap();
    let mut output = BufReader::new(peer.stdout.take().unwrap()).lines();
    let ready = timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ready.starts_with("http3-bench-server-v7"), "{ready}");
    println!("{ready}");
    println!(
        "client_pid={} peer_pid={} seconds={seconds} workers=8",
        std::process::id(),
        peer.id().unwrap()
    );
    let endpoint = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut sender, driver) = Builder::new(Exec)
        .options(
            Http3Options::builder()
                .send_grease(false)
                .max_concurrent_requests(8)
                .qpack_encoder_table_capacity(4096)
                .qpack_max_table_capacity(Some(4096))
                .qpack_blocked_streams(Some(8))
                .build(),
        )
        .handshake(crate::native::Connection::new(connection.clone()))
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    for n in 0..32 {
        request(&mut sender, 8, n).await;
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let complete = Arc::new(AtomicU64::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for worker in 0..8 {
        let mut sender = sender.clone();
        let complete = complete.clone();
        tasks.spawn(async move {
            let mut n = 0;
            while Instant::now() < deadline {
                timeout(Duration::from_secs(10), request(&mut sender, worker, n))
                    .await
                    .unwrap();
                complete.fetch_add(1, Ordering::Relaxed);
                n += 1;
            }
        });
    }
    let mut progress = tokio::time::interval(Duration::from_secs(10));
    progress.tick().await;
    while !tasks.is_empty() {
        tokio::select! {
            result = tasks.join_next() => { result.unwrap().unwrap(); }
            _ = progress.tick() => { println!("elapsed={:.3} complete={}", started.elapsed().as_secs_f64(), complete.load(Ordering::Relaxed)); }
        }
    }
    let count = complete.load(Ordering::Relaxed) + 32;
    assert!(
        count > 2000,
        "did not exceed even the native server initial credit: {count}"
    );
    assert!(connection.stats().frame_rx.max_streams_bidi > 0);
    drop(sender);
    driver.await.unwrap().unwrap();
    endpoint.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    drop(input); // Native server exits on EOF and frees all connection state.
    let report = timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    println!("{report}");
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(report["requests"].as_u64(), Some(count));
    assert!(report["request_dynamic_sections"].as_u64().unwrap() > count / 2);
    assert!(report["response_dynamic_sections"].as_u64().unwrap() > count / 2);
    assert!(timeout(Duration::from_secs(5), peer.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    println!(
        "requests={count} cleanup=passed; client={:?}",
        connection.stats()
    );
}
async fn request(
    sender: &mut wreq_proto::conn::http3::SendRequest<Full<Bytes>>,
    worker: u32,
    n: u64,
) {
    let value = format!("{worker:02}-{n:016}-{}", "x".repeat(256));
    sender.ready().await.unwrap();
    let response = sender
        .try_send_request(
            Request::get("https://localhost:4433/")
                .header("x-churn", &value)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-churn"], value);
    assert!(response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty());
}
