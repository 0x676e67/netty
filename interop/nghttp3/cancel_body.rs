//! Response cancellation against the independent nghttp3/ngtcp2 peer.
#[path = "../../tests/support/quic.rs"]
mod native;
#[path = "../../tests/http3/tls.rs"]
mod tls;

use std::{future::Future, process::Stdio, sync::Arc, time::Duration};

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    task::JoinSet,
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
async fn nghttp3_canceled_responses_release_streams_before_close() {
    timeout(Duration::from_secs(30), run()).await.unwrap();
}

async fn run() {
    let reservation = std::net::UdpSocket::bind("127.0.0.1:4433").unwrap();
    let (cert, _, mut config) = tls::config();
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
        .args(["4194304", "none", "none", "allow-cancel"])
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    drop(reservation);
    let mut peer = command.spawn().unwrap();
    let mut input = peer.stdin.take().unwrap();
    let mut output = BufReader::new(peer.stdout.take().unwrap()).lines();
    let ready = timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ready.starts_with("http3-bench-server-v7"), "{ready}");
    println!("{ready}");

    let mut transport = quic::TransportConfig::default();
    transport.receive_window(32_768_u32.into());
    transport.stream_receive_window(16_384_u32.into());
    config.transport_config(Arc::new(transport));
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
                .max_concurrent_requests(32)
                .qpack_max_table_capacity(Some(0))
                .qpack_blocked_streams(Some(0))
                .build(),
        )
        .handshake(native::Connection::new(connection.clone()))
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let mut clients = JoinSet::new();
    for i in 0..32 {
        let mut sender = sender.clone();
        clients.spawn(async move {
            for _ in 0..4 {
                request(&mut sender, i % 2 == 0).await;
            }
        });
    }
    while let Some(result) = clients.join_next().await {
        result.unwrap();
    }
    assert!(connection.stats().frame_tx.stop_sending >= 64);
    // Query while the sender and QUIC connection remain live. Reading this
    // snapshot never closes or resets streams on the server.
    let snapshot = timeout(Duration::from_secs(5), async {
        loop {
            input.write_all(b"?").await.unwrap();
            input.flush().await.unwrap();
            let line = output.next_line().await.unwrap().unwrap();
            let snapshot: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(snapshot["schema"], "http3-live-v1");
            assert_eq!(snapshot["live_connections"], 1);
            assert_eq!(snapshot["requests"], 128);
            if snapshot["active_streams"] == 0 {
                break snapshot;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("native streams must drain before connection close");
    assert_eq!(snapshot["canceled_streams"], 64);
    assert_eq!(snapshot["stopped_responses"], 64);
    assert_eq!(snapshot["reset_requests"], 0);
    println!("nghttp3 pre-close: {snapshot}");
    request(&mut sender, false).await;
    drop(sender);
    driver.await.unwrap().unwrap();
    endpoint.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    drop(input);
    let report = output.next_line().await.unwrap().unwrap();
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(report["requests"], 129);
    assert_eq!(report["canceled_streams"], 64);
    assert_eq!(report["stopped_responses"], 64);
    assert!(peer.wait().await.unwrap().success());
    println!("nghttp3 post-cancel reuse and normal shutdown passed: {report}");
}

async fn request(sender: &mut wreq_proto::conn::http3::SendRequest<Full<Bytes>>, cancel: bool) {
    sender.ready().await.unwrap();
    let response = sender
        .try_send_request(
            Request::get("https://localhost:4433/")
                .header("x-churn", "body-cancel-control")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), http::Version::HTTP_3);
    assert_eq!(response.headers()["content-length"], "4194304");
    let mut body = response.into_body();
    if cancel {
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(!first.is_empty());
        assert!(first.iter().all(|&byte| byte == b'A'));
    } else {
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 4 * 1024 * 1024);
        assert!(bytes.iter().all(|&byte| byte == b'A'));
    }
}
