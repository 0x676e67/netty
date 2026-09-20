//! Native QPACK cancellation and subsequent dynamic-table eviction.
#[path = "../../tests/support/quic.rs"]
mod native;
mod observe;
#[path = "../../tests/http3/tls.rs"]
mod tls;
use std::{future::Future, process::Stdio, sync::Arc, time::Duration};

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

#[derive(Clone, Copy, Debug)]
enum Mode {
    FixedAuthorityControl,
    SensitiveControl,
    BlockedResponse,
    PartialRequest,
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canceled_qpack_headers_release_dynamic_references_and_credit() {
    let selected = std::env::var("H3_QPACK_CASE").ok();
    assert!(
        selected.as_deref().is_none_or(|name| matches!(
            name,
            "fixed-control" | "sensitive-control" | "blocked-response" | "partial-request"
        )),
        "unknown H3_QPACK_CASE"
    );
    for mode in [
        Mode::FixedAuthorityControl,
        Mode::SensitiveControl,
        Mode::BlockedResponse,
        Mode::PartialRequest,
    ] {
        let name = match mode {
            Mode::FixedAuthorityControl => "fixed-control",
            Mode::SensitiveControl => "sensitive-control",
            Mode::BlockedResponse => "blocked-response",
            Mode::PartialRequest => "partial-request",
        };
        if selected.as_deref().is_some_and(|selected| selected != name) {
            continue;
        }
        timeout(Duration::from_secs(60), run(mode)).await.unwrap();
    }
}
async fn run(mode: Mode) {
    // Fail if the fixed fixture port is already owned; never stop another server.
    let port = std::net::UdpSocket::bind("127.0.0.1:4433").unwrap();
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
        .args(["131072", "none", "both", "allow-cancel"])
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

    let endpoint = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut transport = quic::TransportConfig::default();
    transport.stream_receive_window(32768_u32.into());
    config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect("127.0.0.1:4433".parse().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();

    let sensitive = !matches!(mode, Mode::FixedAuthorityControl);
    let observation = observe::State::new(false);
    let (mut sender, driver) = Builder::new(Exec)
        .options(
            Http3Options::builder()
                .send_grease(false)
                .max_concurrent_requests(1)
                .qpack_encoder_table_capacity(4096)
                .qpack_max_table_capacity(Some(4096))
                .qpack_blocked_streams(Some(1))
                .build(),
        )
        .handshake(observation.wrap(crate::native::Connection::new(connection.clone())))
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    // Complete traffic in both directions before probing cancellation; otherwise
    // the first outgoing request may predate peer SETTINGS and be stateless.
    for n in 0..16 {
        request(&mut sender, n, sensitive).await;
    }
    assert!(observation.request_dynamic());
    assert!(observation.dynamic().is_some());
    let stream = 64;
    match mode {
        Mode::FixedAuthorityControl | Mode::SensitiveControl => {
            request(&mut sender, 16, sensitive).await;
        }
        Mode::BlockedResponse => {
            observation.pause_encoder();
            sender.ready().await.unwrap();
            let mut pending = Box::pin(sender.try_send_request(make_request(100_000, sensitive)));
            assert!(timeout(Duration::from_millis(100), pending.as_mut())
                .await
                .is_err());
            assert!(observation.encoder_is_held());
            assert!(observation
                .response_insert_counts()
                .iter()
                .any(|&(id, count)| id == stream && count != 0));
            drop(pending);
            timeout(Duration::from_secs(2), observation.canceled(stream))
                .await
                .unwrap();
            observation.resume();
            println!("{mode:?} stream={stream}: nonzero RIC, withheld encoder data, exact QPACK cancellation observed");
        }
        Mode::PartialRequest => {
            observation.pause_request_headers(stream);
            sender.ready().await.unwrap();
            let mut pending = Box::pin(sender.try_send_request(make_request(16, sensitive)));
            tokio::select! {
                result = pending.as_mut() => panic!("partial HEADERS unexpectedly completed: {result:?}"),
                observed = timeout(Duration::from_secs(2), observation.request_headers_partial(stream)) => { observed.unwrap(); },
            }
            assert!(
                observation
                    .request_insert_counts()
                    .iter()
                    .any(|&(id, count)| id == stream && count != 0),
                "canceled request did not carry dynamic references"
            );
            assert!(timeout(Duration::from_millis(100), pending.as_mut())
                .await
                .is_err());
            drop(pending);
            println!(
                "{mode:?} stream={stream}: canceled after exactly 8 HEADERS bytes with nonzero RIC"
            );
        }
    }
    for n in 17..=80 {
        request(&mut sender, n, sensitive).await;
    }
    let counts = if matches!(mode, Mode::BlockedResponse) {
        observation.response_insert_counts()
    } else {
        observation.request_insert_counts()
    };
    let distinct = counts
        .iter()
        .filter(|(id, count)| *id > stream && *count != 0)
        .map(|(_, count)| *count)
        .collect::<std::collections::BTreeSet<_>>();
    let progress_ok = if matches!(mode, Mode::FixedAuthorityControl) {
        // This fixed-version control diagnoses the previously failed assertion;
        // it must not be mistaken for a post-cancellation reference leak.
        let tail = counts
            .iter()
            .filter(|(id, count)| *id >= 196 && *count != 0)
            .map(|(_, count)| *count)
            .collect::<std::collections::BTreeSet<_>>();
        tail.len() == 1
    } else {
        distinct.len() >= 28
    };
    println!(
        "{mode:?}: {} distinct encoded RIC values across 64 subsequent responses/requests",
        distinct.len()
    );
    observation.stop_capture();
    for n in 81..=2064 {
        request(&mut sender, n, sensitive).await;
    }
    assert!(connection.stats().frame_rx.max_streams_bidi > 0);
    drop(sender);
    driver.await.unwrap().unwrap();
    endpoint.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    drop(input);
    let report = timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    println!("{mode:?}: {report}");
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    let partial = matches!(mode, Mode::PartialRequest);
    let canceled = matches!(mode, Mode::BlockedResponse | Mode::PartialRequest);
    assert_eq!(
        report["requests"].as_u64(),
        Some(if partial { 2064 } else { 2065 })
    );
    assert_eq!(
        report["canceled_streams"].as_u64(),
        Some(u64::from(canceled))
    );
    assert_eq!(
        report["stopped_responses"].as_u64(),
        Some(u64::from(canceled))
    );
    assert_eq!(report["reset_requests"].as_u64(), Some(u64::from(partial)));
    assert!(report["response_dynamic_sections"].as_u64().unwrap() > 2000);
    assert!(timeout(Duration::from_secs(5), peer.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    // Finish and report the peer's reset/credit assertions even when compression
    // progress fails, so a table-reuse defect is not mislabeled a cancel failure.
    assert!(
        progress_ok,
        "encoder did not advance beyond a 4 KiB table: {counts:?}"
    );
}
fn make_request(n: u64, sensitive: bool) -> Request<Full<Bytes>> {
    // The client intentionally transmits only acknowledged dynamic references:
    // prime each new value, then repeat it so the next section can reference it.
    let value_id = if n == 16 {
        7
    } else if n >= 17 {
        8 + (n - 17) / 2
    } else {
        n / 2
    };
    let value = format!("{value_id:016}-{}", "x".repeat(256));
    let mut request = Request::get("https://localhost:4433/")
        .header("x-churn", value)
        .body(Full::new(Bytes::new()))
        .unwrap();
    if sensitive {
        let mut sensitivity = http3::PseudoHeaderSensitivity::default();
        sensitivity.set_sensitive(http3::PseudoId::Authority, true);
        request.extensions_mut().insert(sensitivity);
    }
    request
}
async fn request(
    sender: &mut wreq_proto::conn::http3::SendRequest<Full<Bytes>>,
    n: u64,
    sensitive: bool,
) {
    timeout(Duration::from_secs(5), async {
        let request = make_request(n, sensitive);
        let expected = request.headers()["x-churn"].clone();
        sender.ready().await.unwrap();
        let response = sender.try_send_request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-churn"], expected);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 131072);
        assert!(bytes.iter().all(|b| *b == b'A'));
    })
    .await
    .unwrap();
}
