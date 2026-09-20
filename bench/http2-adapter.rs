//! Isolated HTTP/2 adapter comparison; upstream Hyper serves both clients.
#[path = "../tests/support/tokiort.rs"]
mod server_rt;

use std::{
    convert::Infallible,
    future::{poll_fn, Future},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

mod runtime_matrix;
use runtime_matrix::{Case, Measurement, Samples};

#[derive(Clone, Default)]
struct Exec(Arc<AtomicUsize>);

struct Active(Arc<AtomicUsize>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<F: Future + Send + 'static> wreq_proto::rt::Executor<F> for Exec
where
    F::Output: Send,
{
    fn execute(&self, future: F) {
        self.0.fetch_add(1, Ordering::AcqRel);
        let active = Active(self.0.clone());
        tokio::spawn(async move {
            let _active = active;
            future.await;
        });
    }
}

#[derive(Clone)]
enum Sender {
    Direct(http2::client::SendRequest<Bytes>),
    Proto(wreq_proto::conn::http2::SendRequest<Full<Bytes>>),
}

impl Sender {
    async fn request(&mut self, payload: Bytes) {
        let len = payload.len();
        let request = Request::post("http://localhost/bench").header("content-length", len);
        match self {
            Self::Direct(sender) => {
                poll_fn(|cx| sender.poll_ready(cx)).await.unwrap();
                let (response, mut send) = sender
                    .send_request(request.body(()).unwrap(), len == 0)
                    .unwrap();
                if len != 0 {
                    // Match PipeToSendStream's minimal claim before queuing Full<Bytes>.
                    send.reserve_capacity(1);
                    while send.capacity() == 0 {
                        let available =
                            poll_fn(|cx| send.poll_capacity(cx)).await.unwrap().unwrap();
                        if available != 0 {
                            break;
                        }
                    }
                    send.send_data(payload, true).unwrap();
                }
                drop(send);
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.version(), http::Version::HTTP_2);
                let mut body = response.into_body();
                let mut received = 0;
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    assert!(data.iter().all(|&byte| byte == 7));
                    received += data.len();
                    body.flow_control().release_capacity(data.len()).unwrap();
                }
                assert_eq!(received, len);
                assert!(body.trailers().await.unwrap().is_none());
            }
            Self::Proto(sender) => {
                sender.ready().await.unwrap();
                let response = sender
                    .try_send_request(request.body(Full::new(payload)).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.version(), http::Version::HTTP_2);
                let mut body = response.into_body();
                let mut received = 0;
                while let Some(frame) = body.frame().await {
                    let data = frame.unwrap().into_data().unwrap();
                    assert!(data.iter().all(|&byte| byte == 7));
                    received += data.len();
                }
                assert_eq!(received, len);
            }
        }
    }
}

async fn run(sender: &Sender, payload: &Bytes, concurrency: usize, seconds: u64) -> (Samples, f64) {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let mut workers = JoinSet::new();
    for _ in 0..concurrency {
        let mut sender = sender.clone();
        let payload = payload.clone();
        workers.spawn(async move {
            let mut samples = Samples::new();
            while Instant::now() < deadline {
                let started = Instant::now();
                timeout(Duration::from_secs(10), sender.request(payload.clone()))
                    .await
                    .unwrap();
                samples.record(started.elapsed());
            }
            samples
        });
    }
    let mut samples = Samples::new();
    while let Some(result) = workers.join_next().await {
        samples.merge(result.unwrap());
    }
    (samples, started.elapsed().as_secs_f64())
}

async fn measure(case: Case) -> Measurement {
    let Case {
        proto,
        concurrency,
        seconds,
        server_runtime,
        barrier,
    } = case;
    let bytes: usize = std::env::var("CLIENT_BENCH_BYTES").map_or(0, |s| s.parse().unwrap());
    let payload = Bytes::from(vec![7; bytes]);
    let expected = payload.clone();
    let listener = server_runtime
        .spawn(async { TcpListener::bind("127.0.0.1:0").await.unwrap() })
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let received = count.clone();
    let server = server_runtime.spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
            let count = count.clone();
            let expected = expected.clone();
            async move {
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    expected
                );
                count.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(
                    Response::builder()
                        .header("content-length", expected.len())
                        .body(Full::new(expected))
                        .unwrap(),
                )
            }
        });
        hyper::server::conn::http2::Builder::new(server_rt::TokioExecutor)
            .serve_connection(server_rt::TokioIo::new(socket), service)
            .await
            .unwrap();
    });
    let socket = TcpStream::connect(addr).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let exec = Exec::default();
    let (sender, driver) = if proto {
        let (sender, connection) = wreq_proto::conn::http2::Builder::new(exec.clone())
            .handshake(socket)
            .await
            .unwrap();
        (
            Sender::Proto(sender),
            tokio::spawn(async move {
                connection.await.unwrap();
            }),
        )
    } else {
        // Match wreq-proto's defaults rather than compare different flow-control settings.
        let opts = wreq_proto::http2::Http2Options::default();
        let (sender, connection) = http2::client::Builder::new()
            .initial_max_send_streams(opts.initial_max_send_streams)
            .initial_window_size(opts.initial_window_size)
            .initial_connection_window_size(opts.initial_conn_window_size)
            .max_send_buffer_size(opts.max_send_buffer_size)
            .max_local_error_reset_streams(opts.max_local_error_reset_streams)
            .max_frame_size(opts.max_frame_size.unwrap())
            .max_header_list_size(opts.max_header_list_size.unwrap())
            .handshake(socket)
            .await
            .unwrap();
        (
            Sender::Direct(sender),
            tokio::spawn(async move {
                connection.await.unwrap();
            }),
        )
    };
    let (warmup, _) = run(&sender, &payload, concurrency, 1).await;
    barrier.wait().await;
    let started = Instant::now();
    let (samples, _) = run(&sender, &payload, concurrency, seconds).await;
    let finished = Instant::now();
    drop(sender);
    timeout(Duration::from_secs(10), driver)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), async {
        while exec.0.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client tasks leaked");
    assert_eq!(
        received.load(Ordering::Relaxed) as u64,
        warmup.total + samples.total
    );
    Measurement {
        samples,
        started,
        finished,
    }
}

fn main() {
    let bytes: usize = std::env::var("CLIENT_BENCH_BYTES").map_or(0, |s| s.parse().unwrap());
    assert!(
        matches!(bytes, 0 | 4096),
        "HTTP/2 handoff supports CLIENT_BENCH_BYTES=0 or 4096"
    );
    runtime_matrix::run("http2", measure);
}
