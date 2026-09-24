//! Runs a pending exchange synchronously when transport close wakes it.
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use futures_util::{
    future::{poll_fn, BoxFuture},
    task::AtomicWaker,
};
use netty::rt::quic::{self as rt, DatagramConnection, OpenStreams};

use super::*;

#[derive(Clone, Default)]
struct Jobs(Arc<Queue>);

#[derive(Default)]
struct Queue {
    jobs: Mutex<Vec<BoxFuture<'static, ()>>>,
    waker: AtomicWaker,
    connection_submitted: AtomicBool,
    /// Queue the connection task too, so a test drives it in lockstep.
    inline_task: bool,
}

#[derive(Clone)]
struct Transport<T> {
    inner: T,
    jobs: Jobs,
}

// ===== impl Jobs =====

impl Jobs {
    fn inline_task() -> Self {
        Self(Arc::new(Queue {
            inline_task: true,
            ..Queue::default()
        }))
    }

    fn poll(&self, cx: &mut Context<'_>) {
        self.0.waker.register(cx.waker());
        self.0
            .jobs
            .lock()
            .unwrap()
            .retain_mut(|job| job.as_mut().poll(cx).is_pending());
    }
}

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for Jobs {
    fn execute(&self, job: F) {
        // Handshake submits the connection before it can submit exchanges.
        let is_exchange = self.0.connection_submitted.swap(true, Ordering::Relaxed);
        if self.0.inline_task || is_exchange {
            self.0.jobs.lock().unwrap().push(Box::pin(job));
            self.0.waker.wake();
        } else {
            tokio::spawn(job);
        }
    }
}

// ===== impl Transport =====

impl<T: rt::Connection<Bytes>> rt::Connection<Bytes> for Transport<T> {
    type RecvStream = T::RecvStream;

    type OpenStreams = Transport<T::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, rt::ConnectionError>> {
        self.inner.poll_accept_recv(cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, rt::ConnectionError>> {
        self.inner.poll_accept_bidi(cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        Transport {
            inner: self.inner.opener(),
            jobs: self.jobs.clone(),
        }
    }
}

impl<T: OpenStreams<Bytes>> OpenStreams<Bytes> for Transport<T> {
    type SendStream = T::SendStream;

    type BidiStream = T::BidiStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, rt::StreamError>> {
        self.inner.poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, rt::StreamError>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.inner.close(code, reason);
        // Model another executor polling the awakened request before close returns.
        self.jobs
            .poll(&mut Context::from_waker(std::task::Waker::noop()));
    }
}

impl<T: DatagramConnection> DatagramConnection for Transport<T> {
    type Sender = T::Sender;

    type Receiver = T::Receiver;

    fn take_datagrams(&mut self) -> Option<(Self::Sender, Self::Receiver)> {
        self.inner.take_datagrams()
    }
}

#[tokio::test]
async fn datagram_failure_preserves_cause_when_close_wakes_pending_request() {
    for response_started in [false, true] {
        check_cause(response_started).await;
    }
}

async fn check_cause(response_started: bool) {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let peer = server.clone();
        let jobs = Jobs::default();
        let ((mut tx, driver), mut server) = tokio::join!(
            async {
                Builder::new(jobs.clone())
                    .handshake_with_datagrams(Transport {
                        inner: native::Connection::new(client),
                        jobs: jobs.clone(),
                    })
                    .await
                    .unwrap()
            },
            async {
                h3::server::builder()
                    .enable_datagram(true)
                    .build::<_, Bytes>(h3_quinn::Connection::new(server))
                    .await
                    .unwrap()
            }
        );
        let driver = tokio::spawn(driver);
        let (seen, mut received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            if response_started {
                stream
                    .send_response(
                        Response::builder()
                            .header("content-length", 1)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            }
            seen.send(()).unwrap();
            assert!(server.accept().await.is_err());
            drop(stream);
            server
        });
        let mut response = std::pin::pin!(tx.try_send_request(
            Request::get("https://localhost/pending")
                .body(Full::new(Bytes::new()))
                .unwrap()
        ));
        let mut head = None;
        let mut seen = false;
        poll_fn(|cx| {
            jobs.poll(cx);
            if head.is_none() {
                if let Poll::Ready(result) = response.as_mut().poll(cx) {
                    assert!(response_started);
                    head = Some(result.unwrap());
                }
            }
            if !seen {
                if let Poll::Ready(result) = Pin::new(&mut received).poll(cx) {
                    result.unwrap();
                    seen = true;
                }
            }
            if seen && (!response_started || head.is_some()) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        // The missing Quarter Stream ID is a connection-level HTTP Datagram error.
        // https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
        peer.send_datagram(Bytes::new()).unwrap();
        let connection_error = driver.await.unwrap().unwrap_err();
        let request_error = if let Some(head) = head {
            head.into_body().collect().await.unwrap_err()
        } else {
            response.await.unwrap_err().into_error()
        };
        eprintln!("connection={connection_error:?}; request={request_error:?}");
        assert!(jobs.0.jobs.lock().unwrap().is_empty());
        assert_datagram_cause(&connection_error);
        assert_datagram_cause(&request_error);
        let _server = server.await.unwrap();
        match peer.closed().await {
            quinn::ConnectionError::ApplicationClosed(error) => {
                assert_eq!(error.error_code.into_inner(), 0x33);
            }
            error => panic!("unexpected peer close: {error:?}"),
        }
    })
    .await;
}

fn assert_datagram_cause(error: &netty::Error) {
    use std::error::Error;
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(http3::error::ConnectionError::Local {
            error: http3::error::LocalError::Application { code, .. },
        }) = cause.downcast_ref::<http3::error::ConnectionError>()
        {
            assert_eq!(*code, http3::error::Code::H3_DATAGRAM_ERROR);
            return;
        }
        source = cause.source();
    }
    panic!("missing HTTP Datagram connection cause: {error:?}");
}

#[tokio::test]
async fn late_datagram_after_response_drop_preserves_upload() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let observed = client.clone();
        let peer = server.clone();
        let jobs = Jobs::inline_task();
        let ((mut tx, mut driver), mut server) = tokio::join!(
            async {
                Builder::new(jobs.clone())
                    .handshake_with_datagrams(native::Connection::new(client))
                    .await
                    .unwrap()
            },
            async {
                h3::server::builder()
                    .enable_datagram(true)
                    .build::<_, Bytes>(h3_quinn::Connection::new(server))
                    .await
                    .unwrap()
            }
        );
        let (upload, ready) = oneshot::channel();
        let body = http_body_util::StreamBody::new(futures_util::stream::once(async move {
            ready.await.unwrap();
            Ok::<_, std::convert::Infallible>(http_body::Frame::data(Bytes::from_static(b"upload")))
        }));
        let (dropped, body_dropped) = oneshot::channel();
        let (finished, upload_received) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let request = tokio::spawn(async move {
                let (_, stream) = resolver.resolve_request().await.unwrap();
                let id = stream.id().into_inner();
                let (mut send, mut recv) = stream.split();
                send.send_response(Response::new(())).await.unwrap();
                body_dropped.await.unwrap();
                loop {
                    if let Err(error) = send.send_data(Bytes::from(vec![1; 64 * 1024])).await {
                        assert!(matches!(error,
                            h3::error::StreamError::RemoteTerminate { code, .. }
                                if code == h3::error::Code::H3_REQUEST_CANCELLED));
                        break;
                    }
                }
                // Inject a late packet after the receive direction was abandoned.
                // It must be discarded even though the upload remains active.
                // https://www.rfc-editor.org/rfc/rfc9297.html#section-2.1
                peer.send_datagram(Bytes::from(vec![(id / 4) as u8, 7]))
                    .unwrap();
                let mut received = BytesMut::new();
                while let Some(mut data) = recv.recv_data().await.unwrap() {
                    received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                assert_eq!(received, "upload");
                assert!(recv.recv_trailers().await.unwrap().is_none());
                finished.send(()).unwrap();
            });
            let _ = server.accept().await;
            request.await.unwrap();
        });
        let response = progress(
            tx.try_send_request(
                Request::post("https://localhost/late-datagram")
                    .body(body)
                    .unwrap(),
            ),
            &mut driver,
            &jobs,
        )
        .await
        .unwrap_or_else(|error| panic!("{}", error.error()));
        drop(response);
        dropped.send(()).unwrap();
        progress(
            poll_fn(|_| {
                if observed.stats().frame_rx.datagram > 0 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            }),
            &mut driver,
            &jobs,
        )
        .await;
        // The packet is now in QUIC's receive queue. Poll its HTTP routing and
        // request cancellation before releasing the pending upload.
        progress(std::future::ready(()), &mut driver, &jobs).await;
        upload.send(()).expect("late datagram must preserve upload");
        progress(upload_received, &mut driver, &jobs).await.unwrap();
        drop(tx);
        Pin::new(&mut driver).graceful_shutdown();
        poll_fn(|cx| {
            jobs.poll(cx);
            Pin::new(&mut driver).poll(cx)
        })
        .await
        .unwrap();
        server_task.await.unwrap();
    })
    .await;
}

async fn progress<F, D>(future: F, driver: &mut D, jobs: &Jobs) -> F::Output
where
    F: Future,
    D: Future<Output = Result<(), netty::Error>> + Unpin,
{
    let mut future = std::pin::pin!(future);
    poll_fn(|cx| {
        assert!(Pin::new(&mut *driver).poll(cx).is_pending());
        jobs.poll(cx);
        future.as_mut().poll(cx)
    })
    .await
}
