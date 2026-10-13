#![deny(warnings)]

use std::{
    cell::RefCell,
    convert::Infallible,
    future::{Future, Ready, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_channel::oneshot;
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
};
use http_body_util::Empty;
use hyper::service::service_fn;
use netty::proxy::tunnel::{TunnelConnector, TunnelError};
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};
use tower_service::Service;

use crate::support::TokioIo;

const BANNER: &[u8] = b"SSH-2.0-banner\r\n";

#[derive(Debug)]
struct Pipe(Option<DuplexStream>);

/// Splits Hyper's writes and yields between bytes to exercise fragmented response heads.
struct Fragmented {
    io: DuplexStream,
    yield_write: bool,
}

// ===== impl Pipe =====

impl Service<Uri> for Pipe {
    type Response = DuplexStream;
    type Error = io::Error;
    type Future = Ready<io::Result<DuplexStream>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(match self.0 {
            Some(_) => Ok(()),
            None => Err(io::ErrorKind::ConnectionRefused.into()),
        })
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        assert_eq!(dst, "http://proxy.local:3128");
        std::future::ready(
            self.0
                .take()
                .ok_or_else(|| io::ErrorKind::ConnectionRefused.into()),
        )
    }
}

// ===== impl Fragmented =====

impl AsyncRead for Fragmented {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Fragmented {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.yield_write {
            self.yield_write = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = Pin::new(&mut self.io).poll_write(cx, &buf[..buf.len().min(1)]);
        if matches!(result, Poll::Ready(Ok(n)) if n != 0) {
            self.yield_write = true;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn headers(fields: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for &(name, value) in fields {
        headers.append(name, HeaderValue::from_static(value));
    }
    headers
}

fn auth() -> HeaderValue {
    HeaderValue::from_static("Basic Zm9vOmJhcg==")
}

fn assert_request(request: &Request<hyper::body::Incoming>, authority: &str, expected: &HeaderMap) {
    assert_eq!(request.method(), Method::CONNECT);
    assert_eq!(request.version(), Version::HTTP_11);
    assert_eq!(request.uri().authority().unwrap().as_str(), authority);
    assert!(request.uri().scheme().is_none());
    assert!(request.uri().path_and_query().is_none());
    assert_eq!(request.headers().get_all(HOST).iter().count(), 1);
    assert!(!request.headers().contains_key(CONTENT_LENGTH));
    assert!(!request.headers().contains_key(TRANSFER_ENCODING));
    assert_eq!(request.headers(), expected);
}

async fn bounded<F>(future: F) -> F::Output
where
    F: Future,
{
    if cfg!(miri) {
        return future.await;
    }
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("CONNECT or tunneled IO stalled")
}

#[tokio::test]
async fn connector_establishes_tunnel() {
    type Configure = fn(TunnelConnector<Pipe>) -> TunnelConnector<Pipe>;
    let cases: [(&str, Configure, &str, &[(&str, &str)]); 8] = [
        (
            "https://example.com",
            |c| c.with_auth(auth()),
            "example.com:443",
            &[
                ("host", "example.com:443"),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
            ],
        ),
        (
            "http://example.com",
            |c| {
                c.with_auth(auth())
                    .with_headers(headers(&[("x-trace", "1")]))
            },
            "example.com:80",
            &[
                ("host", "example.com:80"),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
                ("x-trace", "1"),
            ],
        ),
        (
            "https://example.com:8443",
            |c| {
                c.with_headers(headers(&[("x-trace", "1")]))
                    .with_auth(auth())
            },
            "example.com:8443",
            &[
                ("host", "example.com:8443"),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
                ("x-trace", "1"),
            ],
        ),
        (
            "https://[2001:db8::1]",
            |c| {
                c.with_auth(auth())
                    .with_headers(headers(&[("proxy-authorization", "Basic b3RoZXI=")]))
            },
            "[2001:db8::1]:443",
            &[
                ("host", "[2001:db8::1]:443"),
                ("proxy-authorization", "Basic b3RoZXI="),
            ],
        ),
        (
            "https://example.com",
            |c| {
                c.with_headers(headers(&[("x-trace", "1")]))
                    .with_auth(auth())
                    .with_headers(headers(&[("proxy-authorization", "Basic b3RoZXI=")]))
            },
            "example.com:443",
            &[
                ("host", "example.com:443"),
                ("proxy-authorization", "Basic b3RoZXI="),
                ("x-trace", "1"),
            ],
        ),
        (
            "wss://example.com",
            |c| {
                c.with_headers(headers(&[
                    ("via", "a"),
                    ("host", "proxy.example"),
                    ("content-length", "5"),
                    ("transfer-encoding", "chunked"),
                ]))
                .with_headers(headers(&[("via", "b"), ("via", "c")]))
            },
            "example.com:443",
            &[("host", "proxy.example"), ("via", "b"), ("via", "c")],
        ),
        (
            "ws://user:pass@example.com",
            |c| c,
            "example.com:80",
            &[("host", "example.com:80")],
        ),
        (
            "example.com:",
            |c| c,
            "example.com:443",
            &[("host", "example.com:443")],
        ),
    ];

    for (index, (dst, configure, authority, fields)) in cases.into_iter().enumerate() {
        let (client_io, server_io) = tokio::io::duplex(64);
        let (upgrade_tx, upgrade_rx) = oneshot::channel();
        let upgrade_tx = RefCell::new(Some(upgrade_tx));
        // Exercise the full successful range, including statuses other than 200.
        let status = StatusCode::from_u16([200, 204, 299][index % 3]).unwrap();
        let expected = headers(fields);
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            assert_request(&request, authority, &expected);
            upgrade_tx
                .borrow_mut()
                .take()
                .expect("single CONNECT request")
                .send(hyper::upgrade::on(request))
                .expect("upgrade receiver");
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
            }
        });
        let server = async move {
            let connection = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(Fragmented {
                        io: server_io,
                        yield_write: false,
                    }),
                    service,
                )
                .with_upgrades();
            let exchange = async move {
                let upgraded = upgrade_rx
                    .await
                    .expect("CONNECT service")
                    .await
                    .expect("HTTP upgrade");
                let mut io = TokioIo::new(upgraded);
                // Write before reading so loss of early tunnel data stalls the client.
                io.write_all(BANNER).await.expect("server-first banner");
                let mut ping = [0; 4];
                io.read_exact(&mut ping).await.expect("tunneled ping");
                assert_eq!(&ping, b"ping");
                io.write_all(b"pong").await.expect("tunneled pong");
            };
            let (connection, ()) = tokio::join!(connection, exchange);
            connection.expect("Hyper proxy connection");
        };
        let client = async move {
            let mut connector = configure(TunnelConnector::new(
                "http://proxy.local:3128".parse().unwrap(),
                Pipe(Some(client_io)),
            ));
            let debug = format!("{connector:?}");
            for secret in ["Zm9vOmJhcg==", "b3RoZXI="] {
                assert!(!debug.contains(secret), "{debug}");
            }
            poll_fn(|cx| connector.poll_ready(cx))
                .await
                .expect("connector ready");
            let mut io = connector.call(dst.parse().unwrap()).await.expect("tunnel");
            let mut banner = [0; BANNER.len()];
            io.read_exact(&mut banner)
                .await
                .expect("early tunnel bytes");
            assert_eq!(&banner, BANNER);
            io.write_all(b"ping").await.expect("tunneled ping");
            let mut pong = [0; 4];
            io.read_exact(&mut pong).await.expect("tunneled pong");
            assert_eq!(&pong, b"pong");
        };
        bounded(async { tokio::join!(server, client) }).await;
    }
}

#[tokio::test]
async fn connector_reports_proxy_rejection() {
    for status in [StatusCode::PROXY_AUTHENTICATION_REQUIRED, StatusCode::FOUND] {
        let (client_io, server_io) = tokio::io::duplex(64);
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            assert_request(
                &request,
                "example.com:443",
                &headers(&[("host", "example.com:443")]),
            );
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
            }
        });
        let server = async move {
            hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(Fragmented {
                        io: server_io,
                        yield_write: false,
                    }),
                    service,
                )
                .await
                .expect("Hyper proxy rejection");
        };
        let client = async move {
            let mut connector = TunnelConnector::new(
                "http://proxy.local:3128".parse().unwrap(),
                Pipe(Some(client_io)),
            );
            poll_fn(|cx| connector.poll_ready(cx))
                .await
                .expect("connector ready");
            match (
                status,
                connector.call("https://example.com".parse().unwrap()).await,
            ) {
                (
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    Err(TunnelError::ProxyAuthRequired),
                )
                | (StatusCode::FOUND, Err(TunnelError::TunnelUnsuccessful(StatusCode::FOUND))) => {}
                (_, Err(err)) => panic!("unexpected tunnel error: {err:?}"),
                (_, Ok(_)) => panic!("rejected CONNECT established a tunnel"),
            }
        };
        bounded(async { tokio::join!(server, client) }).await;
    }
}
