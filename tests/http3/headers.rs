use http_body::Body;

use super::*;

struct Preserve;

impl netty::ext::OnPreserveHeaderCallback for Preserve {
    fn call(&self, headers: &mut HeaderMap) {
        // The callback must see automatically inserted framing fields.
        assert_eq!(headers["content-length"], "0");
        let mut old = std::mem::take(headers);
        headers.insert("x-last", old.remove("x-last").unwrap());
        headers.insert("x-first", old.remove("x-first").unwrap());
        headers.extend(old);
        headers.insert("x-preserved", "yes".parse().unwrap());
    }

    fn call_visit(
        &self,
        _: &mut HeaderMap,
        _: &mut dyn FnMut(&dyn AsRef<[u8]>, &http::HeaderValue),
    ) {
        panic!("HTTP/3 uses the header map callback, like HTTP/2");
    }
}

#[tokio::test]
async fn preserve_header_callback_reaches_peer_in_order() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let mut drive = Box::pin(driver);
        let peer = tokio::spawn(async move {
            let (request, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.headers()["x-preserved"], "yes");
            let names: Vec<_> = request.headers().keys().map(|name| name.as_str()).collect();
            assert_eq!(
                names,
                ["x-last", "x-first", "content-length", "x-preserved"]
            );
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let mut request = Request::post("https://localhost/")
            .header("x-first", "one")
            .header("x-last", "two")
            .body(Full::new(Bytes::new()))
            .unwrap();
        netty::ext::on_preserve_header(&mut request, Preserve);
        tx.try_send_request(request)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        drop(tx);
        drive.as_mut().graceful_shutdown();
        drive.await.unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn request_content_length_matches_method_and_body() {
    let cases = [
        ("GET", "", None),
        ("HEAD", "", None),
        ("DELETE", "", None),
        ("OPTIONS", "", None),
        ("POST", "", Some("0")),
        ("PUT", "", Some("0")),
        ("PATCH", "", Some("0")),
        ("GET", "data", Some("4")),
        ("GET", "", Some("0")),
    ];
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let mut drive = Box::pin(driver);
        let peer = tokio::spawn(async move {
            for (method, body, length) in cases {
                let (request, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.method(), method);
                assert_eq!(
                    request
                        .headers()
                        .get("content-length")
                        .map(|v| v.to_str().unwrap()),
                    length,
                    "{method}"
                );
                let mut received = BytesMut::new();
                while let Some(mut data) = stream.recv_data().await.unwrap() {
                    received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                assert_eq!(received.as_ref(), body.as_bytes());
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            }
            let _ = server.accept().await;
        });
        for (index, (method, body, _)) in cases.into_iter().enumerate() {
            let mut request = Request::builder().method(method).uri("https://localhost/");
            if index == cases.len() - 1 {
                request = request.header("content-length", "0");
            }
            tx.try_send_request(
                request
                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        }
        drop(tx);
        drive.as_mut().graceful_shutdown();
        drive.await.unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn connection_headers_are_stripped_before_sending() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let mut drive = Box::pin(driver);
        let peer = tokio::spawn(async move {
            for te in [None, Some("trailers")] {
                let (request, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                for name in [
                    "connection",
                    "keep-alive",
                    "proxy-connection",
                    "upgrade",
                    "transfer-encoding",
                    "x-hop",
                ] {
                    assert!(!request.headers().contains_key(name), "{name}");
                }
                assert_eq!(request.headers()["x-end-to-end"], "kept");
                assert_eq!(request.headers().get("te").map(|v| v.to_str().unwrap()), te);
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
            }
            let _ = server.accept().await;
        });
        for te in ["gzip", "trailers"] {
            let request = Request::get("https://localhost/")
                .header("connection", "keep-alive, x-hop")
                .header("keep-alive", "timeout=5")
                .header("proxy-connection", "keep-alive")
                .header("upgrade", "websocket")
                .header("transfer-encoding", "chunked")
                .header("x-hop", "removed")
                .header("x-end-to-end", "kept")
                .header("te", te)
                .body(Full::new(Bytes::new()))
                .unwrap();
            tx.try_send_request(request)
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap();
        }
        drop(tx);
        drive.as_mut().graceful_shutdown();
        drive.await.unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn informational_content_length_does_not_set_final_body_length() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let mut drive = Box::pin(driver);
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            // More heads than one poll budget must still reach the final response.
            for length in ["0", "123"].into_iter().cycle().take(40) {
                stream
                    .send_response(
                        Response::builder()
                            .status(103)
                            .header("content-length", length)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            }
            stream
                .send_response(
                    Response::builder()
                        .header("content-length", "4")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.send_data(Bytes::from_static(b"done")).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "done"
        );
        drop(tx);
        drive.as_mut().graceful_shutdown();
        drive.await.unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn response_size_hint_tracks_data_and_keeps_trailers() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let mut drive = Box::pin(driver);
        let (resume, resumed) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream
                .send_response(
                    Response::builder()
                        .header("content-length", "6")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.send_data(Bytes::from_static(b"one")).await.unwrap();
            resumed.await.unwrap();
            stream.send_data(Bytes::from_static(b"two")).await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", "yes".parse().unwrap());
            stream.send_trailers(trailers).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        assert_eq!(body.size_hint().exact(), Some(6));
        let mut left = 6;
        while left > 3 {
            let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
            left -= data.len() as u64;
            assert_eq!(body.size_hint().exact(), Some(left));
        }
        assert_eq!(left, 3);
        resume.send(()).unwrap();
        while left > 0 {
            let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
            left -= data.len() as u64;
            assert_eq!(body.size_hint().exact(), Some(left));
        }
        assert!(
            !body.is_end_stream(),
            "zero remaining bytes must not hide trailers"
        );
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap()["x-finished"],
            "yes"
        );
        assert!(body.frame().await.is_none());
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        drop(tx);
        drive.as_mut().graceful_shutdown();
        drive.await.unwrap();
        peer.await.unwrap();
    })
    .await;
}
