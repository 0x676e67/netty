use super::*;

#[tokio::test]
async fn upload_failure_cancels_unread_response_and_releases_request() {
    type Body = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

    for poll_body in [false, true] {
        bounded(async {
            let Pair {
                mut tx,
                driver,
                mut server,
                _endpoints,
                ..
            } = pair_with::<Body, _>(
                Http3Options::builder().max_concurrent_requests(1).build(),
                Exec,
            )
            .await;
            let drive = tokio::spawn(driver);
            let (canceled, cancellation_seen) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let resolver = server.accept().await.unwrap().unwrap();
                let first = tokio::spawn(async move {
                    let (_, stream) = resolver.resolve_request().await.unwrap();
                    let (mut send, mut recv) = stream.split();
                    send.send_response(Response::new(())).await.unwrap();
                    assert!(matches!(recv.recv_data().await,
                        Err(h3::error::StreamError::RemoteTerminate { code, .. })
                            if code == h3::error::Code::H3_REQUEST_CANCELLED));
                    loop {
                        if let Err(error) = send.send_data(Bytes::from(vec![1; 64 * 1024])).await {
                            assert!(matches!(error,
                                h3::error::StreamError::RemoteTerminate { code, .. }
                                    if code == h3::error::Code::H3_REQUEST_CANCELLED));
                            break;
                        }
                    }
                    canceled.send(()).unwrap();
                });
                let (_, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert!(stream.recv_data().await.unwrap().is_none());
                stream.send_response(Response::new(())).await.unwrap();
                stream.finish().await.unwrap();
                first.await.unwrap();
                let _ = server.accept().await;
            });
            let (fail, failed) = oneshot::channel();
            let upload = http_body_util::StreamBody::new(futures_util::stream::once(async move {
                failed.await.unwrap();
                Err::<http_body::Frame<Bytes>, _>(std::io::Error::other(
                    "upload failed after response",
                ))
            }))
            .boxed();
            let response = tx
                .try_send_request(
                    Request::post("https://localhost/failing")
                        .body(upload)
                        .unwrap(),
                )
                .await
                .unwrap();
            let mut body = response.into_body();
            let mut frame = tokio_test::task::spawn(body.frame());
            if poll_body {
                assert!(frame.poll().is_pending());
            }
            fail.send(()).unwrap();
            // Both RESET_STREAM and STOP_SENDING must reach the peer while the
            // application retains the response without advancing its Body.
            cancellation_seen.await.unwrap();
            let response = tx
                .try_send_request(
                    Request::get("https://localhost/healthy")
                        .body(
                            Full::new(Bytes::new())
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
            if poll_body {
                assert!(frame.is_woken(), "upload failure must wake a pending Body");
            }
            let error = match frame.poll() {
                std::task::Poll::Ready(Some(Err(error))) => error,
                result => panic!("expected the upload error, got {result:?}"),
            };
            assert!(error.is_user(), "{error:?}");
            let cause = std::iter::successors(Some(&error as &dyn std::error::Error), |error| {
                error.source()
            })
            .find_map(|error| error.downcast_ref::<std::io::Error>())
            .expect("original upload error is retained");
            assert_eq!(cause.to_string(), "upload failed after response");
            drop(frame);
            assert!(body.frame().await.is_none());
            drop(tx);
            drive.await.unwrap().unwrap();
            peer.await.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn dropping_response_body_preserves_pending_upload() {
    bounded(async {
        let (upload, ready) = oneshot::channel();
        let body = http_body_util::StreamBody::new(futures_util::stream::once(async move {
            ready.await.unwrap();
            Ok::<_, std::convert::Infallible>(http_body::Frame::data(Bytes::from_static(b"upload")))
        }));
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_with(Http3Options::default(), Exec).await;
        let drive = tokio::spawn(driver);
        let (dropped, body_dropped) = oneshot::channel();
        let (stopped, receive_stopped) = oneshot::channel();
        let (finished, upload_received) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let resolver = server.accept().await.unwrap().unwrap();
            let request = tokio::spawn(async move {
                let (_, stream) = resolver.resolve_request().await.unwrap();
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
                stopped.send(()).unwrap();
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
        let response = tx
            .try_send_request(
                Request::post("https://localhost/independent-directions")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap_or_else(|error| panic!("{}", error.error()));
        drop(response);
        dropped.send(()).unwrap();
        // Observe STOP_SENDING before resuming the upload, so an implementation
        // that cancels both halves cannot accidentally finish sending first.
        receive_stopped.await.unwrap();
        upload.send(()).expect("response drop must preserve upload");
        upload_received.await.unwrap();
        drop(tx);
        drive.await.unwrap().unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn graceful_shutdown_returns_queued_requests_and_honors_external_deadline() {
    for expire in [false, true] {
        bounded(async {
            let Pair {
                mut tx,
                driver,
                mut server,
                _endpoints,
                ..
            } = pair(Http3Options::builder().max_concurrent_requests(1).build()).await;
            let (shutdown, requested) = oneshot::channel();
            let (draining, started) = oneshot::channel();
            let client = tokio::spawn(async move {
                let mut driver = Box::pin(driver);
                tokio::select! {
                    result = &mut driver => panic!("connection ended before shutdown: {result:?}"),
                    result = requested => result.unwrap(),
                }
                driver.as_mut().graceful_shutdown();
                futures_util::future::poll_fn(|cx| {
                    assert!(driver.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                draining.send(()).unwrap();
                if expire {
                    // The peer deliberately keeps the response unfinished, so
                    // only the caller's deadline can terminate this drain.
                    assert!(timeout(Duration::ZERO, driver.as_mut()).await.is_err());
                    drop(driver);
                } else {
                    driver.await.unwrap();
                }
            });
            let (finish, permitted) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let (request, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.uri().path(), "/active");
                stream
                    .send_response(
                        Response::builder()
                            .header("content-length", 5)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if permitted.await.unwrap() {
                    stream
                        .send_data(Bytes::from_static(b"drain"))
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }
                match server.accept().await {
                    Ok(None) => {}
                    Err(error) if error.is_h3_no_error() => {}
                    _ => panic!("queued request reached peer or connection failed"),
                }
            });
            let response = tx
                .try_send_request(
                    Request::get("https://localhost/active")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let queued = tx.try_send_request(
                Request::get("https://localhost/queued")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            );
            let mut blocked = tx.clone();
            futures_util::future::poll_fn(|cx| {
                assert!(matches!(
                    blocked.poll_ready(cx),
                    std::task::Poll::Ready(Ok(()))
                ));
                std::task::Poll::Ready(())
            })
            .await;
            shutdown.send(()).unwrap();
            started.await.unwrap();
            assert!(blocked.ready().await.is_err());
            assert!(tx.is_closed());
            let returned = queued.await.unwrap_err().take_message().unwrap();
            assert_eq!(returned.uri().path(), "/queued");
            finish.send(!expire).unwrap();
            let body = response.into_body().collect().await;
            if expire {
                assert!(
                    body.is_err(),
                    "deadline turned a partial response into clean EOF"
                );
            } else {
                assert_eq!(body.unwrap().to_bytes(), "drain");
            }
            client.await.unwrap();
            peer.await.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn no_error_abort_does_not_complete_unfinished_response() {
    for close_connection in [false, true] {
        for length in [None, Some(1), Some(2)] {
            bounded(async {
                let Pair {
                    mut tx,
                    driver,
                    mut server,
                    server_quic,
                    _endpoints,
                } = pair(Http3Options::default()).await;
                let drive = tokio::spawn(driver);
                let (abort, ready) = oneshot::channel();
                let peer = tokio::spawn(async move {
                    let (_, mut stream) = server
                        .accept()
                        .await
                        .unwrap()
                        .unwrap()
                        .resolve_request()
                        .await
                        .unwrap();
                    let mut headers = Response::builder();
                    if let Some(length) = length {
                        headers = headers.header("content-length", length);
                    }
                    stream
                        .send_response(headers.body(()).unwrap())
                        .await
                        .unwrap();
                    stream.send_data(Bytes::from_static(b"x")).await.unwrap();
                    // H3_NO_ERROR does not replace a response FIN, even when
                    // Content-Length is satisfied. RFC 9114 sections 4.1 and 8:
                    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
                    ready.await.unwrap();
                    if close_connection {
                        server_quic.close(
                            quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value()).unwrap(),
                            b"closed",
                        );
                    } else {
                        stream.stop_stream(h3::error::Code::H3_NO_ERROR);
                        let (_, mut survivor) = server
                            .accept()
                            .await
                            .unwrap()
                            .unwrap()
                            .resolve_request()
                            .await
                            .unwrap();
                        survivor.send_response(Response::new(())).await.unwrap();
                        survivor
                            .send_data(Bytes::from_static(b"healthy"))
                            .await
                            .unwrap();
                        survivor.finish().await.unwrap();
                    }
                    let _ = server.accept().await;
                });
                let response = tx
                    .try_send_request(
                        Request::get("https://localhost/incomplete")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let mut body = response.into_body();
                assert_eq!(
                    body.frame().await.unwrap().unwrap().into_data().unwrap(),
                    "x"
                );
                {
                    let mut frame = std::pin::pin!(body.frame());
                    futures_util::future::poll_fn(|cx| {
                        assert!(frame.as_mut().poll(cx).is_pending());
                        std::task::Poll::Ready(())
                    })
                    .await;
                }
                abort.send(()).unwrap();
                let error = body
                    .frame()
                    .await
                    .expect("unfinished response became EOF")
                    .unwrap_err();
                assert!(!error.is_user());
                assert!(body.frame().await.is_none());
                assert!(http_body::Body::is_end_stream(&body));
                if close_connection {
                    drive.await.unwrap().unwrap();
                    assert!(tx.is_closed());
                    let error = tx
                        .try_send_request(
                            Request::get("https://localhost/closed")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                        .await
                        .unwrap_err();
                    assert!(error.message().is_some());
                } else {
                    let response = tx
                        .try_send_request(
                            Request::get("https://localhost/survivor")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.into_body().collect().await.unwrap().to_bytes(),
                        "healthy"
                    );
                    drop(tx);
                    drive.await.unwrap().unwrap();
                }
                peer.await.unwrap();
            })
            .await;
        }
    }
}

#[tokio::test]
async fn zero_length_headers_do_not_wait_for_fin_or_discard_trailers() {
    for with_trailers in [false, true] {
        bounded(async {
            let Pair {
                mut tx,
                driver,
                mut server,
                _endpoints,
                ..
            } = pair(Http3Options::default()).await;
            let drive = tokio::spawn(driver);
            let (finish, ready) = oneshot::channel();
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
                            .header("content-length", 0)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                ready.await.unwrap();
                if with_trailers {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("x-finished", "yes".parse().unwrap());
                    stream.send_trailers(trailers).await.unwrap();
                }
                stream.finish().await.unwrap();
                let _ = server.accept().await;
            });
            let response = tx
                .try_send_request(
                    Request::get("https://localhost/empty")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let mut body = response.into_body();
            assert!(!http_body::Body::is_end_stream(&body));
            {
                let mut frame = std::pin::pin!(body.frame());
                futures_util::future::poll_fn(|cx| {
                    assert!(frame.as_mut().poll(cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
            }
            finish.send(()).unwrap();
            let body = body.collect().await.unwrap();
            if with_trailers {
                assert_eq!(body.trailers().unwrap()["x-finished"], "yes");
            } else {
                assert!(body.trailers().is_none());
            }
            assert!(body.to_bytes().is_empty());
            drop(tx);
            drive.await.unwrap().unwrap();
            peer.await.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn empty_data_frames_do_not_end_response() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let drive = tokio::spawn(driver);
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
                        .header("content-length", 3)
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            // Empty DATA is permitted between body frames; it is not FIN.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
            for data in [Bytes::new(), Bytes::from_static(b"abc"), Bytes::new()] {
                stream.send_data(data).await.unwrap();
            }
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", "yes".parse().unwrap());
            stream.send_trailers(trailers).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/empty-data")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["x-finished"], "yes");
        assert_eq!(body.to_bytes(), "abc");
        drop(tx);
        drive.await.unwrap().unwrap();
        peer.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn small_response_data_is_delivered_before_peer_sends_more() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair(Http3Options::default()).await;
        let drive = tokio::spawn(driver);
        let (consumed, ready) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream
                .send_data(Bytes::from_static(b"first"))
                .await
                .unwrap();
            // The client must receive this partial batch without a FIN, a
            // full batch, a second DATA frame, or an elapsed flush timer.
            ready.await.unwrap();
            stream
                .send_data(Bytes::from_static(b"second"))
                .await
                .unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-finished", "yes".parse().unwrap());
            stream.send_trailers(trailers).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/stream")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        let mut first = BytesMut::new();
        while first.len() < 5 {
            first.extend_from_slice(&body.frame().await.unwrap().unwrap().into_data().unwrap());
        }
        assert_eq!(first, "first");
        consumed.send(()).unwrap();
        let rest = body.collect().await.unwrap();
        assert_eq!(rest.trailers().unwrap()["x-finished"], "yes");
        assert_eq!(rest.to_bytes(), "second");
        drop(tx);
        drive.await.unwrap().unwrap();
        peer.await.unwrap();
    })
    .await;
}
