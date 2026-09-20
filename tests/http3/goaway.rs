use std::{
    pin::Pin,
    task::{Context, Poll},
};

use super::*;

#[derive(Debug)]
struct Started(Option<oneshot::Sender<()>>);

impl http_body::Body for Started {
    type Data = Bytes;

    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if let Some(started) = self.0.take() {
            let _ = started.send(());
        }
        Poll::Ready(None)
    }
}

#[tokio::test]
async fn decreasing_goaway_rejects_boundary_streams_without_peer_resets() {
    bounded(async {
        let Pair {
            mut tx,
            driver,
            mut server,
            _endpoints,
            ..
        } = pair_with::<Started, _>(Http3Options::default(), Exec).await;
        let drive = tokio::spawn(driver);
        let (goaway, requested) = oneshot::channel();
        let (lower, lowered) = oneshot::channel();
        let (finish, permitted) = oneshot::channel();
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
            requested.await.unwrap();
            // Only stream 0 is accepted. Lower the wire boundary from 8 to 4
            // without accepting those streams or sending an individual reset.
            server.shutdown(2).await.unwrap();
            lowered.await.unwrap();
            server.shutdown(1).await.unwrap();
            permitted.await.unwrap();
            stream
                .send_data(Bytes::from_static(b"accepted"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            server
        });
        let accepted = tx
            .try_send_request(
                Request::get("https://localhost/accepted")
                    .body(Started(None))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (started, written) = oneshot::channel();
        let rejected = tx.try_send_request(
            Request::get("https://localhost/rejected")
                .body(Started(Some(started)))
                .unwrap(),
        );
        let rejected = tokio::spawn(rejected);
        written.await.unwrap();
        let (started, written) = oneshot::channel();
        let later = tokio::spawn(
            tx.try_send_request(
                Request::get("https://localhost/later")
                    .body(Started(Some(started)))
                    .unwrap(),
            ),
        );
        written.await.unwrap();
        goaway.send(()).unwrap();
        let error = later.await.unwrap().unwrap_err();
        assert_rejection(error.error(), 8, 8);
        lower.send(()).unwrap();
        let error = rejected.await.unwrap().unwrap_err();
        assert!(!error.error().is_timeout());
        assert_rejection(error.error(), 4, 4);
        finish.send(()).unwrap();
        assert_eq!(
            accepted.into_body().collect().await.unwrap().to_bytes(),
            "accepted"
        );
        let _server = peer.await.unwrap();
        drop(tx);
        drive.await.unwrap().unwrap();
    })
    .await;
}

fn assert_rejection(error: &wreq_proto::Error, stream: u64, boundary: u64) {
    assert!(error.is_h3_request_rejected());
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if let Some(::http3::error::StreamError::GoawayRejected {
            stream_id,
            boundary: actual,
            ..
        }) = source.downcast_ref::<::http3::error::StreamError>()
        {
            assert_eq!(stream_id.into_inner(), stream);
            assert_eq!(actual.into_inner(), boundary);
            return;
        }
        source = source.source().expect("missing GOAWAY rejection source");
    }
}

#[tokio::test]
async fn goaway_cancels_partially_written_headers_without_resuming_transport() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let pause = pause::Pause::default();
        let (mut tx, driver) = Builder::new(Exec)
            .handshake::<_, ClientBody>(pause.wrap(crate::native::Connection::new(client)))
            .await
            .unwrap();
        let drive = tokio::spawn(driver);
        let mut server = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let request = tx.try_send_request(
            Request::get("https://localhost/partial")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        );
        pause.blocked().await;
        server.shutdown(0).await.unwrap();
        let error = request.await.unwrap_err();
        assert_rejection(error.error(), 0, 0);
        drop(tx);
        drive.await.unwrap().unwrap();
        // Forwarding a rejected request as another upload's Body error must not
        // classify that second request as unprocessed by its own peer.
        assert_user_body_error(error.into_error().into()).await;
    })
    .await;
}
