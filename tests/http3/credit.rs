//! Concurrent openers must survive canceled waiters and replenished QUIC credit.
use std::sync::Arc;

use futures_util::{stream::FuturesUnordered, StreamExt};
use tokio::sync::mpsc;

use super::*;

#[derive(Clone)]
struct CompletionExec(mpsc::UnboundedSender<()>);

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for CompletionExec {
    fn execute(&self, future: F) {
        let completed = self.0.clone();
        tokio::spawn(async move {
            future.await;
            let _ = completed.send(());
        });
    }
}

#[tokio::test]
async fn canceled_openers_do_not_strand_other_credit_waiters() {
    bounded(async {
        const REQUESTS: usize = 32;
        let (_, mut server_config, client_config) = tls::config();
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(0_u32.into());
        server_config.transport_config(Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let client_stats = client.clone();
        let server_quic = server.clone();
        let pause = pause::Pause::default();
        pause.resume();
        let (completed, mut completions) = mpsc::unbounded_channel();
        let (mut tx, driver) = Builder::new(CompletionExec(completed))
            .handshake::<_, ClientBody>(pause.wrap(crate::native::Connection::new(client)))
            .await
            .unwrap();
        let client_driver = tokio::spawn(driver);
        let mut server = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(server))
            .await
            .unwrap();
        let mut requests = Vec::new();
        for index in 0..REQUESTS {
            tx.ready().await.unwrap();
            requests.push(Some(
                tx.try_send_request(
                    Request::get(format!("https://localhost/{index}"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                ),
            ));
            pause.waiting_for_credit().await;
        }
        for request in requests.iter_mut().step_by(2) {
            drop(request.take());
        }
        // Wait for cancellation to destroy the native OpenBi futures before
        // granting credit, so canceled requests cannot race onto the wire.
        for _ in 0..REQUESTS / 2 {
            completions.recv().await.unwrap();
        }
        assert_eq!(pause.observers(), 0);
        server_quic.set_max_concurrent_bi_streams(1_u32.into());
        let peer = tokio::spawn(async move {
            let mut seen = [false; REQUESTS];
            for _ in 0..REQUESTS / 2 {
                let (request, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                let path = request.uri().path();
                let index: usize = path.trim_start_matches('/').parse().unwrap();
                assert!(index < REQUESTS && index % 2 == 1);
                assert!(!seen[index], "duplicate request");
                seen[index] = true;
                assert!(stream.recv_data().await.unwrap().is_none());
                stream.send_response(Response::new(())).await.unwrap();
                stream
                    .send_data(Bytes::copy_from_slice(path.as_bytes()))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
            assert!(seen
                .iter()
                .enumerate()
                .all(|(i, &seen)| seen == (i % 2 == 1)));
            match server.accept().await {
                Ok(None) => {}
                Err(error) if error.is_h3_no_error() => {}
                _ => panic!("unexpected request or connection failure"),
            }
        });
        let mut survivors = requests
            .into_iter()
            .enumerate()
            .filter_map(|(index, request)| request.map(|request| (index, request)))
            .map(|(index, request)| async move {
                let body = request
                    .await
                    .unwrap()
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                assert_eq!(body, format!("/{index}"));
            })
            .collect::<FuturesUnordered<_>>();
        while survivors.next().await.is_some() {}
        for _ in 0..REQUESTS / 2 {
            completions.recv().await.unwrap();
        }
        assert_eq!(pause.observers(), 0);
        assert!(client_stats.stats().frame_rx.max_streams_bidi > 1);
        drop(tx);
        client_driver.await.unwrap().unwrap();
        peer.await.unwrap();
    })
    .await;
}
