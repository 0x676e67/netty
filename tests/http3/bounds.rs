//! The handshake accepts an executor and a QUIC backend that are `Send` but
//! neither `Sync` nor `Unpin`; the QUIC traits only take `&mut self`.
use std::{
    cell::Cell,
    marker::{PhantomData, PhantomPinned},
    task::{Context, Poll},
};

use netty::rt::quic::{self as rt, OpenStreams};

use super::*;

/// Spawns like `Exec` but is not `Sync`.
#[derive(Clone, Copy, Default)]
struct SendOnly(PhantomData<Cell<()>>);

impl<F: Future<Output = ()> + Send + 'static> Executor<F> for SendOnly {
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}

/// Forwards to the native transport; the connection and its opener are
/// neither `Sync` nor `Unpin`.
#[derive(Clone)]
struct Transport<T>(T, PhantomData<Cell<()>>, PhantomPinned);

impl<T: rt::Connection<Bytes>> rt::Connection<Bytes> for Transport<T> {
    type RecvStream = T::RecvStream;

    type OpenStreams = Transport<T::OpenStreams>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::RecvStream>, rt::ConnectionError>> {
        self.0.poll_accept_recv(cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::BidiStream>, rt::ConnectionError>> {
        self.0.poll_accept_bidi(cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        Transport(self.0.opener(), PhantomData, PhantomPinned)
    }
}

impl<T: OpenStreams<Bytes>> OpenStreams<Bytes> for Transport<T> {
    type SendStream = T::SendStream;

    type BidiStream = T::BidiStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, rt::StreamError>> {
        self.0.poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, rt::StreamError>> {
        self.0.poll_open_send(cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.0.close(code, reason);
    }
}

#[tokio::test]
async fn handshake_accepts_send_only_executor_and_non_unpin_backend() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let ((mut tx, driver), mut server) = tokio::join!(
            async {
                Builder::new(SendOnly::default())
                    .handshake::<_, ClientBody>(Transport(
                        native::Connection::new(client),
                        PhantomData,
                        PhantomPinned,
                    ))
                    .await
                    .unwrap()
            },
            async {
                h3::server::builder()
                    .build::<_, Bytes>(h3_quinn::Connection::new(server))
                    .await
                    .unwrap()
            }
        );
        let mut client_driver = Box::pin(driver);
        let server_task = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            let _ = server.accept().await;
        });
        let response = tx
            .try_send_request(
                Request::get("https://localhost/send-only")
                    .body(Full::new(Bytes::new()))
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
        drop(tx);
        client_driver.as_mut().graceful_shutdown();
        client_driver.await.unwrap();
        server_task.await.unwrap();
    })
    .await;
}
