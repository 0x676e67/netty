use std::{
    fmt,
    pin::Pin,
    task::{ready, Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use super::{chan, DecodedLength};
use crate::{proto::http2::ping, Error, Result};

/// A stream of [`Bytes`], used when receiving bodies from the network.
///
/// Note that Users should not instantiate this struct directly. When working with the client,
/// [`Incoming`] is returned to you in responses.
#[must_use = "streams do nothing unless polled"]
pub struct Incoming {
    kind: Kind,
}

enum Kind {
    H1 {
        rx: chan::Receiver,
        content_length: DecodedLength,
    },
    H2 {
        ping: ping::Recorder,
        recv: http2::RecvStream,
        content_length: DecodedLength,
        data_done: bool,
    },
    #[cfg(feature = "http3")]
    H3 {
        rx: chan::Receiver,
        done: bool,
    },
    Empty,
}

/// A sender half created through [`Body::channel()`].
///
/// Useful when wanting to stream chunks from another thread.
///
/// ## Body Closing
///
/// Note that the request body will always be closed normally when the sender is dropped
/// (meaning that the empty terminating chunk will be sent to the remote). If you desire to
/// close the connection with an incomplete response (e.g. in the case of an error during
/// asynchronous processing), call the [`Sender::abort()`] method to abort the body in an
/// abnormal fashion.
///
/// [`Body::channel()`]: struct.Body.html#method.channel
/// [`Sender::abort()`]: struct.Sender.html#method.abort
pub(crate) use super::chan::Sender;

// ===== impl Incoming =====

impl Incoming {
    #[inline]
    pub(crate) fn empty() -> Incoming {
        Incoming { kind: Kind::Empty }
    }

    pub(crate) fn h1(content_length: DecodedLength, wanter: bool) -> (Sender, Incoming) {
        let (tx, rx) = chan::channel(wanter);
        (
            tx,
            Incoming {
                kind: Kind::H1 { content_length, rx },
            },
        )
    }

    #[cfg(feature = "http3")]
    pub(crate) fn h3() -> (Sender, Self) {
        let (tx, rx) = chan::channel(false);
        (
            tx,
            Self {
                kind: Kind::H3 { rx, done: false },
            },
        )
    }

    pub(crate) fn h2(
        recv: http2::RecvStream,
        mut content_length: DecodedLength,
        ping: ping::Recorder,
    ) -> Self {
        // If the stream is already EOS, then the "unknown length" is clearly
        // actually ZERO.
        if !content_length.is_exact() && recv.is_end_stream() {
            content_length = DecodedLength::ZERO;
        }

        Incoming {
            kind: Kind::H2 {
                ping,
                recv,
                content_length,
                data_done: false,
            },
        }
    }
}

impl Body for Incoming {
    type Data = Bytes;

    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.kind {
            Kind::H1 {
                ref mut rx,
                ref mut content_length,
            } => {
                if let Some(chunk) = ready!(rx.poll_next(cx)?) {
                    content_length.sub_if(chunk.len() as u64);
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                Poll::Ready(rx.take_trailers().map(Frame::trailers).map(Ok))
            }
            Kind::H2 {
                ref ping,
                ref mut recv,
                ref mut content_length,
                ref mut data_done,
            } => {
                if !*data_done {
                    match ready!(recv.poll_data(cx)) {
                        Some(Ok(bytes)) => {
                            let _ = recv.flow_control().release_capacity(bytes.len());
                            content_length.sub_if(bytes.len() as u64);
                            ping.record_data(bytes.len());
                            return Poll::Ready(Some(Ok(Frame::data(bytes))));
                        }
                        Some(Err(e)) => {
                            if let Some(http2::Reason::NO_ERROR) = e.reason() {
                                // As mentioned in RFC 7540 Section 8.1, a RST_STREAM with NO_ERROR
                                // indicates an early response, and should cause the body reading
                                // to stop, but not fail it:
                                return Poll::Ready(None);
                            } else {
                                return Poll::Ready(Some(Err(Error::new_body(e))));
                            }
                        }
                        None => {
                            // fall through to trailers
                            *data_done = true;
                        }
                    }
                }

                // after data, check trailers
                match ready!(recv.poll_trailers(cx)) {
                    Ok(t) => {
                        ping.record_non_data();
                        Poll::Ready(Ok(t.map(Frame::trailers)).transpose())
                    }
                    Err(e) => {
                        if let Some(http2::Reason::NO_ERROR) = e.reason() {
                            // Same as above, a RST_STREAM with NO_ERROR indicates an early
                            // response, and should cause reading the trailers to stop, but
                            // not fail it:
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Err(Error::new_h2(e))))
                        }
                    }
                }
            }
            #[cfg(feature = "http3")]
            Kind::H3 {
                ref mut rx,
                ref mut done,
            } => {
                if *done {
                    return Poll::Ready(None);
                }
                match ready!(rx.poll_next(cx)) {
                    Some(Ok(data)) => Poll::Ready(Some(Ok(Frame::data(data)))),
                    Some(Err(error)) => {
                        *done = true;
                        Poll::Ready(Some(Err(error)))
                    }
                    None => {
                        *done = true;
                        Poll::Ready(rx.take_trailers().map(Frame::trailers).map(Ok))
                    }
                }
            }
            Kind::Empty => Poll::Ready(None),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self.kind {
            Kind::H1 { content_length, .. } => content_length == DecodedLength::ZERO,
            Kind::H2 { recv: ref h2, .. } => h2.is_end_stream(),
            #[cfg(feature = "http3")]
            Kind::H3 { done, .. } => done,
            Kind::Empty => true,
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match self.kind {
            Kind::H1 { content_length, .. } | Kind::H2 { content_length, .. } => content_length
                .into_opt()
                .map_or_else(SizeHint::default, SizeHint::with_exact),
            #[cfg(feature = "http3")]
            Kind::H3 { done, .. } => {
                if done {
                    SizeHint::with_exact(0)
                } else {
                    SizeHint::default()
                }
            }
            Kind::Empty => SizeHint::with_exact(0),
        }
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_tuple(stringify!(Incoming));
        match self.kind {
            Kind::Empty => builder.field(&stringify!(Empty)),
            _ => builder.field(&stringify!(Streaming)),
        };
        builder.finish()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "nightly", not(miri)))]
    extern crate test;
    #[cfg(all(feature = "nightly", not(miri)))]
    use std::pin::Pin;

    #[cfg(all(feature = "nightly", not(miri)))]
    use bytes::Bytes;

    #[cfg(all(feature = "nightly", not(miri)))]
    #[bench]
    fn bench_channel_create_and_drop(b: &mut test::Bencher) {
        b.iter(|| {
            let _ = test::black_box(Incoming::h1(
                DecodedLength::CHUNKED,
                /* wanter = */ false,
            ));
        });
    }

    #[cfg(all(feature = "nightly", not(miri)))]
    #[bench]
    fn bench_channel_data_handoff(b: &mut test::Bencher) {
        let (mut tx, mut body) = Incoming::h1(DecodedLength::CHUNKED, /* wanter = */ false);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());

        b.iter(|| {
            assert!(tx.poll_ready(&mut cx).is_ready());
            tx.send_data(Bytes::from_static(b"hello world")).unwrap();
            let frame = match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => frame,
                unexpected => panic!("unexpected body poll: {unexpected:?}"),
            };
            test::black_box(frame);
        });
    }

    #[cfg(all(feature = "nightly", not(miri)))]
    #[bench]
    fn bench_channel_want_transition(b: &mut test::Bencher) {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());

        b.iter(|| {
            let (mut tx, mut body) = Incoming::h1(DecodedLength::CHUNKED, /* wanter = */ true);
            assert!(tx.poll_ready(&mut cx).is_pending());
            assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
            assert!(tx.poll_ready(&mut cx).is_ready());
            let _ = test::black_box((tx, body));
        });
    }

    use std::{mem, task::Poll};

    use http_body_util::BodyExt;

    use super::{Body, DecodedLength, Error, Incoming, Result, Sender, SizeHint};

    impl Incoming {
        /// Create a `Body` stream with an associated sender half.
        ///
        /// Useful when wanting to stream chunks from another thread.
        pub(crate) fn channel() -> (Sender, Incoming) {
            Self::h1(DecodedLength::CHUNKED, /* wanter = */ false)
        }
    }

    impl Sender {
        async fn ready(&mut self) -> Result<()> {
            std::future::poll_fn(|cx| self.poll_ready(cx)).await
        }

        pub(crate) fn abort(mut self) {
            self.send_error(Error::new_body_write_aborted());
        }
    }

    #[test]
    fn test_size_of() {
        // These are mostly to help catch *accidentally* increasing
        // the size by too much.

        let body_size = mem::size_of::<Incoming>();
        let body_expected_size = mem::size_of::<u64>() * 5;
        assert!(
            body_size <= body_expected_size,
            "Body size = {body_size} <= {body_expected_size}",
        );

        //assert_eq!(body_size, mem::size_of::<Option<Incoming>>(), "Option<Incoming>");

        assert_eq!(
            mem::size_of::<Sender>(),
            mem::size_of::<usize>() * 2,
            "Sender"
        );

        assert_eq!(
            mem::size_of::<Sender>(),
            mem::size_of::<Option<Sender>>(),
            "Option<Sender>"
        );
    }

    #[test]
    fn size_hint() {
        fn eq(body: Incoming, b: SizeHint, note: &str) {
            let a = body.size_hint();
            assert_eq!(a.lower(), b.lower(), "lower for {note:?}");
            assert_eq!(a.upper(), b.upper(), "upper for {note:?}");
        }

        eq(Incoming::empty(), SizeHint::with_exact(0), "empty");

        eq(Incoming::channel().1, SizeHint::new(), "channel");

        eq(
            Incoming::h1(DecodedLength::new(4), /* wanter = */ false).1,
            SizeHint::with_exact(4),
            "channel with length",
        );
    }

    #[tokio::test]
    async fn channel_abort() {
        let (tx, mut rx) = Incoming::channel();

        tx.abort();

        let err = rx.frame().await.unwrap().unwrap_err();
        assert!(err.is_body_write_aborted(), "{err:?}");
    }

    #[tokio::test]
    async fn channel_abort_when_buffer_is_full() {
        let (mut tx, mut rx) = Incoming::channel();

        tx.send_data("chunk 1".into()).expect("send 1");
        // buffer is full, but can still send abort
        tx.abort();

        let chunk1 = rx
            .frame()
            .await
            .expect("item 1")
            .expect("chunk 1")
            .into_data()
            .unwrap();
        assert_eq!(chunk1, "chunk 1");

        let err = rx.frame().await.unwrap().unwrap_err();
        assert!(err.is_body_write_aborted(), "{err:?}");
    }

    #[test]
    fn channel_buffers_one() {
        let (mut tx, _rx) = Incoming::channel();

        tx.send_data("chunk 1".into()).expect("send 1");

        // buffer is now full
        let chunk2 = tx.send_data("chunk 2".into()).expect_err("send 2");
        assert_eq!(chunk2, "chunk 2");
    }

    #[tokio::test]
    async fn channel_empty() {
        let (_, mut rx) = Incoming::channel();
        assert!(rx.frame().await.is_none());
    }

    #[test]
    fn channel_ready() {
        let (mut tx, _rx) = Incoming::h1(DecodedLength::CHUNKED, /* wanter = */ false);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());

        assert!(tx_ready.poll().is_ready(), "tx is ready immediately");
    }

    #[test]
    fn channel_wanter() {
        let (mut tx, mut rx) = Incoming::h1(DecodedLength::CHUNKED, /* wanter = */ true);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());
        let mut rx_data = tokio_test::task::spawn(rx.frame());

        assert!(
            tx_ready.poll().is_pending(),
            "tx isn't ready before rx has been polled"
        );

        assert!(rx_data.poll().is_pending(), "poll rx.data");
        assert!(tx_ready.is_woken(), "rx poll wakes tx");

        assert!(
            tx_ready.poll().is_ready(),
            "tx is ready after rx has been polled"
        );
    }

    #[test]
    fn channel_notices_closure() {
        let (mut tx, rx) = Incoming::h1(DecodedLength::CHUNKED, /* wanter = */ true);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());

        assert!(
            tx_ready.poll().is_pending(),
            "tx isn't ready before rx has been polled"
        );

        drop(rx);
        assert!(tx_ready.is_woken(), "dropping rx wakes tx");

        match tx_ready.poll() {
            Poll::Ready(Err(ref e)) if e.is_closed() => (),
            unexpected => panic!("tx poll ready unexpected: {unexpected:?}"),
        }
    }
}
