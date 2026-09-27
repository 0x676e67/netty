//! Trait aliases
//!
//! Traits in this module ease setting bounds and usually automatically
//! implemented by implementing another trait.

pub use self::h2_client::Http2ClientConnExec;
pub(crate) use self::h2_common::Http2UpgradedExec;
#[cfg(feature = "http3")]
pub use self::h3_client::Http3ClientConnExec;

mod h2_common {
    use crate::{proto::http2::upgrade::UpgradedSendStreamTask, rt::Executor};

    pub trait Http2UpgradedExec<B> {
        fn execute_upgrade(&self, future: UpgradedSendStreamTask<B>);
    }

    impl<E, B> Http2UpgradedExec<B> for E
    where
        E: Executor<UpgradedSendStreamTask<B>>,
    {
        fn execute_upgrade(&self, future: UpgradedSendStreamTask<B>) {
            self.execute(future);
        }
    }
}

mod h2_client {
    use std::future::Future;

    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::{error::BoxError, proto::http2::client::H2ClientFuture, rt::Executor};

    /// An executor to spawn http2 futures for the client.
    ///
    /// This trait is implemented for any type that implements [`Executor`]
    /// trait for any future.
    ///
    /// This trait is sealed and cannot be implemented for types outside this crate.
    pub trait Http2ClientConnExec<B, T>:
        super::Http2UpgradedExec<B::Data> + sealed_client::Sealed<(B, T)> + Clone
    where
        B: http_body::Body,
        B::Error: Into<BoxError>,
        T: AsyncRead + AsyncWrite + Unpin,
    {
        #[doc(hidden)]
        fn execute_h2_future(&mut self, future: H2ClientFuture<B, T, Self>);
    }

    impl<E, B, T> Http2ClientConnExec<B, T> for E
    where
        E: Executor<H2ClientFuture<B, T, E>> + super::Http2UpgradedExec<B::Data> + Clone,
        B: http_body::Body + 'static,
        B::Error: Into<BoxError>,
        H2ClientFuture<B, T, E>: Future<Output = ()>,
        T: AsyncRead + AsyncWrite + Unpin,
    {
        #[inline]
        fn execute_h2_future(&mut self, future: H2ClientFuture<B, T, E>) {
            self.execute(future)
        }
    }

    impl<E, B, T> sealed_client::Sealed<(B, T)> for E
    where
        E: Executor<H2ClientFuture<B, T, E>> + super::Http2UpgradedExec<B::Data> + Clone,
        B: http_body::Body + 'static,
        B::Error: Into<BoxError>,
        H2ClientFuture<B, T, E>: Future<Output = ()>,
        T: AsyncRead + AsyncWrite + Unpin,
    {
    }

    mod sealed_client {
        pub trait Sealed<X> {}
    }
}

#[cfg(feature = "http3")]
mod h3_client {
    use bytes::Bytes;

    use crate::{
        proto::http3::client::H3ClientFuture,
        rt::{quic, Executor},
    };

    /// An executor to spawn HTTP/3 futures for the client: the connection
    /// task, body pipes and CONNECT tunnels that outlive their
    /// request future. Body pipes include FIN acknowledgment; request futures
    /// each carry an executor clone.
    ///
    /// Implement [`Executor`] generically for the futures your runtime supports;
    /// the task enum is internal and does not need to be named.
    /// Compatible executors implement this trait automatically.
    ///
    /// This trait is sealed and cannot be implemented for types outside this crate.
    ///
    /// # Example
    ///
    /// ```
    /// use std::future::Future;
    /// use netty::rt::Executor;
    ///
    /// #[derive(Clone)]
    /// struct TokioExecutor;
    ///
    /// impl<F> Executor<F> for TokioExecutor
    /// where
    ///     F: Future<Output = ()> + Send + 'static,
    /// {
    ///     fn execute(&self, future: F) {
    ///         tokio::spawn(future);
    ///     }
    /// }
    /// ```
    pub trait Http3ClientConnExec<Q>: Clone + sealed_client::Sealed<Q>
    where
        Q: quic::Connection<Bytes>,
    {
        #[doc(hidden)]
        fn execute_h3_future(&self, future: H3ClientFuture<Q>);
    }

    impl<E, Q> Http3ClientConnExec<Q> for E
    where
        E: Executor<H3ClientFuture<Q>> + Clone,
        Q: quic::Connection<Bytes>,
    {
        #[inline]
        fn execute_h3_future(&self, future: H3ClientFuture<Q>) {
            self.execute(future)
        }
    }

    impl<E, Q> sealed_client::Sealed<Q> for E
    where
        E: Executor<H3ClientFuture<Q>> + Clone,
        Q: quic::Connection<Bytes>,
    {
    }

    mod sealed_client {
        pub trait Sealed<X> {}
    }
}
