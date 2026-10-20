use std::sync::LockResult;

pub(crate) trait LockResultExt<T> {
    fn panic_if_poisoned(self) -> T;

    /// Takes the guard even from a lock that a panic poisoned, for state that stays consistent
    /// across one.
    #[cfg(feature = "http3-datagram")]
    fn ignore_poison(self) -> T;
}

impl<T> LockResultExt<T> for LockResult<T> {
    #[track_caller]
    fn panic_if_poisoned(self) -> T {
        match self {
            Ok(inner) => inner,
            Err(err) => panic!("lock poisoned by panic: {err}"),
        }
    }

    #[cfg(feature = "http3-datagram")]
    fn ignore_poison(self) -> T {
        self.unwrap_or_else(|error| error.into_inner())
    }
}
