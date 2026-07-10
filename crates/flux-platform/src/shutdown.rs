use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Default)]
// `Rc` makes this zero-sized marker neither Send nor Sync.
struct ThreadAffine(PhantomData<Rc<()>>);

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::ThreadAffine;
    use crate::PlatformError;

    /// A signal-mask guard that must remain on the thread that installed it.
    ///
    /// Moving the guard to another thread would restore a thread-local
    /// `pthread_sigmask` on the wrong thread, so the type is deliberately
    /// neither [`Send`] nor [`Sync`].
    ///
    /// ```compile_fail
    /// use flux_platform::ShutdownSignal;
    ///
    /// let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
    /// std::thread::spawn(move || drop(shutdown));
    /// ```
    pub struct ShutdownSignal {
        fd: OwnedFd,
        previous_mask: libc::sigset_t,
        _thread_affinity: ThreadAffine,
    }

    impl ShutdownSignal {
        pub fn install() -> Result<Self, PlatformError> {
            let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
            // SAFETY: `mask` points to writable storage for one sigset_t.
            if unsafe { libc::sigemptyset(mask.as_mut_ptr()) } != 0 {
                return Err(last_error("initialize shutdown signal set"));
            }
            // SAFETY: sigemptyset initialized `mask`; each call only mutates
            // that set and accepts the named POSIX signal number.
            if unsafe { libc::sigaddset(mask.as_mut_ptr(), libc::SIGINT) } != 0
                || unsafe { libc::sigaddset(mask.as_mut_ptr(), libc::SIGTERM) } != 0
            {
                return Err(last_error("populate shutdown signal set"));
            }
            // SAFETY: the successful calls above initialized the full sigset_t.
            let mask = unsafe { mask.assume_init() };

            let mut previous_mask = MaybeUninit::<libc::sigset_t>::zeroed();
            // SAFETY: both signal-set pointers are valid for this call. Signal
            // masks are thread-local; `ShutdownSignal` is not `Send`, so its
            // Drop implementation restores this mask on the installing thread.
            let block_result = unsafe {
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, previous_mask.as_mut_ptr())
            };
            if block_result != 0 {
                return Err(system_call_error(
                    "block shutdown signals",
                    std::io::Error::from_raw_os_error(block_result),
                ));
            }
            // SAFETY: pthread_sigmask initialized the previous mask on success.
            let previous_mask = unsafe { previous_mask.assume_init() };

            // SAFETY: `mask` is initialized and signalfd creates one new owned
            // descriptor when passed -1.
            let fd = unsafe {
                libc::signalfd(-1, &raw const mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK)
            };
            if fd < 0 {
                let error = last_error("create shutdown signalfd");
                restore_mask(&previous_mask);
                return Err(error);
            }

            Ok(Self {
                // SAFETY: successful signalfd returned a new owned descriptor.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                previous_mask,
                _thread_affinity: ThreadAffine::default(),
            })
        }

        pub fn received(&self) -> Result<bool, PlatformError> {
            let mut information = MaybeUninit::<libc::signalfd_siginfo>::zeroed();
            loop {
                // SAFETY: `information` is writable for exactly one
                // signalfd_siginfo and the descriptor remains valid.
                let received = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        information.as_mut_ptr().cast::<libc::c_void>(),
                        std::mem::size_of::<libc::signalfd_siginfo>(),
                    )
                };
                if received < 0 {
                    let source = std::io::Error::last_os_error();
                    match source.raw_os_error() {
                        Some(libc::EAGAIN) => return Ok(false),
                        Some(libc::EINTR) => continue,
                        _ => {
                            return Err(system_call_error("read shutdown signalfd", source));
                        }
                    }
                }
                let received = usize::try_from(received).map_err(|_| {
                    system_call_error(
                        "read shutdown signalfd",
                        std::io::Error::from_raw_os_error(libc::EPROTO),
                    )
                })?;
                if received != std::mem::size_of::<libc::signalfd_siginfo>() {
                    return Err(system_call_error(
                        "read shutdown signalfd",
                        std::io::Error::from_raw_os_error(libc::EPROTO),
                    ));
                }
                // SAFETY: the exact-size read initialized the whole structure.
                let information = unsafe { information.assume_init() };
                return Ok(information.ssi_signo
                    == u32::try_from(libc::SIGINT).unwrap_or_default()
                    || information.ssi_signo == u32::try_from(libc::SIGTERM).unwrap_or_default());
            }
        }
    }

    impl Drop for ShutdownSignal {
        fn drop(&mut self) {
            restore_mask(&self.previous_mask);
        }
    }

    fn restore_mask(previous_mask: &libc::sigset_t) {
        // SAFETY: `previous_mask` was initialized by pthread_sigmask and the
        // null third argument requests no output.
        let _ = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, previous_mask, std::ptr::null_mut())
        };
    }

    fn last_error(operation: &'static str) -> PlatformError {
        system_call_error(operation, std::io::Error::last_os_error())
    }

    fn system_call_error(operation: &'static str, source: std::io::Error) -> PlatformError {
        PlatformError::SystemCall { operation, source }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod implementation {
    use super::ThreadAffine;
    use crate::PlatformError;

    pub struct ShutdownSignal {
        _thread_affinity: ThreadAffine,
    }

    impl ShutdownSignal {
        pub fn install() -> Result<Self, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }

        pub fn received(&self) -> Result<bool, PlatformError> {
            Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
        }
    }
}

pub use implementation::ShutdownSignal;

#[cfg(test)]
mod tests {
    use super::ShutdownSignal;

    trait AmbiguousIfSend<Marker> {
        fn assert_not_send() {}
    }

    trait AmbiguousIfSync<Marker> {
        fn assert_not_sync() {}
    }

    impl<T: ?Sized> AmbiguousIfSend<()> for T {}

    struct ImplementsSend;

    impl<T: ?Sized + Send> AmbiguousIfSend<ImplementsSend> for T {}

    struct ImplementsSync;

    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<ImplementsSync> for T {}

    #[test]
    fn shutdown_signal_is_thread_affine() {
        // Type inference is unique only when ShutdownSignal does not implement
        // Send; a Send implementation would make both marker impls applicable.
        let _ = <ShutdownSignal as AmbiguousIfSend<_>>::assert_not_send;
        // The same ambiguity check independently protects the Sync invariant.
        let _ = <ShutdownSignal as AmbiguousIfSync<_>>::assert_not_sync;
    }
}
