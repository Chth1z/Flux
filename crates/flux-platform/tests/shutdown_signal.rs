#![cfg(any(target_os = "linux", target_os = "android"))]

use std::thread;
use std::time::{Duration, Instant};

use flux_platform::ShutdownSignal;

#[test]
fn blocked_termination_signal_is_consumed_through_signalfd() {
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");

    // SAFETY: pthread_self returns the live current thread and SIGTERM is
    // blocked by ShutdownSignal before it is delivered.
    let kill_result = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) };
    assert_eq!(kill_result, 0);

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if shutdown.received().expect("read shutdown signal") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "shutdown signal was not observed"
        );
        thread::yield_now();
    }
}

#[test]
fn drop_restores_the_installing_threads_previous_signal_mask() {
    let sigint_was_blocked = signal_is_blocked(libc::SIGINT);
    let sigterm_was_blocked = signal_is_blocked(libc::SIGTERM);

    {
        let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
        assert!(signal_is_blocked(libc::SIGINT));
        assert!(signal_is_blocked(libc::SIGTERM));
        drop(shutdown);
    }

    assert_eq!(signal_is_blocked(libc::SIGINT), sigint_was_blocked);
    assert_eq!(signal_is_blocked(libc::SIGTERM), sigterm_was_blocked);
}

fn signal_is_blocked(signal: libc::c_int) -> bool {
    let mut current = std::mem::MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: a null set pointer queries the calling thread's current mask and
    // `current` is writable storage for the result.
    let mask_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), current.as_mut_ptr()) };
    assert_eq!(mask_result, 0);
    // SAFETY: pthread_sigmask initialized the complete signal set above.
    let current = unsafe { current.assume_init() };
    // SAFETY: `current` is initialized and `signal` is a valid POSIX signal.
    unsafe { libc::sigismember(&raw const current, signal) == 1 }
}
