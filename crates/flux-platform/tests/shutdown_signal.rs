#![cfg(any(target_os = "linux", target_os = "android"))]

use std::thread;
use std::time::{Duration, Instant};

use flux_platform::ShutdownSignal;

#[test]
fn blocked_termination_signal_is_consumed_through_signalfd() {
    let shutdown = ShutdownSignal::install().expect("install shutdown signal source");

    // SAFETY: pthread_self returns the live current thread and SIGTERM is
    // blocked by ShutdownSignal before it is delivered.
    assert_eq!(
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) },
        0
    );

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
