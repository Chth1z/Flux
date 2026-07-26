use std::collections::VecDeque;
use std::num::NonZeroU16;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::generation_engine_config::{
    EngineConfigCompileErrorKind, TproxyEngineConfigRequest, compile_tproxy_engine_config,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

struct ScriptedOperation {
    attempts: VecDeque<RefreshAttempt>,
    rejections: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl ScriptedOperation {
    fn new(
        attempts: impl IntoIterator<Item = RefreshAttempt>,
    ) -> (Self, Arc<Mutex<Vec<[u8; 32]>>>) {
        let rejections = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                attempts: attempts.into_iter().collect(),
                rejections: Arc::clone(&rejections),
            },
            rejections,
        )
    }
}

impl RefreshOperation for ScriptedOperation {
    fn refresh(&mut self) -> RefreshAttempt {
        self.attempts
            .pop_front()
            .expect("test requested an unscripted refresh")
    }

    fn reject(&mut self, digest: [u8; 32]) -> Result<(), SubscriptionRefreshError> {
        self.rejections
            .lock()
            .expect("rejection record lock")
            .push(digest);
        Ok(())
    }
}

struct CountingOperation {
    attempts: VecDeque<RefreshAttempt>,
    refreshes: Arc<AtomicUsize>,
}

impl CountingOperation {
    fn new(attempts: impl IntoIterator<Item = RefreshAttempt>) -> (Self, Arc<AtomicUsize>) {
        let refreshes = Arc::new(AtomicUsize::new(0));
        (
            Self {
                attempts: attempts.into_iter().collect(),
                refreshes: Arc::clone(&refreshes),
            },
            refreshes,
        )
    }
}

impl RefreshOperation for CountingOperation {
    fn refresh(&mut self) -> RefreshAttempt {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        self.attempts
            .pop_front()
            .expect("test requested an unscripted refresh")
    }

    fn reject(&mut self, _digest: [u8; 32]) -> Result<(), SubscriptionRefreshError> {
        Ok(())
    }
}

fn published_attempt(digest: [u8; 32], node_count: u32, cleanup_pending: bool) -> RefreshAttempt {
    RefreshAttempt {
        schedule: RefreshSchedule::Enabled(Duration::from_secs(60)),
        result: Ok(RefreshPayload::Published {
            config: validated_config(digest, node_count),
            cleanup_pending,
        }),
    }
}

fn unchanged_attempt(node_count: u32) -> RefreshAttempt {
    RefreshAttempt {
        schedule: RefreshSchedule::Unchanged,
        result: Ok(RefreshPayload::Unchanged {
            node_count,
            cleanup_pending: false,
        }),
    }
}

fn validated_config(
    snapshot_digest: [u8; 32],
    node_count: u32,
) -> ValidatedSubscriptionEngineConfig {
    let port = NonZeroU16::new(9_898).expect("nonzero test listener");
    let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(b"{}", port))
        .expect("canonical test engine configuration");
    ValidatedSubscriptionEngineConfig {
        desired_state: Arc::new(test_desired_state()),
        bytes: Arc::from(artifact.bytes()),
        content_sha256: *artifact.content_sha256(),
        snapshot_digest,
        node_count,
    }
}

fn test_desired_state() -> FluxConfig {
    FluxConfig::parse(include_str!("../../../../../conf/flux.toml"))
        .expect("packaged test Desired State")
}

fn poll_completion(runtime: &mut SubscriptionRefreshRuntime) -> SubscriptionRefreshCompletion {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if let Some(completion) = runtime.poll() {
            return completion;
        }
        assert!(
            Instant::now() < deadline,
            "subscription worker did not publish a completion"
        );
        thread::yield_now();
    }
}

fn wait_until_idle(client: &SubscriptionRefreshClient) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while client.busy.load(Ordering::Acquire) {
        assert!(
            Instant::now() < deadline,
            "subscription worker remained busy"
        );
        thread::yield_now();
    }
}

#[test]
fn canonical_reconstruction_reports_an_explicit_content_digest_mismatch() {
    let port = NonZeroU16::new(9_898).expect("nonzero test listener");
    let mut config = validated_config([3; 32], 4);
    config.content_sha256 = [0; 32];

    let error = config
        .reconstruct_artifact(port)
        .expect_err("mismatched persisted digest must fail");

    assert_eq!(
        error.kind(),
        EngineConfigCompileErrorKind::ContentDigestMismatch
    );
}

#[test]
fn startup_rejection_restores_only_the_exact_pending_bootstrap_candidate() {
    let digest = [5; 32];
    let (operation, rejections) = ScriptedOperation::new([]);
    let runtime = SubscriptionRefreshRuntime::spawn_worker(
        Box::new(operation),
        None,
        Some(digest),
        TEST_TIMEOUT,
    )
    .expect("subscription runtime");
    let client = runtime.client.clone();

    let error = client
        .reject_bootstrap([6; 32])
        .expect_err("mismatched bootstrap digest must fail closed");
    assert_eq!(error.kind(), SubscriptionRefreshErrorKind::Rollback);
    assert!(rejections.lock().expect("rejection record lock").is_empty());

    client
        .reject_bootstrap(digest)
        .expect("exact startup candidate rollback");
    assert_eq!(
        rejections.lock().expect("rejection record lock").as_slice(),
        &[digest]
    );

    drop(runtime);
    assert_eq!(
        rejections.lock().expect("rejection record lock").as_slice(),
        &[digest],
        "settled startup rollback must not repeat during shutdown"
    );
}

#[test]
fn startup_acceptance_clears_the_drop_guard_and_unaccepted_shutdown_restores() {
    let accepted_digest = [8; 32];
    let (accepted_operation, accepted_rejections) = ScriptedOperation::new([]);
    let accepted = SubscriptionRefreshRuntime::spawn_worker(
        Box::new(accepted_operation),
        None,
        Some(accepted_digest),
        TEST_TIMEOUT,
    )
    .expect("accepted subscription runtime");
    accepted
        .client
        .accept_bootstrap(accepted_digest)
        .expect("commit admitted startup candidate");
    drop(accepted);
    assert!(
        accepted_rejections
            .lock()
            .expect("accepted rejection record lock")
            .is_empty(),
        "admitted startup candidate must remain active"
    );

    let unaccepted_digest = [9; 32];
    let (unaccepted_operation, unaccepted_rejections) = ScriptedOperation::new([]);
    let unaccepted = SubscriptionRefreshRuntime::spawn_worker(
        Box::new(unaccepted_operation),
        None,
        Some(unaccepted_digest),
        TEST_TIMEOUT,
    )
    .expect("unaccepted subscription runtime");
    drop(unaccepted);
    assert_eq!(
        unaccepted_rejections
            .lock()
            .expect("unaccepted rejection record lock")
            .as_slice(),
        &[unaccepted_digest],
        "worker shutdown must restore a bootstrap candidate never admitted by runtime"
    );
}

#[test]
fn manual_refresh_is_busy_until_the_serialized_acceptance_arrives() {
    let digest = [7; 32];
    let (operation, rejections) = ScriptedOperation::new([published_attempt(digest, 5, true)]);
    let mut runtime =
        SubscriptionRefreshRuntime::spawn(Box::new(operation), None).expect("subscription runtime");
    let client = runtime.client.clone();
    let waiting_client = client.clone();
    let waiting = thread::spawn(move || waiting_client.refresh());
    let completion = poll_completion(&mut runtime);

    assert_eq!(
        client.refresh().expect("busy report").disposition(),
        SubscriptionRefreshDisposition::Busy
    );
    let (published, cleanup_pending) = completion.published().expect("published candidate");
    assert_eq!(published.snapshot_digest(), digest);
    assert_eq!(published.node_count(), 5);
    assert!(cleanup_pending);
    completion.respond(SubscriptionRefreshDecision::Accept(
        SubscriptionRefreshReport::updated(12, 5, true),
    ));

    let report = waiting
        .join()
        .expect("manual client thread")
        .expect("accepted refresh");
    assert_eq!(
        report.disposition(),
        SubscriptionRefreshDisposition::Updated
    );
    assert_eq!(report.generation(), Some(12));
    assert_eq!(report.node_count(), Some(5));
    assert!(report.cleanup_pending());
    assert!(rejections.lock().expect("rejection record lock").is_empty());
    wait_until_idle(&client);
}

#[test]
fn rejected_publication_is_rolled_back_before_manual_failure_completes() {
    let digest = [11; 32];
    let (operation, rejections) = ScriptedOperation::new([published_attempt(digest, 2, false)]);
    let mut runtime =
        SubscriptionRefreshRuntime::spawn(Box::new(operation), None).expect("subscription runtime");
    let client = runtime.client.clone();
    let waiting_client = client.clone();
    let waiting = thread::spawn(move || waiting_client.refresh());
    let completion = poll_completion(&mut runtime);
    let activation_error = SubscriptionRefreshError::activation("candidate activation failed");

    completion.respond(SubscriptionRefreshDecision::Reject(
        activation_error.clone(),
    ));

    let error = waiting
        .join()
        .expect("manual client thread")
        .expect_err("rejected refresh must fail");
    assert_eq!(error, activation_error);
    assert_eq!(
        rejections.lock().expect("rejection record lock").as_slice(),
        &[digest]
    );
    wait_until_idle(&client);
}

#[test]
fn missing_acknowledgement_rolls_back_the_published_candidate() {
    let digest = [13; 32];
    let (operation, rejections) = ScriptedOperation::new([published_attempt(digest, 3, false)]);
    let acknowledgement_timeout = Duration::from_millis(20);
    let mut runtime = SubscriptionRefreshRuntime::spawn_with_ack_timeout(
        Box::new(operation),
        None,
        acknowledgement_timeout,
    )
    .expect("subscription runtime");
    let client = runtime.client.clone();
    let waiting_client = client.clone();
    let waiting = thread::spawn(move || waiting_client.refresh());
    let completion = poll_completion(&mut runtime);

    thread::sleep(acknowledgement_timeout + Duration::from_millis(20));

    let error = waiting
        .join()
        .expect("manual client thread")
        .expect_err("unacknowledged refresh must fail");
    assert_eq!(error.kind(), SubscriptionRefreshErrorKind::Activation);
    assert_eq!(
        rejections.lock().expect("rejection record lock").as_slice(),
        &[digest]
    );
    assert!(
        completion.terminal().is_none(),
        "published completion remains a coordinator decision"
    );
    wait_until_idle(&client);
}

#[test]
fn periodic_terminal_outcome_updates_schedule_without_claiming_manual_completion() {
    let attempt = RefreshAttempt {
        schedule: RefreshSchedule::Disabled,
        result: Ok(RefreshPayload::Disabled),
    };
    let (operation, rejections) = ScriptedOperation::new([attempt]);
    let mut runtime =
        SubscriptionRefreshRuntime::spawn(Box::new(operation), Some(Duration::from_millis(1)))
            .expect("subscription runtime");
    let deadline = runtime.next_periodic.expect("periodic deadline");

    runtime.schedule_periodic(deadline);
    let completion = poll_completion(&mut runtime);
    let report = completion
        .terminal()
        .expect("terminal completion")
        .expect("disabled report");
    completion.respond(SubscriptionRefreshDecision::Accept(report));

    assert_eq!(
        report.disposition(),
        SubscriptionRefreshDisposition::Disabled
    );
    assert_eq!(runtime.interval, None);
    assert_eq!(runtime.next_periodic, None);
    assert!(rejections.lock().expect("rejection record lock").is_empty());
    wait_until_idle(&runtime.client);
}

#[test]
fn observed_refresh_schedules_immediately_without_waiting_for_a_periodic_deadline() {
    let (operation, refreshes) = CountingOperation::new([unchanged_attempt(17)]);
    let mut runtime =
        SubscriptionRefreshRuntime::spawn(Box::new(operation), Some(Duration::from_secs(3_600)))
            .expect("subscription runtime");

    runtime.request_observed_refresh();

    assert!(!runtime.observed_refresh_pending);
    let completion = poll_completion(&mut runtime);
    let report = completion
        .terminal()
        .expect("unchanged refresh is terminal")
        .expect("observed refresh succeeds");
    completion.respond(SubscriptionRefreshDecision::Accept(report));
    wait_until_idle(&runtime.client);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[test]
fn busy_observed_refresh_remains_pending_and_retries_when_the_worker_is_idle() {
    let (operation, refreshes) = CountingOperation::new([unchanged_attempt(19)]);
    let mut runtime =
        SubscriptionRefreshRuntime::spawn(Box::new(operation), None).expect("subscription runtime");
    runtime.client.busy.store(true, Ordering::Release);

    runtime.request_observed_refresh();

    assert!(runtime.observed_refresh_pending);
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
    runtime.client.busy.store(false, Ordering::Release);
    runtime.schedule_observed_refresh();
    assert!(!runtime.observed_refresh_pending);

    let completion = poll_completion(&mut runtime);
    let report = completion
        .terminal()
        .expect("unchanged refresh is terminal")
        .expect("retried observed refresh succeeds");
    completion.respond(SubscriptionRefreshDecision::Accept(report));
    wait_until_idle(&runtime.client);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[test]
fn multiple_busy_observations_coalesce_into_one_follow_up_refresh() {
    let (operation, refreshes) =
        CountingOperation::new([unchanged_attempt(23), unchanged_attempt(29)]);
    let mut runtime =
        SubscriptionRefreshRuntime::spawn(Box::new(operation), None).expect("subscription runtime");

    runtime.request_observed_refresh();
    let first = poll_completion(&mut runtime);
    runtime.request_observed_refresh();
    runtime.request_observed_refresh();
    runtime.request_observed_refresh();

    assert!(runtime.observed_refresh_pending);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    let first_report = first
        .terminal()
        .expect("first unchanged refresh is terminal")
        .expect("first observed refresh succeeds");
    first.respond(SubscriptionRefreshDecision::Accept(first_report));
    wait_until_idle(&runtime.client);

    runtime.schedule_observed_refresh();
    assert!(!runtime.observed_refresh_pending);
    let second = poll_completion(&mut runtime);
    let second_report = second
        .terminal()
        .expect("second unchanged refresh is terminal")
        .expect("coalesced observed refresh succeeds");
    second.respond(SubscriptionRefreshDecision::Accept(second_report));
    wait_until_idle(&runtime.client);

    runtime.schedule_observed_refresh();
    assert_eq!(refreshes.load(Ordering::SeqCst), 2);
    assert!(runtime.poll().is_none());
}
