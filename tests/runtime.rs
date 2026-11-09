use herald::runtime::{
    MemoryOperationStore, OperationEvent, OperationId, OperationRecord, OperationState,
    OperationStore, Reservation, RunningLimit, Runtime, Started, StoreBounds, StoreError,
    Submission, SubmitEnvelope, Transport, TransportError,
};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;

struct Ports {
    allow: AtomicBool,
    /// The next authorisation panics, standing in for a failing product port.
    panic_next: AtomicBool,
    /// Deny any request whose input names resource "x", standing in for a per-resource policy.
    deny_x: AtomicBool,
    /// How many requests the observer was told finished as `Unavailable`.
    unavailable_reported: AtomicUsize,
}
impl Ports {
    fn allowing() -> Arc<Self> {
        Arc::new(Self {
            allow: AtomicBool::new(true),
            panic_next: AtomicBool::new(false),
            deny_x: AtomicBool::new(false),
            unavailable_reported: AtomicUsize::new(0),
        })
    }
}
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, request: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move {
            if self.panic_next.swap(false, Ordering::SeqCst) {
                panic!("authoriser failure");
            }
            if self.deny_x.load(Ordering::SeqCst) && request.input["resource"] == "x" {
                return false;
            }
            self.allow.load(Ordering::SeqCst)
        })
    }
}
impl Confirmer for Ports {
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { true })
    }
}
impl Clock for Ports {
    fn now(&self) -> u64 {
        0
    }
}
impl Observer for Ports {
    fn finished(&self, _: &Request, _: u64, result: &Result<Outcome, DispatchError>) {
        if matches!(result, Err(DispatchError::Unavailable)) {
            self.unavailable_reported.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
}

/// Counts executions; optionally never answers, standing in for a runtime lost mid-operation.
struct Mutation {
    calls: Arc<AtomicUsize>,
    stall: bool,
}
impl Handler for Mutation {
    fn invoke<'a>(&'a self, request: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.stall {
                std::future::pending::<()>().await;
            }
            Outcome::Success(json!({"run": n, "echo": request.input}))
        })
    }
}

fn id() -> CapabilityId {
    CapabilityId {
        name: "mutate".into(),
        version: 1,
    }
}
fn dispatcher(ports: &Arc<Ports>, calls: &Arc<AtomicUsize>, stall: bool) -> Arc<Dispatcher> {
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        Arc::new(Mutation {
            calls: calls.clone(),
            stall,
        }),
    )
    .unwrap();
    Arc::new(d)
}
fn request(identity: &str, input: serde_json::Value) -> Request {
    Request {
        capability: id(),
        identity: identity.into(),
        input,
        confirmed: false,
    }
}
async fn open(d: &Arc<Dispatcher>, store: &Arc<MemoryOperationStore>) -> Runtime {
    Runtime::open(d.clone(), store.clone()).await.unwrap().0
}
fn live() -> Cancellation {
    cancellation().1
}

/// A clock a test moves by hand.
#[derive(Default)]
struct HandClock(AtomicU64);
impl HandClock {
    fn advance(&self, by: u64) {
        self.0.fetch_add(by, Ordering::SeqCst);
    }
}
impl Clock for HandClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Records one caller may hold in a test that is not about the quota: far above the few keys any such test submits.
const ROOMY_RECORDS: usize = 1_000;
/// A retention no test's hand-moved clock reaches, so a record in a test that is not about retention is never dropped.
const ROOMY_RETENTION: u64 = u64::MAX;

fn roomy_store() -> Arc<MemoryOperationStore> {
    Arc::new(MemoryOperationStore::bounded(
        StoreBounds::new(ROOMY_RECORDS, ROOMY_RETENTION).unwrap(),
        Arc::new(HandClock::default()),
    ))
}

#[tokio::test]
async fn duplicate_delivery_runs_the_handler_once_and_replays_the_outcome() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let first = runtime
        .submit(request("a", json!({"x": 1})), "k".into(), live())
        .await;
    let second = runtime
        .submit(request("a", json!({"x": 1})), "k".into(), live())
        .await;
    assert_eq!(first.result, second.result);
    assert_eq!(first.id, second.id);
    assert_eq!(
        first.result,
        Ok(Outcome::Success(json!({"run": 1, "echo": {"x": 1}})))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.record_error, None);
}

#[tokio::test]
async fn the_same_key_with_a_different_payload_is_rejected_without_running() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    runtime
        .submit(request("a", json!({"x": 1})), "k".into(), live())
        .await;
    let conflict = runtime
        .submit(request("a", json!({"x": 2})), "k".into(), live())
        .await;
    assert_eq!(conflict.result, Err(DispatchError::KeyConflict));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn keys_are_scoped_to_the_caller() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let a = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    let b = runtime
        .submit(request("b", json!({"other": true})), "k".into(), live())
        .await;
    assert_ne!(a.id, b.id);
    assert!(matches!(b.result, Ok(Outcome::Success(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_retry_needs_fresh_authorisation_and_a_revoked_caller_learns_nothing() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    ports.allow.store(false, Ordering::SeqCst);
    let retry = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert_eq!(retry.result, Err(DispatchError::Denied));
    ports.allow.store(true, Ordering::SeqCst);
    let again = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert!(matches!(again.result, Ok(Outcome::Success(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn an_operation_lost_with_its_host_reads_as_unknown_after_restart_and_is_never_rerun() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let host = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    host.block_on(async {
        let runtime = open(&dispatcher(&ports, &calls, true), &store).await;
        let mut caller = Box::pin(runtime.submit(request("a", json!({})), "k".into(), live()));
        // Drive the submission until the stalled handler has started, then lose the caller.
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::select! { _ = &mut caller => panic!("the handler stalls"), _ = tokio::task::yield_now() => {} }
        }
    });
    host.shutdown_background(); // the host dies with the handler still running

    let after = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    after.block_on(async {
        let (runtime, interrupted) =
            Runtime::open(dispatcher(&ports, &calls, false), store.clone())
                .await
                .unwrap();
        assert_eq!(interrupted.len(), 1);
        let retry = runtime
            .submit(request("a", json!({})), "k".into(), live())
            .await;
        match retry.result {
            Ok(Outcome::Unknown(v)) => assert_eq!(v["state"], "interrupted"),
            other => panic!("expected an unknown outcome, got {other:?}"),
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the handler ran only before the loss"
        );
        let states: Vec<_> = runtime
            .get("a", &retry.id)
            .await
            .unwrap()
            .unwrap()
            .events
            .into_iter()
            .map(|e| e.state)
            .collect();
        assert_eq!(
            states,
            vec![OperationState::Accepted, OperationState::Interrupted]
        );
    });
}

#[tokio::test]
async fn dropping_the_caller_does_not_abandon_the_operation() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let gate = Arc::new(tokio::sync::Notify::new());
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        Arc::new(Gated {
            calls: calls.clone(),
            release: gate.clone(),
        }),
    )
    .unwrap();
    let runtime = Runtime::open(Arc::new(d), store.clone()).await.unwrap().0;
    let mut caller = Box::pin(runtime.submit(request("a", json!({})), "k".into(), live()));
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::select! { _ = &mut caller => panic!("the handler waits"), _ = tokio::task::yield_now() => {} }
    }
    drop(caller); // a timeout, a closed connection
    gate.notify_one();
    let record = loop {
        let record = runtime
            .get("a", &herald_id("a", "k"))
            .await
            .unwrap()
            .unwrap();
        if matches!(record.state(), OperationState::Completed(_)) {
            break record;
        }
        tokio::task::yield_now().await;
    };
    assert!(matches!(
        record.state(),
        OperationState::Completed(Outcome::Success(_))
    ));
    // The retry now replays that recorded outcome.
    let retry = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert!(matches!(retry.result, Ok(Outcome::Success(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct Gated {
    calls: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
}
impl Handler for Gated {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Outcome::Success(json!({"done": true}))
        })
    }
}

/// The identifier a submission with this identity and key receives.
fn herald_id(identity: &str, key: &str) -> OperationId {
    let runtime_side = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update((identity.len() as u64).to_be_bytes());
        h.update(identity.as_bytes());
        h.update(key.as_bytes());
        h.finalize()
    };
    OperationId(format!(
        "op-{}",
        runtime_side
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

struct Panicking;
impl Handler for Panicking {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async { panic!("handler failure") })
    }
}

#[tokio::test]
async fn a_panicking_handler_is_recorded_as_interrupted_not_left_accepted() {
    let ports = Ports::allowing();
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        Arc::new(Panicking),
    )
    .unwrap();
    let runtime = Runtime::open(Arc::new(d), Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap()
        .0;
    let submission = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert_eq!(submission.result, Err(DispatchError::OutcomeLost));
    let record = runtime.get("a", &submission.id).await.unwrap().unwrap();
    assert_eq!(record.state(), &OperationState::Interrupted);
}

#[tokio::test]
async fn a_store_has_one_owner_at_a_time() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let first = open(&dispatcher(&ports, &calls, false), &store).await;
    assert!(
        Runtime::open(dispatcher(&ports, &calls, false), store.clone())
            .await
            .is_err(),
        "a second runtime must not interrupt the first runtime's work"
    );
    drop(first);
    assert!(
        Runtime::open(dispatcher(&ports, &calls, false), store.clone())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_revoked_caller_can_no_longer_read_its_own_operation() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let done = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert!(runtime.get("a", &done.id).await.unwrap().is_some());
    ports.allow.store(false, Ordering::SeqCst);
    assert_eq!(runtime.get("a", &done.id).await.unwrap(), None);
}

#[tokio::test]
async fn object_key_order_does_not_change_the_payload() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let one: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":{"x":1,"y":2}}"#).unwrap();
    let two: serde_json::Value = serde_json::from_str(r#"{"b":{"y":2,"x":1},"a":1}"#).unwrap();
    runtime.submit(request("a", one), "k".into(), live()).await;
    let reordered = runtime.submit(request("a", two), "k".into(), live()).await;
    assert!(matches!(reordered.result, Ok(Outcome::Success(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn clients_read_events_from_their_own_cursor() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let done = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    let all = runtime.events_after("a", &done.id, 0).await.unwrap();
    assert_eq!(all.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![0, 1]);
    let after_first = runtime.events_after("a", &done.id, 1).await.unwrap();
    assert_eq!(after_first.len(), 1);
    assert!(matches!(after_first[0].state, OperationState::Completed(_)));
    assert!(
        runtime
            .events_after("a", &done.id, 2)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        runtime
            .events_after("a", &OperationId("missing".into()), 0)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_request_cancelled_before_dispatch_leaves_no_record() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let (cancel, signal) = cancellation();
    cancel.send(true).unwrap();
    let submission = runtime
        .submit(request("a", json!({})), "k".into(), signal)
        .await;
    assert_eq!(
        submission.result,
        Err(DispatchError::CancelledBeforeDispatch)
    );
    assert_eq!(runtime.get("a", &submission.id).await.unwrap(), None);
    // The same key is then free for a fresh attempt.
    let fresh = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert!(matches!(fresh.result, Ok(Outcome::Success(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A store that cannot reserve, so nothing may run.
struct BrokenStore;
impl OperationStore for BrokenStore {
    fn bounds(&self) -> Option<StoreBounds> {
        None
    }
    fn reserve<'a>(
        &'a self,
        _: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>> {
        Box::pin(async { Err(StoreError("disk full".into())) })
    }
    fn complete<'a>(
        &'a self,
        _: &'a OperationId,
        _: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError("disk full".into())) })
    }
    fn get<'a>(
        &'a self,
        _: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
        Box::pin(async { Ok(None) })
    }
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>> {
        Box::pin(async { Ok(vec![]) })
    }
    fn abandon<'a>(&'a self, _: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn release(&self) {}
}

#[tokio::test]
async fn a_store_that_cannot_reserve_stops_the_handler_from_running() {
    let (ports, calls) = (Ports::allowing(), Arc::new(AtomicUsize::new(0)));
    let (runtime, _) = Runtime::open(dispatcher(&ports, &calls, false), Arc::new(BrokenStore))
        .await
        .unwrap();
    let submission = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert_eq!(
        submission.result,
        Err(DispatchError::Store("disk full".into()))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Carries every envelope through JSON, so only serialisable data crosses the boundary.
struct Loopback(Arc<Runtime>);
impl Transport for Loopback {
    fn submit<'a>(
        &'a self,
        identity: String,
        envelope: SubmitEnvelope,
    ) -> PortFuture<'a, Result<Submission, TransportError>> {
        Box::pin(async move {
            let wire = serde_json::to_string(&envelope).unwrap();
            let received: SubmitEnvelope = serde_json::from_str(&wire).unwrap();
            let reply = self.0.handle(&identity, received, live()).await;
            Ok(serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap())
        })
    }
    fn events_after<'a>(
        &'a self,
        identity: String,
        id: OperationId,
        cursor: u64,
    ) -> PortFuture<'a, Result<Vec<OperationEvent>, TransportError>> {
        Box::pin(async move {
            self.0
                .events_after(&identity, &id, cursor)
                .await
                .map_err(|e| TransportError(e.0))
        })
    }
}

#[tokio::test]
async fn a_remote_client_retrying_after_a_lost_reply_gets_the_same_outcome() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let remote = Loopback(Arc::new(
        open(&dispatcher(&ports, &calls, false), &store).await,
    ));
    let envelope = SubmitEnvelope {
        request: request("a", json!({"x": 1})),
        key: "k".into(),
    };
    let first = remote.submit("a".into(), envelope.clone()).await.unwrap();
    let redelivered = remote.submit("a".into(), envelope).await.unwrap();
    assert_eq!(first, redelivered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let events = remote.events_after("a".into(), first.id, 0).await.unwrap();
    assert_eq!(events.len(), 2);
}

#[tokio::test]
async fn another_callers_operation_reads_as_absent() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let mine = runtime
        .submit(request("a", json!({"secret": 1})), "k".into(), live())
        .await;
    assert!(runtime.get("a", &mine.id).await.unwrap().is_some());
    assert_eq!(runtime.get("b", &mine.id).await.unwrap(), None);
    assert!(runtime.events_after("b", &mine.id, 0).await.is_err());
}

/// Returns an object where the contract promises another shape.
struct Violating;
impl Handler for Violating {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async { Outcome::Success(json!("not an object")) })
    }
}

#[tokio::test]
async fn a_response_that_violates_its_contract_is_recorded_as_unknown_not_left_accepted() {
    let ports = Ports::allowing();
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        Arc::new(Violating),
    )
    .unwrap();
    let store = Arc::new(MemoryOperationStore::default());
    let runtime = Runtime::open(Arc::new(d), store.clone()).await.unwrap().0;
    let submission = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert!(matches!(
        submission.result,
        Err(DispatchError::InvalidOutput(_))
    ));
    let record = runtime.get("a", &submission.id).await.unwrap().unwrap();
    assert!(
        matches!(
            record.state(),
            OperationState::Completed(Outcome::Unknown(_))
        ),
        "the operation must not stay Accepted: {:?}",
        record.state()
    );
}

/// A dispatcher whose only contract has the given error schema and handler.
fn dispatcher_with(
    ports: &Arc<Ports>,
    error_schema: serde_json::Value,
    handler: Arc<dyn Handler>,
) -> Arc<Dispatcher> {
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema,
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        handler,
    )
    .unwrap();
    Arc::new(d)
}

#[tokio::test]
async fn a_task_still_running_after_its_runtime_is_dropped_keeps_the_store_claimed() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let release = Arc::new(tokio::sync::Notify::new());
    let d = dispatcher_with(
        &ports,
        json!({"type":"object"}),
        Arc::new(Gated {
            calls: calls.clone(),
            release: release.clone(),
        }),
    );
    let runtime = Runtime::open(d.clone(), store.clone()).await.unwrap().0;
    let mut caller = Box::pin(runtime.submit(request("a", json!({})), "k".into(), live()));
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::select! { _ = &mut caller => panic!("waits"), _ = tokio::task::yield_now() => {} }
    }
    drop(caller);
    drop(runtime); // the handler is still running on its own task
    assert!(
        Runtime::open(d.clone(), store.clone()).await.is_err(),
        "a new runtime must not recover work a live task is still driving"
    );
    release.notify_one();
    loop {
        if Runtime::open(d.clone(), store.clone()).await.is_ok() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let (reopened, interrupted) = Runtime::open(d, store.clone())
        .await
        .map_or_else(|_| (None, vec![]), |(r, i)| (Some(r), i));
    drop(reopened);
    assert!(
        interrupted.is_empty(),
        "the operation completed, so nothing is interrupted"
    );
}

#[tokio::test]
async fn a_failure_before_admission_does_not_interrupt_another_live_attempt() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let release = Arc::new(tokio::sync::Notify::new());
    let d = dispatcher_with(
        &ports,
        json!({"type":"object"}),
        Arc::new(Gated {
            calls: calls.clone(),
            release: release.clone(),
        }),
    );
    let runtime = Arc::new(Runtime::open(d, store.clone()).await.unwrap().0);
    let first = {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            runtime
                .submit(request("a", json!({})), "k".into(), live())
                .await
        })
    };
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    // A second delivery of the same key panics in the product's authoriser before it reserves anything.
    ports.panic_next.store(true, Ordering::SeqCst);
    let second = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    // Nothing was reserved, so the handler cannot have run and nothing is unknown.
    assert_eq!(second.result, Err(DispatchError::InterruptedBeforeDispatch));
    release.notify_one();
    let first = first.await.unwrap();
    assert!(matches!(first.result, Ok(Outcome::Success(_))));
    let record = runtime.get("a", &first.id).await.unwrap().unwrap();
    assert!(
        matches!(record.state(), OperationState::Completed(_)),
        "the live attempt must still complete: {:?}",
        record.state()
    );
}

#[tokio::test]
async fn runtime_reported_unknown_outcomes_have_a_fixed_shape_whatever_the_error_schema() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let strict = json!({"type":"object","required":["code"]});
    let runtime = Runtime::open(
        dispatcher_with(
            &ports,
            strict.clone(),
            Arc::new(Mutation {
                calls: calls.clone(),
                stall: true,
            }),
        ),
        store.clone(),
    )
    .await
    .unwrap()
    .0;
    let mut caller = Box::pin(runtime.submit(request("a", json!({})), "k".into(), live()));
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::select! { _ = &mut caller => panic!("stalls"), _ = tokio::task::yield_now() => {} }
    }
    // Same key while the first attempt is in flight: the runtime says "accepted", with its own shape.
    let in_flight = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    match in_flight.result {
        Ok(Outcome::Unknown(v)) => {
            assert_eq!(v["state"], "accepted");
            assert!(
                v.get("code").is_none(),
                "not shaped by the capability's error schema"
            );
        }
        other => panic!("expected the runtime's unknown outcome, got {other:?}"),
    }
}

#[tokio::test]
async fn a_read_is_authorised_against_the_input_the_operation_was_submitted_with() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let on_x = runtime
        .submit(request("a", json!({"resource": "x"})), "kx".into(), live())
        .await;
    let on_y = runtime
        .submit(request("a", json!({"resource": "y"})), "ky".into(), live())
        .await;
    ports.deny_x.store(true, Ordering::SeqCst); // the caller is revoked from resource x only
    assert_eq!(runtime.get("a", &on_x.id).await.unwrap(), None);
    assert!(runtime.get("a", &on_y.id).await.unwrap().is_some());
}

#[tokio::test]
async fn a_remote_caller_cannot_submit_as_another_identity() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = Arc::new(open(&dispatcher(&ports, &calls, false), &store).await);
    let remote = Loopback(runtime.clone());
    // Mallory is authenticated as "mallory" but claims to be "victim" inside the envelope.
    let forged = SubmitEnvelope {
        request: request("victim", json!({"x": 1})),
        key: "k".into(),
    };
    let reply = remote.submit("mallory".into(), forged).await.unwrap();
    assert!(matches!(reply.result, Ok(Outcome::Success(_))));
    // The operation belongs to mallory's scope, so the victim's key is untouched.
    assert!(runtime.get("mallory", &reply.id).await.unwrap().is_some());
    let victim = runtime
        .submit(request("victim", json!({"x": 2})), "k".into(), live())
        .await;
    assert!(
        matches!(victim.result, Ok(Outcome::Success(_))),
        "no collision: {:?}",
        victim.result
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// Delegates to a memory store but can be told to fail recovery.
struct FailingRecover {
    inner: MemoryOperationStore,
    fail: AtomicBool,
}
impl OperationStore for FailingRecover {
    fn bounds(&self) -> Option<StoreBounds> {
        self.inner.bounds()
    }
    fn reserve<'a>(
        &'a self,
        r: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>> {
        self.inner.reserve(r)
    }
    fn complete<'a>(
        &'a self,
        id: &'a OperationId,
        o: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>> {
        self.inner.complete(id, o)
    }
    fn get<'a>(
        &'a self,
        id: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
        self.inner.get(id)
    }
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>> {
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err(StoreError("recovery failed".into())) });
        }
        self.inner.recover()
    }
    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>> {
        self.inner.abandon(id)
    }
    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>> {
        self.inner.acquire()
    }
    fn release(&self) {
        self.inner.release()
    }
}

#[tokio::test]
async fn a_failed_recovery_releases_the_store_claim() {
    let (ports, calls) = (Ports::allowing(), Arc::new(AtomicUsize::new(0)));
    let store = Arc::new(FailingRecover {
        inner: MemoryOperationStore::default(),
        fail: AtomicBool::new(true),
    });
    let d = dispatcher(&ports, &calls, false);
    assert!(Runtime::open(d.clone(), store.clone()).await.is_err());
    store.fail.store(false, Ordering::SeqCst);
    assert!(
        Runtime::open(d, store.clone()).await.is_ok(),
        "a failed open must not leave the store claimed"
    );
}

#[tokio::test]
async fn shutdown_stops_a_handler_that_never_completes_and_frees_the_store() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, true), &store).await;
    let mut caller = Box::pin(runtime.submit(request("a", json!({})), "k".into(), live()));
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::select! { _ = &mut caller => panic!("stalls"), _ = tokio::task::yield_now() => {} }
    }
    drop(caller);
    runtime.shutdown().await;
    let (reopened, interrupted) = Runtime::open(dispatcher(&ports, &calls, false), store.clone())
        .await
        .expect("the store is free once the runtime has shut down");
    assert_eq!(interrupted.len(), 1);
    let retry = reopened
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    match retry.result {
        Ok(Outcome::Unknown(v)) => {
            assert_eq!(v["source"], "runtime");
            assert_eq!(v["state"], "interrupted");
        }
        other => panic!("expected the runtime's unknown outcome, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

async fn limited(
    d: &Arc<Dispatcher>,
    store: &Arc<MemoryOperationStore>,
    global: usize,
    per_caller: usize,
) -> Runtime {
    Runtime::open_limited(
        d.clone(),
        store.clone(),
        RunningLimit::new(global, per_caller, Duration::from_secs(600)).unwrap(),
    )
    .await
    .unwrap()
    .0
}

#[test]
fn a_running_limit_that_admits_nobody_gives_one_caller_more_than_the_whole_or_allows_no_time_cannot_be_built()
 {
    let long = Duration::from_secs(1);
    assert!(RunningLimit::new(4, 0, long).is_err());
    assert!(RunningLimit::new(2, 3, long).is_err());
    assert!(RunningLimit::new(2, 2, Duration::ZERO).is_err());
    assert!(RunningLimit::new(2, 2, long).is_ok());
}

#[tokio::test]
async fn detached_operations_are_bounded_per_caller_and_overall_and_a_retry_of_a_running_one_is_free()
 {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        roomy_store(),
    );
    let runtime = limited(&dispatcher(&ports, &calls, true), &store, 3, 2).await;
    let start = |who: &'static str, key: &'static str| {
        runtime.start(request(who, json!({})), key.into(), live())
    };
    assert!(matches!(start("a", "1").await, Started::Running(_)));
    let again = start("a", "1").await;
    assert!(
        matches!(again, Started::Running(_)),
        "a retry of a running key takes no slot: {again:?}"
    );
    assert!(matches!(start("a", "2").await, Started::Running(_)));
    // The caller holds its two; a third is turned away before anything is stored or run.
    let Started::Finished(refused) = start("a", "3").await else {
        panic!("a third operation for one caller is refused")
    };
    assert_eq!(refused.result, Err(DispatchError::Unavailable));
    // Another caller still has the global slot left, and then the runtime is full.
    assert!(matches!(start("b", "1").await, Started::Running(_)));
    let Started::Finished(full) = start("c", "1").await else {
        panic!("the runtime is full")
    };
    assert_eq!(full.result, Err(DispatchError::Unavailable));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "refused requests ran nothing"
    );
    assert!(
        runtime.get("a", &refused.id).await.unwrap().is_none(),
        "a refused request leaves no record"
    );
    // Shutting down stops the stalled handlers and frees the slots with them.
    runtime.shutdown().await;
}

#[tokio::test]
async fn a_finished_operation_frees_its_slot() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        roomy_store(),
    );
    let runtime = limited(&dispatcher(&ports, &calls, false), &store, 1, 1).await;
    for key in ["1", "2", "3"] {
        let done = runtime
            .submit(request("a", json!({})), key.into(), live())
            .await;
        assert!(done.result.is_ok(), "{key}: {:?}", done.result);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_handler_still_running_at_the_ceiling_is_stopped_and_recorded_as_interrupted() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        roomy_store(),
    );
    let (runtime, _) = Runtime::open_limited(
        dispatcher(&ports, &calls, true),
        store.clone(),
        RunningLimit::new(1, 1, Duration::from_millis(100)).unwrap(),
    )
    .await
    .unwrap();
    // The handler never returns. At the ceiling it is stopped and the caller is told it is lost.
    let lost = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert_eq!(lost.result, Err(DispatchError::OutcomeLost));
    let view = runtime.get("a", &lost.id).await.unwrap().unwrap();
    assert_eq!(view.state(), &OperationState::Interrupted);
    // Its slot came back, and the key reads as interrupted instead of running again.
    let retry = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    match retry.result {
        Ok(Outcome::Unknown(v)) => assert_eq!(v["state"], "interrupted"),
        other => panic!("expected the runtime's unknown outcome, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the handler ran once");
    let other = runtime
        .submit(request("a", json!({})), "k2".into(), live())
        .await;
    assert_eq!(
        other.result,
        Err(DispatchError::OutcomeLost),
        "the slot was free"
    );
}

#[tokio::test]
async fn a_confirmation_claimed_in_an_envelope_is_not_taken_from_the_wire() {
    struct Echo(Arc<AtomicBool>);
    impl Confirmer for Echo {
        fn confirm<'a>(&'a self, request: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
            let claimed = request.confirmed;
            self.0.store(claimed, Ordering::SeqCst);
            Box::pin(async move { claimed })
        }
    }
    let ports = Ports::allowing();
    let saw_claim = Arc::new(AtomicBool::new(false));
    let mut d = Dispatcher::new(
        ports.clone(),
        Arc::new(Echo(saw_claim.clone())),
        ports.clone(),
        ports.clone(),
    );
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: true,
            support: Support::Supported,
        },
        Arc::new(Mutation {
            calls: Arc::new(AtomicUsize::new(0)),
            stall: false,
        }),
    )
    .unwrap();
    let store = Arc::new(MemoryOperationStore::default());
    let runtime = open(&Arc::new(d), &store).await;
    let mut claimed = request("a", json!({}));
    claimed.confirmed = true;
    let result = runtime
        .handle(
            "a",
            SubmitEnvelope {
                request: claimed,
                key: "k".into(),
            },
            live(),
        )
        .await;
    assert_eq!(result.result, Err(DispatchError::ConfirmationRequired));
    assert!(
        !saw_claim.load(Ordering::SeqCst),
        "the confirmer saw no claim"
    );
}

/// A store whose reads give other tasks a turn before answering, so a read and the check made before it are not one step. With a gate, the first read waits for the test to open it, which makes the interleaving exact instead of a matter of how many turns it takes.
struct SlowReads {
    inner: MemoryOperationStore,
    gate: Option<Arc<tokio::sync::Notify>>,
    gated: AtomicBool,
}

impl SlowReads {
    fn new(gate: Option<Arc<tokio::sync::Notify>>) -> Self {
        Self {
            inner: MemoryOperationStore::default(),
            gated: AtomicBool::new(gate.is_some()),
            gate,
        }
    }
}

impl OperationStore for SlowReads {
    fn bounds(&self) -> Option<StoreBounds> {
        self.inner.bounds()
    }
    fn reserve<'a>(
        &'a self,
        r: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>> {
        self.inner.reserve(r)
    }
    fn complete<'a>(
        &'a self,
        id: &'a OperationId,
        o: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>> {
        self.inner.complete(id, o)
    }
    fn get<'a>(
        &'a self,
        id: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
        Box::pin(async move {
            if self.gated.swap(false, Ordering::SeqCst) {
                if let Some(gate) = &self.gate {
                    gate.notified().await;
                }
            } else {
                for _ in 0..8 {
                    tokio::task::yield_now().await;
                }
            }
            self.inner.get(id).await
        })
    }
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>> {
        self.inner.recover()
    }
    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>> {
        self.inner.abandon(id)
    }
    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>> {
        self.inner.acquire()
    }
    fn release(&self) {
        self.inner.release()
    }
}

#[tokio::test]
async fn a_read_that_races_the_first_attempt_never_shows_a_running_operation_as_interrupted() {
    let (ports, calls) = (Ports::allowing(), Arc::new(AtomicUsize::new(0)));
    let gate = Arc::new(tokio::sync::Notify::new());
    let store: Arc<dyn OperationStore> = Arc::new(SlowReads::new(Some(gate.clone())));
    let runtime = Arc::new(
        Runtime::open(dispatcher(&ports, &calls, true), store)
            .await
            .unwrap()
            .0,
    );
    // The id a client can compute for itself before it has been told it.
    let id = herald_id("a", "race");
    // The read finds nothing running and goes to the store, which holds it there until the test opens the gate. By then the attempt has started and reserved the record.
    let reader = {
        let runtime = runtime.clone();
        let id = id.clone();
        tokio::spawn(async move { runtime.get("a", &id).await.unwrap() })
    };
    // Let the reader reach the store before the attempt starts.
    tokio::task::yield_now().await;
    let started = runtime
        .start(request("a", json!({})), "race".into(), live())
        .await;
    assert!(matches!(started, Started::Running(_)));
    gate.notify_one();
    let view = reader
        .await
        .unwrap()
        .expect("the record exists once the read finishes");
    assert_eq!(
        view.state(),
        &OperationState::Accepted,
        "a running operation is never shown as interrupted: {view:?}"
    );
    Arc::try_unwrap(runtime)
        .ok()
        .expect("the reader has finished")
        .shutdown()
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_detached_operation_past_the_ceiling_is_interrupted_and_frees_its_slot() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        roomy_store(),
    );
    let (runtime, _) = Runtime::open_limited(
        dispatcher(&ports, &calls, true),
        store.clone(),
        RunningLimit::new(1, 1, Duration::from_secs(60)).unwrap(),
    )
    .await
    .unwrap();
    let started = runtime
        .start(request("a", json!({})), "long".into(), live())
        .await;
    let Started::Running(id) = started else {
        panic!("the handler is running")
    };
    // A retry while it runs is told so, and takes no slot.
    let again = runtime
        .start(request("a", json!({})), "long".into(), live())
        .await;
    assert!(matches!(again, Started::Running(_)));
    // The runtime is full for anyone else.
    let Started::Finished(full) = runtime
        .start(request("a", json!({})), "other".into(), live())
        .await
    else {
        panic!("the limit is reached")
    };
    assert_eq!(full.result, Err(DispatchError::Unavailable));
    assert_eq!(
        runtime.get("a", &id).await.unwrap().unwrap().state(),
        &OperationState::Accepted
    );
    // Time passes beyond the ceiling.
    tokio::time::advance(Duration::from_secs(61)).await;
    // The ceiling stops the handler and records the interruption on the supervising task, which gets its turn as the reads below yield.
    tokio::time::timeout(Duration::from_secs(30), async {
        while runtime.get("a", &id).await.unwrap().unwrap().state() != &OperationState::Interrupted
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the operation was recorded as interrupted");
    // The slot is free again, and a retry of the stopped key replays the unknown outcome.
    let retry = runtime
        .submit(request("a", json!({})), "long".into(), live())
        .await;
    match retry.result {
        Ok(Outcome::Unknown(v)) => assert_eq!(v["state"], "interrupted"),
        other => panic!("expected the runtime's unknown outcome, got {other:?}"),
    }
    let next = runtime
        .start(request("a", json!({})), "next".into(), live())
        .await;
    assert!(
        matches!(next, Started::Running(_)),
        "the slot came back: {next:?}"
    );
    runtime.shutdown().await;
}

/// An authoriser that never answers, standing in for a policy waiting on a person.
struct Waits;
impl Authorizer for Waits {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn a_ceiling_reached_before_the_record_is_reserved_reports_that_nothing_ran() {
    let ports = Ports::allowing();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut d = Dispatcher::new(Arc::new(Waits), ports.clone(), ports.clone(), ports);
    d.register(
        Contract {
            id: id(),
            kind: Kind::Operation,
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"object"}),
            error_schema: json!({"type":"object"}),
            event_schema: json!(true),
            required_capabilities: vec![],
            confirmation_required: false,
            support: Support::Supported,
        },
        Arc::new(Mutation {
            calls: calls.clone(),
            stall: false,
        }),
    )
    .unwrap();
    let store = roomy_store();
    let (runtime, _) = Runtime::open_limited(
        Arc::new(d),
        store.clone(),
        RunningLimit::new(1, 1, Duration::from_secs(60)).unwrap(),
    )
    .await
    .unwrap();
    let submitted = tokio::spawn({
        let runtime = Arc::new(runtime);
        async move {
            runtime
                .submit(request("a", json!({})), "k".into(), live())
                .await
        }
    });
    // The submission waits on the authoriser for ever; once the paused clock passes the ceiling the runtime stops it.
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    let submission = submitted.await.unwrap();
    assert_eq!(
        submission.result,
        Err(DispatchError::InterruptedBeforeDispatch)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the handler never ran");
    assert!(
        store.get(&submission.id).await.unwrap().is_none(),
        "nothing was reserved, so there is no record to mark"
    );
}

#[tokio::test]
async fn a_read_is_not_held_up_by_a_steady_stream_of_starts_elsewhere() {
    let (ports, calls) = (Ports::allowing(), Arc::new(AtomicUsize::new(0)));
    let store: Arc<dyn OperationStore> = Arc::new(SlowReads::new(None));
    let runtime = Arc::new(
        Runtime::open(dispatcher(&ports, &calls, false), store)
            .await
            .unwrap()
            .0,
    );
    let kept = runtime
        .submit(request("a", json!({})), "kept".into(), live())
        .await;
    let reading = Arc::new(AtomicBool::new(true));
    // Many submitters keep starting attempts on other operations for as long as the read is running.
    let churn: Vec<_> = (0..16)
        .map(|worker| {
            let (runtime, reading) = (runtime.clone(), reading.clone());
            tokio::spawn(async move {
                let mut n = 0;
                while reading.load(Ordering::SeqCst) {
                    runtime
                        .submit(
                            request("b", json!({})),
                            format!("other-{worker}-{n}"),
                            live(),
                        )
                        .await;
                    n += 1;
                }
            })
        })
        .collect();
    for _ in 0..20 {
        let view = tokio::time::timeout(Duration::from_secs(30), runtime.get("a", &kept.id))
            .await
            .expect("a read finishes while starts continue elsewhere")
            .unwrap()
            .unwrap();
        assert!(matches!(view.state(), OperationState::Completed(_)));
    }
    reading.store(false, Ordering::SeqCst);
    for worker in churn {
        worker.await.unwrap();
    }
}

#[tokio::test]
async fn two_spellings_of_the_same_number_are_one_payload_and_an_integer_and_a_float_are_two() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let runtime = open(&dispatcher(&ports, &calls, false), &store).await;
    let submit = |input: serde_json::Value| {
        let runtime = &runtime;
        async move {
            runtime
                .submit(request("a", input), "k".into(), live())
                .await
        }
    };
    let first = submit(serde_json::from_str(r#"{"n": 1e5}"#).unwrap()).await;
    assert!(first.result.is_ok());
    // The same number written another way is the same payload: the key replays, and nothing reruns.
    let again = submit(serde_json::from_str(r#"{"n": 100000.0}"#).unwrap()).await;
    assert!(again.result.is_ok(), "{again:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // An integer and a float are different payloads, so the key is a conflict.
    let integer = runtime
        .submit(request("a", json!({"n": 1})), "other".into(), live())
        .await;
    assert!(integer.result.is_ok());
    let float = runtime
        .submit(request("a", json!({"n": 1.0})), "other".into(), live())
        .await;
    assert_eq!(float.result, Err(DispatchError::KeyConflict));
}

fn bounded_store(
    per_caller_records: usize,
    retention: u64,
    clock: &Arc<HandClock>,
) -> Arc<MemoryOperationStore> {
    Arc::new(MemoryOperationStore::bounded(
        StoreBounds::new(per_caller_records, retention).unwrap(),
        clock.clone(),
    ))
}

#[tokio::test]
async fn a_running_limit_needs_a_store_that_declares_its_bounds() {
    let (ports, calls) = (Ports::allowing(), Arc::new(AtomicUsize::new(0)));
    let refused = Runtime::open_limited(
        dispatcher(&ports, &calls, false),
        Arc::new(MemoryOperationStore::default()),
        RunningLimit::new(1, 1, Duration::from_secs(1)).unwrap(),
    )
    .await;
    let Err(error) = refused else {
        panic!("a store with no bounds was accepted")
    };
    assert!(error.0.contains("retention period and a per-caller quota"));
    let clock = Arc::new(HandClock::default());
    assert!(
        Runtime::open_limited(
            dispatcher(&ports, &calls, false),
            bounded_store(1, 1, &clock),
            RunningLimit::new(1, 1, Duration::from_secs(1)).unwrap(),
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn a_caller_at_its_quota_is_turned_away_for_a_new_key_but_not_for_a_replay_or_another_caller()
{
    let (ports, calls, clock) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(HandClock::default()),
    );
    let store = bounded_store(2, 100, &clock);
    let runtime = limited(&dispatcher(&ports, &calls, false), &store, 4, 4).await;
    for key in ["1", "2"] {
        let done = runtime
            .submit(request("a", json!({})), key.into(), live())
            .await;
        assert!(done.result.is_ok(), "{key}: {:?}", done.result);
    }
    let full = runtime
        .submit(request("a", json!({})), "3".into(), live())
        .await;
    assert_eq!(full.result, Err(DispatchError::Unavailable));
    // A full quota is a store's verdict after the request was admitted, so the observer is told, as it is of a key conflict.
    assert_eq!(ports.unavailable_reported.load(Ordering::SeqCst), 1);
    assert!(runtime.get("a", &full.id).await.unwrap().is_none());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the refused key ran nothing"
    );
    let replay = runtime
        .submit(request("a", json!({})), "1".into(), live())
        .await;
    assert!(replay.result.is_ok(), "{:?}", replay.result);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "a replay runs nothing");
    let other = runtime
        .submit(request("b", json!({})), "1".into(), live())
        .await;
    assert!(other.result.is_ok(), "{:?}", other.result);
}

#[tokio::test]
async fn a_finished_record_older_than_the_retention_is_dropped_and_a_running_one_never_is() {
    let (ports, calls, clock) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(HandClock::default()),
    );
    let store = bounded_store(1, 10, &clock);
    let runtime = limited(&dispatcher(&ports, &calls, false), &store, 2, 2).await;
    let first = runtime
        .submit(request("a", json!({})), "1".into(), live())
        .await;
    assert!(first.result.is_ok());
    clock.advance(10);
    let at_retention = runtime
        .submit(request("a", json!({})), "2".into(), live())
        .await;
    assert_eq!(
        at_retention.result,
        Err(DispatchError::Unavailable),
        "a record is kept for the whole retention"
    );
    clock.advance(1);
    let after = runtime
        .submit(request("a", json!({})), "2".into(), live())
        .await;
    assert!(after.result.is_ok(), "{:?}", after.result);
    assert!(runtime.get("a", &first.id).await.unwrap().is_none());
    runtime.shutdown().await;

    let stalled_clock = Arc::new(HandClock::default());
    let store = bounded_store(1, 10, &stalled_clock);
    let runtime = limited(&dispatcher(&ports, &calls, true), &store, 2, 2).await;
    let Started::Running(running) = runtime
        .start(request("a", json!({})), "1".into(), live())
        .await
    else {
        panic!("the stalled operation did not start")
    };
    stalled_clock.advance(1_000);
    let refused = runtime
        .submit(request("a", json!({})), "2".into(), live())
        .await;
    assert_eq!(refused.result, Err(DispatchError::Unavailable));
    assert!(
        runtime.get("a", &running).await.unwrap().is_some(),
        "an operation still running is never dropped"
    );
    runtime.shutdown().await;
}

#[test]
fn store_bounds_that_allow_no_record_or_no_retention_cannot_be_built() {
    assert!(StoreBounds::new(0, 1).is_err());
    assert!(StoreBounds::new(1, 0).is_err());
    assert!(StoreBounds::new(1, 1).is_ok());
}
