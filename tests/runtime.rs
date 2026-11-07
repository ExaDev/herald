use herald::runtime::{
    MemoryOperationStore, OperationEvent, OperationId, OperationRecord, OperationState,
    OperationStore, Reservation, Runtime, StoreError, Submission, SubmitEnvelope, Transport,
    TransportError,
};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Ports {
    allow: AtomicBool,
    /// The next authorisation panics, standing in for a failing product port.
    panic_next: AtomicBool,
    /// Deny any request whose input names resource "x", standing in for a per-resource policy.
    deny_x: AtomicBool,
}
impl Ports {
    fn allowing() -> Arc<Self> {
        Arc::new(Self {
            allow: AtomicBool::new(true),
            panic_next: AtomicBool::new(false),
            deny_x: AtomicBool::new(false),
        })
    }
}
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, request: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move {
            if self.panic_next.swap(false, Ordering::SeqCst) {
                panic!("authorizer failure");
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
    fn finished(&self, _: &Request, _: u64, _: &Result<Outcome, DispatchError>) {}
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
    // A second delivery of the same key panics in the product's authorizer before it reserves anything.
    ports.panic_next.store(true, Ordering::SeqCst);
    let second = runtime
        .submit(request("a", json!({})), "k".into(), live())
        .await;
    assert_eq!(second.result, Err(DispatchError::OutcomeLost));
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
