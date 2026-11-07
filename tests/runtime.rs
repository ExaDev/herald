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
}
impl Ports {
    fn allowing() -> Arc<Self> {
        Arc::new(Self {
            allow: AtomicBool::new(true),
        })
    }
}
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.allow.load(Ordering::SeqCst) })
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

#[tokio::test]
async fn an_operation_lost_mid_flight_reads_as_unknown_after_restart_and_is_never_rerun() {
    let (ports, calls, store) = (
        Ports::allowing(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(MemoryOperationStore::default()),
    );
    let stalled = open(&dispatcher(&ports, &calls, true), &store).await;
    let mut lost = Box::pin(stalled.submit(request("a", json!({})), "k".into(), live()));
    tokio::select! { _ = &mut lost => panic!("the handler stalls"), _ = tokio::task::yield_now() => {} }
    drop(lost); // the runtime is lost with the handler's effect unknown
    drop(stalled);

    // A new runtime opens over the same store and finds the operation.
    let (runtime, interrupted) = Runtime::open(dispatcher(&ports, &calls, false), store.clone())
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
        .get(&retry.id)
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
    let all = runtime.events_after(&done.id, 0).await.unwrap();
    assert_eq!(all.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![0, 1]);
    let after_first = runtime.events_after(&done.id, 1).await.unwrap();
    assert_eq!(after_first.len(), 1);
    assert!(matches!(after_first[0].state, OperationState::Completed(_)));
    assert!(runtime.events_after(&done.id, 2).await.unwrap().is_empty());
    assert!(
        runtime
            .events_after(&OperationId("missing".into()), 0)
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
    assert_eq!(runtime.get(&submission.id).await.unwrap(), None);
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
        envelope: SubmitEnvelope,
    ) -> PortFuture<'a, Result<Submission, TransportError>> {
        Box::pin(async move {
            let wire = serde_json::to_string(&envelope).unwrap();
            let received: SubmitEnvelope = serde_json::from_str(&wire).unwrap();
            let reply = self.0.handle(received, live()).await;
            Ok(serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap())
        })
    }
    fn events_after<'a>(
        &'a self,
        id: OperationId,
        cursor: u64,
    ) -> PortFuture<'a, Result<Vec<OperationEvent>, TransportError>> {
        Box::pin(async move {
            self.0
                .events_after(&id, cursor)
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
    let first = remote.submit(envelope.clone()).await.unwrap();
    let redelivered = remote.submit(envelope).await.unwrap();
    assert_eq!(first, redelivered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let events = remote.events_after(first.id, 0).await.unwrap();
    assert_eq!(events.len(), 2);
}
