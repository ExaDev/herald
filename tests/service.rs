use herald::exposure::{Exposure, Surface};
use herald::runtime::{
    MemoryOperationStore, OperationId, OperationRecord, OperationState, OperationStore,
    Reservation, Runtime, StoreError,
};
use herald::service::{
    Executed, MAX_INPUT_BYTES, MAX_KEY_BYTES, MAX_REQUEST_BYTES, Mode as ServiceMode, Principal,
    Service, Shape, StartResult,
};
use herald::wire::{ErrorCode, WireError};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

/// Product policy. `confirm_claimed` makes the confirmer believe the request's own `confirmed` flag,
/// which is how a test proves the service never sets it.
struct Ports {
    allowed: &'static [&'static str],
    confirm: AtomicBool,
    confirm_claimed: bool,
}
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, r: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.allowed.contains(&r.identity.as_str()) })
    }
}
impl Confirmer for Ports {
    fn confirm<'a>(&'a self, r: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move {
            if self.confirm_claimed {
                r.confirmed
            } else {
                self.confirm.load(Ordering::SeqCst)
            }
        })
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

#[derive(Clone, Copy)]
enum Mode {
    Immediate,
    WaitForRelease,
    Panic,
    Fail,
    Doubt,
}

/// Records every request it is given, so a test can assert what the handler actually saw.
struct Work {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Request>>>,
    release: Arc<Notify>,
    mode: Mode,
}
impl Handler for Work {
    fn invoke<'a>(&'a self, r: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(r.clone());
            match self.mode {
                Mode::WaitForRelease => self.release.notified().await,
                Mode::Panic => panic!("handler failure"),
                Mode::Fail => return Outcome::Error(json!({"why": "refused"})),
                Mode::Doubt => return Outcome::Unknown(json!({"why": "lost the link"})),
                Mode::Immediate => {}
            }
            Outcome::Success(json!({"caller": r.identity, "input": r.input}))
        })
    }
}

fn id(name: &str) -> CapabilityId {
    CapabilityId {
        name: name.into(),
        version: 1,
    }
}
fn contract(name: &str, kind: Kind, confirmation: bool) -> Contract {
    Contract {
        id: id(name),
        kind,
        input_schema: json!({"type":"object"}),
        output_schema: json!({"type":"object"}),
        error_schema: json!({"type":"object"}),
        event_schema: json!(true),
        required_capabilities: vec![],
        confirmation_required: confirmation,
        support: Support::Supported,
    }
}
fn who(name: &str) -> Principal {
    Principal::new(name).unwrap()
}
fn live() -> Cancellation {
    cancellation().1
}
fn all(surface: Surface) -> Exposure {
    [
        "read", "write", "slow", "guarded", "boom", "events", "fails", "doubts",
    ]
    .into_iter()
    .fold(Exposure::none(), |e, n| e.allow(surface, id(n)))
}

struct Fixture {
    dispatcher: Arc<Dispatcher>,
    runtime: Arc<Runtime>,
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Request>>>,
    release: Arc<Notify>,
    ports: Arc<Ports>,
}
impl Fixture {
    fn service(&self, exposure: Exposure) -> Service {
        Service::new(self.dispatcher.clone(), self.runtime.clone(), exposure)
    }
}
async fn fixture_with(confirm_claimed: bool, store: Arc<dyn OperationStore>) -> Fixture {
    let ports = Arc::new(Ports {
        allowed: &["alice", "bob"],
        confirm: AtomicBool::new(true),
        confirm_claimed,
    });
    let (calls, seen, release) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(Mutex::new(vec![])),
        Arc::new(Notify::new()),
    );
    let work = |mode| {
        Arc::new(Work {
            calls: calls.clone(),
            seen: seen.clone(),
            release: release.clone(),
            mode,
        }) as Arc<dyn Handler>
    };
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(contract("read", Kind::Query, false), work(Mode::Immediate))
        .unwrap();
    d.register(
        contract("write", Kind::Operation, false),
        work(Mode::Immediate),
    )
    .unwrap();
    d.register(
        contract("slow", Kind::Operation, false),
        work(Mode::WaitForRelease),
    )
    .unwrap();
    d.register(
        contract("guarded", Kind::Operation, true),
        work(Mode::Immediate),
    )
    .unwrap();
    d.register(contract("boom", Kind::Operation, false), work(Mode::Panic))
        .unwrap();
    d.register(contract("fails", Kind::Operation, false), work(Mode::Fail))
        .unwrap();
    d.register(
        contract("doubts", Kind::Operation, false),
        work(Mode::Doubt),
    )
    .unwrap();
    struct NoSource;
    impl herald::SubscriptionHandler for NoSource {
        fn subscribe<'a>(
            &'a self,
            _: &'a Request,
            _: Cancellation,
        ) -> PortFuture<'a, Result<tokio::sync::mpsc::Receiver<Result<Value, Value>>, Value>>
        {
            Box::pin(async { Ok(tokio::sync::mpsc::channel(1).1) })
        }
    }
    d.register_subscription(
        contract("events", Kind::Subscription, false),
        Arc::new(NoSource),
    )
    .unwrap();
    let dispatcher = Arc::new(d);
    let (runtime, _) = Runtime::open(dispatcher.clone(), store).await.unwrap();
    Fixture {
        dispatcher,
        runtime: Arc::new(runtime),
        calls,
        seen,
        release,
        ports,
    }
}
async fn fixture() -> Fixture {
    fixture_with(false, Arc::new(MemoryOperationStore::default())).await
}

/// Waits for a condition, failing the test instead of spinning forever.
async fn eventually<T>(mut probe: impl AsyncFnMut() -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(found) = probe().await {
                return found;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the condition never held")
}

#[tokio::test]
async fn nothing_is_exposed_until_a_product_says_so() {
    let f = fixture().await;
    let service = f.service(Exposure::none());
    assert!(service.list(&who("alice"), Surface::Mcp).await.is_empty());
    let err = service
        .call(
            &who("alice"),
            Surface::Mcp,
            &id("read"),
            json!({}),
            None,
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exposure_is_per_surface_and_an_unexposed_capability_looks_unknown() {
    let f = fixture().await;
    let service = f.service(all(Surface::Mcp));
    let alice = who("alice");
    // Subscriptions are not advertised until they have a call path.
    assert_eq!(service.list(&alice, Surface::Mcp).await.len(), 7);
    assert!(service.list(&alice, Surface::Api).await.is_empty());
    let unexposed = service
        .call(&alice, Surface::Api, &id("read"), json!({}), None, live())
        .await
        .unwrap_err();
    let unknown = service
        .call(
            &alice,
            Surface::Api,
            &id("nothing"),
            json!({}),
            None,
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(unexposed, unknown);
}

#[tokio::test]
async fn a_denied_caller_learns_nothing_about_exposed_capabilities_from_any_entry_point() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let mallory = who("mallory"); // authenticated, not authorised by the product
    assert!(service.list(&mallory, Surface::Api).await.is_empty());
    let unknown = service
        .call(
            &mallory,
            Surface::Api,
            &id("nothing"),
            json!({}),
            None,
            live(),
        )
        .await
        .unwrap_err();
    // Whatever the kind or the key, a denied caller sees exactly what an unknown capability shows.
    for name in ["read", "write", "slow", "guarded"] {
        for key in [None, Some("k".to_string())] {
            let call = service
                .call(
                    &mallory,
                    Surface::Api,
                    &id(name),
                    json!({}),
                    key.clone(),
                    live(),
                )
                .await
                .unwrap_err();
            assert_eq!(call, unknown, "call {name} {key:?}");
            let start = service
                .start(
                    &mallory,
                    Surface::Api,
                    &id(name),
                    json!({}),
                    key.clone(),
                    live(),
                )
                .await
                .unwrap_err();
            assert_eq!(start, unknown, "start {name} {key:?}");
        }
    }
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_principal_is_the_identity_the_handler_sees_whatever_the_input_claims() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let out = service
        .call(
            &who("alice"),
            Surface::Api,
            &id("read"),
            json!({"identity": "bob", "confirmed": true}),
            None,
            live(),
        )
        .await
        .unwrap();
    match out.outcome {
        Outcome::Success(v) => assert_eq!(v["caller"], "alice"),
        other => panic!("{other:?}"),
    }
    assert_eq!(out.operation, None, "a query leaves no record");
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen[0].identity, "alice");
    assert!(
        !seen[0].confirmed,
        "the service never takes consent from the wire"
    );
}

#[tokio::test]
async fn an_empty_identity_cannot_become_a_principal() {
    assert!(Principal::new("").is_err());
}

#[tokio::test]
async fn an_operation_needs_a_key_replays_on_retry_and_rejects_a_changed_payload() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let missing = service
        .call(&alice, Surface::Api, &id("write"), json!({}), None, live())
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::BadRequest);
    let first = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            json!({"x": 1}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap();
    let again = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            json!({"x": 1}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap();
    assert_eq!(first, again);
    assert!(first.recorded && first.operation.is_some());
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    let clash = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            json!({"x": 2}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(clash.code, ErrorCode::KeyConflict);
}

#[tokio::test]
async fn only_the_products_confirmer_can_confirm_and_a_claim_on_the_wire_is_ignored() {
    // This confirmer believes `request.confirmed`, so setting it in the service would make this pass.
    let f = fixture_with(true, Arc::new(MemoryOperationStore::default())).await;
    let service = f.service(all(Surface::Api));
    let err = service
        .call(
            &who("alice"),
            Surface::Api,
            &id("guarded"),
            json!({"confirmed": true}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ConfirmationRequired);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    // And when the product confirms, the same call goes through.
    let f = fixture().await;
    let ok = f
        .service(all(Surface::Api))
        .call(
            &who("alice"),
            Surface::Api,
            &id("guarded"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await;
    assert!(ok.is_ok());
}

#[tokio::test]
async fn invalid_input_is_a_typed_error_that_never_reaches_the_handler() {
    let f = fixture().await;
    let err = f
        .service(all(Surface::Api))
        .call(
            &who("alice"),
            Surface::Api,
            &id("read"),
            json!("nope"),
            None,
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert!(
        err.detail.is_some(),
        "the caller is told what was wrong with its own input"
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn oversized_keys_and_inputs_are_refused_before_anything_runs() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let key = "k".repeat(MAX_KEY_BYTES + 1);
    let long = service
        .call(
            &who("alice"),
            Surface::Api,
            &id("write"),
            json!({}),
            Some(key),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(long.code, ErrorCode::TooLarge);
    let big = json!({"blob": "x".repeat(MAX_INPUT_BYTES)});
    let large = service
        .call(
            &who("alice"),
            Surface::Api,
            &id("write"),
            big,
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(large.code, ErrorCode::TooLarge);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_oversized_request_gets_one_answer_whether_the_capability_exists_or_not() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let mallory = who("mallory"); // denied everything, so any difference would be a leak
    let alice = who("alice");
    let key = "k".repeat(MAX_KEY_BYTES + 1);
    // Far over the request bound: refused identically before any lookup, for every name.
    let huge = json!({"blob": "x".repeat(MAX_REQUEST_BYTES)});
    // Just over the input bound but inside the envelope allowance: judged after authorisation.
    let big = json!({"blob": "x".repeat(MAX_INPUT_BYTES)});
    for name in ["read", "write", "slow", "nothing"] {
        let long_key = service
            .call(
                &mallory,
                Surface::Api,
                &id(name),
                json!({}),
                Some(key.clone()),
                live(),
            )
            .await
            .unwrap_err();
        let long_start = service
            .start(
                &mallory,
                Surface::Api,
                &id(name),
                json!({}),
                Some(key.clone()),
                live(),
            )
            .await
            .unwrap_err();
        let huge_call = service
            .call(
                &mallory,
                Surface::Api,
                &id(name),
                huge.clone(),
                Some("k".into()),
                live(),
            )
            .await
            .unwrap_err();
        // The key is judged after authorisation, so a denied caller sees only not_found.
        assert_eq!(long_key.code, ErrorCode::NotFound, "{name}");
        assert_eq!(long_start.code, ErrorCode::NotFound, "{name}");
        assert_eq!(huge_call.code, ErrorCode::TooLarge, "{name}");
        let denied = service
            .call(
                &mallory,
                Surface::Api,
                &id(name),
                big.clone(),
                Some("k".into()),
                live(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            denied.code,
            ErrorCode::NotFound,
            "a denied caller sees only not_found for {name}"
        );
    }
    // An authorised caller is told the input is too large.
    let told = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            big,
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(told.code, ErrorCode::TooLarge);
    // An authorised caller is told the key is too long, for an operation.
    let long = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            json!({}),
            Some(key),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(long.code, ErrorCode::TooLarge);
    assert_eq!(
        Service::check_bounds(&huge).unwrap_err().code,
        ErrorCode::TooLarge
    );
    assert!(Service::check_bounds(&json!({"input": {"x": 1}, "idempotency_key": "k"})).is_ok());
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_started_operation_is_followed_through_a_second_service_over_the_same_runtime() {
    let f = fixture().await;
    let mcp = f.service(Exposure::none().allow(Surface::Mcp, id("slow")));
    let api = f.service(Exposure::none().allow(Surface::Api, id("slow")));
    let alice = who("alice");
    let StartResult::Running { operation } = mcp
        .start(
            &alice,
            Surface::Mcp,
            &id("slow"),
            json!({}),
            Some("run".into()),
            live(),
        )
        .await
        .unwrap()
    else {
        panic!("expected a running operation")
    };
    // The adapter that exposes the capability on its own surface can follow what the other one started.
    let view = api
        .operation(&alice, Surface::Api, &operation)
        .await
        .unwrap();
    assert_eq!(view.state(), &OperationState::Accepted);
    // A service that does not expose it cannot, even over the same runtime and the same operation.
    let hidden = f.service(Exposure::none().allow(Surface::Api, id("read")));
    assert_eq!(
        hidden
            .operation(&alice, Surface::Api, &operation)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        hidden
            .events_after(&alice, Surface::Api, &operation, 0)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    // Another caller cannot, and an unauthorised one cannot.
    assert_eq!(
        api.operation(&who("bob"), Surface::Api, &operation)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        api.events_after(&who("bob"), Surface::Api, &operation, 0)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        api.events_after(&who("mallory"), Surface::Api, &operation, 0)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    f.release.notify_one();
    let done = eventually(async || {
        let events = api
            .events_after(&alice, Surface::Api, &operation, 0)
            .await
            .unwrap();
        (events.len() == 2).then_some(events)
    })
    .await;
    assert!(matches!(
        done[1].state,
        OperationState::Completed(Outcome::Success(_))
    ));
    assert_eq!(
        api.events_after(&alice, Surface::Api, &operation, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_retry_of_a_running_key_reports_the_running_operation_not_a_lost_outcome() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let StartResult::Running { operation } = service
        .start(
            &alice,
            Surface::Api,
            &id("slow"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap()
    else {
        panic!("expected running")
    };
    // A second start of the same key points at the same operation and starts nothing new.
    match service
        .start(
            &alice,
            Surface::Api,
            &id("slow"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap()
    {
        StartResult::Running { operation: second } => assert_eq!(second, operation),
        other => panic!("expected the same running operation, got {other:?}"),
    }
    // Waiting on it is refused with a typed error that says to follow, never an unknown outcome.
    let waited = service
        .call(
            &alice,
            Surface::Api,
            &id("slow"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(waited.code, ErrorCode::InProgress);
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.release.notify_one();
}

#[tokio::test]
async fn a_handler_that_panics_after_admission_is_recorded_whichever_way_it_was_started() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let lost = service
        .call(
            &alice,
            Surface::Api,
            &id("boom"),
            json!({}),
            Some("a".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(lost.code, ErrorCode::OutcomeLost);
    let StartResult::Running { operation } = service
        .start(
            &alice,
            Surface::Api,
            &id("boom"),
            json!({}),
            Some("b".into()),
            live(),
        )
        .await
        .unwrap()
    else {
        panic!("expected running")
    };
    // Dropping nothing: the supervisor, not the caller, records the panic.
    let state = eventually(async || {
        let view = service
            .operation(&alice, Surface::Api, &operation)
            .await
            .unwrap();
        (view.state() != &OperationState::Accepted).then(|| view.state().clone())
    })
    .await;
    assert_eq!(state, OperationState::Interrupted);
}

#[tokio::test]
async fn a_started_operation_whose_caller_goes_away_before_admission_still_has_its_panic_recorded()
{
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let boom = id("boom");
    let fut = service.start(
        &alice,
        Surface::Api,
        &boom,
        json!({}),
        Some("c".into()),
        live(),
    );
    // Poll the future once, then drop it: the supervisor owns the attempt from here.
    let _ = tokio::time::timeout(Duration::from_millis(0), fut).await;
    let operation = herald_op_id("alice", "c");
    let state = eventually(async || {
        let view = service
            .operation(&alice, Surface::Api, &operation)
            .await
            .ok()?;
        (view.state() != &OperationState::Accepted).then(|| view.state().clone())
    })
    .await;
    assert_eq!(state, OperationState::Interrupted);
}

fn herald_op_id(identity: &str, key: &str) -> OperationId {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((identity.len() as u64).to_be_bytes());
    h.update(identity.as_bytes());
    h.update(key.as_bytes());
    OperationId(format!(
        "op-{}",
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

#[tokio::test]
async fn shutdown_with_a_started_operation_leaves_it_to_recovery_and_the_store_free() {
    let store = Arc::new(MemoryOperationStore::default());
    let f = fixture_with(false, store.clone()).await;
    let alice = who("alice");
    let service = f.service(all(Surface::Api));
    let StartResult::Running { operation } = service
        .start(
            &alice,
            Surface::Api,
            &id("slow"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap()
    else {
        panic!("expected running")
    };
    drop(service);
    let runtime = Arc::try_unwrap(f.runtime)
        .ok()
        .expect("the fixture holds the only handle");
    runtime.shutdown().await;
    let (reopened, interrupted) = Runtime::open(f.dispatcher.clone(), store)
        .await
        .expect("the store is free after shutdown");
    assert_eq!(interrupted, vec![operation.clone()]);
    let view = reopened.get("alice", &operation).await.unwrap().unwrap();
    assert_eq!(view.state(), &OperationState::Interrupted);
}

/// A store whose `complete` fails, so a handler's outcome cannot be recorded.
struct ForgetfulStore(MemoryOperationStore);
impl OperationStore for ForgetfulStore {
    fn reserve<'a>(
        &'a self,
        r: OperationRecord,
    ) -> PortFuture<'a, Result<Reservation, StoreError>> {
        self.0.reserve(r)
    }
    fn complete<'a>(
        &'a self,
        _: &'a OperationId,
        _: Outcome,
    ) -> PortFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Err(StoreError("/var/lib/secret/path: disk full".into())) })
    }
    fn get<'a>(
        &'a self,
        id: &'a OperationId,
    ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
        self.0.get(id)
    }
    fn recover<'a>(&'a self) -> PortFuture<'a, Result<Vec<OperationId>, StoreError>> {
        self.0.recover()
    }
    fn abandon<'a>(&'a self, id: &'a OperationId) -> PortFuture<'a, Result<(), StoreError>> {
        self.0.abandon(id)
    }
    fn acquire<'a>(&'a self) -> PortFuture<'a, Result<(), StoreError>> {
        self.0.acquire()
    }
    fn release(&self) {
        self.0.release()
    }
}

#[tokio::test]
async fn an_outcome_that_could_not_be_recorded_is_flagged_and_store_errors_stay_opaque() {
    let f = fixture_with(
        false,
        Arc::new(ForgetfulStore(MemoryOperationStore::default())),
    )
    .await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let out = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap();
    assert!(
        !out.recorded,
        "the handler ran but its outcome was not stored"
    );
    // A store failure on a read reaches the client as a fixed message, never the store's own text.
    let broken = fixture_with(false, Arc::new(MemoryOperationStore::default())).await;
    struct Failing;
    impl OperationStore for Failing {
        fn reserve<'a>(
            &'a self,
            _: OperationRecord,
        ) -> PortFuture<'a, Result<Reservation, StoreError>> {
            Box::pin(async { Ok(Reservation::New) })
        }
        fn complete<'a>(
            &'a self,
            _: &'a OperationId,
            _: Outcome,
        ) -> PortFuture<'a, Result<(), StoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn get<'a>(
            &'a self,
            _: &'a OperationId,
        ) -> PortFuture<'a, Result<Option<OperationRecord>, StoreError>> {
            Box::pin(async {
                Err(StoreError(
                    "sqlite: constraint failed at /var/lib/secret/db".into(),
                ))
            })
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
    drop(broken);
    let failing = fixture_with(false, Arc::new(Failing)).await;
    let err = failing
        .service(all(Surface::Api))
        .operation(&alice, Surface::Api, &OperationId("op-x".into()))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Store);
    assert_eq!(err.message, "storage failed");
    assert!(!err.message.contains("secret"));
}

#[tokio::test]
async fn starting_a_query_is_a_bad_request_only_after_the_caller_is_authorised() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let err = service
        .start(
            &who("alice"),
            Surface::Api,
            &id("read"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_subscription_is_neither_listed_nor_callable_on_these_surfaces() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    assert!(
        service
            .list(&alice, Surface::Api)
            .await
            .iter()
            .all(|d| d.kind != Kind::Subscription)
    );
    let err = service
        .call(&alice, Surface::Api, &id("events"), json!({}), None, live())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn start_results_and_wire_errors_survive_a_serde_round_trip() {
    use herald::service::{CallResult, StartResult};
    let running = StartResult::Running {
        operation: OperationId("op-1".into()),
    };
    let wire = serde_json::to_string(&running).unwrap();
    assert!(wire.contains("\"state\":\"running\""));
    assert_eq!(serde_json::from_str::<StartResult>(&wire).unwrap(), running);
    let finished = StartResult::Finished(CallResult {
        operation: None,
        outcome: Outcome::Success(json!({"a": 1})),
        recorded: true,
        failed: false,
        uncertain: false,
    });
    assert_eq!(
        serde_json::from_str::<StartResult>(&serde_json::to_string(&finished).unwrap()).unwrap(),
        finished
    );
    let error = WireError::from(&DispatchError::SubscriptionSource(json!({"why": "gone"})));
    assert_eq!(error.code, ErrorCode::SourceFailed);
    assert_eq!(
        serde_json::from_str::<WireError>(&serde_json::to_string(&error).unwrap()).unwrap(),
        error
    );
}

#[tokio::test]
async fn a_policy_that_denies_a_null_input_hides_the_capability_from_the_list() {
    // Documented behaviour: listing probes with null, so the policy must answer for it.
    struct DenyNull;
    impl Authorizer for DenyNull {
        fn authorize<'a>(&'a self, r: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
            Box::pin(async move { !r.input.is_null() })
        }
    }
    let f = fixture().await;
    let ports = f.ports.clone();
    let mut d = Dispatcher::new(Arc::new(DenyNull), ports.clone(), ports.clone(), ports);
    d.register(
        contract("read", Kind::Query, false),
        Arc::new(Work {
            calls: f.calls.clone(),
            seen: f.seen.clone(),
            release: f.release.clone(),
            mode: Mode::Immediate,
        }),
    )
    .unwrap();
    let d = Arc::new(d);
    let (runtime, _) = Runtime::open(d.clone(), Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    let service = Service::new(
        d,
        Arc::new(runtime),
        Exposure::none().allow(Surface::Api, id("read")),
    );
    assert!(service.list(&who("alice"), Surface::Api).await.is_empty());
}

#[tokio::test]
async fn an_error_and_an_unknown_outcome_are_flagged_in_the_result_the_same_way_for_every_adapter()
{
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let failed = service
        .call(
            &alice,
            Surface::Api,
            &id("fails"),
            json!({}),
            Some("a".into()),
            live(),
        )
        .await
        .unwrap();
    assert!(failed.failed && !failed.uncertain);
    let doubtful = service
        .call(
            &alice,
            Surface::Api,
            &id("doubts"),
            json!({}),
            Some("b".into()),
            live(),
        )
        .await
        .unwrap();
    assert!(doubtful.uncertain && !doubtful.failed);
    let fine = service
        .call(
            &alice,
            Surface::Api,
            &id("write"),
            json!({}),
            Some("c".into()),
            live(),
        )
        .await
        .unwrap();
    assert!(!fine.failed && !fine.uncertain);
    // The flags are in the serialised result, so a client of any adapter can read them, and a replay keeps them.
    assert_eq!(serde_json::to_value(&failed).unwrap()["failed"], true);
    assert!(serde_json::to_value(&fine).unwrap().get("failed").is_none());
    let replay = service
        .call(
            &alice,
            Surface::Api,
            &id("doubts"),
            json!({}),
            Some("b".into()),
            live(),
        )
        .await
        .unwrap();
    assert!(replay.uncertain);
}

#[tokio::test]
async fn the_shape_of_a_payload_is_judged_only_after_the_caller_is_authorised() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let mallory = who("mallory");
    let strict = |_: &Kind| Shape::Envelope;
    let malformed = [
        json!({}),
        json!({"input": {}, "extra": 1}),
        json!({"input": {}, "idempotency_key": 5}),
        json!({"input": {}, "detach": "yes"}),
    ];
    for payload in malformed {
        let denied = service
            .prepare(
                &mallory,
                Surface::Api,
                &id("write"),
                payload.clone(),
                strict,
            )
            .await
            .unwrap_err();
        let unknown = service
            .prepare(
                &mallory,
                Surface::Api,
                &id("nothing"),
                payload.clone(),
                strict,
            )
            .await
            .unwrap_err();
        assert_eq!(
            denied, unknown,
            "a denied caller learns nothing from {payload}"
        );
        let authorised = service
            .prepare(&alice, Surface::Api, &id("write"), payload.clone(), strict)
            .await
            .unwrap_err();
        assert_eq!(authorised.code, ErrorCode::BadRequest, "{payload}");
    }
    let ok = service
        .prepare(
            &alice,
            Surface::Api,
            &id("write"),
            json!({"input": {"x": 1}, "idempotency_key": "k", "detach": true}),
            strict,
        )
        .await
        .unwrap();
    assert!(ok.detach && ok.key.as_deref() == Some("k"));
    let wait_only = service
        .prepare(
            &alice,
            Surface::Api,
            &id("write"),
            json!({"input": {}, "detach": true}),
            |_| Shape::EnvelopeWait,
        )
        .await
        .unwrap_err();
    assert_eq!(wait_only.code, ErrorCode::BadRequest);
    let direct = service
        .prepare(&alice, Surface::Api, &id("read"), json!({"x": 1}), |_| {
            Shape::Direct
        })
        .await
        .unwrap();
    assert_eq!(
        (direct.key, direct.detach, direct.input),
        (None, false, json!({"x": 1}))
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn execute_follows_the_requested_mode_and_refuses_to_start_a_query() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let alice = who("alice");
    let prepared = service
        .prepare(
            &alice,
            Surface::Api,
            &id("slow"),
            json!({"input": {}, "idempotency_key": "k", "detach": true}),
            |_| Shape::Envelope,
        )
        .await
        .unwrap();
    match service
        .execute(
            &alice,
            &id("slow"),
            prepared,
            ServiceMode::AsRequested,
            live(),
        )
        .await
        .unwrap()
    {
        Executed::Start(StartResult::Running { .. }) => {}
        other => panic!("a detach request starts the operation, got {other:?}"),
    }
    let query = service
        .prepare(&alice, Surface::Api, &id("read"), json!({}), |_| {
            Shape::Direct
        })
        .await
        .unwrap();
    let refused = service
        .execute(&alice, &id("read"), query, ServiceMode::Start, live())
        .await
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::BadRequest);
    f.release.notify_one();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_of_a_running_key_is_always_the_same_running_operation_whatever_the_scheduling() {
    let f = fixture().await;
    let service = Arc::new(f.service(all(Surface::Api)));
    let alice = who("alice");
    let StartResult::Running { operation } = service
        .start(
            &alice,
            Surface::Api,
            &id("slow"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap()
    else {
        panic!("expected running")
    };
    for round in 0..100 {
        let retries: Vec<_> = (0..4)
            .map(|_| {
                let service = service.clone();
                let alice = alice.clone();
                tokio::spawn(async move {
                    service
                        .start(
                            &alice,
                            Surface::Api,
                            &id("slow"),
                            json!({}),
                            Some("k".into()),
                            live(),
                        )
                        .await
                })
            })
            .collect();
        for retry in retries {
            match retry.await.unwrap() {
                Ok(StartResult::Running { operation: second }) => {
                    assert_eq!(second, operation, "round {round}")
                }
                other => {
                    panic!("round {round}: expected the same running operation, got {other:?}")
                }
            }
        }
    }
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    f.release.notify_one();
}

#[tokio::test]
async fn capability_names_must_be_addressable_on_every_surface() {
    let f = fixture().await;
    let ports = f.ports.clone();
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports);
    let work = || {
        Arc::new(Work {
            calls: f.calls.clone(),
            seen: f.seen.clone(),
            release: f.release.clone(),
            mode: Mode::Immediate,
        })
    };
    for bad in [
        "",
        "a/b",
        "a b",
        "a?x",
        "a{b}",
        "caf\u{e9}",
        "herald.cancel",
        "thing.v2",
        "thing.v10",
    ] {
        let err = d
            .register(contract(bad, Kind::Query, false), work())
            .unwrap_err();
        assert!(
            matches!(err, DispatchError::InvalidName(_)),
            "{bad:?} -> {err:?}"
        );
    }
    for good in [
        "read",
        "a.b",
        "a_b-c",
        "v2",
        "thing.version",
        "thing.v",
        "x.v2y",
    ] {
        d.register(contract(good, Kind::Query, false), work())
            .unwrap_or_else(|e| panic!("{good:?} -> {e:?}"));
    }
}

/// Allows the first authorisation and refuses every later one, as an expiring grant would.
struct Flaky(AtomicUsize);
impl Authorizer for Flaky {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.0.fetch_add(1, Ordering::SeqCst) == 0 })
    }
}

#[tokio::test]
async fn a_denial_after_the_first_authorisation_still_looks_like_an_unknown_capability() {
    let flaky = Arc::new(Flaky(AtomicUsize::new(0)));
    let ports = Arc::new(Ports {
        allowed: &["alice"],
        confirm: AtomicBool::new(true),
        confirm_claimed: false,
    });
    let mut d = Dispatcher::new(flaky, ports.clone(), ports.clone(), ports);
    let calls = Arc::new(AtomicUsize::new(0));
    d.register(
        contract("read", Kind::Query, false),
        Arc::new(Work {
            calls: calls.clone(),
            seen: Arc::new(Mutex::new(vec![])),
            release: Arc::new(Notify::new()),
            mode: Mode::Immediate,
        }),
    )
    .unwrap();
    let d = Arc::new(d);
    let (runtime, _) = Runtime::open(d.clone(), Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    let service = Service::new(
        d,
        Arc::new(runtime),
        Exposure::none().allow(Surface::Api, id("read")),
    );
    let error = service
        .call(
            &who("alice"),
            Surface::Api,
            &id("read"),
            json!({}),
            None,
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound, "not denied: {error:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_subscription_is_not_a_capability_a_service_can_call_whatever_the_payload() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    for payload in [json!({}), json!({"extra": 1}), json!([1])] {
        let error = service
            .call(
                &who("alice"),
                Surface::Api,
                &id("events"),
                payload.clone(),
                None,
                live(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound, "{payload}");
    }
}

#[tokio::test]
async fn a_query_input_field_named_like_the_key_is_input_and_not_a_key() {
    let f = fixture().await;
    let service = f.service(all(Surface::Api));
    let long = "k".repeat(MAX_KEY_BYTES + 1);
    let prepared = service
        .prepare(
            &who("alice"),
            Surface::Api,
            &id("read"),
            json!({"idempotency_key": long}),
            |_| Shape::Direct,
        )
        .await
        .unwrap();
    assert_eq!(prepared.key, None);
    assert_eq!(prepared.input["idempotency_key"], json!(long));
}

#[tokio::test]
async fn a_validator_message_in_an_error_is_bounded_whatever_the_input() {
    use herald::wire::MAX_DETAIL_BYTES;
    let quoted = DispatchError::InvalidInput("é".repeat(MAX_DETAIL_BYTES));
    let error = WireError::from(&quoted);
    let Some(Value::String(detail)) = error.detail else {
        panic!("a detail")
    };
    assert!(detail.len() <= MAX_DETAIL_BYTES);
    assert!(
        detail.chars().all(|c| c == 'é'),
        "cut on a character boundary"
    );
}
