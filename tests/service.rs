use herald::exposure::{Exposure, Surface};
use herald::runtime::{MemoryOperationStore, OperationState, Runtime};
use herald::service::{Principal, Service, StartResult};
use herald::wire::ErrorCode;
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::sync::Notify;

struct Ports {
    /// Identities the product authorises. Anything else is denied.
    allowed: &'static [&'static str],
    confirm: AtomicBool,
}
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, r: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.allowed.contains(&r.identity.as_str()) })
    }
}
impl Confirmer for Ports {
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.confirm.load(Ordering::SeqCst) })
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

/// Echoes who the dispatcher saw, and optionally waits to be released.
struct Work {
    calls: Arc<AtomicUsize>,
    release: Option<Arc<Notify>>,
}
impl Handler for Work {
    fn invoke<'a>(&'a self, r: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(release) = &self.release {
                release.notified().await;
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

struct Fixture {
    service: Service,
    calls: Arc<AtomicUsize>,
    release: Arc<Notify>,
    ports: Arc<Ports>,
}
async fn fixture(exposure: Exposure) -> Fixture {
    let ports = Arc::new(Ports {
        allowed: &["alice", "bob"],
        confirm: AtomicBool::new(true),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let mut d = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    d.register(
        contract("read", Kind::Query, false),
        Arc::new(Work {
            calls: calls.clone(),
            release: None,
        }),
    )
    .unwrap();
    d.register(
        contract("write", Kind::Operation, false),
        Arc::new(Work {
            calls: calls.clone(),
            release: None,
        }),
    )
    .unwrap();
    d.register(
        contract("slow", Kind::Operation, false),
        Arc::new(Work {
            calls: calls.clone(),
            release: Some(release.clone()),
        }),
    )
    .unwrap();
    d.register(
        contract("guarded", Kind::Operation, true),
        Arc::new(Work {
            calls: calls.clone(),
            release: None,
        }),
    )
    .unwrap();
    let d = Arc::new(d);
    let (runtime, _) = Runtime::open(d.clone(), Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    Fixture {
        service: Service::new(d, Arc::new(runtime), exposure),
        calls,
        release,
        ports,
    }
}
fn all(surface: Surface) -> Exposure {
    ["read", "write", "slow", "guarded"]
        .into_iter()
        .fold(Exposure::none(), |e, n| e.allow(surface, id(n)))
}
fn live() -> Cancellation {
    cancellation().1
}

#[tokio::test]
async fn nothing_is_exposed_until_a_product_says_so() {
    let f = fixture(Exposure::none()).await;
    let alice = Principal::new("alice");
    assert!(f.service.list(&alice, Surface::Mcp).await.is_empty());
    let err = f
        .service
        .call(&alice, Surface::Mcp, &id("read"), json!({}), None, live())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exposure_is_per_surface_and_an_unexposed_capability_looks_unknown() {
    let f = fixture(all(Surface::Mcp)).await;
    let alice = Principal::new("alice");
    assert_eq!(f.service.list(&alice, Surface::Mcp).await.len(), 4);
    assert!(f.service.list(&alice, Surface::Api).await.is_empty());
    let unexposed = f
        .service
        .call(&alice, Surface::Api, &id("read"), json!({}), None, live())
        .await
        .unwrap_err();
    let unknown = f
        .service
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
    assert_eq!(
        unexposed, unknown,
        "the two are indistinguishable to the caller"
    );
}

#[tokio::test]
async fn the_principal_replaces_any_identity_the_caller_supplies_and_listing_follows_authorisation()
{
    let f = fixture(all(Surface::Api)).await;
    let mallory = Principal::new("mallory"); // not authorised by the product
    assert!(
        f.service.list(&mallory, Surface::Api).await.is_empty(),
        "an unauthorised caller sees no capabilities"
    );
    let denied = f
        .service
        .call(&mallory, Surface::Api, &id("read"), json!({}), None, live())
        .await
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::Denied);
    let alice = Principal::new("alice");
    // The input claims another identity; the handler sees the authenticated one.
    let out = f
        .service
        .call(
            &alice,
            Surface::Api,
            &id("read"),
            json!({"identity": "bob"}),
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
}

#[tokio::test]
async fn an_operation_needs_a_key_replays_on_retry_and_rejects_a_changed_payload() {
    let f = fixture(all(Surface::Api)).await;
    let alice = Principal::new("alice");
    let missing = f
        .service
        .call(&alice, Surface::Api, &id("write"), json!({}), None, live())
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::BadRequest);
    let first = f
        .service
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
    let again = f
        .service
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
    let clash = f
        .service
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
async fn a_callers_claim_of_confirmation_is_not_taken_from_the_wire() {
    let f = fixture(all(Surface::Api)).await;
    f.ports.confirm.store(false, Ordering::SeqCst);
    let alice = Principal::new("alice");
    let err = f
        .service
        .call(
            &alice,
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
}

#[tokio::test]
async fn invalid_input_is_a_typed_error_that_never_reaches_the_handler() {
    let f = fixture(all(Surface::Api)).await;
    let err = f
        .service
        .call(
            &Principal::new("alice"),
            Surface::Api,
            &id("read"),
            json!("not an object"),
            None,
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_started_operation_is_observed_through_a_second_service_over_the_same_runtime() {
    let f = fixture(all(Surface::Api).allow(Surface::Mcp, id("slow"))).await;
    let alice = Principal::new("alice");
    let started = f
        .service
        .start(
            &alice,
            Surface::Mcp,
            &id("slow"),
            json!({}),
            Some("run".into()),
            live(),
        )
        .await
        .unwrap();
    let StartResult::Running { operation } = started else {
        panic!("expected a running operation, got {started:?}")
    };
    // Another adapter, another surface, the same caller: the running operation is visible.
    let view = f
        .service
        .operation(&alice, Surface::Api, &operation)
        .await
        .unwrap();
    assert_eq!(view.state(), &OperationState::Accepted);
    // Another caller cannot see it, and a surface that does not expose it cannot either.
    let bob = Principal::new("bob");
    assert_eq!(
        f.service
            .operation(&bob, Surface::Api, &operation)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    let only_mcp = fixture(Exposure::none().allow(Surface::Mcp, id("slow"))).await;
    assert_eq!(
        only_mcp
            .service
            .operation(&alice, Surface::Api, &operation)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    f.release.notify_one();
    let done = loop {
        let events = f
            .service
            .events_after(&alice, Surface::Api, &operation, 0)
            .await
            .unwrap();
        if events.len() == 2 {
            break events;
        }
        tokio::task::yield_now().await;
    };
    assert!(matches!(
        done[1].state,
        OperationState::Completed(Outcome::Success(_))
    ));
    assert_eq!(
        f.service
            .events_after(&alice, Surface::Api, &operation, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn starting_a_query_or_a_denied_request_finishes_immediately_with_a_typed_error() {
    let f = fixture(all(Surface::Api)).await;
    let alice = Principal::new("alice");
    let query = f
        .service
        .start(
            &alice,
            Surface::Api,
            &id("read"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(query.code, ErrorCode::BadRequest);
    let denied = f
        .service
        .start(
            &Principal::new("mallory"),
            Surface::Api,
            &id("slow"),
            json!({}),
            Some("k".into()),
            live(),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::Denied);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}
