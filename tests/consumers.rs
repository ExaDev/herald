use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Policy;
impl Authorizer for Policy {
    fn authorize<'a>(&'a self, request: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { request.identity == "permitted" })
    }
}
impl Confirmer for Policy {
    fn confirm<'a>(&'a self, request: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { request.confirmed })
    }
}
struct TestClock;
impl Clock for TestClock {
    fn now(&self) -> u64 {
        42
    }
}
#[derive(Default)]
struct Audit(AtomicUsize);
impl Observer for Audit {
    fn finished(&self, _: &Request, at: u64, _: &Result<Outcome, DispatchError>) {
        assert_eq!(at, 42);
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
}
struct Device(Arc<AtomicUsize>);
impl Handler for Device {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Outcome::Unknown(json!({"reason":"device disconnected"}))
        })
    }
}
struct Service;
impl Handler for Service {
    fn invoke<'a>(&'a self, request: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move { Outcome::Success(request.input.clone()) })
    }
}
fn contract(
    name: &str,
    version: u32,
    confirmation_required: bool,
    input_schema: Value,
) -> Contract {
    Contract {
        id: CapabilityId {
            name: name.into(),
            version,
        },
        kind: Kind::Operation,
        input_schema,
        output_schema: json!({"type":"object"}),
        error_schema: json!({"type":"object"}),
        event_schema: json!({"type":"object"}),
        required_capabilities: vec![],
        confirmation_required,
        support: Support::Supported,
    }
}
fn request(name: &str, version: u32, input: Value) -> Request {
    Request {
        capability: CapabilityId {
            name: name.into(),
            version,
        },
        identity: "permitted".into(),
        input,
        confirmed: true,
    }
}
#[tokio::test]
async fn independent_device_and_service_observe_policy_validation_and_unknown_outcomes() {
    let audit = Arc::new(Audit::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = Dispatcher::new(
        Arc::new(Policy),
        Arc::new(Policy),
        Arc::new(TestClock),
        audit.clone(),
    );
    dispatcher
        .register(
            contract(
                "power",
                1,
                true,
                json!({"type":"object","required":["state"]}),
            ),
            Arc::new(Device(calls.clone())),
        )
        .unwrap();
    dispatcher
        .register(
            contract("status", 1, false, json!({"type":"object"})),
            Arc::new(Service),
        )
        .unwrap();
    assert_eq!(dispatcher.contracts().count(), 2);
    let (_, signal) = cancellation();
    let mut denied = request("power", 1, json!({"state":"on"}));
    denied.identity = "denied".into();
    assert_eq!(
        dispatcher.dispatch(denied, signal.clone()).await,
        Err(DispatchError::Denied)
    );
    let mut unconfirmed = request("power", 1, json!({"state":"on"}));
    unconfirmed.confirmed = false;
    assert_eq!(
        dispatcher.dispatch(unconfirmed, signal.clone()).await,
        Err(DispatchError::ConfirmationRequired)
    );
    assert!(matches!(
        dispatcher
            .dispatch(request("power", 1, json!({})), signal.clone())
            .await,
        Err(DispatchError::InvalidInput(_))
    ));
    assert_eq!(
        dispatcher
            .dispatch(request("status", 1, json!({"ready":true})), signal.clone())
            .await,
        Ok(Outcome::Success(json!({"ready":true})))
    );
    assert_eq!(
        dispatcher
            .dispatch(request("power", 1, json!({"state":"on"})), signal)
            .await,
        Ok(Outcome::Unknown(json!({"reason":"device disconnected"})))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(audit.0.load(Ordering::SeqCst), 5);
}
#[tokio::test]
async fn versions_are_independent_and_pre_cancelled_work_does_not_run() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut dispatcher = Dispatcher::new(
        Arc::new(Policy),
        Arc::new(Policy),
        Arc::new(TestClock),
        Arc::new(Audit::default()),
    );
    dispatcher
        .register(
            contract("power", 1, false, json!({"type":"object"})),
            Arc::new(Device(calls.clone())),
        )
        .unwrap();
    dispatcher
        .register(
            contract("power", 2, false, json!({"type":"string"})),
            Arc::new(Device(calls.clone())),
        )
        .unwrap();
    let (sender, signal) = cancellation();
    sender.send(true).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(request("power", 1, json!({})), signal)
            .await,
        Err(DispatchError::CancelledBeforeDispatch)
    );
    let (_, signal) = cancellation();
    assert!(matches!(
        dispatcher
            .dispatch(request("power", 2, json!({})), signal)
            .await,
        Err(DispatchError::InvalidInput(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
