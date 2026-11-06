use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Kind, Observer, Outcome, PortFuture, Request, SubscriptionHandler, Support, cancellation,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

struct Ports(Mutex<Vec<Result<(), DispatchError>>>);
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { true })
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
    fn subscription_opened(&self, _: &Request, _: u64, result: &Result<(), DispatchError>) {
        self.0.lock().unwrap().push(result.clone());
    }
}
impl SubscriptionHandler for Ports {
    fn subscribe<'a>(
        &'a self,
        _: &'a Request,
        _: Cancellation,
    ) -> PortFuture<'a, mpsc::Receiver<Result<Value, Value>>> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test]
async fn interrupted_subscription_setup_is_audited_as_unknown() {
    let ports = Arc::new(Ports(Mutex::new(vec![])));
    let mut dispatcher =
        Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    let id = CapabilityId {
        name: "events".into(),
        version: 1,
    };
    dispatcher
        .register_subscription(
            Contract {
                id: id.clone(),
                kind: Kind::Subscription,
                input_schema: json!(true),
                output_schema: json!(true),
                error_schema: json!(true),
                event_schema: json!(true),
                required_capabilities: vec![],
                confirmation_required: false,
                support: Support::Supported,
            },
            ports.clone(),
        )
        .unwrap();
    let (_sender, signal) = cancellation();
    let mut future = Box::pin(dispatcher.subscribe(
        Request {
            capability: id,
            identity: "test".into(),
            input: json!(null),
            confirmed: false,
        },
        signal,
    ));
    tokio::select! { _ = &mut future => panic!("setup unexpectedly completed"), _ = tokio::task::yield_now() => {} }
    drop(future);
    assert_eq!(
        *ports.0.lock().unwrap(),
        vec![Err(DispatchError::OutcomeLost)]
    );
}
