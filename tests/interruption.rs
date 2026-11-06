use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use serde_json::json;
use std::sync::{Arc, Mutex};
struct Ports(Mutex<Vec<Result<Outcome, DispatchError>>>);
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
    fn finished(&self, _: &Request, _: u64, result: &Result<Outcome, DispatchError>) {
        self.0.lock().unwrap().push(result.clone());
    }
    fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
}
impl Handler for Ports {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(std::future::pending())
    }
}
struct Completion(tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>);
impl Handler for Completion {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            self.0.lock().await.take().unwrap().await.unwrap();
            Outcome::Success(json!(null))
        })
    }
}
#[tokio::test]
async fn detached_operation_finishes_after_caller_drops_handle() {
    let ports = Arc::new(Ports(Mutex::new(vec![])));
    let mut dispatcher =
        Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    let id = CapabilityId {
        name: "detached".into(),
        version: 1,
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    dispatcher
        .register(
            Contract {
                id: id.clone(),
                kind: Kind::Operation,
                input_schema: json!(true),
                output_schema: json!(true),
                error_schema: json!(true),
                event_schema: json!(true),
                required_capabilities: vec![],
                confirmation_required: false,
                support: Support::Supported,
            },
            Arc::new(Completion(tokio::sync::Mutex::new(Some(rx)))),
        )
        .unwrap();
    let (_sender, signal) = cancellation();
    let handle = Arc::new(dispatcher).start(
        Request {
            capability: id,
            identity: "test".into(),
            input: json!(null),
            confirmed: false,
        },
        signal,
    );
    drop(handle);
    tx.send(()).unwrap();
    for _ in 0..10 {
        if !ports.0.lock().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        *ports.0.lock().unwrap(),
        vec![Ok(Outcome::Success(json!(null)))]
    );
}

#[tokio::test]
async fn dropping_a_started_handler_reports_unknown_outcome() {
    let ports = Arc::new(Ports(Mutex::new(vec![])));
    let mut dispatcher =
        Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    let id = CapabilityId {
        name: "mutation".into(),
        version: 1,
    };
    dispatcher
        .register(
            Contract {
                id: id.clone(),
                kind: Kind::Operation,
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
    let mut future = Box::pin(dispatcher.dispatch(
        Request {
            capability: id,
            identity: "test".into(),
            input: json!(null),
            confirmed: false,
        },
        signal,
    ));
    tokio::select! { _ = &mut future => panic!("handler unexpectedly completed"), _ = tokio::task::yield_now() => {} }
    drop(future);
    assert_eq!(
        *ports.0.lock().unwrap(),
        vec![Err(DispatchError::OutcomeLost)]
    );
}
