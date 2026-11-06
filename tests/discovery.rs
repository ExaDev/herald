use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, SubscriptionHandler, Support,
    cancellation,
};
use serde_json::json;
use std::sync::Arc;

struct Ports;
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
    fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
}
impl Handler for Ports {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async { Outcome::Success(json!(null)) })
    }
}
impl SubscriptionHandler for Ports {
    fn subscribe<'a>(
        &'a self,
        _: &'a Request,
        _: Cancellation,
    ) -> PortFuture<
        'a,
        Result<
            tokio::sync::mpsc::Receiver<Result<serde_json::Value, serde_json::Value>>,
            serde_json::Value,
        >,
    > {
        Box::pin(async {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tx.send(Ok(json!(1))).await.unwrap();
            tx.send(Ok(json!("bad"))).await.unwrap();
            tx.send(Err(json!({"reason":"failed"}))).await.unwrap();
            tx.send(Err(json!("invalid"))).await.unwrap();
            Ok(rx)
        })
    }
}
#[tokio::test]
async fn subscription_events_are_validated() {
    let ports = Arc::new(Ports);
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
                error_schema: json!({"type":"object"}),
                event_schema: json!({"type":"integer"}),
                required_capabilities: vec![],
                confirmation_required: false,
                support: Support::Supported,
            },
            ports,
        )
        .unwrap();
    let (_sender, signal) = cancellation();
    let request = Request {
        capability: id.clone(),
        identity: "test".into(),
        input: json!(null),
        confirmed: false,
    };
    let mut subscription = dispatcher.subscribe(request, signal).await.unwrap();
    assert_eq!(subscription.recv().await, Some(Ok(json!(1))));
    assert!(matches!(
        subscription.recv().await,
        Some(Err(DispatchError::InvalidEvent(_)))
    ));
    assert_eq!(
        subscription.recv().await,
        Some(Err(DispatchError::SubscriptionSource(
            json!({"reason":"failed"})
        )))
    );
    assert!(matches!(
        subscription.recv().await,
        Some(Err(DispatchError::InvalidError(_)))
    ));
    assert_eq!(subscription.recv().await, None);
    assert_eq!(dispatcher.validate_event(&id, &json!(1)), Ok(()));
    assert!(matches!(
        dispatcher.validate_event(&id, &json!("bad")),
        Err(DispatchError::InvalidEvent(_))
    ));
}

#[tokio::test]
async fn discovery_preserves_support_and_denies_unavailable_operations() {
    let ports = Arc::new(Ports);
    let mut dispatcher =
        Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports.clone());
    for (name, support) in [
        ("yes", Support::Supported),
        ("no", Support::Unsupported),
        ("unknown", Support::Unknown),
    ] {
        dispatcher
            .register(
                Contract {
                    id: CapabilityId {
                        name: name.into(),
                        version: 1,
                    },
                    kind: Kind::Query,
                    input_schema: json!(true),
                    output_schema: json!(true),
                    error_schema: json!(true),
                    event_schema: json!(true),
                    required_capabilities: vec![],
                    confirmation_required: false,
                    support,
                },
                ports.clone(),
            )
            .unwrap();
    }
    let states: Vec<_> = dispatcher
        .contracts()
        .map(|c| (&*c.id.name, &c.support))
        .collect();
    assert_eq!(
        states,
        vec![
            ("no", &Support::Unsupported),
            ("unknown", &Support::Unknown),
            ("yes", &Support::Supported)
        ]
    );
    for (name, expected) in [
        ("no", Err(DispatchError::Unsupported)),
        ("unknown", Err(DispatchError::SupportUnknown)),
        ("yes", Ok(Outcome::Success(json!(null)))),
    ] {
        let (_sender, signal) = cancellation();
        let request = Request {
            capability: CapabilityId {
                name: name.into(),
                version: 1,
            },
            identity: "test".into(),
            input: json!(null),
            confirmed: false,
        };
        assert_eq!(dispatcher.dispatch(request, signal).await, expected);
    }
}
