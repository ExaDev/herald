use async_trait::async_trait;
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use kvm_core::{
    Capabilities, Capability, Confirmation, Control, ControlOutcome, Device, DeviceStatus, Error,
    MouseMode, Snapshot, VideoStream,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Ports;
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, request: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { request.identity == "allowed" })
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
struct FakeDevice(AtomicUsize);
#[async_trait]
impl Device for FakeDevice {
    async fn video(&self) -> kvm_core::Result<Box<dyn VideoStream>> {
        Err(Error::Unsupported("video".into()))
    }
    async fn status(&self) -> kvm_core::Result<DeviceStatus> {
        Ok(DeviceStatus {
            info: json!({}),
            hid: json!({}),
            streamer: json!({}),
        })
    }
    async fn capabilities(&self) -> kvm_core::Result<Capabilities> {
        Ok(Capabilities {
            status: Capability::Supported,
            snapshot: Capability::Unsupported,
            keyboard: Capability::Unknown,
            mouse: Capability::Unknown,
            mouse_mode: MouseMode::Unknown,
            live_video: Capability::Unsupported,
            power: Capability::Supported,
            switch: Capability::Unknown,
            gpio: Capability::Unknown,
            media: Capability::Unknown,
        })
    }
    async fn snapshot(&self) -> kvm_core::Result<Snapshot> {
        Err(Error::Unsupported("snapshot".into()))
    }
    async fn key(&self, _: &str, _: bool) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn mouse_button(&self, _: &str, _: bool) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn mouse_move(&self, _: i16, _: i16) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn release_inputs(&self) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn control(&self, _: Control, _: Confirmation) -> kvm_core::Result<ControlOutcome> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::AmbiguousControl("lost response".into()))
    }
}
struct DeviceRead(Arc<FakeDevice>);
impl Handler for DeviceRead {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            let status = self.0.status().await.unwrap();
            Outcome::Success(serde_json::to_value(status).unwrap())
        })
    }
}
struct DeviceAdapter(Arc<FakeDevice>);
impl Handler for DeviceAdapter {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            match self
                .0
                .control(
                    Control::Power(kvm_core::PowerAction::On),
                    Confirmation::new(),
                )
                .await
            {
                Err(Error::AmbiguousControl(reason)) => Outcome::Unknown(json!({"reason": reason})),
                other => panic!("unexpected outcome: {other:?}"),
            }
        })
    }
}
/// A device whose control request is in flight until the test ends, standing in for a lost response.
struct StalledDevice {
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}
#[async_trait]
impl Device for StalledDevice {
    async fn video(&self) -> kvm_core::Result<Box<dyn VideoStream>> {
        Err(Error::Unsupported("video".into()))
    }
    async fn status(&self) -> kvm_core::Result<DeviceStatus> {
        Err(Error::Unsupported("status".into()))
    }
    async fn capabilities(&self) -> kvm_core::Result<Capabilities> {
        Err(Error::Unsupported("capabilities".into()))
    }
    async fn snapshot(&self) -> kvm_core::Result<Snapshot> {
        Err(Error::Unsupported("snapshot".into()))
    }
    async fn key(&self, _: &str, _: bool) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn mouse_button(&self, _: &str, _: bool) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn mouse_move(&self, _: i16, _: i16) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn release_inputs(&self) -> kvm_core::Result<()> {
        Ok(())
    }
    async fn control(&self, _: Control, _: Confirmation) -> kvm_core::Result<ControlOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        std::future::pending().await
    }
}
/// Reports a cancelled in-flight control as an unknown outcome, never as a failure or a retry.
struct CancellableControl(Arc<StalledDevice>);
impl Handler for CancellableControl {
    fn invoke<'a>(&'a self, _: &'a Request, mut cancel: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            tokio::select! {
                _ = self.0.control(Control::Power(kvm_core::PowerAction::On), Confirmation::new()) => {
                    panic!("stalled device unexpectedly answered")
                }
                () = cancel.cancelled() => Outcome::Unknown(json!({"reason": "cancelled after the request was sent"})),
            }
        })
    }
}
fn contract(name: &str) -> Contract {
    Contract {
        id: CapabilityId {
            name: name.into(),
            version: 1,
        },
        kind: Kind::Operation,
        input_schema: json!({"type":"object"}),
        output_schema: json!({"type":"object"}),
        error_schema: json!({"type":"object"}),
        event_schema: json!(true),
        required_capabilities: vec![],
        confirmation_required: true,
        support: Support::Supported,
    }
}
#[tokio::test]
async fn pinned_kvm_device_status_is_read_through_dispatch() {
    let device = Arc::new(FakeDevice(AtomicUsize::new(0)));
    let ports = Arc::new(Ports);
    let mut dispatcher = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports);
    let mut spec = contract("status");
    spec.kind = Kind::Query;
    spec.confirmation_required = false;
    let request = Request {
        capability: spec.id.clone(),
        identity: "allowed".into(),
        input: json!({}),
        confirmed: false,
    };
    dispatcher
        .register(spec, Arc::new(DeviceRead(device.clone())))
        .unwrap();
    let (_sender, signal) = cancellation();
    let expected = serde_json::to_value(device.status().await.unwrap()).unwrap();
    assert_eq!(
        dispatcher.dispatch(request, signal).await,
        Ok(Outcome::Success(expected))
    );
    assert_eq!(device.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pinned_kvm_device_preserves_ambiguous_control_without_retry() {
    let device = Arc::new(FakeDevice(AtomicUsize::new(0)));
    let ports = Arc::new(Ports);
    let mut dispatcher = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports);
    let spec = contract("power");
    let request = Request {
        capability: spec.id.clone(),
        identity: "allowed".into(),
        input: json!({}),
        confirmed: true,
    };
    dispatcher
        .register(spec, Arc::new(DeviceAdapter(device.clone())))
        .unwrap();
    let (_sender, signal) = cancellation();
    assert_eq!(
        dispatcher.dispatch(request, signal).await,
        Ok(Outcome::Unknown(json!({"reason":"lost response"})))
    );
    assert_eq!(device.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_an_in_flight_kvm_control_reports_unknown_without_retry() {
    let device = Arc::new(StalledDevice {
        calls: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
    });
    let ports = Arc::new(Ports);
    let mut dispatcher = Dispatcher::new(ports.clone(), ports.clone(), ports.clone(), ports);
    let spec = contract("power");
    let request = Request {
        capability: spec.id.clone(),
        identity: "allowed".into(),
        input: json!({}),
        confirmed: true,
    };
    dispatcher
        .register(spec, Arc::new(CancellableControl(device.clone())))
        .unwrap();
    let (sender, signal) = cancellation();
    let handle = Arc::new(dispatcher).start(request, signal);
    device.entered.notified().await;
    sender.send(true).unwrap();
    assert_eq!(
        handle.await.unwrap(),
        Ok(Outcome::Unknown(
            json!({"reason": "cancelled after the request was sent"})
        ))
    );
    assert_eq!(device.calls.load(Ordering::SeqCst), 1);
}
