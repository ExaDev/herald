//! Read-only check of Herald in front of a physical PiKVM or GLKVM through KVM's published client.
//!
//! Ignored by default, so CI and ordinary runs never touch hardware. Run it against a device you own:
//!
//!   HERALD_KVMD_ENDPOINT=https://device.example/ HERALD_KVMD_USER=... HERALD_KVMD_PASSWORD=... \
//!   [HERALD_KVMD_CA_FILE=/path/ca.pem] [HERALD_KVMD_PROFILE=glkvm] \
//!   cargo test --test live_device -- --ignored --nocapture
//!
//! It reads status and discovers capabilities only. It never sends a control, key or mouse event,
//! and it prints no credential.

use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use kvm_core::{Capability, Device, DeviceProfile};
use kvm_kvmd::{Config, Kvmd};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use url::Url;

struct Ports;
impl Authorizer for Ports {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { true })
    }
}
impl Confirmer for Ports {
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { false }) // a live read never needs confirmation, and nothing here may be confirmed
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

struct ReadStatus(Arc<Kvmd>);
impl Handler for ReadStatus {
    fn invoke<'a>(&'a self, _: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            match self.0.status().await {
                Ok(s) => {
                    Outcome::Success(json!({"info": s.info, "hid": s.hid, "streamer": s.streamer}))
                }
                Err(e) => Outcome::Error(json!({"error": e.to_string()})),
            }
        })
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to run this test against a device"))
}

#[tokio::test]
#[ignore = "touches a physical device: run it by hand with the HERALD_KVMD_* variables"]
async fn herald_reads_status_and_discovery_from_a_physical_device() {
    let profile = match std::env::var("HERALD_KVMD_PROFILE").as_deref() {
        Ok("glkvm") => DeviceProfile::GlKvm,
        _ => DeviceProfile::PiKvm,
    };
    let ca = std::env::var("HERALD_KVMD_CA_FILE")
        .ok()
        .map(|p| std::fs::read(p).expect("readable CA file"));
    let device = Arc::new(
        Kvmd::with_basic_auth(
            Config {
                endpoint: Url::parse(&env("HERALD_KVMD_ENDPOINT")).expect("a valid endpoint URL"),
                profile,
                trusted_ca_pem: ca,
                insecure_tls: false,
                timeout: Duration::from_secs(10),
            },
            &env("HERALD_KVMD_USER"),
            &env("HERALD_KVMD_PASSWORD"),
        )
        .expect("a client for the device"),
    );
    device
        .check_auth()
        .await
        .expect("the device accepts the credentials");

    // Discovery from the physical device decides what Herald will dispatch.
    let found = device.capabilities().await.expect("capability discovery");
    println!(
        "discovered: power={:?} switch={:?} gpio={:?} media={:?} mouse_mode={:?}",
        found.power, found.switch, found.gpio, found.media, found.mouse_mode
    );
    let support = |c: Capability| match c {
        Capability::Supported => Support::Supported,
        Capability::Unsupported => Support::Unsupported,
        Capability::Unknown => Support::Unknown,
    };
    let policy = Arc::new(Ports);
    let mut dispatcher = Dispatcher::new(policy.clone(), policy.clone(), policy.clone(), policy);
    let id = CapabilityId {
        name: "status".into(),
        version: 1,
    };
    dispatcher
        .register(
            Contract {
                id: id.clone(),
                kind: Kind::Query,
                input_schema: json!({"type":"object"}),
                output_schema: json!({"type":"object","required":["info","hid","streamer"]}),
                error_schema: json!({"type":"object"}),
                event_schema: json!(true),
                required_capabilities: vec![],
                confirmation_required: false,
                support: support(found.status),
            },
            Arc::new(ReadStatus(device)),
        )
        .unwrap();
    let (_cancel, signal) = cancellation();
    let outcome = dispatcher
        .dispatch(
            Request {
                capability: id,
                identity: "operator".into(),
                input: json!({}),
                confirmed: false,
            },
            signal,
        )
        .await;
    match outcome {
        Ok(Outcome::Success(status)) => {
            assert!(status["info"].is_object(), "the device reported its info");
            println!(
                "status read through Herald: ok ({} top-level fields)",
                status.as_object().map_or(0, |o| o.len())
            );
        }
        other => panic!("the live read failed: {other:?}"),
    }
}
