//! Herald in front of KVM's real `Kvmd` client. The client is an independent implementation of the
//! pinned `Device` contract: it authenticates, discovers capabilities over HTTP and reports an
//! unconfirmed control as an ambiguous outcome. A local HTTPS server stands in for the device and
//! counts every request, so each test can assert what reached the hardware.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri, header},
    response::IntoResponse,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use herald::runtime::{MemoryOperationStore, Runtime};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support, cancellation,
};
use kvm_core::{
    Capability, Confirmation, Control, ControlOutcome, Device, DeviceProfile, Error, PowerAction,
};
use kvm_kvmd::{Config, Kvmd};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use url::Url;

const BASIC: &str = "Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=";

#[derive(Clone, Copy, PartialEq)]
enum Post {
    Succeed,
    Fail,
    Hang,
}

struct Device_ {
    posts: AtomicUsize,
    unauthorised: AtomicUsize,
    power_led: AtomicBool,
    mode: Mutex<Post>,
}
type Shared = Arc<Device_>;

fn authorised(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(BASIC)
}
fn reply(state: &Shared, headers: &HeaderMap, result: Value) -> (StatusCode, Json<Value>) {
    if !authorised(headers) {
        state.unauthorised.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "result": {}})),
        );
    }
    (StatusCode::OK, Json(json!({"ok": true, "result": result})))
}
async fn check(State(s): State<Shared>, h: HeaderMap) -> impl IntoResponse {
    reply(&s, &h, json!({}))
}
async fn info(State(s): State<Shared>, h: HeaderMap, uri: Uri) -> impl IntoResponse {
    let result = if uri.path().ends_with("/hid") {
        json!({"enabled": true, "online": true,
               "keyboard": {"online": true, "outputs": {"available": [], "active": ""}},
               "mouse": {"online": true, "absolute": true, "outputs": {"available": [], "active": ""}}})
    } else {
        json!({"online": true})
    };
    reply(&s, &h, result)
}
async fn atx(State(s): State<Shared>, h: HeaderMap) -> impl IntoResponse {
    let led = s.power_led.load(Ordering::SeqCst);
    reply(&s, &h, json!({"enabled": true, "leds": {"power": led}}))
}
async fn gpio(State(s): State<Shared>, h: HeaderMap) -> impl IntoResponse {
    // No `outputs` object: the client cannot tell whether GPIO exists, so it reports Unknown.
    reply(&s, &h, json!({"state": {}}))
}
async fn msd(State(s): State<Shared>, h: HeaderMap) -> impl IntoResponse {
    reply(&s, &h, json!({"enabled": false}))
}
async fn switch_absent() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
async fn power(State(s): State<Shared>, h: HeaderMap, uri: Uri) -> impl IntoResponse {
    s.posts.fetch_add(1, Ordering::SeqCst);
    let mode = *s.mode.lock().unwrap();
    match mode {
        Post::Hang => std::future::pending::<()>().await,
        Post::Fail => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false})),
            );
        }
        Post::Succeed => {}
    }
    let on = uri.query().is_some_and(|q| q.contains("action=on"));
    s.power_led.store(on, Ordering::SeqCst);
    reply(&s, &h, json!({}))
}

struct Server {
    endpoint: Url,
    ca: Vec<u8>,
    state: Shared,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve() -> Server {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let ca = certified.cert.pem().into_bytes();
    let key = certified.key_pair.serialize_pem().into_bytes();
    let tls = RustlsConfig::from_pem(ca.clone(), key).await.unwrap();
    let state: Shared = Arc::new(Device_ {
        posts: AtomicUsize::new(0),
        unauthorised: AtomicUsize::new(0),
        power_led: AtomicBool::new(false),
        mode: Mutex::new(Post::Succeed),
    });
    let app = Router::new()
        .route("/api/auth/check", get(check))
        .route("/api/info", get(info))
        .route("/api/hid", get(info))
        .route("/api/streamer", get(info))
        .route("/api/atx", get(atx))
        .route("/api/gpio", get(gpio))
        .route("/api/msd", get(msd))
        .route("/api/switch", get(switch_absent))
        .route("/api/atx/power", post(power))
        .with_state(state.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    Server {
        endpoint: Url::parse(&format!("https://localhost:{port}/")).unwrap(),
        ca,
        state,
        task,
    }
}

fn kvmd(server: &Server, password: &str) -> Arc<Kvmd> {
    Arc::new(
        Kvmd::with_basic_auth(
            Config {
                endpoint: server.endpoint.clone(),
                profile: DeviceProfile::PiKvm,
                trusted_ca_pem: Some(server.ca.clone()),
                insecure_tls: false,
                timeout: Duration::from_secs(5),
            },
            "test-user",
            password,
        )
        .unwrap(),
    )
}

/// Product policy ports. The device is the independent part; policy is the product's.
struct Policy {
    authorise: AtomicBool,
    confirm: AtomicBool,
}
impl Policy {
    fn new(authorise: bool, confirm: bool) -> Arc<Self> {
        Arc::new(Self {
            authorise: AtomicBool::new(authorise),
            confirm: AtomicBool::new(confirm),
        })
    }
}
impl Authorizer for Policy {
    fn authorize<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.authorise.load(Ordering::SeqCst) })
    }
}
impl Confirmer for Policy {
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { self.confirm.load(Ordering::SeqCst) })
    }
}
impl Clock for Policy {
    fn now(&self) -> u64 {
        0
    }
}
impl Observer for Policy {
    fn finished(&self, _: &Request, _: u64, _: &Result<Outcome, DispatchError>) {}
    fn subscription_opened(&self, _: &Request, _: u64, _: &Result<(), DispatchError>) {}
}

/// Reads device status through the real client.
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

/// Switches power on through the real client. An unconfirmed control is an unknown outcome, never a
/// failure to retry. Cancellation after the request is sent is reported the same way.
struct PowerOn(Arc<Kvmd>);
impl Handler for PowerOn {
    fn invoke<'a>(&'a self, _: &'a Request, mut cancel: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            let control = self
                .0
                .control(Control::Power(PowerAction::On), Confirmation::new());
            tokio::select! {
                result = control => match result {
                    Ok(ControlOutcome::ObservedMatching) => Outcome::Success(json!({"observed": "matching"})),
                    Ok(ControlOutcome::Unverified) => Outcome::Success(json!({"observed": "unverified"})),
                    Err(Error::AmbiguousControl(reason)) => Outcome::Unknown(json!({"reason": reason})),
                    Err(other) => Outcome::Error(json!({"error": other.to_string()})),
                },
                () = cancel.cancelled() => Outcome::Unknown(json!({"reason": "cancelled after the request was sent"})),
            }
        })
    }
}

fn cap(name: &str) -> CapabilityId {
    CapabilityId {
        name: name.into(),
        version: 1,
    }
}
fn contract(name: &str, kind: Kind, confirmation: bool, support: Support) -> Contract {
    Contract {
        id: cap(name),
        kind,
        input_schema: json!({"type":"object"}),
        output_schema: json!({"type":"object"}),
        error_schema: json!({"type":"object"}),
        event_schema: json!(true),
        required_capabilities: vec![],
        confirmation_required: confirmation,
        support,
    }
}
fn request(name: &str) -> Request {
    Request {
        capability: cap(name),
        identity: "operator".into(),
        input: json!({}),
        confirmed: false,
    }
}
fn support_of(c: Capability) -> Support {
    match c {
        Capability::Supported => Support::Supported,
        Capability::Unsupported => Support::Unsupported,
        Capability::Unknown => Support::Unknown,
    }
}
fn live() -> Cancellation {
    cancellation().1
}
fn dispatcher(policy: &Arc<Policy>, device: &Arc<Kvmd>, power: Support) -> Dispatcher {
    let mut d = Dispatcher::new(
        policy.clone(),
        policy.clone(),
        policy.clone(),
        policy.clone(),
    );
    d.register(
        contract("status", Kind::Query, false, Support::Supported),
        Arc::new(ReadStatus(device.clone())),
    )
    .unwrap();
    d.register(
        contract("power", Kind::Operation, true, power),
        Arc::new(PowerOn(device.clone())),
    )
    .unwrap();
    d
}

#[tokio::test]
async fn a_status_read_reaches_the_authenticated_device_and_a_bad_password_does_not() {
    let server = serve().await;
    let policy = Policy::new(true, true);
    let good = dispatcher(&policy, &kvmd(&server, "test-password"), Support::Supported);
    match good.dispatch(request("status"), live()).await {
        Ok(Outcome::Success(v)) => assert_eq!(v["streamer"]["online"], true),
        other => panic!("expected the device status, got {other:?}"),
    }
    let bad = dispatcher(&policy, &kvmd(&server, "wrong"), Support::Supported);
    assert!(matches!(
        bad.dispatch(request("status"), live()).await,
        Ok(Outcome::Error(_))
    ));
    assert!(
        server.state.unauthorised.load(Ordering::SeqCst) > 0,
        "the device refused the credentials"
    );
}

#[tokio::test]
async fn product_authorisation_and_confirmation_stop_a_control_before_it_reaches_the_device() {
    let server = serve().await;
    let device = kvmd(&server, "test-password");
    let denied = Policy::new(false, true);
    assert_eq!(
        dispatcher(&denied, &device, Support::Supported)
            .dispatch(request("power"), live())
            .await,
        Err(DispatchError::Denied)
    );
    let unconfirmed = Policy::new(true, false);
    let mut claimed = request("power");
    claimed.confirmed = true; // a caller's claim is not consent
    assert_eq!(
        dispatcher(&unconfirmed, &device, Support::Supported)
            .dispatch(claimed, live())
            .await,
        Err(DispatchError::ConfirmationRequired)
    );
    assert_eq!(
        server.state.posts.load(Ordering::SeqCst),
        0,
        "nothing reached the device"
    );
    let allowed = Policy::new(true, true);
    assert_eq!(
        dispatcher(&allowed, &device, Support::Supported)
            .dispatch(request("power"), live())
            .await,
        Ok(Outcome::Success(json!({"observed": "matching"})))
    );
    assert_eq!(server.state.posts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn capability_discovery_from_the_real_client_drives_supported_unsupported_and_unknown() {
    let server = serve().await;
    let device = kvmd(&server, "test-password");
    let found = device.capabilities().await.unwrap();
    assert_eq!(
        (found.power, found.switch, found.gpio, found.media),
        (
            Capability::Supported,
            Capability::Unsupported,
            Capability::Unknown,
            Capability::Unsupported
        )
    );
    let policy = Policy::new(true, true);
    let mut d = Dispatcher::new(
        policy.clone(),
        policy.clone(),
        policy.clone(),
        policy.clone(),
    );
    for (name, support) in [
        ("power", support_of(found.power)),
        ("switch", support_of(found.switch)),
        ("gpio", support_of(found.gpio)),
    ] {
        d.register(
            contract(name, Kind::Operation, false, support),
            Arc::new(PowerOn(device.clone())),
        )
        .unwrap();
    }
    let listed: Vec<_> = d
        .contracts()
        .map(|c| (c.id.name.clone(), c.support.clone()))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("gpio".to_string(), Support::Unknown),
            ("power".to_string(), Support::Supported),
            ("switch".to_string(), Support::Unsupported),
        ]
    );
    assert_eq!(
        d.dispatch(request("switch"), live()).await,
        Err(DispatchError::Unsupported)
    );
    assert_eq!(
        d.dispatch(request("gpio"), live()).await,
        Err(DispatchError::SupportUnknown)
    );
    assert_eq!(
        server.state.posts.load(Ordering::SeqCst),
        0,
        "absence is not denial, and neither reached the device"
    );
}

#[tokio::test]
async fn an_unconfirmed_control_is_an_unknown_outcome_and_a_keyed_retry_never_reposts() {
    let server = serve().await;
    *server.state.mode.lock().unwrap() = Post::Fail;
    let policy = Policy::new(true, true);
    let dispatcher = Arc::new(dispatcher(
        &policy,
        &kvmd(&server, "test-password"),
        Support::Supported,
    ));
    let (runtime, _) = Runtime::open(dispatcher, Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    let first = runtime
        .submit(request("power"), "retry-me".into(), live())
        .await;
    match &first.result {
        Ok(Outcome::Unknown(v)) => assert!(v["reason"].as_str().is_some()),
        other => panic!("expected an unknown outcome, got {other:?}"),
    }
    assert_eq!(server.state.posts.load(Ordering::SeqCst), 1);
    // The device recovers, and the client retries with the same key.
    *server.state.mode.lock().unwrap() = Post::Succeed;
    let retry = runtime
        .submit(request("power"), "retry-me".into(), live())
        .await;
    assert_eq!(
        retry.result, first.result,
        "the recorded unknown outcome is replayed"
    );
    assert_eq!(
        server.state.posts.load(Ordering::SeqCst),
        1,
        "no second POST reached the device"
    );
}

#[tokio::test]
async fn cancelling_a_control_the_device_never_answers_reports_unknown_after_one_post() {
    let server = serve().await;
    *server.state.mode.lock().unwrap() = Post::Hang;
    let policy = Policy::new(true, true);
    let dispatcher = Arc::new(dispatcher(
        &policy,
        &kvmd(&server, "test-password"),
        Support::Supported,
    ));
    let (cancel, signal) = cancellation();
    let handle = dispatcher.start(request("power"), signal);
    while server.state.posts.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cancel.send(true).unwrap();
    assert_eq!(
        handle.await.unwrap(),
        Ok(Outcome::Unknown(
            json!({"reason": "cancelled after the request was sent"})
        ))
    );
    assert_eq!(server.state.posts.load(Ordering::SeqCst), 1);
}
