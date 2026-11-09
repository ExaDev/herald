//! The HTTP API over a real socket, driven by `reqwest`, plus the parity and cross-adapter checks against the MCP adapter over the same service.

use axum::http::{HeaderMap, header};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support,
    exposure::{Exposure, Surface},
    runtime::{MemoryOperationStore, RunningLimit, Runtime, StoreBounds},
    service::{Principal, Service},
};
use herald_boundary::{Authentication, Authenticator, Boundary, Limits, OriginPolicy};
use herald_mcp::{HeraldMcp, rmcp};
use reqwest::{Client, Method, StatusCode};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

/// Generous limits: these suites test behaviour, not load.
fn limits() -> Limits {
    Limits::new(Duration::from_secs(60), 64, 64).unwrap()
}

const ORIGIN: &str = "https://app.example.test";

struct Policy;
impl Authorizer for Policy {
    fn authorize<'a>(&'a self, r: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { ["alice", "bob"].contains(&r.identity.as_str()) })
    }
}
impl Confirmer for Policy {
    // Only a capability that requires confirmation asks, and the product never gives it.
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { false })
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
#[derive(Clone, Copy)]
enum Behaviour {
    Succeed,
    Fail,
    Doubt,
    /// Waits only for the release and never looks at its cancellation, like a handler that cannot be interrupted.
    Stubborn,
    /// Never returns and ignores its cancellation, like a query waiting on a dead backend.
    Stuck,
    Panic,
    /// A response that breaks the capability's output schema.
    Invalid,
}
struct Work {
    calls: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    release: Option<Arc<Notify>>,
    behaviour: Behaviour,
}
impl Handler for Work {
    fn invoke<'a>(&'a self, r: &'a Request, mut cancel: Cancellation) -> PortFuture<'a, Outcome> {
        if matches!(self.behaviour, Behaviour::Stuck) {
            drop(cancel);
            return Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
                Outcome::Success(json!({}))
            });
        }
        if matches!(self.behaviour, Behaviour::Stubborn) {
            // A handler that cannot be interrupted does not even keep the cancellation it is given: it is dropped as this function returns, before the future below runs.
            drop(cancel);
            return Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(release) = &self.release {
                    release.notified().await;
                }
                Outcome::Success(json!({"caller": r.identity, "input": r.input}))
            });
        }
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(release) = &self.release {
                tokio::select! {
                    () = release.notified() => {}
                    () = cancel.cancelled() => {
                        self.cancelled.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            let body = json!({"caller": r.identity, "input": r.input});
            match self.behaviour {
                Behaviour::Succeed | Behaviour::Stubborn | Behaviour::Stuck => {
                    Outcome::Success(body)
                }
                Behaviour::Fail => Outcome::Error(body),
                Behaviour::Doubt => Outcome::Unknown(body),
                Behaviour::Panic => panic!("handler failure"),
                Behaviour::Invalid => Outcome::Success(json!(5)),
            }
        })
    }
}
struct Tokens;
impl Authenticator for Tokens {
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Authentication> {
        Box::pin(async move {
            let principal: Option<Principal> =
                (|| match headers.get(header::AUTHORIZATION)?.to_str().ok()? {
                    "Bearer alice-token" => Principal::new("alice").ok(),
                    "Bearer bob-token" => Principal::new("bob").ok(),
                    "Bearer mallory-token" => Principal::new("mallory").ok(),
                    _ => None,
                })();
            principal.into()
        })
    }
}

fn id(name: &str) -> CapabilityId {
    CapabilityId {
        name: name.into(),
        version: 1,
    }
}
fn contract(name: &str, kind: Kind) -> Contract {
    Contract {
        id: id(name),
        kind,
        input_schema: json!({"type":"object","properties":{"x":{"type":"integer"}},"additionalProperties":false}),
        output_schema: json!({"type":"object"}),
        error_schema: json!({"type":"object"}),
        event_schema: json!(true),
        required_capabilities: vec![],
        confirmation_required: false,
        support: Support::Supported,
    }
}

struct World {
    service: Arc<Service>,
    calls: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    release: Arc<Notify>,
    base: String,
    client: Client,
    _server: tokio::task::JoinHandle<()>,
}
async fn world() -> World {
    world_with(None, limits()).await
}

/// Records one caller may hold in these suites, far above the few keys any test submits.
const ROOMY_RECORDS: usize = 1_000;
/// A retention the fixed clock never reaches, so no record is dropped while a test runs.
const ROOMY_RETENTION: u64 = 1;

/// A store whose bounds these suites do not reach.
fn roomy_store() -> Arc<MemoryOperationStore> {
    Arc::new(MemoryOperationStore::bounded(
        StoreBounds::new(ROOMY_RECORDS, ROOMY_RETENTION).unwrap(),
        Arc::new(Policy),
    ))
}

/// A running limit generous enough that these suites test behaviour, not the limit.
fn roomy_running_limit() -> RunningLimit {
    RunningLimit::new(64, 64, Duration::from_secs(600)).unwrap()
}

/// A world whose runtime and boundary are bounded as stated, to test the limits themselves.
async fn world_with(running: Option<RunningLimit>, boundary_limits: Limits) -> World {
    let policy = Arc::new(Policy);
    let (calls, release) = (Arc::new(AtomicUsize::new(0)), Arc::new(Notify::new()));
    let cancelled = Arc::new(AtomicUsize::new(0));
    let mut d = Dispatcher::new(policy.clone(), policy.clone(), policy.clone(), policy);
    for (name, kind, wait, behaviour) in [
        ("read", Kind::Query, false, Behaviour::Succeed),
        ("write", Kind::Operation, false, Behaviour::Succeed),
        ("slow", Kind::Operation, true, Behaviour::Succeed),
        ("hang", Kind::Query, true, Behaviour::Succeed),
        ("fails", Kind::Operation, false, Behaviour::Fail),
        ("doubts", Kind::Operation, false, Behaviour::Doubt),
        ("stubborn", Kind::Query, true, Behaviour::Stubborn),
        ("stuck", Kind::Query, false, Behaviour::Stuck),
        ("panics", Kind::Operation, false, Behaviour::Panic),
        ("panicq", Kind::Query, false, Behaviour::Panic),
        ("invalid", Kind::Operation, false, Behaviour::Invalid),
        ("confirms", Kind::Operation, false, Behaviour::Succeed),
        ("unsupported", Kind::Query, false, Behaviour::Succeed),
        ("unsure", Kind::Query, false, Behaviour::Succeed),
        ("scalar", Kind::Query, false, Behaviour::Succeed),
        ("wide", Kind::Operation, false, Behaviour::Succeed),
    ] {
        let mut contract = contract(name, kind);
        match name {
            "confirms" => contract.confirmation_required = true,
            "unsupported" => contract.support = Support::Unsupported,
            "unsure" => contract.support = Support::Unknown,
            // A query whose input is not an object cannot be an MCP tool's arguments.
            "scalar" => contract.input_schema = json!({"type": "integer"}),
            // Accepts any object, so a test can send an input of exactly the largest size.
            "wide" => contract.input_schema = json!({"type": "object"}),
            _ => {}
        }
        d.register(
            contract,
            Arc::new(Work {
                calls: calls.clone(),
                cancelled: cancelled.clone(),
                release: wait.then(|| release.clone()),
                behaviour,
            }),
        )
        .unwrap();
    }
    let d = Arc::new(d);
    let store = roomy_store();
    let (runtime, _) = match running {
        Some(limit) => Runtime::open_limited(d.clone(), store, limit).await,
        None => Runtime::open_limited(d.clone(), store, roomy_running_limit()).await,
    }
    .unwrap();
    // Exposed on both surfaces, so parity can be checked against the MCP adapter.
    let exposure = [
        "read",
        "write",
        "slow",
        "hang",
        "fails",
        "doubts",
        "stubborn",
        "stuck",
        "panics",
        "panicq",
        "invalid",
        "confirms",
        "unsupported",
        "unsure",
        "scalar",
        "wide",
    ]
    .into_iter()
    .fold(Exposure::none(), |e, n| {
        e.allow(Surface::Api, id(n)).allow(Surface::Mcp, id(n))
    });
    let service = Arc::new(Service::new(Arc::new(runtime), exposure));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin_policy =
        OriginPolicy::new([format!("127.0.0.1:{port}")], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), origin_policy, boundary_limits).unwrap();
    let app = herald_http::router(service.clone(), boundary).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    World {
        service,
        calls,
        cancelled,
        release,
        base: format!("http://127.0.0.1:{port}/v1"),
        client: Client::new(),
        _server: server,
    }
}

async fn mcp_client(
    w: &World,
    identity: &str,
) -> rmcp::service::RunningService<rmcp::service::RoleClient, ()> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let handler = HeraldMcp::stdio(w.service.clone(), Principal::new(identity).unwrap());
    tokio::spawn(async move {
        let _ = handler.serve(server_io).await.unwrap().waiting().await;
    });
    ().serve(client_io).await.unwrap()
}

/// Polls `condition` until it holds. The bound is a backstop so a failure reports instead of hanging; every caller waits on an event another task will cause.
async fn wait_until(condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the awaited event happened");
}

struct Reply {
    status: StatusCode,
    body: Value,
}
impl World {
    async fn send(
        &self,
        token: Option<&str>,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Reply {
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        Reply {
            status,
            body: response.json().await.unwrap_or(Value::Null),
        }
    }
    async fn post(&self, token: &str, path: &str, body: Value) -> Reply {
        self.send(Some(token), Method::POST, path, Some(body)).await
    }
    async fn get(&self, token: &str, path: &str) -> Reply {
        self.send(Some(token), Method::GET, path, None).await
    }
}
fn code(reply: &Reply) -> &str {
    reply.body["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("not a typed error: {}", reply.body))
}

#[tokio::test]
async fn a_query_and_an_operation_round_trip_with_replay_and_conflict() {
    let w = world().await;
    let read = w
        .post(
            "alice-token",
            "/capabilities/read/1/call",
            json!({"input": {"x": 1}}),
        )
        .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["outcome"]["Success"]["caller"], "alice");
    let key = json!({"input": {"x": 1}, "idempotency_key": "k"});
    let first = w
        .post("alice-token", "/capabilities/write/1/call", key.clone())
        .await;
    let again = w
        .post("alice-token", "/capabilities/write/1/call", key)
        .await;
    assert_eq!((first.status, &first.body), (StatusCode::OK, &again.body));
    let clash = w
        .post(
            "alice-token",
            "/capabilities/write/1/call",
            json!({"input": {"x": 2}, "idempotency_key": "k"}),
        )
        .await;
    assert_eq!(
        (clash.status, code(&clash)),
        (StatusCode::CONFLICT, "key_conflict")
    );
    assert_eq!(w.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn every_failure_is_a_typed_json_error_with_the_right_status() {
    let w = world().await;
    let cases: Vec<(Reply, StatusCode, &str)> = vec![
        (
            w.send(None, Method::GET, "/capabilities", None).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        ),
        (
            w.get("wrong-token", "/capabilities").await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        ),
        (
            w.post(
                "alice-token",
                "/capabilities/read/1/call",
                json!({"input": "no"}),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_input",
        ),
        (
            w.post(
                "alice-token",
                "/capabilities/write/1/call",
                json!({"input": {}}),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            w.post(
                "alice-token",
                "/capabilities/nothing/1/call",
                json!({"input": {}}),
            )
            .await,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            w.post(
                "alice-token",
                "/capabilities/read/1/call",
                json!({"input": {}, "extra": 1}),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            w.get("alice-token", "/nowhere").await,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            w.get("alice-token", "/capabilities/read/1/call").await,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        ),
        (
            w.get("alice-token", "/operations/op-missing").await,
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ];
    for (reply, status, expected) in cases {
        assert_eq!(
            (reply.status, code(&reply)),
            (status, expected),
            "{}",
            reply.body
        );
    }
    // A body that is not JSON at all is a typed error too, and its text is not echoed back.
    let garbage = w
        .client
        .post(format!("{}/capabilities/read/1/call", w.base))
        .header("authorization", "Bearer alice-token")
        .header("content-type", "application/json")
        .body("{not json SECRET-TEXT")
        .send()
        .await
        .unwrap();
    assert_eq!(garbage.status(), StatusCode::BAD_REQUEST);
    let text = garbage.text().await.unwrap();
    assert!(
        text.contains("bad_request") && !text.contains("SECRET-TEXT"),
        "{text}"
    );
    assert_eq!(w.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unauthorised_caller_sees_nothing_and_every_call_looks_unknown() {
    let w = world().await;
    assert_eq!(
        w.get("mallory-token", "/capabilities").await.body["capabilities"],
        json!([])
    );
    let unknown = w
        .post(
            "mallory-token",
            "/capabilities/nothing/1/call",
            json!({"input": {}}),
        )
        .await;
    for (name, body) in [
        ("read", json!({"input": {}})),
        ("write", json!({"input": {}})),
        ("write", json!({"input": {}, "idempotency_key": "k"})),
    ] {
        for verb in ["call", "start"] {
            let denied = w
                .post(
                    "mallory-token",
                    &format!("/capabilities/{name}/1/{verb}"),
                    body.clone(),
                )
                .await;
            let unknown = w
                .post(
                    "mallory-token",
                    &format!("/capabilities/nothing/1/{verb}"),
                    body.clone(),
                )
                .await;
            assert_eq!(
                (denied.status, &denied.body),
                (unknown.status, &unknown.body),
                "{name} {verb}"
            );
        }
    }
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(w.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_boundary_refuses_a_foreign_origin_and_host_and_serves_a_listed_origin() {
    let w = world().await;
    for origin in ["https://evil.example", "null"] {
        let r = w
            .client
            .get(format!("{}/capabilities", w.base))
            .header("authorization", "Bearer alice-token")
            .header("origin", origin)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{origin}");
        assert!(r.text().await.unwrap().contains("forbidden_origin"));
    }
    let listed = w
        .client
        .get(format!("{}/capabilities", w.base))
        .header("authorization", "Bearer alice-token")
        .header("origin", ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let rebound = w
        .client
        .get(format!("{}/capabilities", w.base))
        .header("authorization", "Bearer alice-token")
        .header("host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_started_operation_is_followed_by_id_and_other_callers_cannot_see_it() {
    let w = world().await;
    let started = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "run"}),
        )
        .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let operation = started.body["operation"].as_str().unwrap().to_owned();
    let again = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "run"}),
        )
        .await;
    assert_eq!(
        (again.status, again.body["operation"].as_str().unwrap()),
        (StatusCode::ACCEPTED, operation.as_str())
    );
    let waited = w
        .post(
            "alice-token",
            "/capabilities/slow/1/call",
            json!({"input": {}, "idempotency_key": "run"}),
        )
        .await;
    assert_eq!(
        (waited.status, code(&waited)),
        (StatusCode::CONFLICT, "in_progress")
    );
    assert_eq!(
        code(
            &w.get("bob-token", &format!("/operations/{operation}"))
                .await
        ),
        "not_found"
    );
    w.release.notify_one();
    let events = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let r = w
                .get(
                    "alice-token",
                    &format!("/operations/{operation}/events?cursor=0"),
                )
                .await;
            let events = r.body["events"].as_array().unwrap().clone();
            if events.len() == 2 {
                return events;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed");
    assert_eq!(
        events[1]["state"]["Completed"]["Success"]["caller"],
        "alice"
    );
    assert_eq!(
        w.get(
            "alice-token",
            &format!("/operations/{operation}/events?cursor=1")
        )
        .await
        .body["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(w.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_operation_started_over_mcp_is_followed_over_http_and_the_two_agree() {
    let w = world().await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let handler = HeraldMcp::stdio(w.service.clone(), Principal::new("alice").unwrap());
    tokio::spawn(async move {
        let _ = handler.serve(server_io).await.unwrap().waiting().await;
    });
    let mcp = ().serve(client_io).await.unwrap();
    let arguments = json!({"idempotency_key": "x", "input": {}, "detach": true})
        .as_object()
        .cloned()
        .unwrap();
    let started = mcp
        .call_tool(CallToolRequestParams::new("slow.v1".to_string()).with_arguments(arguments))
        .await
        .unwrap();
    let operation = started.structured_content.unwrap()["operation"]
        .as_str()
        .unwrap()
        .to_owned();
    // HTTP, authenticated as the same caller, follows what MCP started.
    let view = w
        .get("alice-token", &format!("/operations/{operation}"))
        .await;
    assert_eq!(view.status, StatusCode::OK);
    assert_eq!(view.body["events"].as_array().unwrap().len(), 1);
    w.release.notify_one();
    // And the same query gives the same outcome on both adapters.
    let over_http = w
        .post(
            "alice-token",
            "/capabilities/read/1/call",
            json!({"input": {"x": 3}}),
        )
        .await;
    let over_mcp = mcp
        .call_tool(
            CallToolRequestParams::new("read.v1".to_string())
                .with_arguments(json!({"x": 3}).as_object().cloned().unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(over_http.body, over_mcp.structured_content.unwrap());
}

/// The component a `{"$ref": "#/components/schemas/<name>"}` points at.
fn component<'a>(doc: &'a Value, reference: &Value) -> &'a Value {
    let name = reference["$ref"]
        .as_str()
        .and_then(|r| r.strip_prefix("#/components/schemas/"))
        .unwrap_or_else(|| panic!("not a component reference: {reference}"));
    &doc["components"]["schemas"][name]
}

#[tokio::test]
async fn the_openapi_document_is_generated_for_the_caller_from_the_contracts() {
    let w = world().await;
    let doc = w.get("alice-token", "/openapi.json").await.body;
    assert_eq!(doc["openapi"], "3.1.0");
    let call = &doc["paths"]["/v1/capabilities/write/1/call"]["post"];
    let input =
        &call["requestBody"]["content"]["application/json"]["schema"]["properties"]["input"];
    assert_eq!(component(&doc, input)["properties"]["x"]["type"], "integer");
    assert_eq!(call["operationId"], "call_write_v1");
    assert!(
        doc["paths"]["/v1/capabilities/write/1/start"].is_object(),
        "an operation can be started"
    );
    assert!(
        doc["paths"]["/v1/capabilities/read/1/start"].is_null(),
        "a query cannot"
    );
    assert!(doc["paths"]["/v1/operations/{id}/events"].is_object());
    // The document lists exactly what the caller may use, so an unauthorised caller's has no capabilities.
    let hidden = w.get("mallory-token", "/openapi.json").await.body;
    assert!(
        hidden["paths"]
            .as_object()
            .unwrap()
            .keys()
            .all(|p| !p.starts_with("/v1/capabilities/")),
        "no capability path for a caller who may use none"
    );
}

#[tokio::test]
async fn error_and_unknown_outcomes_are_reported_in_a_200_with_their_flags() {
    let w = world().await;
    let failed = w
        .post(
            "alice-token",
            "/capabilities/fails/1/call",
            json!({"input": {}, "idempotency_key": "f"}),
        )
        .await;
    assert_eq!(failed.status, StatusCode::OK);
    assert_eq!(failed.body["failed"], true);
    assert!(failed.body["outcome"]["Error"].is_object());
    let doubted = w
        .post(
            "alice-token",
            "/capabilities/doubts/1/call",
            json!({"input": {}, "idempotency_key": "d"}),
        )
        .await;
    assert_eq!(doubted.status, StatusCode::OK);
    assert_eq!(doubted.body["uncertain"], true);
    assert!(doubted.body["outcome"]["Unknown"].is_object());
}

#[tokio::test]
async fn malformed_requests_get_typed_errors_that_do_not_depend_on_the_capability() {
    let w = world().await;
    let raw = |path: &'static str, token: &'static str| {
        w.client
            .post(format!("{}{path}", w.base))
            .header("authorization", format!("Bearer {token}"))
    };
    // Not JSON: a typed 415, whatever the capability.
    for path in ["/capabilities/read/1/call", "/capabilities/nothing/1/call"] {
        let r = raw(path, "mallory-token")
            .header("content-type", "text/plain")
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(r.text().await.unwrap().contains("unsupported_media"));
    }
    // Too large: a typed 413, the same for an exposed, an unexposed and an unknown capability, and for a caller the product denies.
    let huge = format!("{{\"input\":\"{}\"}}", "a".repeat(2 << 20));
    let mut replies = Vec::new();
    for (token, path) in [
        ("alice-token", "/capabilities/read/1/call"),
        ("alice-token", "/capabilities/nothing/1/call"),
        ("mallory-token", "/capabilities/read/1/call"),
    ] {
        let r = raw(path, token)
            .header("content-type", "application/json")
            .body(huge.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        replies.push(r.text().await.unwrap());
    }
    assert!(
        replies
            .iter()
            .all(|r| r == &replies[0] && r.contains("too_large"))
    );
    // An undecodable path segment and a bad cursor are typed 400s, not plain text.
    let bad_path = w.get("alice-token", "/operations/%FF/events").await;
    assert_eq!(
        (bad_path.status, code(&bad_path)),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    let bad_cursor = w
        .get("alice-token", "/operations/op-1/events?cursor=abc")
        .await;
    assert_eq!(
        (bad_cursor.status, code(&bad_cursor)),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    // Only the canonical spelling of a version resolves.
    for version in ["01", "+1", "x", "99999999999"] {
        let r = w
            .post(
                "alice-token",
                &format!("/capabilities/read/{version}/call"),
                json!({"input": {}}),
            )
            .await;
        assert_eq!(
            (r.status, code(&r)),
            (StatusCode::NOT_FOUND, "not_found"),
            "{version}"
        );
    }
    assert_eq!(w.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_boundary_covers_routes_that_do_not_exist_and_marks_every_answer_uncacheable() {
    let w = world().await;
    // Outside /v1, unauthenticated: the guard answers, not a bare 404.
    let r = w
        .client
        .get(w.base.replace("/v1", "/elsewhere"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert_eq!(r.headers()["www-authenticate"], "Bearer");
    // Authenticated, outside /v1: a typed not_found.
    let r = w
        .client
        .get(w.base.replace("/v1", "/elsewhere"))
        .header("authorization", "Bearer alice-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(r.headers()["vary"], "Authorization");
    assert!(r.text().await.unwrap().contains("not_found"));
}

/// How a parity row runs: a call to completion, or a start (a detached call over MCP).
#[derive(Clone, Copy, PartialEq)]
enum Route {
    Call,
    Start,
}

#[tokio::test]
async fn http_and_mcp_give_the_same_answer_for_the_same_request() {
    // Two identical worlds, so each row is a fresh execution on both adapters and not a replay of the other's: HTTP runs against the first, MCP against the second, in the same order.
    let w = world().await;
    let mcp_world = world().await;
    let mcp = mcp_client(&mcp_world, "alice").await;
    let mallory = mcp_client(&mcp_world, "mallory").await;
    let huge_key = "k".repeat(300);
    let blob = "x".repeat(herald::service::MAX_INPUT_BYTES);
    // (capability, input, key, route, caller, expected HTTP status, expected error code or `None` for a result). The expectations are stated, so a bug both adapters share is still caught.
    type Row<'a> = (
        &'a str,
        Value,
        Option<&'a str>,
        Route,
        &'a str,
        u16,
        Option<&'a str>,
    );
    let rows: Vec<Row> = vec![
        (
            "read",
            json!({"x": 1}),
            None,
            Route::Call,
            "alice",
            200,
            None,
        ),
        (
            "read",
            json!({"x": "bad"}),
            None,
            Route::Call,
            "alice",
            422,
            Some("invalid_input"),
        ),
        (
            "write",
            json!({"x": 1}),
            Some("p1"),
            Route::Call,
            "alice",
            200,
            None,
        ),
        (
            "write",
            json!({"x": 2}),
            Some("p1"),
            Route::Call,
            "alice",
            409,
            Some("key_conflict"),
        ),
        (
            "write",
            json!({"x": 1}),
            None,
            Route::Call,
            "alice",
            400,
            Some("bad_request"),
        ),
        (
            "write",
            json!({"x": "bad"}),
            Some("p2"),
            Route::Call,
            "alice",
            422,
            Some("invalid_input"),
        ),
        (
            "fails",
            json!({}),
            Some("p3"),
            Route::Call,
            "alice",
            200,
            None,
        ),
        (
            "doubts",
            json!({}),
            Some("p4"),
            Route::Call,
            "alice",
            200,
            None,
        ),
        (
            "nothing",
            json!({}),
            Some("p5"),
            Route::Call,
            "alice",
            404,
            Some("not_found"),
        ),
        (
            "write",
            json!({}),
            Some(huge_key.as_str()),
            Route::Call,
            "alice",
            413,
            Some("too_large"),
        ),
        (
            "write",
            json!({"blob": blob}),
            Some("p6"),
            Route::Call,
            "alice",
            413,
            Some("too_large"),
        ),
        // Start: running, the same key again, a synchronous retry of the running key, a completed key started again (a finished start), and a denied caller.
        (
            "slow",
            json!({}),
            Some("p7"),
            Route::Start,
            "alice",
            202,
            None,
        ),
        (
            "slow",
            json!({}),
            Some("p7"),
            Route::Start,
            "alice",
            202,
            None,
        ),
        (
            "slow",
            json!({}),
            Some("p7"),
            Route::Call,
            "alice",
            409,
            Some("in_progress"),
        ),
        (
            "write",
            json!({"x": 1}),
            Some("p1"),
            Route::Start,
            "alice",
            200,
            None,
        ),
        (
            "fails",
            json!({}),
            Some("p3"),
            Route::Start,
            "alice",
            200,
            None,
        ),
        (
            "write",
            json!({"x": 1}),
            Some("p8"),
            Route::Call,
            "mallory",
            404,
            Some("not_found"),
        ),
        (
            "slow",
            json!({}),
            Some("p9"),
            Route::Start,
            "mallory",
            404,
            Some("not_found"),
        ),
        // Failures other than the caller's: a capability that wants consent the product never gives, one that cannot be supported, and handlers that break their contract or panic. The ones whose effect may have happened name the operation to follow.
        (
            "confirms",
            json!({}),
            Some("q1"),
            Route::Call,
            "alice",
            428,
            Some("confirmation_required"),
        ),
        (
            "unsupported",
            json!({}),
            None,
            Route::Call,
            "alice",
            501,
            Some("unsupported"),
        ),
        (
            "unsure",
            json!({}),
            None,
            Route::Call,
            "alice",
            503,
            Some("support_unknown"),
        ),
        (
            "invalid",
            json!({}),
            Some("q2"),
            Route::Call,
            "alice",
            502,
            Some("contract_violation"),
        ),
        (
            "panics",
            json!({}),
            Some("q3"),
            Route::Call,
            "alice",
            504,
            Some("outcome_lost"),
        ),
        (
            "panicq",
            json!({}),
            None,
            Route::Call,
            "alice",
            504,
            Some("outcome_lost"),
        ),
    ];
    for (name, input, key, route, caller, status, code) in rows {
        let caller_mcp = if caller == "alice" { &mcp } else { &mallory };
        // A query takes its input directly over MCP; an operation takes an envelope.
        let is_query = matches!(name, "read" | "panicq" | "unsupported" | "unsure");
        let mut arguments = if is_query {
            input.clone()
        } else {
            json!({"input": input})
        };
        let mut body = json!({"input": input});
        if let Some(key) = key {
            arguments["idempotency_key"] = json!(key);
            body["idempotency_key"] = json!(key);
        }
        if route == Route::Start {
            arguments["detach"] = json!(true);
        }
        let over_mcp = caller_mcp
            .call_tool(
                CallToolRequestParams::new(format!("{name}.v1"))
                    .with_arguments(arguments.as_object().cloned().unwrap()),
            )
            .await
            .unwrap();
        let verb = if route == Route::Start {
            "start"
        } else {
            "call"
        };
        let over_http = w
            .post(
                &format!("{caller}-token"),
                &format!("/capabilities/{name}/1/{verb}"),
                body,
            )
            .await;
        let label = format!("{name} {input} {key:?} {verb} {caller}");
        assert_eq!(over_http.status.as_u16(), status, "{label}");
        assert_eq!(
            over_http.body,
            over_mcp.structured_content.clone().unwrap(),
            "{label}"
        );
        match code {
            Some(code) => assert_eq!(over_http.body["error"]["code"], code, "{label}"),
            None => assert!(over_http.body.get("error").is_none(), "{label}"),
        }
        // An error that means the operation may have run names it, and a query has none to name.
        if matches!(
            code,
            Some("contract_violation" | "outcome_lost" | "in_progress")
        ) {
            assert_eq!(
                over_http.body["error"]["detail"]["operation"].is_string(),
                key.is_some() && name != "panicq",
                "{label}: {}",
                over_http.body
            );
        }
        // The failure signals agree: a typed error or an error outcome is a tool error on MCP.
        let http_failed = over_http.status.as_u16() >= 400 || over_http.body["failed"] == true;
        assert_eq!(over_mcp.is_error == Some(true), http_failed, "{label}");
    }
    // The finished start is tagged, the running one too, and the failed one carries its flag.
    let finished = w
        .post(
            "alice-token",
            "/capabilities/write/1/start",
            json!({"input": {"x": 1}, "idempotency_key": "p1"}),
        )
        .await;
    assert_eq!(finished.body["state"], "finished");
    let failed = w
        .post(
            "alice-token",
            "/capabilities/fails/1/start",
            json!({"input": {}, "idempotency_key": "p3"}),
        )
        .await;
    assert_eq!(
        (
            failed.body["state"].as_str(),
            failed.body["failed"].as_bool()
        ),
        (Some("finished"), Some(true))
    );
    // Each world ran every row fresh. A handler ran for: the read; the write `p1` (its replay as a start did not run); `p3`, `p4` and `p7`; the contract violation, the panicking operation and the panicking query. Rows refused before the handler (shape, bounds, consent, support, conflict, denial, unknown) ran nothing, and a replay that re-ran a handler would show here although its body would match.
    assert_eq!(w.calls.load(Ordering::SeqCst), 8, "the HTTP world");
    assert_eq!(mcp_world.calls.load(Ordering::SeqCst), 8, "the MCP world");
    w.release.notify_one();
    mcp_world.release.notify_one();
}

#[tokio::test]
async fn a_call_the_client_abandons_is_cancelled_and_a_started_operation_is_not() {
    let w = world().await;
    let abandoning = tokio::spawn(
        Client::new()
            .post(format!("{}/capabilities/slow/1/call", w.base))
            .header("authorization", "Bearer alice-token")
            .json(&json!({"input": {}, "idempotency_key": "abandon"}))
            .send(),
    );
    // Abort only once the handler is running, so what follows is the abandonment and not a request that never arrived.
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    abandoning.abort();
    wait_until(|| w.cancelled.load(Ordering::SeqCst) == 1).await;

    let started = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "detached"}),
        )
        .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    // The start request has ended and the handler is running, uncancelled.
    wait_until(|| w.calls.load(Ordering::SeqCst) == 2).await;
    w.release.notify_one();
    let operation = started.body["operation"].as_str().unwrap().to_owned();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let view = w
                .get("alice-token", &format!("/operations/{operation}"))
                .await;
            if view.body["events"].as_array().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the detached operation completed");
    assert_eq!(w.cancelled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_abandoned_query_is_told_to_stop_too() {
    let w = world().await;
    let abandoning = tokio::spawn(
        Client::new()
            .post(format!("{}/capabilities/hang/1/call", w.base))
            .header("authorization", "Bearer alice-token")
            .json(&json!({"input": {}}))
            .send(),
    );
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    abandoning.abort();
    wait_until(|| w.cancelled.load(Ordering::SeqCst) == 1).await;
}

#[test]
fn the_document_keeps_schema_references_resolvable_and_advertises_the_boundary_scheme() {
    use herald::{Support, service::Descriptor};
    let descriptor = Descriptor {
        id: id("shape"),
        kind: Kind::Operation,
        input_schema: json!({
            "type": "object",
            "properties": {"point": {"$ref": "#/$defs/Point"}},
            "$defs": {"Point": {"type": "object", "properties": {"x": {"type": "integer"}}}}
        }),
        output_schema: json!({"type": "object"}),
        error_schema: json!({"type": "object"}),
        confirmation_required: false,
        support: Support::Supported,
    };
    let scheme = json!({"type": "apiKey", "in": "header", "name": "x-key"});
    let doc = herald_http::document(&[descriptor], &scheme);
    let body = &doc["paths"]["/v1/capabilities/shape/1/call"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"];
    assert_eq!(body["required"], json!(["input", "idempotency_key"]));
    let input = component(&doc, &body["properties"]["input"]);
    assert!(
        input.get("$defs").is_none(),
        "definitions moved to components"
    );
    let point = component(&doc, &input["properties"]["point"]);
    assert_eq!(point["properties"]["x"]["type"], "integer");
    assert_eq!(doc["components"]["securitySchemes"]["credentials"], scheme);
    let start = &doc["paths"]["/v1/capabilities/shape/1/start"]["post"]["responses"];
    assert!(start["202"].is_object(), "a started operation answers 202");
    let events = &doc["paths"]["/v1/operations/{id}/events"]["get"]["parameters"];
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "cursor")
    );
    assert!(doc["components"]["schemas"]["ErrorResponse"].is_object());
}

#[test]
fn components_do_not_collide_when_names_differ_only_in_punctuation() {
    use herald::{Support, service::Descriptor};
    let shaped = |name: &str, property: &str| Descriptor {
        id: id(name),
        kind: Kind::Query,
        input_schema: json!({
            "type": "object",
            "properties": {"p": {"$ref": "#/$defs/Shared"}, "self": {"$ref": "#"}},
            "$defs": {"Shared": {"type": "object", "properties": {property: {"type": "integer"}}}}
        }),
        output_schema: json!({"type": "object"}),
        error_schema: json!({"type": "object"}),
        confirmation_required: false,
        support: Support::Supported,
    };
    let doc = herald_http::document(
        &[
            shaped("a.b", "first"),
            shaped("a-b", "second"),
            shaped("a_b", "third"),
        ],
        &json!({"type": "http", "scheme": "bearer"}),
    );
    let schemas = &doc["components"]["schemas"];
    for (name, property) in [("a.b", "first"), ("a-b", "second"), ("a_b", "third")] {
        let body = &doc["paths"][format!("/v1/capabilities/{name}/1/call")]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["properties"]["input"];
        let input = schemas[body["$ref"].as_str().unwrap().rsplit('/').next().unwrap()].clone();
        let shared = input["properties"]["p"]["$ref"].as_str().unwrap();
        let target = &schemas[shared.rsplit('/').next().unwrap()];
        assert!(
            target["properties"][property].is_object(),
            "{name} resolves to its own definition"
        );
        assert_eq!(
            input["properties"]["self"]["$ref"], body["$ref"],
            "a pointer to the schema's own root points at its component"
        );
    }
}

#[tokio::test]
async fn an_operation_started_over_http_is_followed_over_mcp_and_the_two_agree() {
    let w = world().await;
    let mcp = mcp_client(&w, "alice").await;
    let started = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "x"}),
        )
        .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    let operation = started.body["operation"].as_str().unwrap().to_owned();
    let follow = |tool: &'static str, arguments: Value| {
        let mcp = &mcp;
        async move {
            mcp.call_tool(
                CallToolRequestParams::new(tool.to_string())
                    .with_arguments(arguments.as_object().cloned().unwrap()),
            )
            .await
            .unwrap()
        }
    };
    let over_mcp = follow(herald_mcp::OPERATION_TOOL, json!({"id": operation})).await;
    let over_http = w
        .get("alice-token", &format!("/operations/{operation}"))
        .await;
    assert_eq!(over_mcp.structured_content.unwrap(), over_http.body);
    w.release.notify_one();
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    let done = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let events = follow(
                herald_mcp::EVENTS_TOOL,
                json!({"id": operation, "cursor": 1}),
            )
            .await;
            let events = events.structured_content.unwrap();
            if !events["events"].as_array().unwrap().is_empty() {
                return events;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed");
    let over_http = w
        .get(
            "alice-token",
            &format!("/operations/{operation}/events?cursor=1"),
        )
        .await;
    assert_eq!(done, over_http.body);
}

#[tokio::test]
async fn both_adapters_served_from_one_guarded_router_share_one_boundary() {
    let w = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = OriginPolicy::new([address.to_string()], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits()).unwrap();
    let app = herald_boundary::Guarded::new(
        herald_http::routes(w.service.clone(), &boundary).unwrap(),
        boundary.clone(),
    )
    .merge(herald_mcp::routes(w.service.clone(), &boundary).unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let client = Client::new();
    let base = format!("http://{address}");
    // Every path is behind the boundary, the API's, the MCP transport's and one that is neither.
    for path in ["/v1/capabilities", "/mcp", "/elsewhere"] {
        let r = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
        let r = client
            .get(format!("{base}{path}"))
            .header("authorization", "Bearer alice-token")
            .header("origin", "https://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let listed = client
        .get(format!("{base}/v1/capabilities"))
        .header("authorization", "Bearer alice-token")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    // And MCP works on the same listener.
    let config =
        rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
            format!("{base}/mcp"),
        )
        .auth_header("alice-token".to_string());
    let mcp = ()
        .serve(rmcp::transport::StreamableHttpClientTransport::from_config(
            config,
        ))
        .await
        .unwrap();
    assert!(!mcp.list_all_tools().await.unwrap().is_empty());
}

/// A validator for the response schema the document declares for `path`, `method` and `status`.
fn response_validator(
    doc: &Value,
    path: &str,
    method: &str,
    status: &str,
) -> jsonschema::Validator {
    let schema =
        &doc["paths"][path][method]["responses"][status]["content"]["application/json"]["schema"];
    assert!(
        schema.is_object(),
        "{path} {method} {status} declares a schema"
    );
    let mut root = schema.clone();
    root["components"] = doc["components"].clone();
    jsonschema::validator_for(&root).expect("a valid schema")
}

#[tokio::test]
async fn real_responses_validate_against_the_document_that_describes_them() {
    let w = world().await;
    let doc = w.get("alice-token", "/openapi.json").await.body;
    let check = |path: &'static str, method: &'static str, reply: &Reply| {
        let status = reply.status.as_u16().to_string();
        let declared = if doc["paths"][path][method]["responses"][status.as_str()].is_object() {
            status
        } else if reply.status.is_client_error() {
            "4XX".to_owned()
        } else {
            "5XX".to_owned()
        };
        let validator = response_validator(&doc, path, method, &declared);
        assert!(
            validator.is_valid(&reply.body),
            "{path} {method} {} returned {}",
            reply.status,
            reply.body
        );
    };
    let call_path = "/v1/capabilities/write/1/call";
    let start_path = "/v1/capabilities/slow/1/start";
    check(
        call_path,
        "post",
        &w.post(
            "alice-token",
            "/capabilities/write/1/call",
            json!({"input": {"x": 1}, "idempotency_key": "a"}),
        )
        .await,
    );
    check(
        call_path,
        "post",
        &w.post(
            "alice-token",
            "/capabilities/write/1/call",
            json!({"input": {"x": 2}, "idempotency_key": "a"}),
        )
        .await,
    );
    check(
        call_path,
        "post",
        &w.post(
            "alice-token",
            "/capabilities/write/1/call",
            json!({"input": {"x": "bad"}, "idempotency_key": "b"}),
        )
        .await,
    );
    check(
        "/v1/capabilities/fails/1/call",
        "post",
        &w.post(
            "alice-token",
            "/capabilities/fails/1/call",
            json!({"input": {}, "idempotency_key": "f"}),
        )
        .await,
    );
    check(
        "/v1/capabilities/doubts/1/call",
        "post",
        &w.post(
            "alice-token",
            "/capabilities/doubts/1/call",
            json!({"input": {}, "idempotency_key": "d"}),
        )
        .await,
    );
    check(
        "/v1/capabilities/read/1/call",
        "post",
        &w.post(
            "alice-token",
            "/capabilities/read/1/call",
            json!({"input": {"x": 1}}),
        )
        .await,
    );
    let running = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "s"}),
        )
        .await;
    assert_eq!(running.status, StatusCode::ACCEPTED);
    check(start_path, "post", &running);
    let operation = running.body["operation"].as_str().unwrap().to_owned();
    check(
        "/v1/operations/{id}",
        "get",
        &w.get("alice-token", &format!("/operations/{operation}"))
            .await,
    );
    check(
        "/v1/operations/{id}",
        "get",
        &w.get("alice-token", "/operations/op-missing").await,
    );
    w.release.notify_one();
    wait_until(|| w.calls.load(Ordering::SeqCst) >= 1).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let events = w
                .get(
                    "alice-token",
                    &format!("/operations/{operation}/events?cursor=0"),
                )
                .await;
            if events.body["events"].as_array().unwrap().len() == 2 {
                check("/v1/operations/{id}/events", "get", &events);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed");
    let finished = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "s"}),
        )
        .await;
    assert_eq!(finished.body["state"], "finished");
    check(start_path, "post", &finished);
    // Something the document does not describe is refused.
    let validator = response_validator(&doc, call_path, "post", "200");
    assert!(!validator.is_valid(&json!({"outcome": 1})));
}

#[tokio::test]
async fn an_unknown_path_under_the_api_prefix_is_behind_the_boundary_too() {
    let w = world().await;
    let r = w
        .client
        .get(format!("{}/nowhere", w.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = w
        .client
        .delete(format!("{}/capabilities", w.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn detached_operations_give_their_request_slot_back_so_they_can_be_followed() {
    let w = world_with(None, Limits::new(Duration::from_secs(60), 1, 1).unwrap()).await;
    let started = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "long"}),
        )
        .await;
    assert_eq!(started.status, StatusCode::ACCEPTED);
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    // The handler is still running, and the only request slot is free: the operation can be read.
    let operation = started.body["operation"].as_str().unwrap().to_owned();
    let view = w
        .get("alice-token", &format!("/operations/{operation}"))
        .await;
    assert_eq!(view.status, StatusCode::OK, "{}", view.body);
    // A synchronous call keeps its slot while the handler runs, so a second request is shed.
    let holding = tokio::spawn(
        Client::new()
            .post(format!("{}/capabilities/hang/1/call", w.base))
            .header("authorization", "Bearer alice-token")
            .json(&json!({"input": {}}))
            .send(),
    );
    wait_until(|| w.calls.load(Ordering::SeqCst) == 2).await;
    let shed = w.get("alice-token", "/capabilities").await;
    assert_eq!(
        (shed.status, code(&shed)),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    holding.abort();
    w.release.notify_waiters();
}

#[tokio::test]
async fn a_handler_that_ignores_its_cancellation_keeps_the_slot_after_the_deadline() {
    let w = world_with(None, Limits::new(Duration::from_secs(3), 1, 1).unwrap()).await;
    let request = tokio::spawn(
        Client::new()
            .post(format!("{}/capabilities/stubborn/1/call", w.base))
            .header("authorization", "Bearer alice-token")
            .json(&json!({"input": {}}))
            .send(),
    );
    // The handler is running and cannot be interrupted. Its request ends at the deadline.
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    let timed_out = request.await.unwrap().unwrap();
    assert_eq!(timed_out.status(), StatusCode::GATEWAY_TIMEOUT);
    // The request is gone, but the handler is not, so its slot is still taken: the next request is shed. Without the hold the deadline would have freed the slot.
    let shed = w.get("alice-token", "/capabilities").await;
    assert_eq!(
        (shed.status, code(&shed)),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    assert_eq!(
        w.cancelled.load(Ordering::SeqCst),
        0,
        "it never looked at its cancellation"
    );
    // Once the handler returns, the slot comes back.
    w.release.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if w.get("alice-token", "/capabilities").await.status == StatusCode::OK {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the slot came back once the handler returned");
}

#[tokio::test]
async fn one_caller_cannot_take_every_slot() {
    let w = world_with(None, Limits::new(Duration::from_secs(60), 2, 1).unwrap()).await;
    let holding = tokio::spawn(
        Client::new()
            .post(format!("{}/capabilities/stubborn/1/call", w.base))
            .header("authorization", "Bearer alice-token")
            .json(&json!({"input": {}}))
            .send(),
    );
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    // Alice holds her one share, so a second request of hers is turned away while another caller, and the unauthenticated, still reach the boundary.
    let again = w.get("alice-token", "/capabilities").await;
    assert_eq!(
        (again.status, code(&again)),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    let bob = w.get("bob-token", "/capabilities").await;
    assert_eq!(bob.status, StatusCode::OK);
    let nobody = w.send(None, Method::GET, "/capabilities", None).await;
    assert_eq!(nobody.status, StatusCode::UNAUTHORIZED);
    w.release.notify_waiters();
    holding.await.unwrap().unwrap();
    // Her share comes back when her request ends.
    let after = w.get("alice-token", "/capabilities").await;
    assert_eq!(after.status, StatusCode::OK);
}

#[tokio::test]
async fn the_runtimes_running_limit_is_a_typed_503_on_both_adapters() {
    let w = world_with(
        Some(RunningLimit::new(1, 1, Duration::from_secs(600)).unwrap()),
        limits(),
    )
    .await;
    let first = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "one"}),
        )
        .await;
    assert_eq!(first.status, StatusCode::ACCEPTED);
    let refused = w
        .post(
            "alice-token",
            "/capabilities/slow/1/start",
            json!({"input": {}, "idempotency_key": "two"}),
        )
        .await;
    assert_eq!(
        (refused.status, code(&refused)),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    let mcp = mcp_client(&w, "alice").await;
    let over_mcp = mcp
        .call_tool(
            CallToolRequestParams::new("slow.v1".to_string()).with_arguments(
                json!({"input": {}, "idempotency_key": "three", "detach": true})
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(over_mcp.is_error, Some(true));
    assert_eq!(over_mcp.structured_content.unwrap(), refused.body);
    w.release.notify_waiters();
}

#[tokio::test]
async fn the_size_bound_is_judged_before_the_version_is_read() {
    let w = world().await;
    // Many short numbers: each is three bytes of number and four with its comma on the wire, and nine once parsed and written back, so the body passes the transport's limit and fails the service's.
    let numbers = vec!["1e5"; herald::service::MAX_REQUEST_BYTES / 6].join(",");
    let body = format!("{{\"input\":{{\"n\":[{numbers}]}}}}");
    assert!(
        body.len() <= herald::service::MAX_REQUEST_BYTES,
        "inside the transport's bound"
    );
    for version in ["1", "01", "x"] {
        for name in ["read", "nothing"] {
            let r = w
                .client
                .post(format!("{}/capabilities/{name}/{version}/call", w.base))
                .header("authorization", "Bearer mallory-token")
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                r.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "{name} {version}"
            );
        }
    }
}

#[tokio::test]
async fn the_capability_list_is_typed_in_the_document() {
    let w = world().await;
    let doc = w.get("alice-token", "/openapi.json").await.body;
    let items = &doc["paths"]["/v1/capabilities"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"]["properties"]["capabilities"]["items"];
    assert_eq!(
        items["required"],
        json!([
            "id",
            "kind",
            "input_schema",
            "output_schema",
            "error_schema",
            "confirmation_required",
            "support"
        ])
    );
    let listed = w.get("alice-token", "/capabilities").await.body;
    let mut root = items.clone();
    root["components"] = doc["components"].clone();
    let validator = jsonschema::validator_for(&root).unwrap();
    for capability in listed["capabilities"].as_array().unwrap() {
        assert!(validator.is_valid(capability), "{capability}");
    }
}

#[tokio::test]
async fn the_route_chooses_whether_to_wait_so_http_refuses_a_detach_flag_that_mcp_takes() {
    let w = world().await;
    for (path, detach) in [
        ("call", false),
        ("call", true),
        ("start", false),
        ("start", true),
    ] {
        let r = w
            .post(
                "alice-token",
                &format!("/capabilities/write/1/{path}"),
                json!({"input": {}, "idempotency_key": format!("d-{path}-{detach}"), "detach": detach}),
            )
            .await;
        assert_eq!(
            (r.status, code(&r)),
            (StatusCode::BAD_REQUEST, "bad_request"),
            "{path} {detach}"
        );
    }
    let mcp = mcp_client(&w, "alice").await;
    for detach in [false, true] {
        let r = mcp
            .call_tool(
                CallToolRequestParams::new("write.v1".to_string()).with_arguments(
                    json!({"input": {}, "idempotency_key": format!("m-{detach}"), "detach": detach})
                        .as_object()
                        .cloned()
                        .unwrap(),
                ),
            )
            .await
            .unwrap();
        assert_ne!(r.is_error, Some(true), "MCP takes the flag: {detach}");
        // `write` finishes at once, so a detached call to it is a finished start, not a run: either way the body says which.
        let body = r.structured_content.unwrap();
        assert_eq!(body.get("state").is_some(), detach, "{detach}: {body}");
    }
}

#[test]
fn operation_ids_are_identifiers_even_when_names_fold_together() {
    use herald::{Support, service::Descriptor};
    let query = |name: &str| Descriptor {
        id: id(name),
        kind: Kind::Query,
        input_schema: json!({"type": "object"}),
        output_schema: json!({"type": "object"}),
        error_schema: json!({"type": "object"}),
        confirmation_required: false,
        support: Support::Supported,
    };
    let doc = herald_http::document(
        &[query("a.b"), query("a-b"), query("a_b"), query("plain")],
        &json!({"type": "http", "scheme": "bearer"}),
    );
    let mut ids: Vec<String> = ["a.b", "a-b", "a_b", "plain"]
        .iter()
        .map(|name| {
            doc["paths"][format!("/v1/capabilities/{name}/1/call")]["post"]["operationId"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(ids[3], "call_plain_v1");
    assert!(
        ids.iter()
            .all(|i| i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')),
        "{ids:?}"
    );
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4, "distinct");
}

#[tokio::test]
async fn a_service_over_an_unbounded_runtime_cannot_be_served_over_a_network() {
    let policy = Arc::new(Policy);
    let d = Arc::new(Dispatcher::new(
        policy.clone(),
        policy.clone(),
        policy.clone(),
        policy,
    ));
    let (runtime, _) = Runtime::open(d, Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    let service = Arc::new(Service::new(Arc::new(runtime), Exposure::none()));
    let boundary = Boundary::new(
        Arc::new(Tokens),
        OriginPolicy::new(["127.0.0.1:8080".to_string()], [ORIGIN.to_string()]).unwrap(),
        limits(),
    )
    .unwrap();
    assert!(herald_http::routes(service.clone(), &boundary).is_err());
    assert!(herald_http::router(service, boundary).is_err());
}

#[tokio::test]
async fn an_operation_started_over_mcp_on_the_shared_router_is_followed_to_completion_over_http() {
    let w = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = OriginPolicy::new([address.to_string()], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits()).unwrap();
    let app = herald_boundary::Guarded::new(
        herald_http::routes(w.service.clone(), &boundary).unwrap(),
        boundary.clone(),
    )
    .merge(herald_mcp::routes(w.service.clone(), &boundary).unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let config =
        rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
            format!("http://{address}/mcp"),
        )
        .auth_header("alice-token".to_string());
    let mcp = ()
        .serve(rmcp::transport::StreamableHttpClientTransport::from_config(
            config,
        ))
        .await
        .unwrap();
    let started = mcp
        .call_tool(
            CallToolRequestParams::new("slow.v1".to_string()).with_arguments(
                json!({"input": {}, "idempotency_key": "shared", "detach": true})
                    .as_object()
                    .cloned()
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
    let started = started.structured_content.unwrap();
    assert_eq!(started["state"], "running");
    let operation = started["operation"].as_str().unwrap().to_owned();
    // The same token on the same listener follows it over the API, through to completion.
    let client = Client::new();
    let read = |path: String| {
        let client = client.clone();
        async move {
            client
                .get(format!("http://{address}/v1{path}"))
                .header("authorization", "Bearer alice-token")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    assert_eq!(
        read(format!("/operations/{operation}")).await["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    w.release.notify_waiters();
    let done = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let view = read(format!("/operations/{operation}")).await;
            if view["events"].as_array().unwrap().len() == 2 {
                return view;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed");
    assert_eq!(
        done["events"][1]["state"]["Completed"]["Success"]["caller"],
        "alice"
    );
}

#[tokio::test]
async fn http_and_mcp_offer_the_same_capabilities_for_the_same_caller() {
    let w = world().await;
    let mcp = mcp_client(&w, "alice").await;
    let listed = w.get("alice-token", "/capabilities").await.body;
    let mut over_http: Vec<String> = listed["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            format!(
                "{}.v{}",
                c["id"]["name"].as_str().unwrap(),
                c["id"]["version"]
            )
        })
        .collect();
    let mut over_mcp: Vec<String> = mcp
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.name.to_string())
        .filter(|name| !name.starts_with("herald."))
        .collect();
    // The one capability MCP cannot offer is a query whose input is not an object.
    over_http.retain(|name| name != "scalar.v1");
    over_http.sort();
    over_mcp.sort();
    assert_eq!(over_http, over_mcp);
    // And the schemas of what each describes: an operation's MCP input embeds the API's input schema.
    for capability in listed["capabilities"].as_array().unwrap() {
        let name = capability["id"]["name"].as_str().unwrap();
        if name == "scalar" {
            continue;
        }
        let tool = mcp
            .list_all_tools()
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.name == format!("{name}.v1"))
            .unwrap();
        let input = Value::Object((*tool.input_schema).clone());
        if capability["kind"] == "Operation" {
            assert_eq!(
                input["properties"]["input"], capability["input_schema"],
                "{name}"
            );
        } else {
            assert_eq!(input, capability["input_schema"], "{name}");
        }
    }
}

#[tokio::test]
async fn a_method_the_route_does_not_take_is_a_typed_405_that_names_what_it_takes() {
    let w = world().await;
    let r = w
        .client
        .get(format!("{}/capabilities/read/1/call", w.base))
        .header("authorization", "Bearer alice-token")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(r.headers()["allow"], "POST");
    assert!(r.text().await.unwrap().contains("method_not_allowed"));
}

#[tokio::test]
async fn a_query_that_never_returns_is_stopped_at_the_ceiling_after_its_caller_has_gone_and_then_gives_its_slot_back()
 {
    let w = world_with(
        Some(RunningLimit::new(64, 64, Duration::from_secs(5)).unwrap()),
        Limits::new(Duration::from_secs(60), 1, 1).unwrap(),
    )
    .await;
    let abandoning = tokio::spawn(
        Client::new()
            .post(format!("{}/capabilities/stuck/1/call", w.base))
            .header("authorization", "Bearer alice-token")
            .json(&json!({"input": {}}))
            .send(),
    );
    wait_until(|| w.calls.load(Ordering::SeqCst) == 1).await;
    abandoning.abort();
    // The client is gone but the handler is not: it holds the only slot until the ceiling stops it.
    let shed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let r = w.get("alice-token", "/capabilities").await;
            if r.status == StatusCode::SERVICE_UNAVAILABLE {
                return r;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shed while the abandoned query is still running");
    assert_eq!(code(&shed), "unavailable");
    // At the ceiling the query is stopped with nobody waiting for it, and its slot comes back.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if w.get("alice-token", "/capabilities").await.status == StatusCode::OK {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the ceiling released the slot");
}

#[tokio::test]
async fn the_documents_request_bodies_accept_what_the_service_accepts_and_refuse_what_it_refuses() {
    let w = world().await;
    let doc = w.get("alice-token", "/openapi.json").await.body;
    let body_schema = |path: &str| {
        let mut root =
            doc["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]
                .clone();
        assert!(root.is_object(), "{path} declares a request body");
        root["components"] = doc["components"].clone();
        jsonschema::validator_for(&root).expect("a valid schema")
    };
    // An operation needs its key; a query accepts one and does not need it.
    let write = body_schema("/v1/capabilities/write/1/call");
    assert!(write.is_valid(&json!({"input": {"x": 1}, "idempotency_key": "k"})));
    assert!(
        !write.is_valid(&json!({"input": {"x": 1}})),
        "an operation needs its key"
    );
    assert!(!write.is_valid(&json!({"input": {"x": 1}, "idempotency_key": ""})));
    assert!(!write.is_valid(&json!({"input": {"x": 1}, "idempotency_key": "k", "extra": 1})));
    let read = body_schema("/v1/capabilities/read/1/call");
    assert!(read.is_valid(&json!({"input": {"x": 1}})));
    assert!(read.is_valid(&json!({"input": {"x": 1}, "idempotency_key": "k"})));
    assert!(
        !read.is_valid(&json!({"input": {"x": "no"}})),
        "the input schema applies"
    );
    assert!(
        !read.is_valid(&json!({"idempotency_key": "k"})),
        "the input is required"
    );
    // And the service agrees about the query key: accepted, ignored.
    let accepted = w
        .post(
            "alice-token",
            "/capabilities/read/1/call",
            json!({"input": {"x": 1}, "idempotency_key": "ignored"}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
}

#[tokio::test]
async fn an_operation_started_over_http_on_the_shared_router_is_followed_over_network_mcp() {
    let w = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = OriginPolicy::new([address.to_string()], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits()).unwrap();
    let app = herald_boundary::Guarded::new(
        herald_http::routes(w.service.clone(), &boundary).unwrap(),
        boundary.clone(),
    )
    .merge(herald_mcp::routes(w.service.clone(), &boundary).unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let started = Client::new()
        .post(format!("http://{address}/v1/capabilities/slow/1/start"))
        .header("authorization", "Bearer alice-token")
        .json(&json!({"input": {}, "idempotency_key": "http-first"}))
        .send()
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let operation = started.json::<Value>().await.unwrap()["operation"]
        .as_str()
        .unwrap()
        .to_owned();
    let config =
        rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
            format!("http://{address}/mcp"),
        )
        .auth_header("alice-token".to_string());
    let mcp = ()
        .serve(rmcp::transport::StreamableHttpClientTransport::from_config(
            config,
        ))
        .await
        .unwrap();
    let follow = |tool: &'static str| {
        let (mcp, operation) = (&mcp, operation.clone());
        async move {
            mcp.call_tool(
                CallToolRequestParams::new(tool.to_string())
                    .with_arguments(json!({"id": operation}).as_object().cloned().unwrap()),
            )
            .await
            .unwrap()
            .structured_content
            .unwrap()
        }
    };
    assert_eq!(
        follow(herald_mcp::OPERATION_TOOL).await["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    w.release.notify_waiters();
    let done = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let view = follow(herald_mcp::OPERATION_TOOL).await;
            if view["events"].as_array().unwrap().len() == 2 {
                return view;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed");
    assert_eq!(
        done["events"][1]["state"]["Completed"]["Success"]["caller"],
        "alice"
    );
}

#[tokio::test]
async fn a_request_at_exactly_the_largest_input_and_longest_key_is_accepted_over_http() {
    use herald::service::{MAX_INPUT_BYTES, MAX_KEY_BYTES};
    let w = world().await;
    let input = json!({"pad": "x".repeat(MAX_INPUT_BYTES - 10)});
    assert_eq!(input.to_string().len(), MAX_INPUT_BYTES);
    let accepted = w
        .post(
            "alice-token",
            "/capabilities/wide/1/call",
            json!({"input": input, "idempotency_key": "k".repeat(MAX_KEY_BYTES)}),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    let over = w
        .post(
            "alice-token",
            "/capabilities/wide/1/call",
            json!({"input": {"pad": "x".repeat(MAX_INPUT_BYTES - 9)}, "idempotency_key": "other"}),
        )
        .await;
    assert_eq!(
        (over.status, code(&over)),
        (StatusCode::PAYLOAD_TOO_LARGE, "too_large")
    );
}

#[tokio::test]
async fn a_call_that_reaches_the_request_deadline_is_told_to_stop() {
    let w = world_with(None, Limits::new(Duration::from_secs(3), 64, 64).unwrap()).await;
    let ended = w
        .client
        .post(format!("{}/capabilities/hang/1/call", w.base))
        .header("authorization", "Bearer alice-token")
        .json(&json!({"input": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(ended.status(), StatusCode::GATEWAY_TIMEOUT);
    // The handler is cooperative, so it sees its cancellation and returns.
    wait_until(|| w.cancelled.load(Ordering::SeqCst) == 1).await;
}

#[tokio::test]
async fn the_events_route_takes_no_query_parameter_but_cursor() {
    let w = world().await;
    let r = w
        .get("alice-token", "/operations/op-x/events?cursor=0&junk=1")
        .await;
    assert_eq!(
        (r.status, code(&r)),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
}

#[tokio::test]
async fn what_mcp_says_about_a_tool_matches_what_the_document_says_about_its_route() {
    let w = world().await;
    let doc = w.get("alice-token", "/openapi.json").await.body;
    let mcp = mcp_client(&w, "alice").await;
    let tools = mcp.list_all_tools().await.unwrap();
    let facts = |name: &str| {
        tools
            .iter()
            .find(|t| t.name == format!("{name}.v1"))
            .unwrap_or_else(|| panic!("{name} is a tool"))
            .meta
            .as_ref()
            .unwrap()
            .0["herald"]
            .clone()
    };
    for (name, kind) in [
        ("confirms", "Operation"),
        ("unsupported", "Query"),
        ("unsure", "Query"),
        ("write", "Operation"),
        ("read", "Query"),
    ] {
        let meta = facts(name);
        let route = &doc["paths"][format!("/v1/capabilities/{name}/1/call")]["post"];
        assert_eq!(meta["kind"], kind, "{name}");
        assert_eq!(meta["kind"], route["x-herald-kind"], "{name}");
        assert_eq!(
            meta["confirmation_required"], route["x-herald-confirmation-required"],
            "{name}"
        );
        assert_eq!(meta["support"], route["x-herald-support"], "{name}");
    }
    assert_eq!(facts("confirms")["confirmation_required"], true);
    assert_eq!(facts("unsupported")["support"], "Unsupported");
}
