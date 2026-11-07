//! The HTTP API over a real socket, driven by `reqwest`, plus the parity and cross-adapter checks
//! against the MCP adapter over the same service.

use axum::http::{HeaderMap, header};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support,
    exposure::{Exposure, Surface},
    runtime::{MemoryOperationStore, Runtime},
    service::{Principal, Service},
};
use herald_boundary::{Authenticator, Boundary, OriginPolicy};
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

const ORIGIN: &str = "https://app.example.test";

struct Policy;
impl Authorizer for Policy {
    fn authorize<'a>(&'a self, r: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move { ["alice", "bob"].contains(&r.identity.as_str()) })
    }
}
impl Confirmer for Policy {
    fn confirm<'a>(&'a self, _: &'a Request, _: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async { true })
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
struct Tokens;
impl Authenticator for Tokens {
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Option<Principal>> {
        Box::pin(async move {
            match headers.get(header::AUTHORIZATION)?.to_str().ok()? {
                "Bearer alice-token" => Principal::new("alice").ok(),
                "Bearer bob-token" => Principal::new("bob").ok(),
                "Bearer mallory-token" => Principal::new("mallory").ok(),
                _ => None,
            }
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
    release: Arc<Notify>,
    base: String,
    client: Client,
    _server: tokio::task::JoinHandle<()>,
}
async fn world() -> World {
    let policy = Arc::new(Policy);
    let (calls, release) = (Arc::new(AtomicUsize::new(0)), Arc::new(Notify::new()));
    let mut d = Dispatcher::new(policy.clone(), policy.clone(), policy.clone(), policy);
    for (name, kind, wait) in [
        ("read", Kind::Query, false),
        ("write", Kind::Operation, false),
        ("slow", Kind::Operation, true),
    ] {
        d.register(
            contract(name, kind),
            Arc::new(Work {
                calls: calls.clone(),
                release: wait.then(|| release.clone()),
            }),
        )
        .unwrap();
    }
    let d = Arc::new(d);
    let (runtime, _) = Runtime::open(d.clone(), Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    // Exposed on both surfaces, so parity can be checked against the MCP adapter.
    let exposure = ["read", "write", "slow"]
        .into_iter()
        .fold(Exposure::none(), |e, n| {
            e.allow(Surface::Api, id(n)).allow(Surface::Mcp, id(n))
        });
    let service = Arc::new(Service::new(d, Arc::new(runtime), exposure));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin_policy =
        OriginPolicy::new([format!("127.0.0.1:{port}")], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), origin_policy);
    let app = herald_http::router(service.clone(), boundary);
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    World {
        service,
        calls,
        release,
        base: format!("http://127.0.0.1:{port}/v1"),
        client: Client::new(),
        _server: server,
    }
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
            "bad_request",
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
async fn the_boundary_refuses_a_foreign_origin_and_host_before_credentials_are_read() {
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

#[tokio::test]
async fn the_openapi_document_is_generated_for_the_caller_from_the_contracts() {
    let w = world().await;
    let doc = w.get("alice-token", "/openapi.json").await.body;
    assert_eq!(doc["openapi"], "3.1.0");
    let call = &doc["paths"]["/v1/capabilities/write/1/call"]["post"];
    assert_eq!(
        call["requestBody"]["content"]["application/json"]["schema"]["properties"]["input"]["properties"]
            ["x"]["type"],
        "integer"
    );
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
            .all(|p| p.starts_with("/v1/operations"))
    );
}
