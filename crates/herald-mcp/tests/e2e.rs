//! Real `rmcp` clients against the adapter over both transports. The stdio-style transport is an
//! in-memory pipe carrying the same newline-delimited JSON-RPC that stdio does; the network transport
//! is streamable HTTP on a real socket behind the boundary.

use axum::http::{HeaderMap, header};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support,
    exposure::{Exposure, Surface},
    runtime::{MemoryOperationStore, Runtime},
    service::{Principal, Service},
};
use herald_boundary::{Authentication, Authenticator, Boundary, Limits, OriginPolicy};
use herald_mcp::{EVENTS_TOOL, HeraldMcp, OPERATION_TOOL, rmcp, router};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Map, Value, json};
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
    Limits::new(Duration::from_secs(60), 64).unwrap()
}

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

#[derive(Clone, Copy)]
enum Behaviour {
    Succeed,
    Fail,
    Doubt,
}

struct Work {
    calls: Arc<AtomicUsize>,
    release: Option<Arc<Notify>>,
    behaviour: Behaviour,
}
impl Handler for Work {
    fn invoke<'a>(&'a self, r: &'a Request, _: Cancellation) -> PortFuture<'a, Outcome> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(release) = &self.release {
                release.notified().await;
            }
            let body = json!({"caller": r.identity, "input": r.input});
            match self.behaviour {
                Behaviour::Succeed => Outcome::Success(body),
                Behaviour::Fail => Outcome::Error(body),
                Behaviour::Doubt => Outcome::Unknown(body),
            }
        })
    }
}

/// Bearer tokens the product accepts, and who they name.
struct Tokens;
impl Authenticator for Tokens {
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Authentication> {
        Box::pin(async move {
            let principal: Option<Principal> = (|| match headers.get(header::AUTHORIZATION)?.to_str().ok()? {
                "Bearer alice-token" => Principal::new("alice").ok(),
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
    release: Arc<Notify>,
    url: String,
    _server: tokio::task::JoinHandle<()>,
}

async fn world() -> World {
    let policy = Arc::new(Policy);
    let (calls, release) = (Arc::new(AtomicUsize::new(0)), Arc::new(Notify::new()));
    let mut d = Dispatcher::new(policy.clone(), policy.clone(), policy.clone(), policy);
    for (name, kind, wait, behaviour) in [
        ("read", Kind::Query, false, Behaviour::Succeed),
        ("write", Kind::Operation, false, Behaviour::Succeed),
        ("slow", Kind::Operation, true, Behaviour::Succeed),
        ("fails", Kind::Operation, false, Behaviour::Fail),
        ("doubts", Kind::Operation, false, Behaviour::Doubt),
    ] {
        d.register(
            contract(name, kind),
            Arc::new(Work {
                calls: calls.clone(),
                release: wait.then(|| release.clone()),
                behaviour,
            }),
        )
        .unwrap();
    }
    let d = Arc::new(d);
    let (runtime, _) = Runtime::open(d.clone(), Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    let exposure = ["read", "write", "slow", "fails", "doubts"]
        .into_iter()
        .fold(Exposure::none(), |e, n| e.allow(Surface::Mcp, id(n)));
    let service = Arc::new(Service::new(d, Arc::new(runtime), exposure));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let policy = OriginPolicy::new([format!("127.0.0.1:{port}")], [ORIGIN.to_string()]).unwrap();
    let app = router(service.clone(), Boundary::new(Arc::new(Tokens), policy, limits()));
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    World {
        service,
        calls,
        release,
        url: format!("http://127.0.0.1:{port}/mcp"),
        _server: server,
    }
}

type Client = RunningService<rmcp::service::RoleClient, ()>;

async fn stdio_client(world: &World, identity: &str) -> Client {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let handler = HeraldMcp::stdio(world.service.clone(), Principal::new(identity).unwrap());
    tokio::spawn(async move {
        let running = handler.serve(server_io).await.unwrap();
        let _ = running.waiting().await;
    });
    ().serve(client_io).await.unwrap()
}

async fn network_client(world: &World, token: &str) -> Client {
    let config = StreamableHttpClientTransportConfig::with_uri(world.url.clone())
        .auth_header(token.to_string());
    ().serve(StreamableHttpClientTransport::from_config(config))
        .await
        .unwrap()
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}
async fn call(client: &Client, tool: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args(arguments)))
        .await
        .unwrap_or_else(|e| panic!("protocol error calling {tool}: {e}"))
}
fn structured(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("structured content")
}
fn is_error(result: &CallToolResult) -> bool {
    result.is_error == Some(true)
}
fn error_code(result: &CallToolResult) -> String {
    structured(result)["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn tools(client: &Client) -> Vec<(String, Value)> {
    let mut found: Vec<_> = client
        .list_all_tools()
        .await
        .unwrap()
        .into_iter()
        .map(|t| (t.name.to_string(), Value::Object((*t.input_schema).clone())))
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

#[tokio::test]
async fn both_transports_expose_the_same_tools_with_the_same_schemas() {
    let world = world().await;
    let over_stdio = tools(&stdio_client(&world, "alice").await).await;
    let over_network = tools(&network_client(&world, "alice-token").await).await;
    assert_eq!(over_stdio, over_network);
    let names: Vec<_> = over_stdio.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "doubts.v1",
            "fails.v1",
            EVENTS_TOOL,
            OPERATION_TOOL,
            "read.v1",
            "slow.v1",
            "write.v1"
        ]
    );
    // An operation tool wraps the capability's input with an idempotency key.
    let write = &over_stdio.iter().find(|(n, _)| n == "write.v1").unwrap().1;
    assert_eq!(write["required"], json!(["idempotency_key", "input"]));
    assert_eq!(
        write["properties"]["input"]["properties"]["x"]["type"],
        "integer"
    );
}

#[tokio::test]
async fn the_same_calls_give_the_same_results_over_both_transports() {
    let world = world().await;
    let stdio = stdio_client(&world, "alice").await;
    let network = network_client(&world, "alice-token").await;
    for (tool, arguments) in [
        ("read.v1", json!({"x": 1})),
        ("read.v1", json!({"x": "not an integer"})),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 1}}),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 1}}),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 2}}),
        ),
        ("write.v1", json!({"input": {"x": 1}})),
        (
            "write.v1",
            json!({"idempotency_key": "k2", "input": {"x": "bad"}}),
        ),
        ("nothing.v1", json!({})),
        ("read", json!({})),
        ("read.v01", json!({"x": 1})),
        ("read.v+1", json!({"x": 1})),
        (
            "fails.v1",
            json!({"idempotency_key": "f1", "input": {"x": 1}}),
        ),
        (
            "doubts.v1",
            json!({"idempotency_key": "d1", "input": {"x": 1}}),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k3", "input": {}, "detach": "yes"}),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k3", "input": {}, "extra": 1}),
        ),
    ] {
        let a = call(&stdio, tool, arguments.clone()).await;
        let b = call(&network, tool, arguments.clone()).await;
        assert_eq!(is_error(&a), is_error(&b), "{tool} {arguments}");
        assert_eq!(structured(&a), structured(&b), "{tool} {arguments}");
    }
    // Spot-check the actual outcomes, so equality cannot be two identical failures.
    let ok = call(&stdio, "read.v1", json!({"x": 1})).await;
    assert!(!is_error(&ok));
    assert_eq!(structured(&ok)["outcome"]["Success"]["caller"], "alice");
    assert_eq!(
        error_code(&call(&stdio, "read.v1", json!({"x": "no"})).await),
        "invalid_input"
    );
    assert_eq!(
        error_code(
            &call(
                &stdio,
                "write.v1",
                json!({"idempotency_key": "k1", "input": {"x": 2}})
            )
            .await
        ),
        "key_conflict"
    );
    assert_eq!(
        error_code(&call(&stdio, "write.v1", json!({"input": {"x": 1}})).await),
        "bad_request"
    );
    assert_eq!(
        error_code(&call(&stdio, "nothing.v1", json!({})).await),
        "not_found"
    );
    // Handler runs: three successful reads (stdio, network and the spot check above), the write for
    // `k1` exactly once though it was delivered three times over two transports, and `f1` and `d1`
    // once each, though each went over both transports. Nothing else ran: the invalid, conflicting,
    // keyless, unknown and mis-shaped calls never reached a handler.
    assert_eq!(world.calls.load(Ordering::SeqCst), 3 + 1 + 1 + 1);
}

#[tokio::test]
async fn an_unauthorised_caller_sees_no_tools_and_every_call_looks_like_an_unknown_tool() {
    let world = world().await;
    for client in [
        stdio_client(&world, "mallory").await,
        network_client(&world, "mallory-token").await,
    ] {
        let listed: Vec<_> = tools(&client).await.into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            listed,
            vec![EVENTS_TOOL, OPERATION_TOOL],
            "only the follow tools, which show nothing"
        );
        let unknown = structured(&call(&client, "nothing.v1", json!({})).await);
        for (tool, arguments) in [
            ("read.v1", json!({})),
            ("write.v1", json!({})),
            ("write.v1", json!({"idempotency_key": "k", "input": {}})),
            (
                "slow.v1",
                json!({"idempotency_key": "k", "input": {}, "detach": true}),
            ),
        ] {
            let denied = call(&client, tool, arguments.clone()).await;
            assert!(is_error(&denied));
            assert_eq!(
                structured(&denied),
                unknown,
                "{tool} {arguments} must look like an unknown tool"
            );
        }
    }
    assert_eq!(world.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_operation_started_over_one_transport_is_followed_over_the_other() {
    let world = world().await;
    let stdio = stdio_client(&world, "alice").await;
    let network = network_client(&world, "alice-token").await;
    let started = call(
        &stdio,
        "slow.v1",
        json!({"idempotency_key": "run", "input": {}, "detach": true}),
    )
    .await;
    assert!(!is_error(&started));
    let operation = structured(&started)["operation"]
        .as_str()
        .unwrap()
        .to_owned();
    // The network client, authenticated as the same caller, sees it running.
    let view = call(&network, OPERATION_TOOL, json!({"id": operation})).await;
    assert!(!is_error(&view));
    assert_eq!(structured(&view)["events"].as_array().unwrap().len(), 1);
    // Another authenticated, authorised caller cannot see it.
    let bob = stdio_client(&world, "bob").await;
    assert_eq!(
        error_code(&call(&bob, OPERATION_TOOL, json!({"id": operation})).await),
        "not_found"
    );
    world.release.notify_one();
    let events = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let r = call(&network, EVENTS_TOOL, json!({"id": operation, "cursor": 0})).await;
            let events = structured(&r)["events"].as_array().unwrap().clone();
            if events.len() == 2 {
                return events;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the operation completed");
    assert_eq!(
        events[1]["state"]["Completed"]["Success"]["caller"],
        "alice"
    );
    assert_eq!(world.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_retry_of_a_running_key_is_in_progress_not_a_lost_outcome() {
    let world = world().await;
    let client = stdio_client(&world, "alice").await;
    call(
        &client,
        "slow.v1",
        json!({"idempotency_key": "k", "input": {}, "detach": true}),
    )
    .await;
    let waited = tokio::time::timeout(
        Duration::from_secs(10),
        call(
            &client,
            "slow.v1",
            json!({"idempotency_key": "k", "input": {}}),
        ),
    )
    .await
    .expect("a retry of a running key answers instead of waiting");
    assert!(is_error(&waited));
    assert_eq!(error_code(&waited), "in_progress");
    assert_eq!(
        world.calls.load(Ordering::SeqCst),
        1,
        "the retry ran nothing"
    );
    world.release.notify_one();
}

#[tokio::test]
async fn malformed_follow_arguments_are_protocol_errors_not_tool_results() {
    let world = world().await;
    let client = stdio_client(&world, "alice").await;
    let result = client
        .call_tool(
            CallToolRequestParams::new(OPERATION_TOOL.to_string())
                .with_arguments(args(json!({"id": 7}))),
        )
        .await;
    assert!(result.is_err(), "a non-string id is a malformed request");
}

#[tokio::test]
async fn an_error_outcome_is_flagged_and_an_unknown_one_is_marked_uncertain_on_both_transports() {
    let world = world().await;
    for client in [
        stdio_client(&world, "alice").await,
        network_client(&world, "alice-token").await,
    ] {
        let failed = call(
            &client,
            "fails.v1",
            json!({"idempotency_key": "f", "input": {}}),
        )
        .await;
        assert!(is_error(&failed), "an error outcome is a tool error");
        assert_eq!(structured(&failed)["failed"], true);
        assert!(structured(&failed)["outcome"]["Error"].is_object());

        let doubted = call(
            &client,
            "doubts.v1",
            json!({"idempotency_key": "d", "input": {}}),
        )
        .await;
        assert!(!is_error(&doubted), "an unknown outcome is not a failure");
        assert_eq!(structured(&doubted)["uncertain"], true);
        assert!(structured(&doubted)["outcome"]["Unknown"].is_object());
    }
}

#[tokio::test]
async fn an_oversized_request_gets_one_answer_whatever_it_names() {
    let world = world().await;
    for client in [
        stdio_client(&world, "alice").await,
        stdio_client(&world, "mallory").await,
        network_client(&world, "mallory-token").await,
    ] {
        let huge_key = "k".repeat(300);
        let mut answers = Vec::new();
        for tool in ["write.v1", "nothing.v1", "read.v1"] {
            let result = call(
                &client,
                tool,
                json!({"idempotency_key": huge_key, "input": {}}),
            )
            .await;
            assert!(is_error(&result));
            answers.push(structured(&result));
        }
        assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
        assert_eq!(answers[0]["error"]["code"], "bad_request");
    }
    assert_eq!(world.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn events_are_read_from_the_cursor_given() {
    let world = world().await;
    let client = stdio_client(&world, "alice").await;
    let done = call(
        &client,
        "write.v1",
        json!({"idempotency_key": "e", "input": {}}),
    )
    .await;
    let operation = structured(&done)["operation"].as_str().unwrap().to_owned();
    for (cursor, expected) in [(0, 2), (1, 1), (2, 0), (99, 0)] {
        let r = call(
            &client,
            EVENTS_TOOL,
            json!({"id": operation, "cursor": cursor}),
        )
        .await;
        assert_eq!(
            structured(&r)["events"].as_array().unwrap().len(),
            expected,
            "cursor {cursor}"
        );
    }
    let default = call(&client, EVENTS_TOOL, json!({"id": operation})).await;
    assert_eq!(structured(&default)["events"].as_array().unwrap().len(), 2);
    for bad in [
        json!({"id": operation, "cursor": -1}),
        json!({"id": operation, "cursor": "0"}),
    ] {
        let result = client
            .call_tool(
                CallToolRequestParams::new(EVENTS_TOOL.to_string()).with_arguments(args(bad)),
            )
            .await;
        assert!(result.is_err(), "a malformed cursor is a protocol error");
    }
}

/// POSTs a JSON-RPC `initialize` to the network transport with the given headers.
async fn initialize(world: &World, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(&world.url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}}
        }));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().await.unwrap()
}

#[tokio::test]
async fn the_network_transport_enforces_authentication_and_origin_policy_at_its_boundary() {
    let world = world().await;
    let bearer = ("authorization", "Bearer alice-token");
    for (headers, status, code) in [
        (vec![], 401, "unauthenticated"),
        (
            vec![("authorization", "Bearer wrong")],
            401,
            "unauthenticated",
        ),
        (
            vec![bearer, ("origin", "https://evil.test")],
            403,
            "forbidden_origin",
        ),
        (vec![bearer, ("origin", "null")], 403, "forbidden_origin"),
        (
            vec![bearer, ("host", "rebound.test")],
            403,
            "forbidden_origin",
        ),
    ] {
        let response = initialize(&world, &headers).await;
        assert_eq!(response.status().as_u16(), status, "{headers:?}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], code, "{headers:?}");
    }
    // Refused requests ran nothing, and an admitted one works and creates no session.
    let response = initialize(&world, &[bearer, ("origin", ORIGIN)]).await;
    assert_eq!(response.status().as_u16(), 200);
    assert!(
        response.headers().get("mcp-session-id").is_none(),
        "the transport is stateless: there is no session to steal or exhaust"
    );
}

#[tokio::test]
async fn the_sdk_refuses_a_foreign_origin_even_without_the_boundary() {
    let world = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = OriginPolicy::new([address.to_string()], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits());
    let app = herald_mcp::routes(world.service.clone(), &boundary);
    let url = format!("http://{address}/mcp");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let response = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("origin", "https://evil.test")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
async fn the_unguarded_routes_refuse_every_call_because_no_boundary_named_a_caller() {
    let world = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = OriginPolicy::new([address.to_string()], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits());
    let app = herald_mcp::routes(world.service.clone(), &boundary);
    let url = format!("http://{address}/mcp");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = StreamableHttpClientTransportConfig::with_uri(url);
    let client = ().serve(StreamableHttpClientTransport::from_config(config)).await;
    let client = client.expect("the SDK admits a host in its list; the handler refuses the call");
    assert!(client.list_all_tools().await.is_err());
    assert_eq!(world.calls.load(Ordering::SeqCst), 0);
}
