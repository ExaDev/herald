//! Real `rmcp` clients against the adapter over both transports. The stdio-style transport is an in-memory pipe carrying the same newline-delimited JSON-RPC that stdio does; the network transport is streamable HTTP on a real socket behind the boundary.

use axum::http::{HeaderMap, header};
use herald::{
    Authorizer, Cancellation, CapabilityId, Clock, Confirmer, Contract, DispatchError, Dispatcher,
    Handler, Kind, Observer, Outcome, PortFuture, Request, Support,
    exposure::{Exposure, Surface},
    runtime::{MemoryOperationStore, RunningLimit, Runtime},
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
    Limits::new(Duration::from_secs(60), 64, 64).unwrap()
}

const ORIGIN: &str = "https://app.example.test";

/// Holds the authorisation of the `gated` capability until it is released, like a product whose policy store stalls.
#[derive(Default)]
struct Gate {
    entered: AtomicUsize,
    release: Notify,
}

#[derive(Default)]
struct Policy {
    gate: Arc<Gate>,
}
impl Authorizer for Policy {
    fn authorize<'a>(&'a self, r: &'a Request, c: &'a Contract) -> PortFuture<'a, bool> {
        Box::pin(async move {
            if c.id.name == "gated" {
                self.gate.entered.fetch_add(1, Ordering::SeqCst);
                self.gate.release.notified().await;
            }
            ["alice", "bob"].contains(&r.identity.as_str())
        })
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
                Behaviour::Succeed | Behaviour::Stubborn => Outcome::Success(body),
                Behaviour::Panic => panic!("handler failure"),
                Behaviour::Invalid => Outcome::Success(json!(5)),
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
            let principal: Option<Principal> =
                (|| match headers.get(header::AUTHORIZATION)?.to_str().ok()? {
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
    cancelled: Arc<AtomicUsize>,
    release: Arc<Notify>,
    gate: Arc<Gate>,
    url: String,
    _server: tokio::task::JoinHandle<()>,
}

async fn world() -> World {
    world_with(limits()).await
}

/// A world whose boundary is bounded as stated, to test the limits themselves.
async fn world_with(boundary_limits: Limits) -> World {
    let policy = Arc::new(Policy::default());
    let gate = policy.gate.clone();
    let (calls, release) = (Arc::new(AtomicUsize::new(0)), Arc::new(Notify::new()));
    let cancelled = Arc::new(AtomicUsize::new(0));
    let mut d = Dispatcher::new(policy.clone(), policy.clone(), policy.clone(), policy);
    for (name, kind, wait, behaviour) in [
        ("read", Kind::Query, false, Behaviour::Succeed),
        ("gated", Kind::Query, false, Behaviour::Succeed),
        ("write", Kind::Operation, false, Behaviour::Succeed),
        ("slow", Kind::Operation, true, Behaviour::Succeed),
        ("hang", Kind::Query, true, Behaviour::Succeed),
        ("stubborn", Kind::Query, true, Behaviour::Stubborn),
        ("fails", Kind::Operation, false, Behaviour::Fail),
        ("doubts", Kind::Operation, false, Behaviour::Doubt),
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
    let (runtime, _) = Runtime::open_limited(
        d.clone(),
        Arc::new(MemoryOperationStore::default()),
        RunningLimit::new(64, 64, Duration::from_secs(600)).unwrap(),
    )
    .await
    .unwrap();
    let exposure = [
        "read",
        "gated",
        "write",
        "slow",
        "hang",
        "stubborn",
        "fails",
        "doubts",
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
    .fold(Exposure::none(), |e, n| e.allow(Surface::Mcp, id(n)));
    let service = Arc::new(Service::new(Arc::new(runtime), exposure));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let policy = OriginPolicy::new([format!("127.0.0.1:{port}")], [ORIGIN.to_string()]).unwrap();
    let app = router(
        service.clone(),
        Boundary::new(Arc::new(Tokens), policy, boundary_limits).unwrap(),
    )
    .unwrap();
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
        gate,
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
        .map(|t| {
            // Everything a client reads about a tool, so two transports cannot differ in any of it.
            let described = json!({
                "input": *t.input_schema,
                "output": t.output_schema.as_ref().map(|s| (**s).clone()),
                "annotations": t.annotations,
                "meta": t.meta,
                "description": t.description,
            });
            (t.name.to_string(), described)
        })
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
            "confirms.v1",
            "doubts.v1",
            "fails.v1",
            "hang.v1",
            EVENTS_TOOL,
            OPERATION_TOOL,
            "invalid.v1",
            "panicq.v1",
            "panics.v1",
            "read.v1",
            "slow.v1",
            "stubborn.v1",
            "unsupported.v1",
            "unsure.v1",
            "wide.v1",
            "write.v1"
        ]
    );
    // An operation tool wraps the capability's input with an idempotency key.
    let write = &over_stdio.iter().find(|(n, _)| n == "write.v1").unwrap().1;
    assert_eq!(
        write["input"]["required"],
        json!(["idempotency_key", "input"])
    );
    assert_eq!(
        write["input"]["properties"]["input"]["properties"]["x"]["type"],
        "integer"
    );
    // A query changes nothing and says so; an operation does not claim to. The product's facts ride in `_meta`.
    let read = &over_stdio.iter().find(|(n, _)| n == "read.v1").unwrap().1;
    assert_eq!(read["annotations"]["readOnlyHint"], true);
    assert_eq!(write["annotations"]["readOnlyHint"], false);
    assert_eq!(write["meta"]["herald"]["kind"], "Operation");
    assert_eq!(write["meta"]["herald"]["confirmation_required"], false);
    assert_eq!(write["meta"]["herald"]["support"], "Supported");
    assert!(
        read["output"]["anyOf"].is_array(),
        "every capability tool declares its output"
    );
}

#[tokio::test]
async fn the_same_calls_give_the_same_results_over_both_transports() {
    /// What a row must produce, so equality between the transports cannot be two identical mistakes.
    enum Expect {
        /// A result with an outcome or a start state, not flagged as an error.
        Result,
        /// A result whose operation reported an error outcome: flagged, with `failed`.
        Failed,
        /// A typed error with this code.
        Code(&'static str),
    }
    use Expect::{Code, Failed, Result as Ok_};
    // Two identical worlds, so each row is a fresh execution on both transports and not a replay of the other's.
    let world = world().await;
    let network_world = world_with(limits()).await;
    let stdio = stdio_client(&world, "alice").await;
    let network = network_client(&network_world, "alice-token").await;
    let rows: Vec<(&str, Value, Expect)> = vec![
        ("read.v1", json!({"x": 1}), Ok_),
        (
            "read.v1",
            json!({"x": "not an integer"}),
            Code("invalid_input"),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 1}}),
            Ok_,
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 1}}),
            Ok_,
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 2}}),
            Code("key_conflict"),
        ),
        ("write.v1", json!({"input": {"x": 1}}), Code("bad_request")),
        (
            "write.v1",
            json!({"idempotency_key": "k2", "input": {"x": "bad"}}),
            Code("invalid_input"),
        ),
        ("nothing.v1", json!({}), Code("not_found")),
        ("read", json!({}), Code("not_found")),
        ("read.v01", json!({"x": 1}), Code("not_found")),
        ("read.v+1", json!({"x": 1}), Code("not_found")),
        (
            "fails.v1",
            json!({"idempotency_key": "f1", "input": {"x": 1}}),
            Failed,
        ),
        (
            "doubts.v1",
            json!({"idempotency_key": "d1", "input": {"x": 1}}),
            Ok_,
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k3", "input": {}, "detach": "yes"}),
            Code("bad_request"),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k3", "input": {}, "extra": 1}),
            Code("bad_request"),
        ),
        // Start and detach: running, the same key started again, a synchronous retry of the running key, a completed key started again (a finished start), and a failed one.
        (
            "slow.v1",
            json!({"idempotency_key": "s1", "input": {}, "detach": true}),
            Ok_,
        ),
        (
            "slow.v1",
            json!({"idempotency_key": "s1", "input": {}, "detach": true}),
            Ok_,
        ),
        (
            "slow.v1",
            json!({"idempotency_key": "s1", "input": {}}),
            Code("in_progress"),
        ),
        (
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 1}, "detach": true}),
            Ok_,
        ),
        (
            "fails.v1",
            json!({"idempotency_key": "f1", "input": {"x": 1}, "detach": true}),
            Failed,
        ),
        // Over the input bound but inside the request bound: judged after authorisation.
        (
            "write.v1",
            json!({"idempotency_key": "big", "input": {"blob": "x".repeat(herald::service::MAX_INPUT_BYTES)}}),
            Code("too_large"),
        ),
        // Failures other than the caller's. Those whose effect may have happened name the operation.
        (
            "confirms.v1",
            json!({"idempotency_key": "q1", "input": {}}),
            Code("confirmation_required"),
        ),
        ("unsupported.v1", json!({}), Code("unsupported")),
        ("unsure.v1", json!({}), Code("support_unknown")),
        (
            "invalid.v1",
            json!({"idempotency_key": "q2", "input": {}}),
            Code("contract_violation"),
        ),
        (
            "panics.v1",
            json!({"idempotency_key": "q3", "input": {}}),
            Code("outcome_lost"),
        ),
        ("panicq.v1", json!({}), Code("outcome_lost")),
    ];
    for (tool, arguments, expect) in rows {
        let a = call(&stdio, tool, arguments.clone()).await;
        let b = call(&network, tool, arguments.clone()).await;
        assert_eq!(is_error(&a), is_error(&b), "{tool} {arguments}");
        assert_eq!(structured(&a), structured(&b), "{tool} {arguments}");
        match expect {
            Ok_ => {
                assert!(!is_error(&a), "{tool} {arguments}: {}", structured(&a));
                let body = structured(&a);
                assert!(
                    body.get("outcome").is_some() || body.get("state").is_some(),
                    "{tool} {arguments}: {body}"
                );
            }
            Failed => {
                assert!(is_error(&a), "{tool} {arguments}");
                assert_eq!(structured(&a)["failed"], true, "{tool} {arguments}");
            }
            Code(code) => {
                assert!(is_error(&a), "{tool} {arguments}");
                assert_eq!(error_code(&a), code, "{tool} {arguments}");
                // An error that means the operation may have run names it, a query has none.
                if matches!(code, "contract_violation" | "outcome_lost" | "in_progress") {
                    assert_eq!(
                        structured(&a)["error"]["detail"]["operation"].is_string(),
                        tool != "panicq.v1",
                        "{tool} {arguments}: {}",
                        structured(&a)
                    );
                }
            }
        }
    }
    // The started operation is one operation, and a finished start says so.
    let finished = structured(
        &call(
            &stdio,
            "write.v1",
            json!({"idempotency_key": "k1", "input": {"x": 1}, "detach": true}),
        )
        .await,
    );
    assert_eq!(finished["state"], "finished");
    let running = structured(
        &call(
            &stdio,
            "slow.v1",
            json!({"idempotency_key": "s1", "input": {}, "detach": true}),
        )
        .await,
    );
    assert_eq!(running["state"], "running");
    // Each world ran every row fresh. A handler ran for: the read; the write `k1` (its replay and its detached repeat did not run); `f1`, `d1` and `s1`; the contract violation, the panicking operation and the panicking query. Rows refused before the handler (shape, bounds, consent, support, conflict, unknown) ran nothing.
    for (name, world) in [("stdio", &world), ("network", &network_world)] {
        assert_eq!(world.calls.load(Ordering::SeqCst), 8, "{name} world");
    }
    world.release.notify_one();
    network_world.release.notify_one();
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
async fn unreadable_follow_arguments_are_typed_results_a_model_can_read_on_both_transports() {
    let world = world().await;
    for client in [
        stdio_client(&world, "alice").await,
        network_client(&world, "alice-token").await,
    ] {
        for (tool, arguments) in [
            (OPERATION_TOOL, json!({"id": 7})),
            (OPERATION_TOOL, json!({})),
            (EVENTS_TOOL, json!({"id": "op-x", "cursor": -1})),
            (EVENTS_TOOL, json!({"id": "op-x", "cursor": "0"})),
            // The published schema allows no other argument, so none is taken.
            (OPERATION_TOOL, json!({"id": "op-x", "extra": 1})),
            (EVENTS_TOOL, json!({"id": "op-x", "cursor": 0, "extra": 1})),
        ] {
            let result = call(&client, tool, arguments.clone()).await;
            assert!(is_error(&result), "{tool} {arguments}");
            assert_eq!(error_code(&result), "bad_request", "{tool} {arguments}");
        }
    }
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
    let huge = "x".repeat(herald::service::MAX_REQUEST_BYTES);
    let long_key = "k".repeat(herald::service::MAX_KEY_BYTES + 1);
    for client in [
        stdio_client(&world, "alice").await,
        stdio_client(&world, "mallory").await,
    ] {
        // Over the request bound: judged before any lookup, so every name gives the same answer.
        let mut answers = Vec::new();
        for tool in ["write.v1", "nothing.v1", "read.v1"] {
            let result = call(
                &client,
                tool,
                json!({"idempotency_key": "k", "input": {"blob": huge}}),
            )
            .await;
            assert!(is_error(&result));
            answers.push(structured(&result));
        }
        assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
        assert_eq!(answers[0]["error"]["code"], "too_large");
    }
    // On the network the transport enforces the same bound before the handler runs, as a typed 413.
    let response = reqwest::Client::new()
        .post(&world.url)
        .header("authorization", "Bearer mallory-token")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(format!("{{\"pad\":\"{huge}\"}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 413);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "too_large");
    // A key over its bound is judged after authorisation: a denied caller and an unknown tool look the same, and only an authorised caller is told.
    let mallory = stdio_client(&world, "mallory").await;
    let alice = stdio_client(&world, "alice").await;
    let arguments = json!({"idempotency_key": long_key, "input": {}});
    let denied = structured(&call(&mallory, "write.v1", arguments.clone()).await);
    let unknown = structured(&call(&mallory, "nothing.v1", arguments.clone()).await);
    assert_eq!(denied, unknown);
    assert_eq!(denied["error"]["code"], "not_found");
    let told = call(&alice, "write.v1", arguments).await;
    assert_eq!(error_code(&told), "too_large");
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
        let result = call(&client, EVENTS_TOOL, bad).await;
        assert_eq!(error_code(&result), "bad_request");
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
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits()).unwrap();
    let app = herald_mcp::routes(world.service.clone(), &boundary).unwrap();
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
    // The SDK's refusal is a plain-text body, and the adapter makes it a typed one.
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden_origin");
}

#[tokio::test]
async fn the_unguarded_routes_refuse_every_call_because_no_boundary_named_a_caller() {
    let world = world().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = OriginPolicy::new([address.to_string()], [ORIGIN.to_string()]).unwrap();
    let boundary = Boundary::new(Arc::new(Tokens), policy, limits()).unwrap();
    let app = herald_mcp::routes(world.service.clone(), &boundary).unwrap();
    let url = format!("http://{address}/mcp");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = StreamableHttpClientTransportConfig::with_uri(url);
    let client = ().serve(StreamableHttpClientTransport::from_config(config)).await;
    let client = client.expect("the SDK admits a host in its list; the handler refuses the call");
    // A call is a typed wiring fault, the same code the HTTP adapter reports, and not an authentication failure.
    let refused = call(&client, "read.v1", json!({"x": 1})).await;
    assert!(is_error(&refused));
    assert_eq!(error_code(&refused), "contract_violation");
    assert!(
        structured(&refused)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("boundary")
    );
    // Listing has no tool result to carry a typed error, so it is a protocol error that names the fault.
    let listing = client
        .list_all_tools()
        .await
        .expect_err("no boundary named a caller");
    assert!(listing.to_string().contains("boundary"), "{listing}");
    assert_eq!(world.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refusals_from_the_sdk_and_unmatched_paths_are_typed_errors() {
    let world = world().await;
    let base = world.url.trim_end_matches("/mcp").to_owned();
    let client = reqwest::Client::new();
    let authed =
        |request: reqwest::RequestBuilder| request.header("authorization", "Bearer alice-token");
    // Each refusal with the status it keeps and the typed code it gets. The SDK refuses a GET on a stateless service and a POST with the wrong media type; the router refuses what it has no route for.
    let cases = [
        (
            authed(client.get(format!("{base}/mcp"))),
            405,
            "method_not_allowed",
        ),
        (
            authed(client.post(format!("{base}/mcp")))
                .header("content-type", "text/plain")
                .header("accept", "application/json, text/event-stream")
                .body("x"),
            415,
            "unsupported_media",
        ),
        // The wrong `Accept` is the SDK's 406, which keeps its status and gets the media-type code.
        (
            authed(client.post(format!("{base}/mcp")))
                .header("content-type", "application/json")
                .header("accept", "text/plain")
                .body("{}"),
            406,
            "unsupported_media",
        ),
        (
            authed(client.get(format!("{base}/mcp/anything"))),
            404,
            "not_found",
        ),
        (
            authed(client.get(format!("{base}/elsewhere"))),
            404,
            "not_found",
        ),
    ];
    for (request, status, code) in cases {
        let response = request.send().await.unwrap();
        assert_eq!(response.status().as_u16(), status, "{code}");
        let content_type = response.headers()["content-type"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            content_type.starts_with("application/json"),
            "{status} {content_type}"
        );
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"]["code"], code, "{status} {body}");
    }
}

#[tokio::test]
async fn a_tool_schema_keeps_its_own_pointers_valid_once_nested_in_the_operation_wrapper() {
    let descriptor = herald::service::Descriptor {
        id: id("shape"),
        kind: Kind::Operation,
        input_schema: json!({
            "type": "object",
            "properties": {
                "point": {"$ref": "#/$defs/Point"},
                "next": {"$ref": "#"},
                "again": {"$ref": "#/properties/point"}
            },
            "$defs": {"Point": {"type": "object", "properties": {"back": {"$ref": "#"}}}}
        }),
        output_schema: json!({"type": "object"}),
        error_schema: json!({"type": "object"}),
        confirmation_required: false,
        support: Support::Supported,
    };
    let schema = herald_mcp::tool_input_schema(&descriptor);
    assert!(schema["properties"]["input"].get("$defs").is_none());
    assert_eq!(
        schema["$defs"]["Point"]["properties"]["back"]["$ref"],
        "#/properties/input"
    );
    let input = &schema["properties"]["input"]["properties"];
    assert_eq!(input["point"]["$ref"], "#/$defs/Point");
    assert_eq!(input["next"]["$ref"], "#/properties/input");
    assert_eq!(
        input["again"]["$ref"],
        "#/properties/input/properties/point"
    );
}

#[tokio::test]
async fn a_network_call_the_client_abandons_cancels_the_handler_and_a_detached_start_survives() {
    let world = world().await;
    let rpc = |id: u64, tool: &str, arguments: Value| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments}})
    };
    let post = |client: &reqwest::Client, body: Value| {
        client
            .post(&world.url)
            .header("authorization", "Bearer alice-token")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
    };
    let client = reqwest::Client::new();
    let abandoning = {
        let request = post(
            &client,
            rpc(
                1,
                "slow.v1",
                json!({"idempotency_key": "abandon", "input": {}}),
            ),
        );
        tokio::spawn(request)
    };
    // Abort only once the handler is running, so what follows is the abandonment and not a request that never arrived.
    wait_until(|| world.calls.load(Ordering::SeqCst) == 1).await;
    abandoning.abort();
    wait_until(|| world.cancelled.load(Ordering::SeqCst) == 1).await;

    let started = post(
        &client,
        rpc(
            2,
            "slow.v1",
            json!({"idempotency_key": "detached", "input": {}, "detach": true}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(started.status().as_u16(), 200);
    let started: Value = started.json().await.unwrap();
    let operation = started["result"]["structuredContent"]["operation"]
        .as_str()
        .unwrap()
        .to_owned();
    // The start request has ended. The operation is still running, not cancelled: releasing it completes it, and nothing was told to stop.
    wait_until(|| world.calls.load(Ordering::SeqCst) == 2).await;
    world.release.notify_one();
    let network = network_client(&world, "alice-token").await;
    wait_for_events(&network, &operation, 2).await;
    assert_eq!(world.cancelled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_stdio_call_the_client_cancels_is_cancelled_by_the_protocol() {
    use rmcp::model::{CallToolRequest, ClientRequest};
    use rmcp::service::PeerRequestOptions;
    let world = world().await;
    let client = stdio_client(&world, "alice").await;
    let params = CallToolRequestParams::new("slow.v1".to_string())
        .with_arguments(args(json!({"idempotency_key": "c", "input": {}})));
    let handle = client
        .peer()
        .send_cancellable_request(
            ClientRequest::CallToolRequest(CallToolRequest::new(params)),
            PeerRequestOptions::no_options(),
        )
        .await
        .unwrap();
    wait_until(|| world.calls.load(Ordering::SeqCst) == 1).await;
    handle.cancel(Some("test".into())).await.unwrap();
    wait_until(|| world.cancelled.load(Ordering::SeqCst) == 1).await;
}

/// Polls `condition` until it holds, giving up after a generous bound so a failure reports instead of hanging. The bound is only a backstop: every caller waits on an event another task will cause.
async fn wait_until(condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the awaited event happened");
}

/// Reads `operation`'s events over `client` until there are `count` of them.
async fn wait_for_events(client: &Client, operation: &str, count: usize) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let events = call(client, EVENTS_TOOL, json!({"id": operation})).await;
            if structured(&events)["events"].as_array().unwrap().len() >= count {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the operation reached the awaited state");
}

#[tokio::test]
async fn every_result_a_tool_returns_validates_against_the_output_schema_it_declared() {
    let world = world().await;
    let listed = network_client(&world, "alice-token")
        .await
        .list_all_tools()
        .await
        .unwrap();
    let schema_of = |name: &str| {
        let tool = listed.iter().find(|t| t.name == name).unwrap();
        let schema =
            Value::Object((**tool.output_schema.as_ref().expect("an output schema")).clone());
        jsonschema::validator_for(&schema).expect("a valid schema")
    };
    for client in [
        stdio_client(&world, "alice").await,
        network_client(&world, "alice-token").await,
    ] {
        for (tool, arguments) in [
            ("read.v1", json!({"x": 1})),
            ("read.v1", json!({"x": "bad"})),
            (
                "write.v1",
                json!({"idempotency_key": "w", "input": {"x": 1}}),
            ),
            (
                "write.v1",
                json!({"idempotency_key": "w", "input": {"x": 1}, "detach": true}),
            ),
            (
                "write.v1",
                json!({"idempotency_key": "w", "input": {"x": 2}}),
            ),
            ("fails.v1", json!({"idempotency_key": "f", "input": {}})),
            ("doubts.v1", json!({"idempotency_key": "d", "input": {}})),
            (
                "slow.v1",
                json!({"idempotency_key": "s", "input": {}, "detach": true}),
            ),
        ] {
            let result = structured(&call(&client, tool, arguments.clone()).await);
            assert!(
                schema_of(tool).is_valid(&result),
                "{tool} {arguments} returned {result}"
            );
        }
    }
    // A result the schema was never meant to admit is refused.
    assert!(!schema_of("read.v1").is_valid(&json!({"outcome": 3})));
    world.release.notify_one();
}

#[test]
fn definitions_in_input_output_and_error_schemas_resolve_in_the_published_tool_schemas() {
    let descriptor = herald::service::Descriptor {
        id: id("shape"),
        kind: Kind::Operation,
        input_schema: json!({
            "type": "object",
            "properties": {"a": {"$ref": "#/definitions/A"}, "again": {"$ref": "#/properties/a"}},
            "definitions": {"A": {"type": "object", "properties": {"b": {"$ref": "#/definitions/B"}}},
                            "B": {"type": "integer"}}
        }),
        output_schema: json!({
            "type": "object", "properties": {"n": {"$ref": "#/$defs/N"}, "me": {"$ref": "#"}},
            "$defs": {"N": {"type": "integer"}}
        }),
        error_schema: json!({
            "type": "object", "properties": {"why": {"$ref": "#/$defs/N"}},
            "$defs": {"N": {"type": "string"}}
        }),
        confirmation_required: false,
        support: Support::Supported,
    };
    let input = herald_mcp::tool_input_schema(&descriptor);
    let input = jsonschema::validator_for(&input).expect("input schema is valid");
    assert!(
        input.is_valid(
            &json!({"idempotency_key": "k", "input": {"a": {"b": 1}, "again": {"b": 2}}})
        )
    );
    assert!(!input.is_valid(&json!({"idempotency_key": "k", "input": {"a": {"b": "x"}}})));

    let output = herald_mcp::tool_output_schema(&descriptor);
    let output = jsonschema::validator_for(&output).expect("output schema is valid");
    let success = |body: Value| json!({"operation": "op-1", "outcome": {"Success": body}});
    assert!(output.is_valid(&success(json!({"n": 1, "me": {"n": 2}}))));
    assert!(!output.is_valid(&success(json!({"n": "x"}))));
    // The two capabilities' `N` definitions do not collide: the error's is a string.
    assert!(output.is_valid(&json!({"operation": "op-1", "outcome": {"Error": {"why": "text"}}})));
    assert!(!output.is_valid(&json!({"operation": "op-1", "outcome": {"Error": {"why": 3}}})));
}

#[tokio::test]
async fn a_refusal_the_sdk_makes_keeps_the_headers_the_status_requires() {
    let world = world().await;
    let response = reqwest::Client::new()
        .get(&world.url)
        .header("authorization", "Bearer alice-token")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 405);
    assert!(
        response.headers().get("allow").is_some(),
        "a 405 names the allowed methods"
    );
}

#[tokio::test]
async fn an_abandoned_network_query_is_told_to_stop() {
    let world = world().await;
    let post = |body: Value| {
        reqwest::Client::new()
            .post(&world.url)
            .header("authorization", "Bearer alice-token")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&body)
            .send()
    };
    let rpc = |id: u64, tool: &str, arguments: Value| {
        json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments}})
    };
    let abandoning = tokio::spawn(post(rpc(1, "hang.v1", json!({}))));
    wait_until(|| world.calls.load(Ordering::SeqCst) == 1).await;
    abandoning.abort();
    wait_until(|| world.cancelled.load(Ordering::SeqCst) == 1).await;
}

#[tokio::test]
async fn the_follow_tools_declare_output_schemas_their_results_satisfy() {
    let world = world().await;
    let client = network_client(&world, "alice-token").await;
    let listed = client.list_all_tools().await.unwrap();
    let done = structured(
        &call(
            &client,
            "write.v1",
            json!({"idempotency_key": "w", "input": {}}),
        )
        .await,
    );
    let operation = done["operation"].as_str().unwrap().to_owned();
    for (tool, arguments) in [
        (OPERATION_TOOL, json!({"id": operation})),
        (EVENTS_TOOL, json!({"id": operation})),
    ] {
        let schema = listed.iter().find(|t| t.name == tool).unwrap();
        let schema =
            Value::Object((**schema.output_schema.as_ref().expect("an output schema")).clone());
        let validator = jsonschema::validator_for(&schema).unwrap();
        let result = structured(&call(&client, tool, arguments).await);
        assert!(validator.is_valid(&result), "{tool}: {result}");
        assert!(!validator.is_valid(&json!({"unrelated": true})));
    }
}

/// POSTs a `tools/call` to the network transport and returns the response.
async fn rpc_call(world: &World, tool: &str, arguments: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(&world.url)
        .header("authorization", "Bearer alice-token")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": tool, "arguments": arguments}}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_detached_mcp_start_gives_its_slot_back_so_the_operation_can_be_followed() {
    let world = world_with(Limits::new(Duration::from_secs(60), 1, 1).unwrap()).await;
    let started = rpc_call(
        &world,
        "slow.v1",
        json!({"idempotency_key": "long", "input": {}, "detach": true}),
    )
    .await;
    assert_eq!(started.status().as_u16(), 200);
    let started: Value = started.json().await.unwrap();
    let operation = started["result"]["structuredContent"]["operation"]
        .as_str()
        .unwrap()
        .to_owned();
    wait_until(|| world.calls.load(Ordering::SeqCst) == 1).await;
    // The handler is running and the only request slot is free: the operation can be read.
    let view = rpc_call(&world, OPERATION_TOOL, json!({"id": operation})).await;
    assert_eq!(view.status().as_u16(), 200);
    let view: Value = view.json().await.unwrap();
    assert_ne!(view["result"]["isError"], true, "{view}");
    world.release.notify_waiters();
}

#[tokio::test]
async fn a_synchronous_mcp_call_holds_the_slot_until_its_handler_returns_even_after_its_deadline() {
    let world = world_with(Limits::new(Duration::from_secs(3), 1, 1).unwrap()).await;
    let request = tokio::spawn({
        let client = reqwest::Client::new();
        client
            .post(&world.url)
            .header("authorization", "Bearer alice-token")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "stubborn.v1", "arguments": {}}}))
            .send()
    });
    // The handler is running and cannot be interrupted. The request ends at the deadline.
    wait_until(|| world.calls.load(Ordering::SeqCst) == 1).await;
    let ended = request.await.unwrap().unwrap();
    assert_eq!(ended.status().as_u16(), 504);
    // The request is gone, but the handler is not, so its slot is still taken: the next request is shed with a typed 503. Without the hold the deadline would have freed the slot.
    let shed = rpc_call(&world, "read.v1", json!({"x": 1})).await;
    assert_eq!(shed.status().as_u16(), 503);
    let body: Value = shed.json().await.unwrap();
    assert_eq!(body["error"]["code"], "unavailable");
    world.release.notify_waiters();
    // Once the handler returns, the slot is free again.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if rpc_call(&world, "read.v1", json!({"x": 1}))
                .await
                .status()
                .as_u16()
                == 200
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the slot came back");
}
#[tokio::test]
async fn an_mcp_call_stalled_in_authorisation_keeps_its_slot_after_the_request_deadline() {
    let world = world_with(Limits::new(Duration::from_secs(3), 1, 1).unwrap()).await;
    let request = tokio::spawn({
        let client = reqwest::Client::new();
        client
            .post(&world.url)
            .header("authorization", "Bearer alice-token")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "gated.v1", "arguments": {}}}))
            .send()
    });
    // The handler is waiting in authorisation, before any execution. The request ends at the deadline.
    wait_until(|| world.gate.entered.load(Ordering::SeqCst) == 1).await;
    let ended = request.await.unwrap().unwrap();
    assert_eq!(ended.status().as_u16(), 504);
    // The request is gone but the handler task is not, so its slot is still taken and the next request is shed. Without the hold from the first await the deadline would have freed the slot while work was still running.
    let shed = rpc_call(&world, "read.v1", json!({"x": 1})).await;
    assert_eq!(shed.status().as_u16(), 503);
    world.gate.release.notify_waiters();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if rpc_call(&world, "read.v1", json!({"x": 1}))
                .await
                .status()
                .as_u16()
                == 200
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the slot came back");
}
#[tokio::test]
async fn a_service_over_an_unbounded_runtime_cannot_be_served_over_a_network() {
    let policy = Arc::new(Policy::default());
    let mut d = Dispatcher::new(policy.clone(), policy.clone(), policy.clone(), policy);
    d.register(
        contract("read", Kind::Query),
        Arc::new(Work {
            calls: Arc::new(AtomicUsize::new(0)),
            cancelled: Arc::new(AtomicUsize::new(0)),
            release: None,
            behaviour: Behaviour::Succeed,
        }),
    )
    .unwrap();
    let d = Arc::new(d);
    let (runtime, _) = Runtime::open(d, Arc::new(MemoryOperationStore::default()))
        .await
        .unwrap();
    let service = Arc::new(Service::new(Arc::new(runtime), Exposure::none()));
    assert!(HeraldMcp::network(service.clone()).is_err());
    let address = "127.0.0.1:8080".to_string();
    let boundary = Boundary::new(
        Arc::new(Tokens),
        OriginPolicy::new([address], [ORIGIN.to_string()]).unwrap(),
        limits(),
    )
    .unwrap();
    assert!(herald_mcp::routes(service.clone(), &boundary).is_err());
    assert!(herald_mcp::router(service, boundary).is_err());
    // Stdio has no network to be flooded from, so it needs no bound.
    let _ = HeraldMcp::stdio(
        Arc::new(Service::new(
            Arc::new(
                Runtime::open(
                    Arc::new(Dispatcher::new(
                        Arc::new(Policy),
                        Arc::new(Policy),
                        Arc::new(Policy),
                        Arc::new(Policy),
                    )),
                    Arc::new(MemoryOperationStore::default()),
                )
                .await
                .unwrap()
                .0,
            ),
            Exposure::none(),
        )),
        Principal::new("alice").unwrap(),
    );
}

#[tokio::test]
async fn the_follow_tools_are_read_only_and_their_output_schemas_are_objects_at_the_root() {
    let world = world().await;
    let listed = network_client(&world, "alice-token")
        .await
        .list_all_tools()
        .await
        .unwrap();
    for name in [OPERATION_TOOL, EVENTS_TOOL] {
        let tool = listed.iter().find(|t| t.name == name).unwrap();
        let schema = tool.output_schema.as_ref().expect("an output schema");
        assert_eq!(schema["type"], "object", "{name}: an object at the root");
        let validator = jsonschema::validator_for(&Value::Object((**schema).clone())).unwrap();
        let failed = structured(
            &call(
                &network_client(&world, "alice-token").await,
                name,
                json!({"id": "op-missing"}),
            )
            .await,
        );
        assert!(
            validator.is_valid(&failed),
            "{name}: a failed follow matches its schema: {failed}"
        );
        assert!(
            schema["$defs"].is_object(),
            "{name}: its definitions travel with it"
        );
        assert_eq!(
            tool.annotations.as_ref().and_then(|a| a.read_only_hint),
            Some(true),
            "{name} only reads"
        );
    }
}

#[test]
fn an_operation_input_nested_in_the_wrapper_names_no_dialect_of_its_own() {
    let descriptor = herald::service::Descriptor {
        id: id("shape"),
        kind: Kind::Operation,
        input_schema: json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"a": {"type": "integer"}}
        }),
        output_schema: json!({"type": "object"}),
        error_schema: json!({"type": "object"}),
        confirmation_required: false,
        support: Support::Supported,
    };
    let schema = herald_mcp::tool_input_schema(&descriptor);
    assert!(schema["properties"]["input"].get("$schema").is_none());
    assert_eq!(
        schema["properties"]["input"]["properties"]["a"]["type"],
        "integer"
    );
    jsonschema::validator_for(&schema).expect("the wrapper is a valid schema");
}

#[tokio::test]
async fn a_query_whose_input_is_not_an_object_is_not_offered_as_a_tool_but_is_still_checked_if_named()
 {
    let world = world().await;
    let client = network_client(&world, "alice-token").await;
    let listed = client.list_all_tools().await.unwrap();
    assert!(
        listed.iter().all(|t| t.name != "scalar.v1"),
        "arguments are an object, so a scalar input has no tool"
    );
    // Named anyway, it is judged like any other call: the arguments object is not an integer.
    let refused = call(&client, "scalar.v1", json!({})).await;
    assert_eq!(error_code(&refused), "invalid_input");
}

#[tokio::test]
async fn a_request_at_exactly_the_largest_input_and_longest_key_is_accepted_not_refused() {
    use herald::service::{MAX_INPUT_BYTES, MAX_KEY_BYTES};
    let world = world().await;
    // `{"pad":"..."}` is ten bytes around the padding, and the service bounds the serialised input.
    let input = json!({"pad": "x".repeat(MAX_INPUT_BYTES - 10)});
    assert_eq!(input.to_string().len(), MAX_INPUT_BYTES);
    let key = "k".repeat(MAX_KEY_BYTES);
    let over_network = call(
        &network_client(&world, "alice-token").await,
        "wide.v1",
        json!({"idempotency_key": key, "input": input}),
    )
    .await;
    assert!(!is_error(&over_network), "{}", structured(&over_network));
    let over_stdio = call(
        &stdio_client(&world, "alice").await,
        "wide.v1",
        json!({"idempotency_key": "k".repeat(MAX_KEY_BYTES - 1), "input": input}),
    )
    .await;
    assert!(!is_error(&over_stdio), "{}", structured(&over_stdio));
    // One byte more is refused as too large.
    let over = call(
        &stdio_client(&world, "alice").await,
        "wide.v1",
        json!({"idempotency_key": "other", "input": {"pad": "x".repeat(MAX_INPUT_BYTES - 9)}}),
    )
    .await;
    assert_eq!(error_code(&over), "too_large");
}

#[tokio::test]
async fn a_synchronous_mcp_call_that_reaches_the_request_deadline_is_told_to_stop() {
    let world = world_with(Limits::new(Duration::from_secs(3), 64, 64).unwrap()).await;
    let ended = rpc_call(&world, "hang.v1", json!({})).await;
    assert_eq!(ended.status().as_u16(), 504);
    let body: Value = ended.json().await.unwrap();
    assert_eq!(body["error"]["code"], "timed_out");
    // The handler is cooperative, so it sees its cancellation and returns.
    wait_until(|| world.cancelled.load(Ordering::SeqCst) == 1).await;
}
