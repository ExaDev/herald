//! Herald capabilities as MCP tools, served with the official Rust SDK (`rmcp`).
//!
//! One handler serves every transport. Stdio carries a fixed principal the product chose when it started the process. The network transport takes the principal the boundary authenticated and put on the request, and refuses a call that has none. Every call goes through [`Service`], so exposure, authorisation, consent, idempotency and error typing are decided exactly as on the HTTP API.
//!
//! Tools:
//! - a query is `name.vN` and takes its input object directly;
//! - an operation is `name.vN` and takes `{"idempotency_key", "input", "detach"?}`;
//! - `herald.operation` and `herald.events` follow an operation by id.
//!
//! A query whose input schema does not declare `type: object` at its root has no arguments object to take, so it is not offered as a tool.
//!
//! A tool-level failure is a result with `isError: true` and a typed [`WireError`]. A result whose operation reported an error outcome is also flagged, and one whose outcome is unknown carries `"uncertain": true` in its body, as it does on the HTTP API. Both adapters build the body with [`Executed::body`](herald::service::Executed::body). Arguments the follow tools cannot read, such as a cursor that is not a non-negative integer, are typed `bad_request` results like any other refusal, so a model can read them and correct the call. Arguments that are not an object are an MCP protocol error, which the SDK raises before the handler runs.
//!
//! Every capability tool declares an output schema, built from the capability's own and the shared result shapes, so a client can check results the same way a client of the HTTP API can.
//!
//! rmcp logs each request it receives and each result it returns at `debug` level through `tracing`, and those hold tool arguments, idempotency keys and operation outputs, so a product must not enable `debug` or `trace` logging for the `rmcp` target where its logs are not as private as its data.
//!
//! The network transport is stateless: no session is created, so a session id cannot be stolen, replayed or used to end another caller's stream, and a caller cannot open sessions to exhaust the server. Every request is authenticated on its own.

use herald::{
    Cancellation, CapabilityId, Kind,
    contract_schema::{call_result, input_is_object, shared_schemas, start_result},
    exposure::Surface,
    runtime::OperationId,
    schema_refs::{lift_schema, rewrite_refs, strip_resource_keywords},
    service::{
        Descriptor, Executed, MAX_KEY_BYTES, Mode, Principal, Service, Shape, UnboundedRuntime,
    },
    wire::{ErrorCode, WireError},
};
use herald_boundary::{Admitted, Boundary, Guarded, error_response};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, InitializeResult,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, Tool,
    },
    service::{RequestContext, RoleServer},
};
use serde_json::{Map, Value, json};
use std::{borrow::Cow, sync::Arc};

pub use rmcp;

/// What a network handler says when it finds no caller: the boundary that names one is not installed.
const MISSING_BOUNDARY: &str = "the boundary middleware is not installed";

/// The tool that reads an operation's state.
pub const OPERATION_TOOL: &str = "herald.operation";
/// The tool that reads an operation's events from a cursor.
pub const EVENTS_TOOL: &str = "herald.events";

/// Where the caller's identity comes from.
#[derive(Clone)]
enum Identity {
    /// Stdio has no authentication step: the product names the principal when it starts the process.
    Fixed(Principal),
    /// Network: the principal the boundary put on the request. Without one the call is refused.
    FromRequest,
}

/// The MCP handler: one implementation behind every transport, taking the caller from the transport (a fixed principal for stdio, the boundary's for the network) and everything else from the [`Service`].
#[derive(Clone)]
pub struct HeraldMcp {
    service: Arc<Service>,
    identity: Identity,
}

impl HeraldMcp {
    /// For a transport with no authentication step, such as stdio.
    pub fn stdio(service: Arc<Service>, principal: Principal) -> Self {
        Self {
            service,
            identity: Identity::Fixed(principal),
        }
    }

    /// For a network transport behind `herald-boundary`. Fails if the service's runtime has no bound on running operations, since a detached call leaves work running after its request ends.
    pub fn network(service: Arc<Service>) -> Result<Self, UnboundedRuntime> {
        service.require_running_limit()?;
        Ok(Self {
            service,
            identity: Identity::FromRequest,
        })
    }

    /// The in-flight slot of the HTTP request carrying this call, if there is one. Stdio has none.
    fn admitted(context: &RequestContext<RoleServer>) -> Option<Admitted> {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Admitted>())
            .cloned()
    }

    fn principal(&self, context: &RequestContext<RoleServer>) -> Option<Principal> {
        match &self.identity {
            Identity::Fixed(principal) => Some(principal.clone()),
            Identity::FromRequest => context
                .extensions
                .get::<http::request::Parts>()
                .and_then(|parts| parts.extensions.get::<Principal>())
                .cloned(),
        }
    }
}

/// `name.vN`, the tool name for a capability.
pub fn tool_name(id: &CapabilityId) -> String {
    format!("{}.v{}", id.name, id.version)
}

/// The capability a tool name addresses. Only the canonical spelling resolves: `read.v01` and `read.v+1` are not `read.v1`, so a rule written against the advertised name cannot be sidestepped.
fn capability_of(tool: &str) -> Option<CapabilityId> {
    let (name, suffix) = tool.rsplit_once(".v")?;
    let version: u32 = suffix.parse().ok()?;
    (version.to_string() == suffix).then(|| CapabilityId {
        name: name.to_owned(),
        version,
    })
}

fn object(value: Value) -> Arc<Map<String, Value>> {
    match value {
        Value::Object(map) => Arc::new(map),
        _ => Arc::new(Map::new()),
    }
}

/// The input schema as a tool exposes it: a query's own schema as it is, and an operation's wrapped with the idempotency key and the detach flag. Inside the wrapper the schema sits at `properties/input`, so its pointers to itself are moved there, and its definitions are hoisted to the wrapper root so `#/$defs/...` pointers resolve unchanged.
pub fn tool_input_schema(descriptor: &Descriptor) -> Value {
    match descriptor.kind {
        Kind::Operation => {
            let mut input = descriptor.input_schema.clone();
            // A schema nested in the wrapper does not name its own dialect.
            strip_resource_keywords(&mut input);
            // The schema now sits at `properties/input`, so a pointer to its own root or into it moves with it. Pointers to `$defs` stay valid because the definitions are hoisted below.
            rewrite_refs(&mut input, &|reference| {
                if reference == "#" {
                    return Some("#/properties/input".to_owned());
                }
                let keeps = ["#/$defs/", "#/definitions/"]
                    .iter()
                    .any(|root| reference.starts_with(root));
                (!keeps)
                    .then(|| reference.strip_prefix("#/"))
                    .flatten()
                    .map(|pointer| format!("#/properties/input/{pointer}"))
            });
            // The definitions move to the wrapper's root, where `#/$defs/...` pointers resolve.
            let mut hoisted = Map::new();
            if let Value::Object(map) = &mut input {
                for definitions in ["$defs", "definitions"] {
                    if let Some(found) = map.remove(definitions) {
                        hoisted.insert(definitions.to_owned(), found);
                    }
                }
            }
            let mut wrapper = json!({
                "type": "object",
                "required": ["idempotency_key", "input"],
                "additionalProperties": false,
                "properties": {
                    "idempotency_key": {
                        "type": "string",
                        "minLength": 1,
                        "description": format!("At most {MAX_KEY_BYTES} bytes. A retry with the same key replays the recorded outcome."),
                    },
                    "input": input,
                    "detach": {
                        "type": "boolean",
                        "description": "Return the operation id as soon as it is running instead of waiting for its outcome."
                    }
                }
            });
            for (name, definitions) in hoisted {
                wrapper[name] = definitions;
            }
            wrapper
        }
        _ => descriptor.input_schema.clone(),
    }
}

fn tool_of(descriptor: &Descriptor) -> Tool {
    Tool::new(
        Cow::Owned(tool_name(&descriptor.id)),
        Cow::Owned(match descriptor.kind {
            Kind::Operation => format!(
                "Operation {} (version {}).",
                descriptor.id.name, descriptor.id.version
            ),
            _ => format!(
                "Query {} (version {}).",
                descriptor.id.name, descriptor.id.version
            ),
        }),
        object(tool_input_schema(descriptor)),
    )
    .with_raw_output_schema(object(tool_output_schema(descriptor)))
    // A query changes nothing, which a client may rely on to call it without asking. Whether a capability needs confirmation and whether it is supported are the product's to state, and ride in `_meta`, where the HTTP document carries them as `x-herald-*` extensions.
    .annotate(rmcp::model::ToolAnnotations::default().read_only(descriptor.kind == Kind::Query))
    .with_meta(rmcp::model::MetaObject(object_map(json!({
        "herald": {
            "kind": descriptor.kind,
            "confirmation_required": descriptor.confirmation_required,
            "support": descriptor.support,
        }
    }))))
}

fn object_map(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// The output schema a capability tool declares: a result of the capability, or for an operation a start result too, or a typed error. The capability's own schemas and the shared shapes sit in `$defs` at the schema root, so every pointer resolves from there.
pub fn tool_output_schema(descriptor: &Descriptor) -> Value {
    const BASE: &str = "#/$defs/";
    let mut defs = shared_schemas(BASE);
    let output = lift_schema(&descriptor.output_schema, "output", &mut defs, BASE);
    let error = lift_schema(&descriptor.error_schema, "error", &mut defs, BASE);
    let result = call_result(&output, &error);
    let mut results = vec![result.clone()];
    if descriptor.kind == Kind::Operation {
        results.push(start_result(&result));
    }
    results.push(json!({"$ref": format!("{BASE}ErrorResponse")}));
    json!({"type": "object", "anyOf": results, "$defs": defs})
}

fn follow_tool(name: &'static str, description: &'static str, schema: Value) -> Tool {
    Tool::new(
        Cow::Borrowed(name),
        Cow::Borrowed(description),
        object(schema),
    )
}

fn failure(error: WireError) -> CallToolResponse {
    CallToolResult::structured_error(json!({ "error": error })).into()
}
fn success(value: Value) -> CallToolResponse {
    CallToolResult::structured(value).into()
}
fn not_found() -> CallToolResponse {
    failure(WireError::new(ErrorCode::NotFound, "no such capability"))
}

/// A result, in the body every adapter shares. A result whose operation reported an error outcome is flagged as a tool error, the same signal on every path. An unknown outcome is not an error: it carries `"uncertain": true` so a client sees the operation may have run.
fn executed_response(executed: &Executed) -> CallToolResponse {
    if executed.failed() {
        CallToolResult::structured_error(executed.body()).into()
    } else {
        success(executed.body())
    }
}

/// The text of a refused follow-tool argument, as a typed result.
fn bad_argument(message: &'static str) -> CallToolResponse {
    failure(WireError::new(ErrorCode::BadRequest, message))
}

/// A cancellation that fires when the request's token does. Over stdio the protocol's cancel notification fires it. Over the stateless network transport the SDK ignores that notification, so the token fires when the client's connection ends. The returned guard stops the forwarding task when the call ends, so it never outlives the request.
fn cancellation_from(context: &RequestContext<RoleServer>) -> (Cancellation, impl Drop) {
    struct Stop(tokio::task::JoinHandle<()>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let (sender, cancellation) = herald::cancellation();
    let token = context.ct.clone();
    let forward = tokio::spawn(async move {
        token.cancelled().await;
        let _ = sender.send(true);
    });
    (cancellation, Stop(forward))
}

impl ServerHandler for HeraldMcp {
    fn get_info(&self) -> InitializeResult {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("herald", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let Some(principal) = self.principal(&context) else {
            // No caller means the handler is running without the boundary that should have named one: a wiring fault, not a failure to authenticate.
            return Err(McpError::internal_error(MISSING_BOUNDARY, None));
        };
        let mut tools: Vec<Tool> = self
            .service
            .list(&principal, Surface::Mcp)
            .await
            .iter()
            // A tool's arguments are an object, so a query whose input schema does not declare `type: object` at its root is not offered.
            .filter(|d| d.kind != Kind::Query || input_is_object(d))
            .map(tool_of)
            .collect();
        // A tool's output schema is an object at its root, as clients of older protocol revisions expect. A failed follow is the typed error body, so the schema admits it as well as the view.
        let shared = |name: &str| {
            json!({
                "type": "object",
                "anyOf": [{"$ref": format!("#/$defs/{name}")}, {"$ref": "#/$defs/ErrorResponse"}],
                "$defs": shared_schemas("#/$defs/")
            })
        };
        // Following an operation only reads it.
        let read_only = || rmcp::model::ToolAnnotations::default().read_only(true);
        tools.push(
            follow_tool(
                OPERATION_TOOL,
                "Read the state of an operation you started.",
                json!({"type":"object","required":["id"],"additionalProperties":false,"properties":{"id":{"type":"string"}}}),
            )
            .with_raw_output_schema(object(shared("OperationView")))
            .annotate(read_only()),
        );
        tools.push(
            follow_tool(
                EVENTS_TOOL,
                "Read an operation's events from a cursor (the number of events already seen).",
                json!({"type":"object","required":["id"],"additionalProperties":false,
                       "properties":{"id":{"type":"string"},"cursor":{"type":"integer","minimum":0}}}),
            )
            .with_raw_output_schema(object(shared("OperationEvents")))
            .annotate(read_only()),
        );
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(principal) = self.principal(&context) else {
            return Ok(failure(WireError::new(
                ErrorCode::ContractViolation,
                MISSING_BOUNDARY,
            )));
        };
        let payload = Value::Object(request.arguments.unwrap_or_default());
        let name = request.name.as_ref();

        // Sizes are judged first and alike for every name, so an oversized request cannot tell an exposed tool from an unknown one.
        if let Err(error) = Service::check_bounds(&payload) {
            return Ok(failure(error));
        }
        let Value::Object(arguments) = &payload else {
            unreachable!("the payload was built as an object");
        };

        if name == OPERATION_TOOL || name == EVENTS_TOOL {
            // The schema published for these tools allows no other argument, so none is accepted.
            let allowed: &[&str] = if name == OPERATION_TOOL {
                &["id"]
            } else {
                &["id", "cursor"]
            };
            if arguments.keys().any(|key| !allowed.contains(&key.as_str())) {
                return Ok(bad_argument("unexpected argument"));
            }
            let Some(id) = arguments.get("id").and_then(Value::as_str) else {
                return Ok(bad_argument("`id` must be a string"));
            };
            let id = OperationId(id.to_owned());
            return Ok(if name == OPERATION_TOOL {
                match self.service.operation(&principal, Surface::Mcp, &id).await {
                    Ok(view) => success(json!(view)),
                    Err(error) => failure(error),
                }
            } else {
                let cursor = match arguments.get("cursor").map(Value::as_u64) {
                    None => 0,
                    Some(Some(cursor)) => cursor,
                    Some(None) => {
                        return Ok(bad_argument("`cursor` must be a non-negative integer"));
                    }
                };
                match self
                    .service
                    .events_after(&principal, Surface::Mcp, &id, cursor)
                    .await
                {
                    Ok(events) => success(json!({ "events": events })),
                    Err(error) => failure(error),
                }
            });
        }

        // An unknown, unexposed or denied tool all look the same: the service authorises before it looks at the payload's shape or tells the caller anything that depends on the capability.
        let Some(capability) = capability_of(name) else {
            return Ok(not_found());
        };
        let prepared = match self
            .service
            .prepare(
                &principal,
                Surface::Mcp,
                &capability,
                payload,
                |kind| match kind {
                    Kind::Operation => Shape::Envelope,
                    _ => Shape::Direct,
                },
            )
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => return Ok(failure(error)),
        };
        // rmcp runs this handler on a task of its own that outlives a request the boundary has already answered, so a call stalled in authorisation can arrive here after its request ended. What the client was told ended is not started, whether or not the call asked to detach; an operation that was started stays the runtime's, which a request's end never reaches.
        if context.ct.is_cancelled() {
            return Ok(failure(WireError::new(
                ErrorCode::Cancelled,
                "cancelled before it ran",
            )));
        }
        // A synchronous call ends when the protocol cancels the request. A detached operation outlives the request that started it, so the request's cancellation must not reach it.
        let detached = *prepared.kind() == Kind::Operation && prepared.detach();
        let (cancellation, _stop) = if detached {
            (herald::cancellation().1, None)
        } else {
            let (cancellation, stop) = cancellation_from(&context);
            (cancellation, Some(stop))
        };
        // Over the network a synchronous call also holds the request's in-flight slot until its handler returns. A detached operation gives the slot back, since the runtime's limit bounds it.
        let cancellation = match Self::admitted(&context) {
            Some(admitted) if !detached => cancellation.with_hold(admitted),
            _ => cancellation,
        };
        let mode = match prepared.kind() {
            Kind::Operation => Mode::AsRequested,
            _ => Mode::Call,
        };
        Ok(
            match self.service.execute(prepared, mode, cancellation).await {
                Ok(executed) => executed_response(&executed),
                Err(error) => failure(error),
            },
        )
    }
}

/// Serves MCP over stdio for `principal`. Stdout carries protocol traffic only.
pub async fn serve_stdio(
    service: Arc<Service>,
    principal: Principal,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rmcp::ServiceExt;
    let running = HeraldMcp::stdio(service, principal)
        .serve(rmcp::transport::stdio())
        .await?;
    running.waiting().await?;
    Ok(())
}

/// The path the network transport is served at.
pub const MCP_PATH: &str = "/mcp";

/// The MCP network transport (streamable HTTP, stateless), with no boundary applied. Compose it with other routes and put the result behind [`Guarded::new`]. Serving this without the boundary leaves every call refused, since the handler takes its principal from the boundary.
///
/// Fails if the service's runtime has no bound on running operations: a detached call leaves work running after its request ends, and nothing else limits how much a caller can leave.
pub fn routes(
    service: Arc<Service>,
    boundary: &Boundary,
) -> Result<axum::Router, UnboundedRuntime> {
    use herald::service::MAX_REQUEST_BYTES;
    use rmcp::transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        streamable_http_server::session::never::NeverSessionManager,
    };
    let policy = boundary.policy();
    // The boundary is the authority on hosts and origins and runs first. The SDK's own checks get the same lists as a second layer; they are laxer (case folding, portless entries), so they only ever see requests the boundary has already admitted.
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(MAX_REQUEST_BYTES)
        .with_allowed_hosts(policy.hosts())
        .with_allowed_origins(policy.origins());
    let network = HeraldMcp::network(service)?;
    let mcp = StreamableHttpService::new(
        move || Ok(network.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    Ok(axum::Router::new()
        .route_service(MCP_PATH, mcp)
        .layer(axum::middleware::from_fn(typed_errors)))
}

/// The typed code and message for a plain-text refusal the SDK made with `status`.
fn refusal(status: axum::http::StatusCode) -> (ErrorCode, &'static str) {
    use axum::http::StatusCode;
    match status {
        StatusCode::PAYLOAD_TOO_LARGE => (ErrorCode::TooLarge, "the request is too large"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE | StatusCode::NOT_ACCEPTABLE => (
            ErrorCode::UnsupportedMedia,
            "the request media type is not supported",
        ),
        StatusCode::NOT_FOUND => (ErrorCode::NotFound, "no such route"),
        StatusCode::METHOD_NOT_ALLOWED => (ErrorCode::MethodNotAllowed, "method not allowed"),
        StatusCode::FORBIDDEN => (
            ErrorCode::ForbiddenOrigin,
            "this host or origin is not served",
        ),
        // A fault of the SDK's own can come after the handler started, so it does not claim that nothing ran: it says the outcome is unknown.
        _ if status.is_server_error() => (
            ErrorCode::OutcomeLost,
            "the server did not complete the request",
        ),
        _ => (ErrorCode::BadRequest, "the request was refused"),
    }
}

/// The SDK answers a request it refuses before any handler runs (wrong `Accept`, `Content-Type` or method, an oversized body, a rejected host) with a plain-text body. Those answers do not depend on the capability named, so they leak nothing, but a client expects every failure to be a typed error: the status stays and the body becomes one. A JSON body, such as the SDK's own JSON-RPC error, is already structured and passes through.
async fn typed_errors(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::header;
    let response = next.run(request).await;
    let status = response.status();
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !(status.is_client_error() || status.is_server_error()) || is_json {
        return response;
    }
    let (code, message) = refusal(status);
    let mut typed = error_response(WireError::new(code, message));
    *typed.status_mut() = status;
    // A 405 must say which methods are allowed, and the SDK's answer does.
    if let Some(allow) = response.headers().get(header::ALLOW) {
        typed.headers_mut().insert(header::ALLOW, allow.clone());
    }
    typed
}

/// The MCP network transport behind the boundary.
pub fn router(service: Arc<Service>, boundary: Arc<Boundary>) -> Result<Guarded, UnboundedRuntime> {
    Ok(Guarded::new(routes(service, &boundary)?, boundary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn every_status_the_sdk_refuses_with_gets_the_code_that_names_it() {
        for (status, code) in [
            (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge),
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ErrorCode::UnsupportedMedia,
            ),
            (StatusCode::NOT_ACCEPTABLE, ErrorCode::UnsupportedMedia),
            (StatusCode::NOT_FOUND, ErrorCode::NotFound),
            (StatusCode::METHOD_NOT_ALLOWED, ErrorCode::MethodNotAllowed),
            (StatusCode::FORBIDDEN, ErrorCode::ForbiddenOrigin),
            (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
            (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::BadRequest),
            // A server fault does not say nothing ran.
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::OutcomeLost),
            (StatusCode::BAD_GATEWAY, ErrorCode::OutcomeLost),
        ] {
            assert_eq!(refusal(status).0, code, "{status}");
        }
    }
}
