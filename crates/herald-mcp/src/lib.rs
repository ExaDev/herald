//! Herald capabilities as MCP tools, served with the official Rust SDK (`rmcp`).
//!
//! One handler serves every transport. Stdio carries a fixed principal the product chose when it
//! started the process. The network transport takes the principal the boundary authenticated and put
//! on the request, and refuses a call that has none. Every call goes through [`Service`], so exposure,
//! authorisation, consent, idempotency and error typing are decided exactly as on the HTTP API.
//!
//! Tools:
//! - a query is `name.vN` and takes its input object directly;
//! - an operation is `name.vN` and takes `{"idempotency_key", "input", "detach"?}`;
//! - `herald.operation` and `herald.events` follow an operation by id.
//!
//! A tool-level failure is a result with `isError: true` and a typed [`WireError`]. A result whose
//! operation reported an error outcome is also flagged, and one whose outcome is unknown carries
//! `"uncertain": true` in its body, as it does on the HTTP API. A malformed request, such as
//! arguments that are not an object, is an MCP protocol error.
//!
//! The network transport is stateless: no session is created, so a session id cannot be stolen,
//! replayed or used to end another caller's stream, and a caller cannot open sessions to exhaust the
//! server. Every request is authenticated on its own.

use herald::{
    Cancellation, CapabilityId, Kind,
    exposure::Surface,
    runtime::OperationId,
    schema_refs::rewrite_refs,
    service::{
        CallResult, Descriptor, Executed, MAX_KEY_BYTES, Mode, Principal, Service, Shape,
        StartResult,
    },
    wire::{ErrorCode, WireError},
};
use herald_boundary::{Boundary, Guarded, error_response};
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

    /// For a network transport behind `herald-boundary`.
    pub fn network(service: Arc<Service>) -> Self {
        Self {
            service,
            identity: Identity::FromRequest,
        }
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

/// The capability a tool name addresses. Only the canonical spelling resolves: `read.v01` and
/// `read.v+1` are not `read.v1`, so a rule written against the advertised name cannot be sidestepped.
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

/// Whether a schema can describe a JSON object, which is all an MCP tool's arguments can be.
fn accepts_object(schema: &Value) -> bool {
    match schema {
        Value::Bool(allowed) => *allowed,
        Value::Object(map) => match map.get("type") {
            None => true,
            Some(Value::String(t)) => t == "object",
            Some(Value::Array(types)) => types.iter().any(|t| t == "object"),
            Some(_) => false,
        },
        _ => false,
    }
}

/// The input schema as a tool exposes it: a query's own schema as it is, and an operation's wrapped
/// with the idempotency key and the detach flag. Inside the wrapper the schema sits at
/// `properties/input`, so its pointers to itself are moved there, and its definitions are hoisted to
/// the wrapper root so `#/$defs/...` pointers resolve unchanged.
pub fn tool_input_schema(descriptor: &Descriptor) -> Value {
    match descriptor.kind {
        Kind::Operation => {
            let mut input = descriptor.input_schema.clone();
            // The schema now sits at `properties/input`, so a pointer to its own root or into it moves
            // with it. Pointers to `$defs` stay valid because the definitions are hoisted below.
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

/// A completed call. A result whose operation reported an error outcome is flagged as a tool error,
/// the same signal on every path. An unknown outcome is not an error: it carries `"uncertain": true`
/// so a client sees the operation may have run.
fn call_response(call: &CallResult) -> CallToolResponse {
    let value = json!(call);
    if call.failed {
        CallToolResult::structured_error(value).into()
    } else {
        success(value)
    }
}

fn executed_response(executed: Executed) -> CallToolResponse {
    match executed {
        Executed::Call(call) => call_response(&call),
        Executed::Start(StartResult::Finished(call)) => call_response(&call),
        Executed::Start(running) => success(json!(running)),
    }
}

fn string_arg<'a>(arguments: &'a Map<String, Value>, name: &str) -> Result<&'a str, McpError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params(format!("`{name}` must be a string"), None))
}

/// A cancellation that fires when the protocol cancels the request. The returned guard stops the
/// forwarding task when the call ends, so it never outlives the request.
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
            return Err(McpError::invalid_request(
                "authentication is required",
                None,
            ));
        };
        let mut tools: Vec<Tool> = self
            .service
            .list(&principal, Surface::Mcp)
            .await
            .iter()
            // A tool's arguments are an object, so a query whose input cannot be one is not offered.
            .filter(|d| d.kind != Kind::Query || accepts_object(&d.input_schema))
            .map(tool_of)
            .collect();
        tools.push(follow_tool(
            OPERATION_TOOL,
            "Read the state of an operation you started.",
            json!({"type":"object","required":["id"],"additionalProperties":false,"properties":{"id":{"type":"string"}}}),
        ));
        tools.push(follow_tool(
            EVENTS_TOOL,
            "Read an operation's events from a cursor (the number of events already seen).",
            json!({"type":"object","required":["id"],"additionalProperties":false,
                   "properties":{"id":{"type":"string"},"cursor":{"type":"integer","minimum":0}}}),
        ));
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let Some(principal) = self.principal(&context) else {
            return Err(McpError::invalid_request(
                "authentication is required",
                None,
            ));
        };
        let payload = Value::Object(request.arguments.unwrap_or_default());
        let name = request.name.as_ref();

        // Sizes are judged first and alike for every name, so an oversized request cannot tell an
        // exposed tool from an unknown one.
        if let Err(error) = Service::check_bounds(&payload) {
            return Ok(failure(error));
        }
        let Value::Object(arguments) = &payload else {
            unreachable!("the payload was built as an object");
        };

        if name == OPERATION_TOOL || name == EVENTS_TOOL {
            let id = OperationId(string_arg(arguments, "id")?.to_owned());
            return Ok(if name == OPERATION_TOOL {
                match self.service.operation(&principal, Surface::Mcp, &id).await {
                    Ok(view) => success(json!(view)),
                    Err(error) => failure(error),
                }
            } else {
                let cursor = match arguments.get("cursor") {
                    None => 0,
                    Some(v) => v.as_u64().ok_or_else(|| {
                        McpError::invalid_params("`cursor` must be a non-negative integer", None)
                    })?,
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

        // An unknown, unexposed or denied tool all look the same: the service authorises before it
        // looks at the payload's shape or tells the caller anything that depends on the capability.
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
        // A synchronous call ends when the protocol cancels the request. A detached operation outlives
        // the request that started it, so the request's cancellation must not reach it.
        let detached = prepared.kind == Kind::Operation && prepared.detach;
        let (cancellation, _stop) = if detached {
            (herald::cancellation().1, None)
        } else {
            let (cancellation, stop) = cancellation_from(&context);
            (cancellation, Some(stop))
        };
        let mode = match prepared.kind {
            Kind::Operation => Mode::AsRequested,
            _ => Mode::Call,
        };
        Ok(
            match self
                .service
                .execute(&principal, &capability, prepared, mode, cancellation)
                .await
            {
                Ok(executed) => executed_response(executed),
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

/// The MCP network transport (streamable HTTP, stateless), with no boundary applied. Compose it with
/// other routes and put the result behind [`Guarded::new`]. Serving this without the boundary leaves
/// every call refused, since the handler takes its principal from the boundary.
pub fn routes(service: Arc<Service>, boundary: &Boundary) -> axum::Router {
    use herald::service::MAX_REQUEST_BYTES;
    use rmcp::transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        streamable_http_server::session::never::NeverSessionManager,
    };
    let policy = boundary.policy();
    // The boundary is the authority on hosts and origins and runs first. The SDK's own checks get the
    // same lists as a second layer; they are laxer (case folding, portless entries), so they only ever
    // see requests the boundary has already admitted.
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(MAX_REQUEST_BYTES)
        .with_allowed_hosts(policy.hosts())
        .with_allowed_origins(policy.origins());
    let mcp = StreamableHttpService::new(
        move || Ok(HeraldMcp::network(service.clone())),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    axum::Router::new()
        .route_service(MCP_PATH, mcp)
        .fallback(|| async { error_response(WireError::new(ErrorCode::NotFound, "no such route")) })
        .layer(axum::middleware::from_fn(typed_errors))
}

/// The SDK answers a request it refuses before any handler runs (wrong `Accept`, `Content-Type` or
/// method, an oversized body, a rejected host) with a plain-text body. Those answers do not depend on
/// the capability named, so they leak nothing, but a client expects every failure to be a typed
/// error: the status stays and the body becomes one. A JSON body, such as the SDK's own JSON-RPC
/// error, is already structured and passes through.
async fn typed_errors(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
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
    let (code, message) = match status {
        StatusCode::PAYLOAD_TOO_LARGE => (ErrorCode::TooLarge, "the request is too large"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE | StatusCode::NOT_ACCEPTABLE => (
            ErrorCode::UnsupportedMedia,
            "the request media type is not supported",
        ),
        StatusCode::NOT_FOUND => (ErrorCode::NotFound, "no such route"),
        _ => (ErrorCode::BadRequest, "the request was refused"),
    };
    let mut typed = error_response(WireError::new(code, message));
    *typed.status_mut() = status;
    typed
}

/// The MCP network transport behind the boundary.
pub fn router(service: Arc<Service>, boundary: Arc<Boundary>) -> Guarded {
    Guarded::new(routes(service, &boundary), boundary)
}
