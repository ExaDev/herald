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
//! A tool-level failure is a result with `isError: true` and a typed [`WireError`]. A malformed
//! request, such as arguments that are not an object, is an MCP protocol error.

use herald::{
    CapabilityId, Kind,
    exposure::Surface,
    runtime::OperationId,
    service::{Descriptor, MAX_KEY_BYTES, Principal, Service},
    wire::{ErrorCode, WireError},
};
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

fn capability_of(tool: &str) -> Option<CapabilityId> {
    let (name, version) = tool.rsplit_once(".v")?;
    Some(CapabilityId {
        name: name.to_owned(),
        version: version.parse().ok()?,
    })
}

fn object(value: Value) -> Arc<Map<String, Value>> {
    match value {
        Value::Object(map) => Arc::new(map),
        _ => Arc::new(Map::new()),
    }
}

/// The input schema as a tool exposes it. A schema that is not an object schema is replaced by the
/// loosest object, because MCP tool arguments are always an object.
fn tool_input_schema(descriptor: &Descriptor) -> Value {
    let input = match &descriptor.input_schema {
        Value::Object(_) => descriptor.input_schema.clone(),
        _ => json!({"type": "object"}),
    };
    match descriptor.kind {
        Kind::Operation => json!({
            "type": "object",
            "required": ["idempotency_key", "input"],
            "additionalProperties": false,
            "properties": {
                "idempotency_key": {"type": "string", "minLength": 1, "maxLength": MAX_KEY_BYTES},
                "input": input,
                "detach": {
                    "type": "boolean",
                    "description": "Return the operation id as soon as it is running instead of waiting for its outcome."
                }
            }
        }),
        _ => input,
    }
}

fn tool_of(descriptor: &Descriptor) -> Tool {
    let mut tool = Tool::new(
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
    );
    tool.output_schema = None;
    tool
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

fn string_arg<'a>(arguments: &'a Map<String, Value>, name: &str) -> Result<&'a str, McpError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params(format!("`{name}` must be a string"), None))
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
        let arguments = request.arguments.unwrap_or_default();
        let name = request.name.as_ref();

        if name == OPERATION_TOOL || name == EVENTS_TOOL {
            let id = OperationId(string_arg(&arguments, "id")?.to_owned());
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

        // An unknown tool, an unexposed one and one the caller may not use all look the same.
        let Some(capability) = capability_of(name) else {
            return Ok(not_found());
        };
        let Some(kind) = self.service.kind(Surface::Mcp, &capability) else {
            return Ok(not_found());
        };
        // The arguments are passed on as received: a missing key or input is judged by the service
        // after it has authorised the caller, so a denied caller cannot probe a tool's shape.
        let cancellation = herald::cancellation().1;
        Ok(match kind {
            Kind::Query => {
                let result = self
                    .service
                    .call(
                        &principal,
                        Surface::Mcp,
                        &capability,
                        Value::Object(arguments),
                        None,
                        cancellation,
                    )
                    .await;
                call_response(result)
            }
            Kind::Operation => {
                let key = arguments
                    .get("idempotency_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let input = arguments.get("input").cloned().unwrap_or(Value::Null);
                if arguments
                    .get("detach")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    match self
                        .service
                        .start(
                            &principal,
                            Surface::Mcp,
                            &capability,
                            input,
                            key,
                            cancellation,
                        )
                        .await
                    {
                        Ok(started) => success(json!(started)),
                        Err(error) => failure(error),
                    }
                } else {
                    let result = self
                        .service
                        .call(
                            &principal,
                            Surface::Mcp,
                            &capability,
                            input,
                            key,
                            cancellation,
                        )
                        .await;
                    call_response(result)
                }
            }
            Kind::Subscription => not_found(),
        })
    }
}

/// A completed call. A product's error outcome is a tool error, an unknown outcome is not: the
/// client must see that the operation may have run.
fn call_response(result: Result<herald::service::CallResult, WireError>) -> CallToolResponse {
    match result {
        Ok(call) => {
            let is_error = matches!(call.outcome, herald::Outcome::Error(_));
            let value = json!(call);
            if is_error {
                CallToolResult::structured_error(value).into()
            } else {
                success(value)
            }
        }
        Err(error) => failure(error),
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

/// The MCP network transport (streamable HTTP) behind the boundary. The boundary refuses a foreign
/// host or origin and an unauthenticated request before the SDK sees it, and the same host and
/// origin lists are handed to the SDK's own checks, so the two cannot disagree.
pub fn router(service: Arc<Service>, boundary: Arc<herald_boundary::Boundary>) -> axum::Router {
    use rmcp::transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        streamable_http_server::session::local::LocalSessionManager,
    };
    let policy = boundary.policy();
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(policy.hosts())
        .with_allowed_origins(policy.origins());
    let mcp = StreamableHttpService::new(
        move || Ok(HeraldMcp::network(service.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    axum::Router::new()
        .nest_service(MCP_PATH, mcp)
        .layer(axum::middleware::from_fn_with_state(
            boundary,
            herald_boundary::Boundary::guard,
        ))
}
