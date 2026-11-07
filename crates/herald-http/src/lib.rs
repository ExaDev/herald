//! Herald capabilities as a versioned JSON API under `/v1`, behind the same boundary as the MCP network transport. Every handler calls [`Service`], so exposure, authorisation, consent, idempotency and error typing are the ones the MCP adapter has. Every failure the router itself produces, including a path, query or body that does not parse, a body that is too large and a route that does not exist, is a typed [`WireError`] as JSON. A connection the server refuses before it reaches the router, for example a malformed request line, is answered by the server.
//!
//! - `GET  /v1/capabilities`: the capabilities the caller may use.
//! - `POST /v1/capabilities/{name}/{version}/call`: run to completion.
//! - `POST /v1/capabilities/{name}/{version}/start`: return once an operation is running.
//! - `GET  /v1/operations/{id}` and `/v1/operations/{id}/events?cursor=N`: follow an operation.
//! - `GET  /v1/openapi.json`: the client contract, generated for the caller from the descriptors.
//!
//! A request body is `{"input": ..., "idempotency_key"?: ...}`. Whether to wait is chosen by the route (`call` or `start`), so a body that also carries a `detach` flag is refused with `bad_request`, where MCP, which has one tool for both, takes the flag. A query whose input schema does not declare `type: object` at its root is in the capability list and the document but is not offered as an MCP tool. A completed call answers 200 with a [`CallResult`](herald::service::CallResult); one whose operation reported an error outcome is still a 200 carrying `"failed": true`, and one whose outcome is unknown carries `"uncertain": true`, exactly as the MCP adapter reports them. A started operation answers 202 with its id, or 200 with `"state": "finished"` and the call's result when it had already finished. Both adapters build the body with [`Executed::body`](herald::service::Executed::body).
//!
//! A `call` that the client abandons cancels the handler cooperatively, whether it is a query or an operation, and the request's in-flight slot is held until the handler returns. A `start` is detached: its request does not cancel it, and it gives the slot back at once.

use axum::{
    Extension, Json, Router,
    extract::{
        DefaultBodyLimit, FromRequest, Path, Query, Request, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use herald::{
    CapabilityId, Kind,
    contract_schema::{call_result, shared_schemas, start_arms},
    exposure::Surface,
    runtime::OperationId,
    schema_refs::lift_schema,
    service::{
        Descriptor, Executed, MAX_KEY_BYTES, MAX_REQUEST_BYTES, Mode, Service, Shape, StartResult,
        UnboundedRuntime,
    },
    wire::{ErrorCode, WireError},
};
use herald_boundary::{Admitted, Authenticated, Boundary, Guarded, error_response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub const API_PREFIX: &str = "/v1";
const SURFACE: Surface = Surface::Api;

/// A JSON body whose failure is a typed error, not axum's plain-text rejection. The body is read as a bare value so that [`Service::prepare`] decides its shape, after exposure and authorisation.
struct TypedJson(Value);

impl<S: Send + Sync> FromRequest<S> for TypedJson {
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<Value>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(error_response(body_error(&rejection))),
        }
    }
}

fn body_error(rejection: &JsonRejection) -> WireError {
    // Fixed messages: serde's text can quote the offending bytes back.
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return WireError::new(ErrorCode::TooLarge, "the request is too large");
    }
    match rejection {
        JsonRejection::MissingJsonContentType(_) => WireError::new(
            ErrorCode::UnsupportedMedia,
            "the request must be application/json",
        ),
        JsonRejection::BytesRejection(_) => {
            WireError::new(ErrorCode::BadRequest, "the request body could not be read")
        }
        _ => WireError::new(ErrorCode::BadRequest, "the request body is not valid JSON"),
    }
}

fn bad_path(_: &PathRejection) -> Response {
    error_response(WireError::new(
        ErrorCode::BadRequest,
        "the path is not valid",
    ))
}

fn bad_query(_: &QueryRejection) -> Response {
    error_response(WireError::new(
        ErrorCode::BadRequest,
        "the query takes only `cursor`, a non-negative integer",
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    #[serde(default)]
    cursor: u64,
}

/// The capability a path names. Only the canonical decimal spelling of a version resolves, as in the MCP tool names, so `01` and `+1` are not `1`.
fn capability(name: String, version: &str) -> Result<CapabilityId, WireError> {
    version
        .parse::<u32>()
        .ok()
        .filter(|v| v.to_string() == version)
        .map(|version| CapabilityId { name, version })
        .ok_or_else(|| WireError::new(ErrorCode::NotFound, "no such capability"))
}

/// Calls the closure when dropped. A handler future dropped by the server because the client went away drops this with it.
struct OnDrop<F: FnMut()>(F);
impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// The API's routes with no boundary applied and no fallback of their own outside `/v1`. Compose them with other routes in [`Guarded`], which adds the boundary and the typed answers for what matches nothing; every handler refuses a request that did not come through the boundary.
///
/// Fails if the service's runtime has no bound on running operations: `/start` leaves work running after its request ends, and nothing else limits how much a caller can leave.
pub fn routes(service: Arc<Service>, boundary: &Boundary) -> Result<Router, UnboundedRuntime> {
    service.require_running_limit()?;
    let security = boundary.security_scheme();
    let api = Router::new()
        .route("/capabilities", get(list))
        .route("/capabilities/{name}/{version}/call", post(call))
        .route("/capabilities/{name}/{version}/start", post(start))
        .route("/operations/{id}", get(operation))
        .route("/operations/{id}/events", get(events))
        .route("/openapi.json", get(openapi))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(Extension(Scheme(security)))
        .with_state(service);
    Ok(Router::new().nest(API_PREFIX, api))
}

/// The API under `/v1`, behind the boundary.
pub fn router(service: Arc<Service>, boundary: Arc<Boundary>) -> Result<Guarded, UnboundedRuntime> {
    Ok(Guarded::new(routes(service, &boundary)?, boundary))
}

async fn not_found() -> Response {
    error_response(WireError::new(ErrorCode::NotFound, "no such route"))
}

async fn method_not_allowed() -> Response {
    error_response(WireError::new(
        ErrorCode::MethodNotAllowed,
        "method not allowed",
    ))
}

fn respond<T: serde::Serialize>(status: StatusCode, result: Result<T, WireError>) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(error) => error_response(error),
    }
}

async fn list(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
) -> Response {
    Json(json!({ "capabilities": service.list(&principal, SURFACE).await })).into_response()
}

/// Runs a capability for the `call` and `start` routes, which differ only in the mode.
async fn run(
    service: Arc<Service>,
    principal: herald::service::Principal,
    admitted: Admitted,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<TypedJson, Response>,
    mode: Mode,
) -> Response {
    let TypedJson(payload) = match body {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Path((name, version)) = match path {
        Ok(path) => path,
        Err(rejection) => return bad_path(&rejection),
    };
    // Bounds apply before the version is read, as they do for every name on MCP.
    if let Err(error) = Service::check_bounds(&payload) {
        return error_response(error);
    }
    let capability = match capability(name, &version) {
        Ok(capability) => capability,
        Err(error) => return error_response(error),
    };
    let prepared = match service
        .prepare(&principal, SURFACE, &capability, payload, |_| {
            Shape::EnvelopeWait
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return error_response(error),
    };
    // A call ends when the client goes away: the handler is told to stop. The service runs the handler on a task of its own, so it sees that signal and winds down.
    let (sender, cancellation) = herald::cancellation();
    // Only a synchronous call keeps the request's slot while its handler runs. A start is detached to outlive the request, so it gives the slot back and the runtime's own limit bounds it.
    let cancellation = if mode == Mode::Call {
        cancellation.with_hold(admitted)
    } else {
        cancellation
    };
    let _cancel_on_drop = (mode == Mode::Call).then(|| {
        OnDrop(move || {
            let _ = sender.send(true);
        })
    });
    match service.execute(prepared, mode, cancellation).await {
        Ok(executed) => {
            let status = match &executed {
                Executed::Start(StartResult::Running { .. }) => StatusCode::ACCEPTED,
                _ => StatusCode::OK,
            };
            (status, Json(executed.body())).into_response()
        }
        Err(error) => error_response(error),
    }
}

async fn call(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    admitted: Admitted,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<TypedJson, Response>,
) -> Response {
    run(service, principal, admitted, path, body, Mode::Call).await
}

async fn start(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    admitted: Admitted,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<TypedJson, Response>,
) -> Response {
    run(service, principal, admitted, path, body, Mode::Start).await
}

async fn operation(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Path(id) = match id {
        Ok(id) => id,
        Err(rejection) => return bad_path(&rejection),
    };
    respond(
        StatusCode::OK,
        service
            .operation(&principal, SURFACE, &OperationId(id))
            .await,
    )
}

async fn events(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    id: Result<Path<String>, PathRejection>,
    cursor: Result<Query<Cursor>, QueryRejection>,
) -> Response {
    let Path(id) = match id {
        Ok(id) => id,
        Err(rejection) => return bad_path(&rejection),
    };
    let Query(cursor) = match cursor {
        Ok(cursor) => cursor,
        Err(rejection) => return bad_query(&rejection),
    };
    let result = service
        .events_after(&principal, SURFACE, &OperationId(id), cursor.cursor)
        .await
        .map(|events| json!({ "events": events }));
    respond(StatusCode::OK, result)
}

/// The security scheme the boundary advertises, carried to the document handler.
#[derive(Clone)]
struct Scheme(Value);

async fn openapi(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    Extension(Scheme(security)): Extension<Scheme>,
) -> Response {
    Json(document(
        &service.list(&principal, SURFACE).await,
        &security,
    ))
    .into_response()
}

/// Names for the document's operations that a client generator can use as identifiers: the capability's name with anything outside letters, digits and `_` folded to `_`, its version, and a number added only when two capabilities fold to the same name (`a.b` and `a-b`). The number depends on which capabilities the caller can see, so an id is stable for a fixed set of visible capabilities.
#[derive(Default)]
struct OperationIds(std::collections::HashSet<String>);

impl OperationIds {
    fn unique(&mut self, id: &CapabilityId, verb: &str) -> String {
        let folded: String = id
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let base = format!("{verb}_{folded}_v{}", id.version);
        let mut candidate = base.clone();
        let mut n = 2;
        while !self.0.insert(candidate.clone()) {
            candidate = format!("{base}_{n}");
            n += 1;
        }
        candidate
    }
}

/// What a listed capability looks like: its identity, kind and schemas.
fn descriptor_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "kind", "input_schema", "output_schema", "error_schema",
                     "confirmation_required", "support"],
        "properties": {
            "id": {"type": "object", "required": ["name", "version"],
                   "properties": {"name": {"type": "string"}, "version": {"type": "integer", "minimum": 0}}},
            "kind": {"enum": ["Query", "Operation"]},
            "input_schema": {},
            "output_schema": {},
            "error_schema": {},
            "confirmation_required": {"type": "boolean"},
            "support": {"enum": ["Supported", "Unsupported", "Unknown"]}
        }
    })
}

/// The OpenAPI 3.1 document for exactly the capabilities in `descriptors`, with `security` as the scheme the boundary's authenticator advertises. Request and result shapes come from the same contracts the handlers validate against and from [`herald::contract_schema`], which is tested against real service values, and this crate's tests validate real responses against the document.
pub fn document(descriptors: &[Descriptor], security: &Value) -> Value {
    const BASE: &str = "#/components/schemas/";
    let mut paths = serde_json::Map::new();
    let mut schemas = shared_schemas(BASE);
    let reference = |name: &str| json!({"$ref": format!("{BASE}{name}")});
    let error = |description: &str| json!({"description": description, "content": {"application/json": {"schema": reference("ErrorResponse")}}});
    // Every failure is the same typed body; the status ranges say which kind.
    let failures = json!({
        "4XX": error("A typed error: the request was refused."),
        "5XX": error("A typed error: the server could not complete the request."),
        "default": error("A typed error.")
    });
    let with_failures = |mut responses: Value| {
        for (status, response) in failures.as_object().expect("an object") {
            responses[status] = response.clone();
        }
        responses
    };
    let mut operation_ids = OperationIds::default();
    for (index, d) in descriptors.iter().enumerate() {
        let base = format!("{API_PREFIX}/capabilities/{}/{}", d.id.name, d.id.version);
        let is_operation = d.kind == Kind::Operation;
        // The position in the list names the components, since names the product chose can collide once their punctuation is folded.
        let prefix = format!("c{index}");
        let input = lift_schema(
            &d.input_schema,
            &format!("{prefix}_input"),
            &mut schemas,
            BASE,
        );
        let output = lift_schema(
            &d.output_schema,
            &format!("{prefix}_output"),
            &mut schemas,
            BASE,
        );
        let failure = lift_schema(
            &d.error_schema,
            &format!("{prefix}_error"),
            &mut schemas,
            BASE,
        );
        let mut properties = json!({"input": input});
        let mut required = vec!["input"];
        if is_operation {
            properties["idempotency_key"] = json!({"type": "string", "minLength": 1,
                "description": format!("At most {MAX_KEY_BYTES} bytes. A retry with the same key replays the recorded outcome.")});
            required.push("idempotency_key");
        } else {
            // A query is not recorded, so a key does nothing. The body still accepts one, so a client that sends the same envelope for every capability keeps working, and its length is bounded all the same.
            properties["idempotency_key"] = json!({"type": "string",
                "description": format!("Optional. A query is not recorded, so a key does nothing, but one longer than {MAX_KEY_BYTES} bytes is refused.")});
        }
        let body = json!({
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "required": required,
                "additionalProperties": false,
                "properties": properties
            }}}
        });
        let result = call_result(&output, &failure);
        let route = |id: String, summary: &str, responses: Value| {
            json!({
                "operationId": id,
                "summary": summary,
                "x-herald-kind": d.kind,
                "x-herald-confirmation-required": d.confirmation_required,
                "x-herald-support": d.support,
                "requestBody": body,
                "responses": with_failures(responses)
            })
        };
        paths.insert(
            format!("{base}/call"),
            json!({"post": route(
                operation_ids.unique(&d.id, "call"),
                "Run to completion.",
                json!({"200": {"description": "The outcome.", "content": {"application/json": {"schema": result}}}}),
            )}),
        );
        if is_operation {
            let (running, finished) = start_arms(&result);
            paths.insert(
                format!("{base}/start"),
                json!({"post": route(
                    operation_ids.unique(&d.id, "start"),
                    "Start and follow.",
                    json!({
                        "200": {"description": "Already finished: `state` is `finished`.",
                            "content": {"application/json": {"schema": finished}}},
                        "202": {"description": "Running: `state` is `running`; follow it by id.",
                            "content": {"application/json": {"schema": running}}}
                    }),
                )}),
            );
        }
    }
    let id = json!({"name": "id", "in": "path", "required": true, "schema": {"type": "string"}});
    let json_response = |description: &str, schema: Value| json!({"description": description, "content": {"application/json": {"schema": schema}}});
    paths.insert(
        format!("{API_PREFIX}/capabilities"),
        json!({"get": {
            "operationId": "list_capabilities",
            "summary": "The capabilities the caller may use.",
            "responses": with_failures(json!({"200": json_response(
                "The capabilities, each with its schemas.",
                json!({"type": "object", "required": ["capabilities"],
                       "properties": {"capabilities": {"type": "array", "items": descriptor_schema()}}}),
            )}))
        }}),
    );
    paths.insert(
        format!("{API_PREFIX}/openapi.json"),
        json!({"get": {
            "operationId": "get_openapi_document",
            "summary": "This document, generated for the caller.",
            "responses": with_failures(json!({"200": json_response("The document.", json!({"type": "object"}))}))
        }}),
    );
    paths.insert(
        format!("{API_PREFIX}/operations/{{id}}"),
        json!({"get": {
            "operationId": "get_operation",
            "summary": "Read an operation you started.",
            "parameters": [id],
            "responses": with_failures(json!({"200": json_response("The operation.", reference("OperationView"))}))
        }}),
    );
    paths.insert(
        format!("{API_PREFIX}/operations/{{id}}/events"),
        json!({"get": {
            "operationId": "get_operation_events",
            "summary": "Read its events from a cursor.",
            "parameters": [
                id,
                {"name": "cursor", "in": "query", "required": false,
                 "schema": {"type": "integer", "minimum": 0, "default": 0},
                 "description": "The number of events already seen."}
            ],
            "responses": with_failures(json!({"200": json_response("The events.", reference("OperationEvents"))}))
        }}),
    );
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Herald API", "version": "1"},
        "security": [{"credentials": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"credentials": security},
            "schemas": schemas
        }
    })
}
