//! Herald capabilities as a versioned JSON API under `/v1`, behind the same boundary as the MCP
//! network transport. Every handler calls [`Service`], so exposure, authorisation, consent,
//! idempotency and error typing are the ones the MCP adapter has. Every failure, including a path,
//! query or body that does not parse, a body that is too large and a route that does not exist, is a
//! typed [`WireError`] as JSON.
//!
//! - `GET  /v1/capabilities`: the capabilities the caller may use.
//! - `POST /v1/capabilities/{name}/{version}/call`: run to completion.
//! - `POST /v1/capabilities/{name}/{version}/start`: return once an operation is running.
//! - `GET  /v1/operations/{id}` and `/v1/operations/{id}/events?cursor=N`: follow an operation.
//! - `GET  /v1/openapi.json`: the client contract, generated for the caller from the descriptors.
//!
//! A request body is `{"input": ..., "idempotency_key"?: ...}`. A completed call answers 200 with a
//! [`CallResult`](herald::service::CallResult); one whose operation reported an error outcome is
//! still a 200 carrying `"failed": true`, and one whose outcome is unknown carries `"uncertain": true`,
//! exactly as the MCP adapter reports them. A started operation answers 202 with its id.
//!
//! A `call` that the client abandons cancels the handler cooperatively. A `start` is detached and is
//! never cancelled by its request.

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
    exposure::Surface,
    runtime::OperationId,
    service::{
        Descriptor, Executed, MAX_KEY_BYTES, MAX_REQUEST_BYTES, Mode, Service, Shape, StartResult,
    },
    wire::{ErrorCode, WireError},
};
use herald_boundary::{Authenticated, Boundary, Guarded, error_response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub const API_PREFIX: &str = "/v1";
const SURFACE: Surface = Surface::Api;

/// A JSON body whose failure is a typed error, not axum's plain-text rejection. The body is read
/// as a bare value so that [`Service::prepare`] decides its shape, after exposure and authorisation.
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
        "`cursor` must be a non-negative integer",
    ))
}

#[derive(Deserialize)]
struct Cursor {
    #[serde(default)]
    cursor: u64,
}

/// The capability a path names. Only the canonical decimal spelling of a version resolves, as in the
/// MCP tool names, so `01` and `+1` are not `1`.
fn capability(name: String, version: &str) -> Result<CapabilityId, WireError> {
    version
        .parse::<u32>()
        .ok()
        .filter(|v| v.to_string() == version)
        .map(|version| CapabilityId { name, version })
        .ok_or_else(|| WireError::new(ErrorCode::NotFound, "no such capability"))
}

/// Calls the closure when dropped. A handler future dropped by the server because the client went
/// away drops this with it.
struct OnDrop<F: FnMut()>(F);
impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// The API's routes with no boundary applied. Compose with other routes and pass the result to
/// [`Guarded::new`]; every handler refuses a request that did not come through the boundary.
pub fn routes(service: Arc<Service>, boundary: &Boundary) -> Router {
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
    Router::new()
        .nest(API_PREFIX, api)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}

/// The API under `/v1`, behind the boundary.
pub fn router(service: Arc<Service>, boundary: Arc<Boundary>) -> Guarded {
    Guarded::new(routes(service, &boundary), boundary)
}

async fn not_found() -> Response {
    error_response(WireError::new(ErrorCode::NotFound, "no such route"))
}

async fn method_not_allowed() -> Response {
    let mut response = error_response(WireError::new(ErrorCode::BadRequest, "method not allowed"));
    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    response
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
    // A call ends when the client goes away. A start outlives its request, so nothing cancels it.
    let (sender, cancellation) = herald::cancellation();
    let _cancel_on_drop = (mode == Mode::Call && prepared.kind == Kind::Operation).then(|| {
        OnDrop(move || {
            let _ = sender.send(true);
        })
    });
    match service
        .execute(&principal, &capability, prepared, mode, cancellation)
        .await
    {
        Ok(Executed::Start(StartResult::Running { operation })) => (
            StatusCode::ACCEPTED,
            Json(json!(StartResult::Running { operation })),
        )
            .into_response(),
        Ok(Executed::Start(finished)) => (StatusCode::OK, Json(json!(finished))).into_response(),
        Ok(Executed::Call(call)) => (StatusCode::OK, Json(json!(call))).into_response(),
        Err(error) => error_response(error),
    }
}

async fn call(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<TypedJson, Response>,
) -> Response {
    run(service, principal, path, body, Mode::Call).await
}

async fn start(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<TypedJson, Response>,
) -> Response {
    run(service, principal, path, body, Mode::Start).await
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

/// Moves a schema's `$defs` or `definitions` into `components` under names prefixed with `prefix`
/// and points its references there, so the schema keeps resolving once it is embedded in the
/// document. Returns the rewritten schema.
fn lift(schema: &Value, prefix: &str, components: &mut serde_json::Map<String, Value>) -> Value {
    fn rewrite(value: &mut Value, prefix: &str) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map.iter_mut() {
                    if key == "$ref" {
                        if let Value::String(reference) = inner {
                            for root in ["#/$defs/", "#/definitions/"] {
                                if let Some(name) = reference.strip_prefix(root) {
                                    *reference = format!("#/components/schemas/{prefix}_{name}");
                                    break;
                                }
                            }
                        }
                    } else {
                        rewrite(inner, prefix);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|item| rewrite(item, prefix)),
            _ => {}
        }
    }
    let mut schema = schema.clone();
    if let Value::Object(map) = &mut schema {
        for root in ["$defs", "definitions"] {
            if let Some(Value::Object(definitions)) = map.remove(root) {
                for (name, mut definition) in definitions {
                    rewrite(&mut definition, prefix);
                    components.insert(format!("{prefix}_{name}"), definition);
                }
            }
        }
    }
    rewrite(&mut schema, prefix);
    schema
}

/// The OpenAPI 3.1 document for exactly the capabilities in `descriptors`, with `security` as the
/// scheme the boundary's authenticator advertises. It is generated from the same contracts the
/// handlers validate against, so the client contract cannot drift from them.
pub fn document(descriptors: &[Descriptor], security: &Value) -> Value {
    let mut paths = serde_json::Map::new();
    let mut schemas = serde_json::Map::new();
    let error = |description: &str| {
        json!({
            "description": description,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}
        })
    };
    for d in descriptors {
        let base = format!("{API_PREFIX}/capabilities/{}/{}", d.id.name, d.id.version);
        let is_operation = d.kind == Kind::Operation;
        let prefix = format!("{}_v{}", d.id.name.replace(['.', '-'], "_"), d.id.version);
        let input = lift(&d.input_schema, &format!("{prefix}_input"), &mut schemas);
        let output = lift(&d.output_schema, &format!("{prefix}_output"), &mut schemas);
        let failure = lift(&d.error_schema, &format!("{prefix}_error"), &mut schemas);
        let mut properties = json!({"input": input});
        let mut required = vec!["input"];
        if is_operation {
            properties["idempotency_key"] = json!({"type": "string", "minLength": 1,
                "description": format!("At most {MAX_KEY_BYTES} bytes. A retry with the same key replays the recorded outcome.")});
            required.push("idempotency_key");
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
        let result = json!({
            "type": "object",
            "required": ["outcome", "recorded"],
            "properties": {
                "operation": {"type": "string"},
                "outcome": {"oneOf": [
                    {"type": "object", "required": ["Success"], "additionalProperties": false, "properties": {"Success": output}},
                    {"type": "object", "required": ["Error"], "additionalProperties": false, "properties": {"Error": failure}},
                    {"type": "object", "required": ["Unknown"], "additionalProperties": false, "properties": {"Unknown": {}}}
                ]},
                "recorded": {"type": "boolean"},
                "failed": {"type": "boolean"},
                "uncertain": {"type": "boolean"}
            }
        });
        let route = |id: String, summary: &str, responses: Value| {
            json!({
                "operationId": id,
                "summary": summary,
                "x-herald-kind": d.kind,
                "x-herald-confirmation-required": d.confirmation_required,
                "requestBody": body,
                "responses": responses
            })
        };
        paths.insert(
            format!("{base}/call"),
            json!({"post": route(
                format!("call_{}_v{}", d.id.name, d.id.version),
                "Run to completion.",
                json!({
                    "200": {"description": "The outcome.", "content": {"application/json": {"schema": result}}},
                    "default": error("A typed error.")
                }),
            )}),
        );
        if is_operation {
            paths.insert(
                format!("{base}/start"),
                json!({"post": route(
                    format!("start_{}_v{}", d.id.name, d.id.version),
                    "Start and follow.",
                    json!({
                        "200": {"description": "Already finished.", "content": {"application/json": {"schema": result}}},
                        "202": {"description": "Running; follow it by id.",
                            "content": {"application/json": {"schema": {
                                "type": "object",
                                "required": ["state", "operation"],
                                "properties": {"state": {"const": "running"}, "operation": {"type": "string"}}
                            }}}},
                        "default": error("A typed error.")
                    }),
                )}),
            );
        }
    }
    let id = json!({"name": "id", "in": "path", "required": true, "schema": {"type": "string"}});
    paths.insert(
        format!("{API_PREFIX}/operations/{{id}}"),
        json!({"get": {
            "operationId": "get_operation",
            "summary": "Read an operation you started.",
            "parameters": [id],
            "responses": {"200": {"description": "The operation."}, "default": error("A typed error.")}
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
            "responses": {"200": {"description": "The events."}, "default": error("A typed error.")}
        }}),
    );
    schemas.insert(
        "ErrorResponse".to_owned(),
        json!({
            "type": "object",
            "required": ["error"],
            "properties": {"error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {"type": "string"},
                    "message": {"type": "string"},
                    "detail": {}
                }
            }}
        }),
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
