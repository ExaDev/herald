//! Herald capabilities as a versioned JSON API under `/v1`, behind the same boundary as the MCP
//! network transport. Every handler calls [`Service`], so exposure, authorisation, consent,
//! idempotency and error typing are the ones the MCP adapter has. Every failure, including a request
//! body that does not parse, is a typed [`WireError`] as JSON.
//!
//! - `GET  /v1/capabilities`: the capabilities the caller may use.
//! - `POST /v1/capabilities/{name}/{version}/call`: run to completion.
//! - `POST /v1/capabilities/{name}/{version}/start`: return once an operation is running.
//! - `GET  /v1/operations/{id}` and `/v1/operations/{id}/events?cursor=N`: follow an operation.
//! - `GET  /v1/openapi.json`: the client contract, generated for the caller from the descriptors.

use axum::{
    Json, Router,
    extract::{FromRequest, Path, Query, Request, State, rejection::JsonRejection},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use herald::{
    CapabilityId,
    exposure::Surface,
    runtime::OperationId,
    service::{Descriptor, MAX_KEY_BYTES, Service, StartResult},
    wire::{ErrorCode, WireError},
};
use herald_boundary::{Authenticated, Boundary, error_response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub const API_PREFIX: &str = "/v1";
const CALL_SURFACE: Surface = Surface::Api;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallBody {
    input: Value,
    #[serde(default)]
    idempotency_key: Option<String>,
}

/// A JSON body whose parse failure is a typed error, not axum's plain-text rejection.
struct TypedJson<T>(T);

impl<S: Send + Sync, T: serde::de::DeserializeOwned> FromRequest<S> for TypedJson<T> {
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(error_response(bad_request(&rejection))),
        }
    }
}

fn bad_request(rejection: &JsonRejection) -> WireError {
    // The status and a fixed message: serde's text can quote the offending bytes back.
    let message = match rejection {
        JsonRejection::MissingJsonContentType(_) => "the request must be application/json",
        JsonRejection::BytesRejection(_) => "the request body could not be read",
        _ => "the request body is not the expected JSON",
    };
    WireError::new(ErrorCode::BadRequest, message)
}

#[derive(Deserialize)]
struct Cursor {
    #[serde(default)]
    cursor: u64,
}

fn capability(name: String, version: u32) -> CapabilityId {
    CapabilityId { name, version }
}

/// The API under `/v1`, with the boundary applied to every route.
pub fn router(service: Arc<Service>, boundary: Arc<Boundary>) -> Router {
    let routes = Router::new()
        .route("/capabilities", get(list))
        .route("/capabilities/{name}/{version}/call", post(call))
        .route("/capabilities/{name}/{version}/start", post(start))
        .route("/operations/{id}", get(operation))
        .route("/operations/{id}/events", get(events))
        .route("/openapi.json", get(openapi))
        .fallback(|| async { error_response(WireError::new(ErrorCode::NotFound, "no such route")) })
        .method_not_allowed_fallback(|| async {
            let mut response =
                error_response(WireError::new(ErrorCode::BadRequest, "method not allowed"));
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            response
        })
        .with_state(service);
    Router::new()
        .nest(API_PREFIX, routes)
        .layer(from_fn_with_state(boundary, Boundary::guard))
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
    Json(json!({ "capabilities": service.list(&principal, CALL_SURFACE).await })).into_response()
}

async fn call(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    Path((name, version)): Path<(String, u32)>,
    body: Result<TypedJson<CallBody>, Response>,
) -> Response {
    let TypedJson(body) = match body {
        Ok(body) => body,
        Err(response) => return response,
    };
    let result = service
        .call(
            &principal,
            CALL_SURFACE,
            &capability(name, version),
            body.input,
            body.idempotency_key,
            herald::cancellation().1,
        )
        .await;
    respond(StatusCode::OK, result)
}

async fn start(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    Path((name, version)): Path<(String, u32)>,
    body: Result<TypedJson<CallBody>, Response>,
) -> Response {
    let TypedJson(body) = match body {
        Ok(body) => body,
        Err(response) => return response,
    };
    let result = service
        .start(
            &principal,
            CALL_SURFACE,
            &capability(name, version),
            body.input,
            body.idempotency_key,
            herald::cancellation().1,
        )
        .await;
    let status = match &result {
        Ok(StartResult::Running { .. }) => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    respond(status, result)
}

async fn operation(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    Path(id): Path<String>,
) -> Response {
    respond(
        StatusCode::OK,
        service
            .operation(&principal, CALL_SURFACE, &OperationId(id))
            .await,
    )
}

async fn events(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
    Path(id): Path<String>,
    Query(cursor): Query<Cursor>,
) -> Response {
    let result = service
        .events_after(&principal, CALL_SURFACE, &OperationId(id), cursor.cursor)
        .await
        .map(|events| json!({ "events": events }));
    respond(StatusCode::OK, result)
}

async fn openapi(
    State(service): State<Arc<Service>>,
    Authenticated(principal): Authenticated,
) -> Response {
    Json(document(&service.list(&principal, CALL_SURFACE).await)).into_response()
}

/// The OpenAPI 3.1 document for exactly the capabilities in `descriptors`. It is generated from the
/// same contracts the handlers validate against, so the client contract cannot drift from them.
pub fn document(descriptors: &[Descriptor]) -> Value {
    let mut paths = serde_json::Map::new();
    let error_responses = json!({
        "default": {
            "description": "A typed error.",
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}
        }
    });
    for d in descriptors {
        let base = format!("{API_PREFIX}/capabilities/{}/{}", d.id.name, d.id.version);
        let body = json!({
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "required": ["input"],
                "additionalProperties": false,
                "properties": {
                    "input": d.input_schema,
                    "idempotency_key": {"type": "string", "minLength": 1, "maxLength": MAX_KEY_BYTES}
                }
            }}}
        });
        let operation = |id: &str, summary: &str| {
            json!({
                "operationId": id,
                "summary": summary,
                "x-herald-kind": d.kind,
                "x-herald-confirmation-required": d.confirmation_required,
                "requestBody": body,
                "responses": {
                    "200": {"description": "The outcome.", "content": {"application/json": {"schema": {"type": "object"}}}},
                    "default": error_responses["default"]
                }
            })
        };
        paths.insert(
            format!("{base}/call"),
            json!({"post": operation(&format!("call_{}_v{}", d.id.name, d.id.version), "Run to completion.")}),
        );
        if d.kind == herald::Kind::Operation {
            paths.insert(
                format!("{base}/start"),
                json!({"post": operation(&format!("start_{}_v{}", d.id.name, d.id.version), "Start and follow.")}),
            );
        }
    }
    for (path, id, summary) in [
        (
            "/operations/{id}",
            "get_operation",
            "Read an operation you started.",
        ),
        (
            "/operations/{id}/events",
            "get_operation_events",
            "Read its events from a cursor.",
        ),
    ] {
        paths.insert(
            format!("{API_PREFIX}{path}"),
            json!({"get": {
                "operationId": id,
                "summary": summary,
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "The result."}, "default": error_responses["default"]}
            }}),
        );
    }
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Herald API", "version": "1"},
        "security": [{"bearer": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "ErrorResponse": {
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
                }
            }
        }
    })
}
