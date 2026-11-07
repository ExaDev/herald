//! The edge every network adapter shares. It runs before any adapter logic: it rejects a request from
//! a host or origin the product does not serve, then authenticates the caller, and only then hands the
//! request on with a [`Principal`] that this crate constructed. Nothing the caller writes in a header or
//! body can choose that identity.
//!
//! This crate defines the hooks. Credentials, tokens and how they are verified belong to the product,
//! which supplies an [`Authenticator`].

use axum::{
    Json,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use herald::{
    PortFuture,
    service::Principal,
    wire::{ErrorCode, WireError},
};
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

/// Verifies a request's credentials and names the caller. The product implements it.
pub trait Authenticator: Send + Sync {
    /// The authenticated caller, or `None` when the credentials are missing or wrong. It must not
    /// trust a header that merely claims an identity.
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Option<Principal>>;
}

/// The hosts and origins a deployment serves. Both lists are required and explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginPolicy {
    hosts: BTreeSet<String>,
    origins: BTreeSet<String>,
}

/// A policy that would reject every request, or admit every request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub &'static str);

impl OriginPolicy {
    /// `hosts` are the exact `Host` header values served, including any port. `origins` are the exact
    /// `Origin` values a browser may send. A request with no `Origin` header is not from a browser and
    /// is allowed, but one with a foreign or `null` origin is refused.
    pub fn new(
        hosts: impl IntoIterator<Item = String>,
        origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, PolicyError> {
        let hosts: BTreeSet<_> = hosts.into_iter().collect();
        let origins: BTreeSet<_> = origins.into_iter().collect();
        if hosts.is_empty() {
            return Err(PolicyError("at least one served host is required"));
        }
        if hosts
            .iter()
            .chain(&origins)
            .any(|v| v == "*" || v.is_empty())
        {
            return Err(PolicyError(
                "a wildcard or empty host or origin is not allowed",
            ));
        }
        Ok(Self { hosts, origins })
    }

    /// The served hosts, for handing the same list to an SDK that also checks them.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// The allowed origins, likewise.
    pub fn origins(&self) -> impl Iterator<Item = &str> {
        self.origins.iter().map(String::as_str)
    }

    fn admits(&self, headers: &HeaderMap) -> bool {
        let host_ok = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|host| self.hosts.contains(host));
        let origin_ok = match headers.get(header::ORIGIN) {
            None => true,
            Some(origin) => origin
                .to_str()
                .ok()
                .is_some_and(|origin| self.origins.contains(origin)),
        };
        host_ok && origin_ok
    }
}

/// Origin policy and authentication, applied as one middleware.
pub struct Boundary {
    authenticator: Arc<dyn Authenticator>,
    policy: OriginPolicy,
}

impl Boundary {
    pub fn new(authenticator: Arc<dyn Authenticator>, policy: OriginPolicy) -> Arc<Self> {
        Arc::new(Self {
            authenticator,
            policy,
        })
    }

    pub fn policy(&self) -> &OriginPolicy {
        &self.policy
    }

    /// Use with `axum::middleware::from_fn_with_state(boundary, Boundary::guard)`.
    pub async fn guard(
        State(boundary): State<Arc<Boundary>>,
        mut request: Request,
        next: Next,
    ) -> Response {
        // The origin check comes first, so a refused request never reaches credential handling.
        if !boundary.policy.admits(request.headers()) {
            return error_response(WireError::new(
                ErrorCode::ForbiddenOrigin,
                "this host or origin is not served",
            ));
        }
        match boundary.authenticator.authenticate(request.headers()).await {
            Some(principal) => {
                request.extensions_mut().insert(principal);
                next.run(request).await
            }
            None => {
                let mut response = error_response(WireError::new(
                    ErrorCode::Unauthenticated,
                    "authentication is required",
                ));
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                response
            }
        }
    }
}

/// The caller the boundary authenticated. A handler asks for this and never reads identity elsewhere.
pub struct Authenticated(pub Principal);

impl<S: Send + Sync> FromRequestParts<S> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(Authenticated)
            // Reaching a handler without the boundary is a wiring mistake, never a caller error.
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the boundary middleware is not installed",
                )
                    .into_response()
            })
    }
}

/// The HTTP status for an error code. One mapping serves every HTTP adapter.
pub fn status_for(code: ErrorCode) -> StatusCode {
    use ErrorCode::*;
    match code {
        NotFound => StatusCode::NOT_FOUND,
        Denied | ForbiddenOrigin => StatusCode::FORBIDDEN,
        Unauthenticated => StatusCode::UNAUTHORIZED,
        Unsupported => StatusCode::NOT_IMPLEMENTED,
        SupportUnknown | Cancelled | Interrupted | Store => StatusCode::SERVICE_UNAVAILABLE,
        ConfirmationRequired => StatusCode::PRECONDITION_REQUIRED,
        InvalidInput => StatusCode::UNPROCESSABLE_ENTITY,
        KeyConflict | InProgress => StatusCode::CONFLICT,
        BadRequest => StatusCode::BAD_REQUEST,
        OutcomeLost => StatusCode::GATEWAY_TIMEOUT,
        ContractViolation | SourceFailed => StatusCode::BAD_GATEWAY,
    }
}

/// A typed error as a JSON response: `{"error": {"code": ..., "message": ...}}`.
pub fn error_response(error: WireError) -> Response {
    (status_for(error.code), Json(json!({ "error": error }))).into_response()
}
