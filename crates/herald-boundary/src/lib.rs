//! The edge every network adapter shares. It runs before any adapter logic: it rejects a request from
//! a host or origin the product does not serve, then authenticates the caller, and only then hands the
//! request on with a [`Principal`] that this crate constructed. Nothing the caller writes in a header or
//! body can choose that identity.
//!
//! This crate defines the hooks. Credentials, tokens and how they are verified belong to the product,
//! which supplies an [`Authenticator`].
//!
//! The boundary serves programmatic clients that send a credential header. Browser clients on another
//! origin also need CORS preflight answers, which this crate does not provide: a product that wants
//! them adds a CORS layer in front, answering only for origins in its [`OriginPolicy`]. The policy
//! refuses every other origin whatever the CORS layer says.

use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::IntoMakeService,
};
use herald::{
    PortFuture,
    service::Principal,
    wire::{ErrorCode, WireError},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc};

/// Verifies a request's credentials and names the caller. The product implements it.
///
/// It runs for every request whose host and origin are served, so it must be cheap and must compare
/// secrets in constant time. It must read a credential from a header the browser does not attach on
/// its own, such as `Authorization`, and must not accept cookies: a request with no `Origin` is
/// admitted as a non-browser client, which is only safe if the credential cannot ride along ambiently.
pub trait Authenticator: Send + Sync {
    /// The authenticated caller, or `None` when the credentials are missing or wrong. It must not
    /// trust a header that merely claims an identity.
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Option<Principal>>;

    /// The OpenAPI security scheme clients use, advertised in the generated contract. Defaults to a
    /// bearer token.
    fn security_scheme(&self) -> Value {
        json!({"type": "http", "scheme": "bearer"})
    }
}

/// The hosts and origins a deployment serves. Both lists are required and explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginPolicy {
    hosts: BTreeSet<String>,
    origins: BTreeSet<String>,
}

/// A policy that would reject every request, admit every request, or never match anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub &'static str);

impl OriginPolicy {
    /// `hosts` are the exact `Host` values served, in lower case, with any port and no scheme or
    /// trailing dot (`api.example.test:8443`). `origins` are the exact `Origin` values a browser may
    /// send: `http` or `https`, a lower-case host, an optional port and nothing else
    /// (`https://app.example.test`). A request with no `Origin` header is not from a browser and is
    /// allowed; one with a foreign or `null` origin is refused. A value that could never match what a
    /// client sends, or that would match too much, is rejected here instead of failing silently.
    pub fn new(
        hosts: impl IntoIterator<Item = String>,
        origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, PolicyError> {
        let hosts: BTreeSet<_> = hosts.into_iter().collect();
        let origins: BTreeSet<_> = origins.into_iter().collect();
        if hosts.is_empty() {
            return Err(PolicyError("at least one served host is required"));
        }
        if hosts.iter().any(|h| !is_host(h)) {
            return Err(PolicyError(
                "a host must be lower case, without a scheme, path, wildcard or trailing dot",
            ));
        }
        if origins.iter().any(|o| !is_origin(o)) {
            return Err(PolicyError(
                "an origin must be http or https, lower case, with a host, an optional port and nothing else",
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

    fn admits(&self, request_host: Option<&str>, headers: &HeaderMap) -> bool {
        // A duplicated Host or Origin is ambiguous, and a front proxy may pick a different one.
        if headers.get_all(header::HOST).iter().count() > 1
            || headers.get_all(header::ORIGIN).iter().count() > 1
        {
            return false;
        }
        let host_ok = request_host.is_some_and(|host| self.hosts.contains(host));
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

fn is_host(value: &str) -> bool {
    !value.is_empty()
        && !value.ends_with('.')
        && value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
        })
}

fn is_origin(value: &str) -> bool {
    value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .is_some_and(is_host)
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

    /// The security scheme the authenticator advertises.
    pub fn security_scheme(&self) -> Value {
        self.authenticator.security_scheme()
    }

    /// Use with `axum::middleware::from_fn_with_state(boundary, Boundary::guard)`, or through
    /// [`Guarded`], which cannot be extended with unguarded routes.
    pub async fn guard(
        State(boundary): State<Arc<Boundary>>,
        mut request: Request,
        next: Next,
    ) -> Response {
        // HTTP/2 carries the authority in the URI and no Host header; HTTP/1.1 carries it in Host.
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| request.uri().authority().map(|a| a.as_str()))
            .map(str::to_owned);
        // The origin check comes first, so a refused request never reaches credential handling.
        let mut response = if !boundary.policy.admits(host.as_deref(), request.headers()) {
            error_response(WireError::new(
                ErrorCode::ForbiddenOrigin,
                "this host or origin is not served",
            ))
        } else {
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
        };
        // Every answer depends on the credential, so no cache may keep or share one.
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::VARY, HeaderValue::from_static("Authorization"));
        response
    }
}

/// A router whose every route is behind the boundary, including routes it will never match. It has
/// no method that adds a route, so nothing can be placed outside the guard afterwards. To serve
/// product routes beside Herald's, build one router from the adapters' unguarded `routes` functions
/// and the product's own, then guard that.
pub struct Guarded(Router);

impl Guarded {
    /// Puts `routes` behind `boundary`: its routes, its fallback and its method-not-allowed answers.
    pub fn new(routes: Router, boundary: Arc<Boundary>) -> Self {
        Self(routes.layer(from_fn_with_state(boundary, Boundary::guard)))
    }

    /// Combines two guarded routers. Each part keeps its own boundary.
    pub fn merge(self, other: Guarded) -> Guarded {
        Guarded(self.0.merge(other.0))
    }

    /// For `axum::serve`.
    pub fn into_make_service(self) -> IntoMakeService<Router> {
        self.0.into_make_service()
    }

    /// For tests that drive the router without a socket. The result is a guarded router; adding to it
    /// is the caller's responsibility and is not covered by the boundary.
    pub fn into_router_for_tests(self) -> Router {
        self.0
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
        TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        UnsupportedMedia => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        OutcomeLost => StatusCode::GATEWAY_TIMEOUT,
        ContractViolation | SourceFailed => StatusCode::BAD_GATEWAY,
    }
}

/// A typed error as a JSON response: `{"error": {"code": ..., "message": ...}}`.
pub fn error_response(error: WireError) -> Response {
    (status_for(error.code), Json(json!({ "error": error }))).into_response()
}
