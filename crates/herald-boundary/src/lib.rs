//! The edge every network adapter shares. It runs before any adapter logic: it rejects a request from
//! a host or origin the product does not serve, then authenticates the caller, and only then hands the
//! request on with a [`Principal`] that this crate constructed. Nothing the caller writes in a header or
//! body can choose that identity.
//!
//! This crate defines the hooks. Credentials, tokens and how they are verified belong to the product,
//! which supplies an [`Authenticator`].
//!
//! The boundary also bounds its own load: each request has a deadline and the number in flight is
//! capped ([`Limits`]), so a slow or numerous caller cannot hold the server open. What it does not
//! bound is how long a connection may take to send its request headers, which is a setting of the
//! server that accepts connections, not of the router.
//!
//! The boundary serves programmatic clients that send a credential header. Browser clients on another
//! origin also need CORS preflight answers, which this crate does not provide: a product that wants
//! them adds a CORS layer in front, answering only for origins in its [`OriginPolicy`]. The policy
//! refuses every other origin whatever the CORS layer says.

use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts, uri::Authority},
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
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// What an [`Authenticator`] decided about a request's credentials.
pub enum Authentication {
    /// The credentials name this caller.
    Authenticated(Principal),
    /// The credentials are missing or wrong.
    Rejected,
    /// The credentials could not be checked, because the product's own backend failed. The caller is
    /// told to retry, which is not the same as being told its credentials are wrong.
    Unavailable,
}

impl From<Option<Principal>> for Authentication {
    fn from(principal: Option<Principal>) -> Self {
        principal.map_or(Self::Rejected, Self::Authenticated)
    }
}

/// Verifies a request's credentials and names the caller. The product implements it.
///
/// It runs for every request whose host and origin are served, so it must be cheap and must compare
/// secrets in constant time. It must read a credential from a header the browser does not attach on
/// its own, such as `Authorization`, and must not accept cookies: a request with no `Origin` is
/// admitted as a non-browser client, which is only safe if the credential cannot ride along ambiently.
/// A request that repeats `Authorization` is refused before it gets here.
///
/// A [`Principal`]'s identity is the key for operation ownership and idempotency scope, so an
/// authenticator that accepts more than one kind of credential or issuer must give identities that
/// cannot collide across them, for example by prefixing the issuer.
pub trait Authenticator: Send + Sync {
    /// The authenticated caller. It must not trust a header that merely claims an identity.
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Authentication>;

    /// The OpenAPI security scheme clients use, advertised in the generated contract. Defaults to a
    /// bearer token.
    fn security_scheme(&self) -> Value {
        json!({"type": "http", "scheme": "bearer"})
    }

    /// The `WWW-Authenticate` challenge sent with a 401. Defaults to the bearer scheme and must match
    /// [`Authenticator::security_scheme`].
    fn challenge(&self) -> &'static str {
        "Bearer"
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
    let Ok(authority) = value.parse::<Authority>() else {
        return false;
    };
    authority.as_str() == value
        && !value.contains('@')
        && !authority.host().is_empty()
        && !authority.host().ends_with('.')
        && value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
        })
        && authority.port().is_none_or(|_| authority.port_u16().is_some())
}

fn is_origin(value: &str) -> bool {
    let (default_port, rest) = if let Some(rest) = value.strip_prefix("https://") {
        (":443", rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (":80", rest)
    } else {
        return false;
    };
    // Browsers leave a scheme's default port out of the Origin they send, so an entry spelling it
    // could never match.
    is_host(rest) && !rest.ends_with(default_port)
}

/// How much load the boundary admits. Both fields are required: a deployment states them, so none is
/// a hidden default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    request_timeout: Duration,
    max_in_flight: usize,
}

/// A limit that would admit no request, or never expire one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitsError(pub &'static str);

impl Limits {
    /// `request_timeout` bounds the whole time from admission to the last response byte; a request
    /// over it is dropped and answered 504, which cancels a synchronous call's handler. Work that
    /// can run longer than this is started as a detached operation and followed, which a request
    /// deadline does not touch. `max_in_flight` is the number of requests served at once; the next
    /// one is answered 503 at once rather than queued.
    pub fn new(request_timeout: Duration, max_in_flight: usize) -> Result<Self, LimitsError> {
        if request_timeout.is_zero() {
            return Err(LimitsError("the request timeout must be positive"));
        }
        if max_in_flight == 0 {
            return Err(LimitsError("at least one request must be admitted at once"));
        }
        Ok(Self {
            request_timeout,
            max_in_flight,
        })
    }
}

/// Load limits, origin policy and authentication, applied as one middleware.
pub struct Boundary {
    authenticator: Arc<dyn Authenticator>,
    policy: OriginPolicy,
    limits: Limits,
    in_flight: Arc<Semaphore>,
}

impl Boundary {
    pub fn new(
        authenticator: Arc<dyn Authenticator>,
        policy: OriginPolicy,
        limits: Limits,
    ) -> Arc<Self> {
        Arc::new(Self {
            authenticator,
            policy,
            limits,
            in_flight: Arc::new(Semaphore::new(limits.max_in_flight)),
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
        request: Request,
        next: Next,
    ) -> Response {
        // Shed load before reading anything: an unauthenticated caller costs a permit, nothing more.
        let mut response = match boundary.in_flight.clone().try_acquire_owned() {
            Err(_) => error_response(WireError::new(
                ErrorCode::Unavailable,
                "the server is busy",
            )),
            Ok(_permit) => {
                // The permit is held until the response is built; the deadline covers the handler.
                match tokio::time::timeout(
                    boundary.limits.request_timeout,
                    boundary.admit(request, next),
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => error_response(WireError::new(
                        ErrorCode::TimedOut,
                        "the request took too long",
                    )),
                }
            }
        };
        // Every answer depends on the credential, so no cache may keep or share one.
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.append(header::VARY, HeaderValue::from_static("Authorization"));
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        response
    }

    async fn admit(&self, mut request: Request, next: Next) -> Response {
        // HTTP/2 carries the authority in the URI and no Host header; HTTP/1.1 carries it in Host,
        // and an absolute-form request line carries it in both. When both are present they must
        // agree, since a proxy or the application may trust the one the policy did not check.
        let header_host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok());
        let uri_host = request.uri().authority().map(Authority::as_str);
        let host = match (header_host, uri_host) {
            (Some(header), Some(uri)) if header != uri => None,
            (header, uri) => header.or(uri),
        };
        // The origin check comes first, so a refused request never reaches credential handling.
        if !self.policy.admits(host, request.headers()) {
            return error_response(WireError::new(
                ErrorCode::ForbiddenOrigin,
                "this host or origin is not served",
            ));
        }
        // A repeated Authorization is ambiguous, and a front proxy may pick a different one.
        let authentication = if request.headers().get_all(header::AUTHORIZATION).iter().count() > 1 {
            Authentication::Rejected
        } else {
            self.authenticator.authenticate(request.headers()).await
        };
        match authentication {
            Authentication::Authenticated(principal) => {
                request.extensions_mut().insert(principal);
                next.run(request).await
            }
            Authentication::Rejected => {
                let mut response = error_response(WireError::new(
                    ErrorCode::Unauthenticated,
                    "authentication is required",
                ));
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(self.authenticator.challenge()),
                );
                response
            }
            Authentication::Unavailable => error_response(WireError::new(
                ErrorCode::Unavailable,
                "authentication is unavailable",
            )),
        }
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
    /// is the caller's responsibility and is not covered by the boundary. Only built with the
    /// `testing` feature, so production code cannot take the guard apart.
    #[cfg(feature = "testing")]
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
                let mut response = error_response(WireError::new(
                    ErrorCode::ContractViolation,
                    "the boundary middleware is not installed",
                ));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                response
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
        SupportUnknown | Cancelled | Interrupted | Store | Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        TimedOut => StatusCode::GATEWAY_TIMEOUT,
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
