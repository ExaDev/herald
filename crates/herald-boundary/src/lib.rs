//! The edge every network adapter shares. It runs before any adapter logic: it rejects a request from a host or origin the product does not serve, then authenticates the caller, and only then hands the request on with the [`Principal`] the product's authenticator named, which this crate attaches to the request. Nothing the caller writes in a header or body can choose that identity.
//!
//! This crate defines the hooks. Credentials, tokens and how they are verified belong to the product, which supplies an [`Authenticator`].
//!
//! The boundary also bounds its own load: each request has a deadline and the number in flight is capped ([`Limits`]), so a slow or numerous caller cannot hold the server open. What it does not bound is how long a connection may take to send its request headers, which is a setting of the server that accepts connections, not of the router.
//!
//! The boundary serves programmatic clients that send a credential header. Browser clients on another origin also need CORS preflight answers, which this crate does not provide: a preflight carries no credential, so the guard would refuse it. A product that needs them answers them in front of this router, for example in a proxy, and only for origins in its [`OriginPolicy`]. The policy refuses every other origin whatever answers in front.

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
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What an [`Authenticator`] decided about a request's credentials.
pub enum Authentication {
    /// The credentials name this caller.
    Authenticated(Principal),
    /// The credentials are missing or wrong.
    Rejected,
    /// The credentials could not be checked, because the product's own backend failed. The caller is told to retry, which is not the same as being told its credentials are wrong.
    Unavailable,
}

impl From<Option<Principal>> for Authentication {
    fn from(principal: Option<Principal>) -> Self {
        principal.map_or(Self::Rejected, Self::Authenticated)
    }
}

/// Verifies a request's credentials and names the caller. The product implements it.
///
/// It runs for every request whose host and origin are served, so it must be cheap and must compare secrets in constant time. It must read a credential from a header the browser does not attach on its own, such as `Authorization`, and must not accept cookies: a request with no `Origin` is admitted as a non-browser client, which is only safe if the credential cannot ride along ambiently. A request that repeats `Authorization` is refused before it gets here.
///
/// A [`Principal`]'s identity is the key for operation ownership and idempotency scope, so an authenticator that accepts more than one kind of credential or issuer must give identities that cannot collide across them, for example by prefixing the issuer.
pub trait Authenticator: Send + Sync {
    /// The authenticated caller. It must not trust a header that merely claims an identity.
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Authentication>;

    /// The OpenAPI security scheme clients use, advertised in the generated contract. Defaults to a bearer token.
    fn security_scheme(&self) -> Value {
        json!({"type": "http", "scheme": "bearer"})
    }

    /// The `WWW-Authenticate` challenge sent with a 401. Defaults to the bearer scheme and must match [`Authenticator::security_scheme`].
    fn challenge(&self) -> &'static str {
        "Bearer"
    }
}

/// The hosts and origins a deployment serves. The host list is required and both are explicit: an empty origin list means no browser origin is served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginPolicy {
    hosts: BTreeSet<String>,
    origins: BTreeSet<String>,
}

/// A policy that would reject every request, admit every request or never match anything, or an authenticator whose challenge cannot be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError(pub &'static str);

impl OriginPolicy {
    /// `hosts` are the exact `Host` values served, in lower case, with any port and no scheme or trailing dot (`api.example.test:8443`). `origins` are the exact `Origin` values a browser may send: `http` or `https`, a lower-case host, an optional port and nothing else (`https://app.example.test`). A request with no `Origin` header is treated as a non-browser client and allowed; one with a foreign or `null` origin is refused. A value that could never match what a client sends, or that would match too much, is rejected here instead of failing silently.
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
                "a host must be lower case letters, digits, '-' and '.' (or a bracketed IPv6 literal) with an optional port, without a scheme, path, wildcard or trailing dot",
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
        // `Authority` reads an out-of-range port as no port, so the digits are checked here. The text after the last colon is a port unless that colon is inside an IPv6 literal.
        && value
            .rsplit_once(':')
            .is_none_or(|(_, port)| port.contains(']') || port.parse::<u16>().is_ok())
}

fn is_origin(value: &str) -> bool {
    let (default_port, rest) = if let Some(rest) = value.strip_prefix("https://") {
        (":443", rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (":80", rest)
    } else {
        return false;
    };
    // Browsers leave a scheme's default port out of the Origin they send, so an entry spelling it could never match.
    is_host(rest) && !rest.ends_with(default_port)
}

/// The in-flight slot of the request being served. Work that must keep the slot after the request ends, such as a handler still winding down after a deadline, holds a clone until it returns.
#[derive(Clone)]
pub struct Admitted {
    _slot: Arc<OwnedSemaphorePermit>,
    /// Set once the caller is known, and shared by every clone, so whoever holds the slot holds the caller's share with it.
    _caller: Arc<std::sync::OnceLock<CallerSlot>>,
}

/// One authenticated caller's share of the in-flight requests, given back when dropped.
struct CallerSlot {
    callers: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    identity: String,
}

impl Drop for CallerSlot {
    fn drop(&mut self) {
        let mut callers = self.callers.lock().expect("caller lock is never poisoned");
        if let Some(count) = callers.get_mut(&self.identity) {
            *count -= 1;
            if *count == 0 {
                callers.remove(&self.identity);
            }
        }
    }
}

/// How much load the boundary admits. Every field is required: a deployment states them, so none is a hidden default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    request_timeout: Duration,
    max_in_flight: usize,
    max_per_caller: usize,
}

/// A limit that would admit no request, or leave none any time to finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitsError(pub &'static str);

impl Limits {
    /// `request_timeout` bounds the time from admission until the response is ready (its status and headers; a route that streams its body afterwards is not covered, and a product that adds one bounds it itself). A request over it is answered 504 and a synchronous call's handler is told to stop. Work that can run longer than this is started as a detached operation and followed, which a request deadline does not touch; the runtime's `RunningLimit` bounds those.
    ///
    /// `max_in_flight` is the number of requests served at once, counting from before the caller is authenticated, and the next one is answered 503 at once rather than queued. A handler that ignores its cancellation keeps its slot after the 504 until it returns ([`Admitted`]), so such handlers cannot accumulate beyond this number. `max_per_caller` is how many of those one authenticated caller may hold, so a single credential cannot take them all; a request beyond it is answered 503 once the caller is known. The count is of requests, and a caller is told apart by its principal, so an authenticator that gives one person several identities gives them several shares. Size the cap with the memory a request costs in mind: a 1 MiB JSON body becomes a value many times larger once parsed, and is copied while the request is prepared.
    pub fn new(
        request_timeout: Duration,
        max_in_flight: usize,
        max_per_caller: usize,
    ) -> Result<Self, LimitsError> {
        if request_timeout.is_zero() {
            return Err(LimitsError("the request timeout must be positive"));
        }
        if max_per_caller == 0 {
            return Err(LimitsError("a caller must be allowed one request"));
        }
        if max_per_caller > max_in_flight {
            return Err(LimitsError("one caller cannot exceed the overall limit"));
        }
        if max_in_flight > Semaphore::MAX_PERMITS {
            return Err(LimitsError(
                "the overall limit is more than a semaphore can hold",
            ));
        }
        Ok(Self {
            request_timeout,
            max_in_flight,
            max_per_caller,
        })
    }
}

/// Load limits, origin policy and authentication, applied as one middleware.
pub struct Boundary {
    authenticator: Arc<dyn Authenticator>,
    policy: OriginPolicy,
    limits: Limits,
    in_flight: Arc<Semaphore>,
    callers: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
    /// The 401 challenge, checked once so a bad one fails at start-up and not on a caller's request.
    challenge: HeaderValue,
}

impl Boundary {
    /// Fails if the authenticator's challenge is not a valid header value.
    pub fn new(
        authenticator: Arc<dyn Authenticator>,
        policy: OriginPolicy,
        limits: Limits,
    ) -> Result<Arc<Self>, PolicyError> {
        let challenge = HeaderValue::from_str(authenticator.challenge())
            .map_err(|_| PolicyError("the authentication challenge is not a valid header value"))?;
        Ok(Arc::new(Self {
            authenticator,
            policy,
            limits,
            in_flight: Arc::new(Semaphore::new(limits.max_in_flight)),
            callers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            challenge,
        }))
    }

    /// Takes one of the caller's shares, or `None` when it already holds as many as it may.
    fn take_caller_slot(&self, identity: &str) -> Option<CallerSlot> {
        let mut callers = self.callers.lock().expect("caller lock is never poisoned");
        let count = callers.entry(identity.to_owned()).or_insert(0);
        if *count >= self.limits.max_per_caller {
            return None;
        }
        *count += 1;
        Some(CallerSlot {
            callers: Arc::clone(&self.callers),
            identity: identity.to_owned(),
        })
    }

    /// The hosts and origins this boundary serves.
    pub fn policy(&self) -> &OriginPolicy {
        &self.policy
    }

    /// The security scheme the authenticator advertises.
    pub fn security_scheme(&self) -> Value {
        self.authenticator.security_scheme()
    }

    /// Use with `axum::middleware::from_fn_with_state(boundary, Boundary::guard)`, or through [`Guarded`], which cannot be extended with unguarded routes.
    pub async fn guard(
        State(boundary): State<Arc<Boundary>>,
        request: Request,
        next: Next,
    ) -> Response {
        // Shed load before reading anything: an unauthenticated caller costs a permit, nothing more.
        let mut response = match boundary.in_flight.clone().try_acquire_owned() {
            Err(_) => error_response(WireError::new(ErrorCode::Unavailable, "the server is busy")),
            Ok(permit) => {
                // The permit travels with the request, so work that outlives the deadline (a handler that has not yet noticed it was cancelled) still holds its slot.
                let admitted = Admitted {
                    _slot: Arc::new(permit),
                    _caller: Arc::new(std::sync::OnceLock::new()),
                };
                // This clone holds the slot until the response is built, whichever handler shape runs, since a handler that takes no extractor drops the request's extensions before it starts.
                let _held = admitted.clone();
                match tokio::time::timeout(
                    boundary.limits.request_timeout,
                    boundary.admit(request, next, admitted),
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

    async fn admit(&self, mut request: Request, next: Next, admitted: Admitted) -> Response {
        // HTTP/2 carries the authority in the URI and no Host header; HTTP/1.1 carries it in Host, and an absolute-form request line carries it in both. When both are present they must agree, since a proxy or the application may trust the one the policy did not check.
        let header_host = request.headers().get(header::HOST).map(|v| v.to_str().ok());
        let uri_host = request.uri().authority().map(Authority::as_str);
        let host = match (header_host, uri_host) {
            // A Host header that cannot be read as text is not one the policy can judge, and a downstream component might read it anyway, so it is refused rather than ignored.
            (Some(None), _) => None,
            (Some(Some(header)), Some(uri)) if header != uri => None,
            (Some(Some(header)), _) => Some(header),
            (None, uri) => uri,
        };
        // The origin check comes first, so a refused request never reaches credential handling.
        if !self.policy.admits(host, request.headers()) {
            return error_response(WireError::new(
                ErrorCode::ForbiddenOrigin,
                "this host or origin is not served",
            ));
        }
        // A repeated Authorization is ambiguous, and a front proxy may pick a different one.
        let authentication = if request
            .headers()
            .get_all(header::AUTHORIZATION)
            .iter()
            .count()
            > 1
        {
            Authentication::Rejected
        } else {
            self.authenticator.authenticate(request.headers()).await
        };
        match authentication {
            Authentication::Authenticated(principal) => {
                // The caller's share is taken once it is known, and held with the request's slot.
                let Some(slot) = self.take_caller_slot(principal.identity()) else {
                    return error_response(WireError::new(
                        ErrorCode::Unavailable,
                        "too many requests from this caller are in progress",
                    ));
                };
                admitted
                    ._caller
                    .set(slot)
                    .unwrap_or_else(|_| unreachable!("a request is authenticated once"));
                request.extensions_mut().insert(principal);
                request.extensions_mut().insert(admitted);
                next.run(request).await
            }
            Authentication::Rejected => {
                let mut response = error_response(WireError::new(
                    ErrorCode::Unauthenticated,
                    "authentication is required",
                ));
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, self.challenge.clone());
                response
            }
            Authentication::Unavailable => error_response(WireError::new(
                ErrorCode::Unavailable,
                "authentication is unavailable",
            )),
        }
    }
}

/// Routes that will be served behind the boundary, including the paths and methods they do not match. The guard and the typed not-found and method-not-allowed answers are applied once, when the router is finished, so routes from several adapters (each built without a fallback of its own) compose with [`Guarded::merge`] and nothing can be added outside the guard afterwards.
pub struct Guarded {
    routes: Router,
    boundary: Arc<Boundary>,
}

impl Guarded {
    /// Routes to serve behind `boundary`. Pass routes that set no fallback of their own outside their prefix, such as the adapters' `routes` functions return; the fallback is added when the router is finished.
    pub fn new(routes: Router, boundary: Arc<Boundary>) -> Self {
        Self { routes, boundary }
    }

    /// Adds more routes, for example another adapter's, behind the same boundary.
    pub fn merge(mut self, routes: Router) -> Self {
        self.routes = self.routes.merge(routes);
        self
    }

    /// The finished router: typed answers for what no route matches, and the guard around all of it.
    fn finish(self) -> Router {
        self.routes
            .fallback(|| async {
                error_response(WireError::new(ErrorCode::NotFound, "no such route"))
            })
            .method_not_allowed_fallback(|| async {
                error_response(WireError::new(
                    ErrorCode::MethodNotAllowed,
                    "method not allowed",
                ))
            })
            .layer(from_fn_with_state(self.boundary, Boundary::guard))
    }

    /// For `axum::serve`.
    pub fn into_make_service(self) -> IntoMakeService<Router> {
        self.finish().into_make_service()
    }

    /// For tests that drive the router without a socket. The result is the finished, guarded router; adding to it is the caller's responsibility and is not covered by the boundary. Only built with the `testing` feature, so production code cannot take the guard apart.
    #[cfg(feature = "testing")]
    pub fn into_router_for_tests(self) -> Router {
        self.finish()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Admitted {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Admitted>()
            .cloned()
            .ok_or_else(missing_boundary)
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
            .ok_or_else(missing_boundary)
    }
}

fn missing_boundary() -> Response {
    let mut response = error_response(WireError::new(
        ErrorCode::ContractViolation,
        "the boundary middleware is not installed",
    ));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

/// The HTTP status for an error code. The HTTP responses the adapters build use it for every typed error they produce. Three cases differ. A tool-level error from the MCP adapter travels in the result of a successful response and has no status of its own. A refusal the MCP SDK makes before a handler runs keeps the status the SDK chose, with a typed body. A missing boundary is a 500.
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
        MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
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
