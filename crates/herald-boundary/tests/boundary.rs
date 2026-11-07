use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    routing::get,
};
use herald::{
    PortFuture,
    service::Principal,
    wire::{ErrorCode, WireError},
};
use herald_boundary::{
    Authenticated, Authenticator, Boundary, Guarded, OriginPolicy, error_response, status_for,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;

/// Accepts exactly one bearer token. A header that claims an identity is ignored.
struct Tokens {
    calls: AtomicUsize,
}
impl Authenticator for Tokens {
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Option<Principal>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            (headers.get(header::AUTHORIZATION)?.to_str().ok()? == "Bearer good-token")
                .then(|| Principal::new("alice").unwrap())
        })
    }
}

fn tokens() -> Arc<Tokens> {
    Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    })
}
fn policy() -> OriginPolicy {
    OriginPolicy::new(
        ["api.example.test".to_string()],
        ["https://app.example.test".to_string()],
    )
    .unwrap()
}
fn app(tokens: Arc<Tokens>) -> Router {
    let routes = Router::new().route(
        "/whoami",
        get(|Authenticated(p): Authenticated| async move { p.identity().to_owned() }),
    );
    Guarded::new(routes, Boundary::new(tokens, policy())).into_router_for_tests()
}
fn request(extra: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder()
        .uri("/whoami")
        .header("host", "api.example.test");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}
async fn body(response: axum::response::Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
const GOOD: (&str, &str) = ("authorization", "Bearer good-token");

#[tokio::test]
async fn a_valid_credential_reaches_the_handler_as_the_authenticated_principal() {
    let response = app(tokens()).oneshot(request(&[GOOD])).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, "alice");
}

#[tokio::test]
async fn a_claimed_identity_header_changes_nothing() {
    let response = app(tokens())
        .oneshot(request(&[GOOD, ("x-identity", "root"), ("x-user", "root")]))
        .await
        .unwrap();
    assert_eq!(body(response).await, "alice");
}

#[tokio::test]
async fn missing_or_wrong_credentials_get_a_typed_401() {
    let tokens = tokens();
    for headers in [
        vec![],
        vec![("authorization", "Bearer wrong")],
        vec![("authorization", "Basic good-token")],
    ] {
        let response = app(tokens.clone())
            .oneshot(request(&headers))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert!(body(response).await.contains("\"unauthenticated\""));
    }
}

#[tokio::test]
async fn a_foreign_or_null_origin_is_refused_before_credentials_are_read() {
    let tokens = tokens();
    for origin in [
        "https://evil.example",
        "null",
        "https://app.example.test.evil.example",
        "HTTPS://APP.EXAMPLE.TEST",
    ] {
        let response = app(tokens.clone())
            .oneshot(request(&[GOOD, ("origin", origin)]))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin}");
        assert!(body(response).await.contains("\"forbidden_origin\""));
    }
    assert_eq!(
        tokens.calls.load(Ordering::SeqCst),
        0,
        "the authenticator never saw a refused origin"
    );
}

#[tokio::test]
async fn a_listed_origin_and_no_origin_at_all_are_both_served() {
    let tokens = tokens();
    let listed = app(tokens.clone())
        .oneshot(request(&[GOOD, ("origin", "https://app.example.test")]))
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let none = app(tokens).oneshot(request(&[GOOD])).await.unwrap();
    assert_eq!(none.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_unserved_or_missing_host_is_refused_against_dns_rebinding() {
    let tokens = tokens();
    let rebound = Request::builder()
        .uri("/whoami")
        .header("host", "attacker.example")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone()).oneshot(rebound).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let upper = Request::builder()
        .uri("/whoami")
        .header("host", "API.EXAMPLE.TEST")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone()).oneshot(upper).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "matching is exact"
    );
    let hostless = Request::builder()
        .uri("/whoami")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone())
            .oneshot(hostless)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_http2_style_request_names_its_authority_in_the_uri_and_is_checked_the_same_way() {
    let tokens = tokens();
    let served = Request::builder()
        .uri("https://api.example.test/whoami")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone()).oneshot(served).await.unwrap().status(),
        StatusCode::OK
    );
    let foreign = Request::builder()
        .uri("https://attacker.example/whoami")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone()).oneshot(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_duplicated_host_or_origin_header_is_ambiguous_and_refused() {
    let tokens = tokens();
    let two_hosts = Request::builder()
        .uri("/whoami")
        .header("host", "api.example.test")
        .header("host", "attacker.example")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone())
            .oneshot(two_hosts)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let two_origins = Request::builder()
        .uri("/whoami")
        .header("host", "api.example.test")
        .header("origin", "https://app.example.test")
        .header("origin", "https://evil.example")
        .header(GOOD.0, GOOD.1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone())
            .oneshot(two_origins)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(tokens.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_answer_carries_no_store_and_vary_authorization_including_refusals() {
    for (request, status) in [
        (request(&[GOOD]), StatusCode::OK),
        (request(&[]), StatusCode::UNAUTHORIZED),
        (
            request(&[GOOD, ("origin", "https://evil.example")]),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let response = app(tokens()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::VARY], "Authorization");
    }
}

#[tokio::test]
async fn the_guard_covers_routes_that_do_not_exist_and_methods_that_are_not_allowed() {
    for uri in ["/nowhere", "/whoami/extra"] {
        let unauthenticated = Request::builder()
            .uri(uri)
            .header("host", "api.example.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app(tokens())
                .oneshot(unauthenticated)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }
    for method in ["POST", "DELETE", "OPTIONS"] {
        let wrong = Request::builder()
            .method(method)
            .uri("/whoami")
            .header("host", "api.example.test")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app(tokens()).oneshot(wrong).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{method}"
        );
    }
}

#[test]
fn a_policy_that_serves_nothing_everything_or_never_matches_cannot_be_built() {
    let hosts = |h: &[&str]| h.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let ok_origin = || vec!["https://a.test".to_string()];
    assert!(
        OriginPolicy::new(Vec::<String>::new(), ok_origin()).is_err(),
        "no host"
    );
    for bad in [
        "*",
        "",
        "API.EXAMPLE.TEST",
        "https://api.example.test",
        "api.example.test/",
        "api.example.test.",
        "a b",
    ] {
        assert!(
            OriginPolicy::new(hosts(&[bad]), ok_origin()).is_err(),
            "host {bad:?}"
        );
    }
    for bad in [
        "*",
        "",
        "null",
        "https://A.TEST",
        "https://a.test/",
        "https://a.test/path",
        "ftp://a.test",
        "a.test",
        "http://localhost:*",
        "https://a.test.",
    ] {
        assert!(
            OriginPolicy::new(hosts(&["h.test"]), vec![bad.to_string()]).is_err(),
            "origin {bad:?}"
        );
    }
    assert!(
        OriginPolicy::new(
            hosts(&["h.test:8443", "[::1]:8443"]),
            vec![
                "https://a.test:8443".to_string(),
                "http://localhost:3000".to_string()
            ]
        )
        .is_ok()
    );
    assert!(OriginPolicy::new(hosts(&["h.test"]), Vec::<String>::new()).is_ok());
}

#[tokio::test]
async fn a_handler_behind_no_boundary_fails_loudly_instead_of_guessing_an_identity() {
    let router = Router::new().route(
        "/whoami",
        get(|Authenticated(p): Authenticated| async move { p.identity().to_owned() }),
    );
    let response = router.oneshot(request(&[])).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// Adding a code without deciding its status fails to compile here, and the table pins every status.
#[test]
fn every_error_code_has_one_stable_http_status() {
    use ErrorCode::*;
    use StatusCode as S;
    fn expected(code: ErrorCode) -> StatusCode {
        match code {
            NotFound => S::NOT_FOUND,
            Denied => S::FORBIDDEN,
            Unsupported => S::NOT_IMPLEMENTED,
            SupportUnknown => S::SERVICE_UNAVAILABLE,
            ConfirmationRequired => S::PRECONDITION_REQUIRED,
            InvalidInput => S::UNPROCESSABLE_ENTITY,
            KeyConflict => S::CONFLICT,
            Cancelled => S::SERVICE_UNAVAILABLE,
            Interrupted => S::SERVICE_UNAVAILABLE,
            OutcomeLost => S::GATEWAY_TIMEOUT,
            ContractViolation => S::BAD_GATEWAY,
            Store => S::SERVICE_UNAVAILABLE,
            BadRequest => S::BAD_REQUEST,
            TooLarge => S::PAYLOAD_TOO_LARGE,
            UnsupportedMedia => S::UNSUPPORTED_MEDIA_TYPE,
            InProgress => S::CONFLICT,
            SourceFailed => S::BAD_GATEWAY,
            Unauthenticated => S::UNAUTHORIZED,
            ForbiddenOrigin => S::FORBIDDEN,
        }
    }
    for code in [
        NotFound,
        Denied,
        Unsupported,
        SupportUnknown,
        ConfirmationRequired,
        InvalidInput,
        KeyConflict,
        Cancelled,
        Interrupted,
        OutcomeLost,
        ContractViolation,
        Store,
        BadRequest,
        TooLarge,
        UnsupportedMedia,
        InProgress,
        SourceFailed,
        Unauthenticated,
        ForbiddenOrigin,
    ] {
        assert_eq!(status_for(code), expected(code), "{code:?}");
        assert_eq!(
            error_response(WireError::new(code, "x")).status(),
            expected(code)
        );
    }
}
