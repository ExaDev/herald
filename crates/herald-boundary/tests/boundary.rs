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
    Authenticated, Authentication, Authenticator, Boundary, Guarded, Limits, OriginPolicy,
    error_response, status_for,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tower::ServiceExt;

/// Accepts exactly one bearer token. A header that claims an identity is ignored.
struct Tokens {
    calls: AtomicUsize,
}
impl Authenticator for Tokens {
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> PortFuture<'a, Authentication> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                == Some("Bearer good-token")
            {
                Authentication::Authenticated(Principal::new("alice").unwrap())
            } else {
                Authentication::Rejected
            }
        })
    }
}

fn limits() -> Limits {
    Limits::new(Duration::from_secs(60), 64, 64).unwrap()
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
    Guarded::new(routes, Boundary::new(tokens, policy(), limits()).unwrap()).into_router_for_tests()
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
    assert!(
        body(response).await.contains("contract_violation"),
        "typed, not plain text"
    );
}

/// Adding a code without deciding its status fails to compile here, and the table pins every status `status_for` gives the errors the adapters produce themselves. A refusal the MCP SDK makes before a handler runs keeps the status the SDK chose, with a typed body, so it is outside this table.
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
            MethodNotAllowed => S::METHOD_NOT_ALLOWED,
            TooLarge => S::PAYLOAD_TOO_LARGE,
            UnsupportedMedia => S::UNSUPPORTED_MEDIA_TYPE,
            InProgress => S::CONFLICT,
            SourceFailed => S::BAD_GATEWAY,
            Unauthenticated => S::UNAUTHORIZED,
            ForbiddenOrigin => S::FORBIDDEN,
            Unavailable => S::SERVICE_UNAVAILABLE,
            TimedOut => S::GATEWAY_TIMEOUT,
        }
    }
    for &code in ErrorCode::ALL {
        assert_eq!(status_for(code), expected(code), "{code:?}");
        assert_eq!(
            error_response(WireError::new(code, "x")).status(),
            expected(code)
        );
    }
}

fn app_with(authenticator: Arc<dyn Authenticator>, limits: Limits, routes: Router) -> Router {
    Guarded::new(
        routes,
        Boundary::new(authenticator, policy(), limits).unwrap(),
    )
    .into_router_for_tests()
}

#[tokio::test]
async fn a_host_header_and_a_uri_authority_that_disagree_are_refused() {
    let agree = Request::builder()
        .uri("http://api.example.test/whoami")
        .header("host", "api.example.test")
        .header("authorization", "Bearer good-token")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens()).oneshot(agree).await.unwrap().status(),
        StatusCode::OK
    );
    for (uri, host) in [
        ("http://evil.test/whoami", "api.example.test"),
        ("http://api.example.test/whoami", "evil.test"),
    ] {
        let split = Request::builder()
            .uri(uri)
            .header("host", host)
            .header("authorization", "Bearer good-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app(tokens()).oneshot(split).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "{uri} {host}"
        );
    }
}

#[tokio::test]
async fn a_repeated_authorization_header_is_refused_before_the_authenticator_sees_it() {
    let seen = tokens();
    let doubled = Request::builder()
        .uri("/whoami")
        .header("host", "api.example.test")
        .header("authorization", "Bearer good-token")
        .header("authorization", "Bearer good-token")
        .body(Body::empty())
        .unwrap();
    let response = app(seen.clone()).oneshot(doubled).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(seen.calls.load(Ordering::SeqCst), 0);
}

/// An authenticator whose backend is down.
struct Down;
impl Authenticator for Down {
    fn authenticate<'a>(&'a self, _: &'a HeaderMap) -> PortFuture<'a, Authentication> {
        Box::pin(async { Authentication::Unavailable })
    }
    fn challenge(&self) -> &'static str {
        "Custom"
    }
}

#[tokio::test]
async fn an_authentication_backend_failure_is_a_retryable_503_not_a_rejected_credential() {
    let routes = Router::new().route("/whoami", get(|| async { "x" }));
    let response = app_with(Arc::new(Down), limits(), routes)
        .oneshot(request(&[GOOD]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().get("www-authenticate").is_none());
    assert!(body(response).await.contains("unavailable"));
}

#[tokio::test]
async fn the_challenge_comes_from_the_authenticator() {
    struct Rejects;
    impl Authenticator for Rejects {
        fn authenticate<'a>(&'a self, _: &'a HeaderMap) -> PortFuture<'a, Authentication> {
            Box::pin(async { Authentication::Rejected })
        }
        fn challenge(&self) -> &'static str {
            "Custom realm=\"x\""
        }
    }
    let routes = Router::new().route("/whoami", get(|| async { "x" }));
    let response = app_with(Arc::new(Rejects), limits(), routes)
        .oneshot(request(&[]))
        .await
        .unwrap();
    assert_eq!(response.headers()["www-authenticate"], "Custom realm=\"x\"");
}

#[tokio::test]
async fn a_request_past_its_deadline_is_dropped_with_a_typed_504() {
    let routes = Router::new().route(
        "/whoami",
        get(|| async {
            std::future::pending::<()>().await;
            "never"
        }),
    );
    let limits = Limits::new(Duration::from_millis(50), 8, 8).unwrap();
    let response = app_with(tokens(), limits, routes)
        .oneshot(request(&[GOOD]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(body(response).await.contains("timed_out"));
}

#[tokio::test]
async fn requests_beyond_the_in_flight_limit_are_shed_at_once_and_a_permit_frees_on_completion() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let held = gate.clone();
    let routes = Router::new().route(
        "/whoami",
        get(move || {
            let held = held.clone();
            async move {
                held.notified().await;
                "done"
            }
        }),
    );
    let router = app_with(
        tokens(),
        Limits::new(Duration::from_secs(30), 1, 1).unwrap(),
        routes,
    );
    let first = tokio::spawn(router.clone().oneshot(request(&[GOOD])));
    tokio::task::yield_now().await;
    // The second request arrives while the first holds the only permit, even though it carries no credential: load is shed before anything is read.
    let second = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let attempt = router.clone().oneshot(request(&[])).await.unwrap();
            if attempt.status() == StatusCode::SERVICE_UNAVAILABLE {
                return attempt;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a second request is shed while the first holds the only slot");
    assert!(body(second).await.contains("unavailable"));
    gate.notify_one();
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    let after = router.clone().oneshot(request(&[])).await.unwrap();
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "the permit was released"
    );
}

#[test]
fn limits_that_admit_nothing_or_leave_no_time_cannot_be_built() {
    let second = Duration::from_secs(1);
    assert!(Limits::new(Duration::ZERO, 1, 1).is_err());
    assert!(Limits::new(second, 0, 0).is_err());
    assert!(
        Limits::new(second, 2, 0).is_err(),
        "a caller must be allowed a request"
    );
    assert!(
        Limits::new(second, 2, 3).is_err(),
        "one caller cannot exceed the whole"
    );
    assert!(Limits::new(second, 1, 1).is_ok());
}

#[test]
fn entries_a_browser_could_never_match_or_that_are_not_authorities_are_rejected() {
    let origins = |o: &str| OriginPolicy::new(["h.test".to_string()], [o.to_string()]);
    for bad in [
        "https://a.test:443",
        "http://a.test:80",
        "https://a.test:99999",
        "https://a.test:b",
        "https://user@a.test",
        "https://a.test/",
        "https://[",
        "https://",
    ] {
        assert!(origins(bad).is_err(), "{bad}");
    }
    for good in [
        "https://a.test",
        "https://a.test:8443",
        "http://a.test:443",
        "https://[::1]:8443",
    ] {
        assert!(origins(good).is_ok(), "{good}");
    }
    for bad in [
        "a:b:c",
        "h.test:99999",
        "user@h.test",
        "h.test:",
        "[",
        ":80",
    ] {
        assert!(
            OriginPolicy::new([bad.to_string()], Vec::<String>::new()).is_err(),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn every_answer_carries_nosniff_and_keeps_a_vary_the_route_set() {
    let routes = Router::new().route(
        "/whoami",
        get(|| async { ([(header::VARY, "Accept")], "x") }),
    );
    let response = app_with(tokens(), limits(), routes)
        .oneshot(request(&[GOOD]))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let vary: Vec<_> = response
        .headers()
        .get_all(header::VARY)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert!(
        vary.contains(&"Accept".to_string()) && vary.contains(&"Authorization".to_string()),
        "{vary:?}"
    );
}

#[tokio::test]
async fn a_host_header_that_is_not_text_is_refused_not_ignored() {
    let request = Request::builder()
        .uri("http://api.example.test/whoami")
        .header(
            "host",
            header::HeaderValue::from_bytes(b"api.example.test\xff").unwrap(),
        )
        .header("authorization", "Bearer good-token")
        .body(Body::empty())
        .unwrap();
    let response = app(tokens()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_plain_handler_holds_the_slot_while_it_runs_even_though_it_reads_nothing() {
    // This handler takes no extractor, so the request is dropped as it starts. The slot must still be held until the response is built, or the limit would never shed anything.
    let gate = Arc::new(tokio::sync::Notify::new());
    let held = gate.clone();
    let routes = Router::new().route(
        "/whoami",
        get(move || {
            let held = held.clone();
            async move {
                held.notified().await;
                "done"
            }
        }),
    );
    let router = app_with(
        tokens(),
        Limits::new(Duration::from_secs(30), 1, 1).unwrap(),
        routes,
    );
    let first = tokio::spawn(router.clone().oneshot(request(&[GOOD])));
    let shed = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            // No credential: if this wins the slot before the first request does, it is answered 401 at once and the loop tries again; once the first holds the slot it is answered 503.
            let attempt = router.clone().oneshot(request(&[])).await.unwrap();
            if attempt.status() == StatusCode::SERVICE_UNAVAILABLE {
                return attempt;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shed while the first request runs");
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    gate.notify_one();
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
}
