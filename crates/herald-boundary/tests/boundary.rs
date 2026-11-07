use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    middleware::from_fn_with_state,
    routing::get,
};
use herald::{PortFuture, service::Principal};
use herald_boundary::{Authenticated, Authenticator, Boundary, OriginPolicy};
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
                .then(|| Principal::new("alice"))
        })
    }
}

fn app(tokens: Arc<Tokens>) -> Router {
    let policy = OriginPolicy::new(
        ["api.example.test".to_string()],
        ["https://app.example.test".to_string()],
    )
    .unwrap();
    let boundary = Boundary::new(tokens, policy);
    Router::new()
        .route(
            "/whoami",
            get(|Authenticated(p): Authenticated| async move { p.identity().to_owned() }),
        )
        .layer(from_fn_with_state(boundary, Boundary::guard))
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

#[tokio::test]
async fn a_valid_credential_reaches_the_handler_as_the_authenticated_principal() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    });
    let response = app(tokens)
        .oneshot(request(&[("authorization", "Bearer good-token")]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, "alice");
}

#[tokio::test]
async fn a_claimed_identity_header_changes_nothing() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    });
    let response = app(tokens)
        .oneshot(request(&[
            ("authorization", "Bearer good-token"),
            ("x-identity", "root"),
            ("x-user", "root"),
        ]))
        .await
        .unwrap();
    assert_eq!(body(response).await, "alice");
}

#[tokio::test]
async fn missing_or_wrong_credentials_get_a_typed_401() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    });
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
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    });
    for origin in [
        "https://evil.example",
        "null",
        "https://app.example.test.evil.example",
    ] {
        let response = app(tokens.clone())
            .oneshot(request(&[
                ("authorization", "Bearer good-token"),
                ("origin", origin),
            ]))
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
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    });
    let listed = app(tokens.clone())
        .oneshot(request(&[
            ("authorization", "Bearer good-token"),
            ("origin", "https://app.example.test"),
        ]))
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let none = app(tokens)
        .oneshot(request(&[("authorization", "Bearer good-token")]))
        .await
        .unwrap();
    assert_eq!(none.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_unserved_or_missing_host_is_refused_against_dns_rebinding() {
    let tokens = Arc::new(Tokens {
        calls: AtomicUsize::new(0),
    });
    let rebound = Request::builder()
        .uri("/whoami")
        .header("host", "attacker.example")
        .header("authorization", "Bearer good-token")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app(tokens.clone()).oneshot(rebound).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let hostless = Request::builder()
        .uri("/whoami")
        .header("authorization", "Bearer good-token")
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

#[test]
fn a_policy_that_serves_nothing_or_everything_cannot_be_built() {
    assert!(OriginPolicy::new(Vec::<String>::new(), ["https://a".to_string()]).is_err());
    assert!(OriginPolicy::new(["*".to_string()], Vec::<String>::new()).is_err());
    assert!(OriginPolicy::new(["h".to_string()], ["*".to_string()]).is_err());
    assert!(OriginPolicy::new(["h".to_string()], Vec::<String>::new()).is_ok());
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
