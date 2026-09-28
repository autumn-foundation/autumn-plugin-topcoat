//! Guards for the axum 0.8 behavior that the plugin design uses. Covers AC-23.
//!
//! If an axum or matchit upgrade changes one of these facts, the design in
//! `docs/adr/0001-mount-topcoat-with-typed-routes.md` needs a review.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use axum::Router;
use axum::body::Body;
use axum::routing::{any, get};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn call(router: &Router, method: &str, path: &str) -> (u16, String) {
    let request = http::Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn panics(f: impl FnOnce()) -> bool {
    catch_unwind(AssertUnwindSafe(f)).is_err()
}

/// Autumn calls `fallback` after it merges plugin routers: a plugin fallback is lost.
#[tokio::test]
async fn a_later_fallback_replaces_a_merged_fallback() {
    let plugin = Router::new().fallback_service(any(|| async { "plugin" }));
    let router = Router::new()
        .merge(plugin)
        .fallback(|| async { "autumn-404" });
    assert_eq!(call(&router, "GET", "/page").await.1, "autumn-404");
}

/// A method-agnostic route shares a path with a host `GET` route.
#[tokio::test]
async fn any_merges_with_get_on_one_path() {
    let router = Router::new()
        .route("/", get(|| async { "host" }))
        .merge(Router::new().route("/", any(|| async { "plugin" })));
    assert_eq!(call(&router, "GET", "/").await.1, "host");
    assert_eq!(call(&router, "HEAD", "/").await.0, 200);
    assert_eq!(call(&router, "POST", "/").await.1, "plugin");
}

/// A catch-all does not match the bare prefix.
#[tokio::test]
async fn catch_all_does_not_match_the_root() {
    let router = Router::new().route("/{*path}", any(|| async { "plugin" }));
    assert_eq!(call(&router, "GET", "/").await.0, 404);
    assert_eq!(call(&router, "GET", "/x").await.1, "plugin");
}

/// A root capture and a root catch-all cannot coexist.
#[test]
fn root_capture_conflicts_with_root_catch_all() {
    assert!(panics(|| {
        let _ = Router::<()>::new()
            .route("/{slug}", get(|| async { "slug" }))
            .route("/{*path}", any(|| async { "plugin" }));
    }));
    assert!(!panics(|| {
        let _ = Router::<()>::new()
            .route("/{slug}", get(|| async { "slug" }))
            .route("/app/{*path}", any(|| async { "plugin" }));
    }));
}

/// A nested router's fallback loses to the root catch-all.
#[tokio::test]
async fn nested_fallback_loses_to_the_catch_all() {
    let api = Router::new()
        .route("/x", get(|| async { "api-x" }))
        .fallback(|| async { "api-404" });
    let router = Router::new()
        .nest("/api", api)
        .route("/{*path}", any(|| async { "plugin" }));
    assert_eq!(call(&router, "GET", "/api/x").await.1, "api-x");
    assert_eq!(call(&router, "GET", "/api/unknown").await.1, "plugin");
}

/// Topcoat cannot answer other methods on a path that Autumn owns.
#[tokio::test]
async fn an_autumn_path_answers_405_for_other_methods() {
    let router = Router::new()
        .route("/about", get(|| async { "about" }))
        .route("/{*path}", any(|| async { "plugin" }));
    assert_eq!(call(&router, "POST", "/about").await.0, 405);
    assert_eq!(call(&router, "POST", "/about/").await.1, "plugin");
}
