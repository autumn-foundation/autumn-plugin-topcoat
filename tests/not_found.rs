//! 404 ownership and excluded prefixes. Covers AC-16.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use autumn_plugin_topcoat::{NotFoundOwner, TopcoatPlugin};
use autumn_web::prelude::*;
use autumn_web::test::{TestApp, TestClient, TestResponse};
use topcoat::context::Cx;
use topcoat::router::error::not_found;
use topcoat::router::{Body, Layer, LayerFuture, Next, Path, Router, page, route};
use topcoat::runtime::RouterBuilderRuntimeExt;
use topcoat::view::{View, view};
use tower::ServiceExt;

#[page("/hello")]
async fn hello() -> topcoat::Result<impl View> {
    Ok(view! { <p>"hello"</p> })
}

#[route(GET "/gone")]
async fn gone() -> topcoat::Result<&'static str> {
    Err(not_found().into())
}

#[get("/autumn")]
async fn autumn_page() -> &'static str {
    "autumn"
}

/// Counts the requests that reach Topcoat.
struct Counter(&'static AtomicUsize);

impl Layer for Counter {
    fn path(&self) -> Option<&Path> {
        None
    }

    fn handle<'a>(&'a self, cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        next.run(cx, body)
    }
}

fn router() -> topcoat::router::RouterBuilder {
    Router::builder().page(hello).route(gone)
}

fn client(plugin: TopcoatPlugin) -> TestClient {
    TestApp::new()
        .routes(routes![autumn_page])
        .plugin(plugin)
        .build()
}

async fn get(client: &TestClient, path: &str, accept: &str) -> TestResponse {
    client.get(path).header("accept", accept).send().await
}

#[tokio::test]
async fn unmatched_paths_get_the_autumn_404() {
    let with_plugin = client(TopcoatPlugin::new().router(router()));
    let without_plugin = TestApp::new().routes(routes![autumn_page]).build();
    for accept in ["application/json", "text/html"] {
        let ours = get(&with_plugin, "/nope", accept).await;
        let theirs = get(&without_plugin, "/nope", accept).await;
        assert_eq!(ours.status, theirs.status, "{accept}");
        assert_eq!(
            ours.header("content-type"),
            theirs.header("content-type"),
            "{accept}"
        );
        assert_eq!(ours.status, 404);
    }
    get(&with_plugin, "/nope", "application/json")
        .await
        .assert_header_contains("content-type", "application/problem+json")
        .assert_body_contains("No route matches /nope");
}

#[tokio::test]
async fn favicon_gets_204_like_autumn() {
    let client = client(TopcoatPlugin::new().router(router()));
    client.get("/favicon.ico").send().await.assert_status(204);
    client.post("/favicon.ico").send().await.assert_status(404);
    let head = http::Request::head("/favicon.ico")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = client.into_router().oneshot(head).await.unwrap();
    assert_eq!(response.status(), 204);
}

#[tokio::test]
async fn topcoat_answers_for_matched_endpoints() {
    let client = client(TopcoatPlugin::new().router(router()));
    let page_404 = get(&client, "/gone", "*/*").await;
    page_404
        .assert_status(404)
        .assert_body_contains("not found");
    assert!(!page_404.text().contains("No route matches"));
    let wrong_method = client.post("/hello").send().await;
    wrong_method.assert_status(405);
    assert!(wrong_method.header("allow").is_some());
    let twin = client.get("/hello/").send().await;
    twin.assert_status(308);
    assert_eq!(twin.header("location"), Some("/hello"));
}

#[tokio::test]
async fn an_unknown_path_rerun_ends_as_the_autumn_404() {
    let client = client(TopcoatPlugin::new().router(router().runtime()));
    client
        .post("/nope")
        .header("x-topcoat-runtime", "true")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body("{\"signals\":{}}")
        .send()
        .await
        .assert_status(404)
        .assert_body_contains("No route matches /nope");
}

#[tokio::test]
async fn the_marker_survives_topcoat_compression() {
    let client = client(TopcoatPlugin::new().router(router()));
    client
        .get("/nope")
        .header("accept", "application/json")
        .header("accept-encoding", "gzip")
        .send()
        .await
        .assert_status(404)
        .assert_body_contains("No route matches /nope");
}

#[tokio::test]
async fn topcoat_can_own_404() {
    let client = client(
        TopcoatPlugin::new()
            .router(router())
            .not_found(NotFoundOwner::Topcoat),
    );
    let response = get(&client, "/nope", "application/json").await;
    response.assert_status(404).assert_body_eq("not found");
}

#[tokio::test]
async fn excluded_prefixes_never_reach_topcoat() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let plugin = TopcoatPlugin::new()
        .router(router().layer(Counter(&CALLS)))
        .exclude("/api");
    let client = client(plugin);
    get(&client, "/api/unknown", "application/json")
        .await
        .assert_status(404)
        .assert_body_contains("No route matches /api/unknown");
    assert_eq!(CALLS.load(Ordering::SeqCst), 0);
    get(&client, "/apix", "application/json")
        .await
        .assert_status(404);
    assert_eq!(CALLS.load(Ordering::SeqCst), 1, "/apix is not under /api");
}
