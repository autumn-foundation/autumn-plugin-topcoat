//! 404 ownership and excluded prefixes. Covers AC-16.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use autumn_plugin_topcoat::{NotFoundOwner, TopcoatPlugin};
use autumn_web::prelude::*;
use autumn_web::test::{TestApp, TestClient, TestResponse};
use topcoat::context::Cx;
use topcoat::router::error::not_found;
use topcoat::router::response::Response;
use topcoat::router::response::response_headers;
use topcoat::router::{
    Body, Compression, HeaderValue, Layer, LayerFuture, Next, Path, Router, header, page, route,
    router,
};
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

/// Returns the response of a sub-request for a path with no Topcoat route.
#[route(GET "/include")]
async fn include(cx: &Cx) -> topcoat::Result<Response> {
    let inner = http::Request::get("/missing-fragment")
        .body(Body::empty())
        .unwrap();
    Ok(router(cx).handle(inner).await)
}

/// Returns the response of a sub-request made from a copy of the request
/// parts. The copy keeps the request extensions.
#[route(GET "/include-parts")]
async fn include_parts(cx: &Cx) -> topcoat::Result<Response> {
    let mut parts = topcoat::router::request::parts(cx).clone();
    parts.uri = "/missing-fragment".parse().unwrap();
    Ok(router(cx)
        .handle(http::Request::from_parts(parts, Body::empty()))
        .await)
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

/// Sets a cookie on each Topcoat response.
struct SetCookie;

impl Layer for SetCookie {
    fn path(&self) -> Option<&Path> {
        None
    }

    fn handle<'a>(&'a self, cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
        response_headers(cx).append(header::SET_COOKIE, HeaderValue::from_static("seen=1"));
        next.run(cx, body)
    }
}

/// Returns the JSON body without the `request_id` field, which differs for
/// each request.
fn problem(response: &TestResponse) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(&response.text()).unwrap();
    value.as_object_mut().unwrap().remove("request_id");
    value
}

/// Returns the HTML body without the request id.
fn html_without_request_id(response: &TestResponse) -> String {
    let text = response.text();
    match response.header("x-request-id") {
        Some(id) => text.replace(id, ""),
        None => text,
    }
}

fn builder() -> topcoat::router::RouterBuilder {
    Router::builder()
        .page(hello)
        .route(gone)
        .route(include)
        .route(include_parts)
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
    let with_plugin = client(TopcoatPlugin::new().router(builder()));
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
        if accept == "application/json" {
            assert_eq!(problem(&ours), problem(&theirs));
        } else {
            assert_eq!(
                html_without_request_id(&ours),
                html_without_request_id(&theirs)
            );
        }
    }
    get(&with_plugin, "/nope", "application/json")
        .await
        .assert_header_contains("content-type", "application/problem+json")
        .assert_body_contains("No route matches /nope");
}

/// Returns the status of a `/favicon.ico` request with `method`.
async fn favicon_status(client: TestClient, method: http::Method) -> http::StatusCode {
    let request = http::Request::builder()
        .method(method)
        .uri("/favicon.ico")
        .body(axum::body::Body::empty())
        .unwrap();
    client
        .into_router()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn favicon_gets_204_like_autumn() {
    for method in [
        http::Method::GET,
        http::Method::HEAD,
        http::Method::POST,
        http::Method::OPTIONS,
    ] {
        let ours = favicon_status(
            client(TopcoatPlugin::new().router(builder())),
            method.clone(),
        );
        let theirs = favicon_status(
            TestApp::new().routes(routes![autumn_page]).build(),
            method.clone(),
        );
        let (ours, theirs) = (ours.await, theirs.await);
        assert_eq!(ours, theirs, "{method}");
        let expected = if method == http::Method::GET || method == http::Method::HEAD {
            204
        } else {
            404
        };
        assert_eq!(ours.as_u16(), expected, "{method}");
    }
}

#[tokio::test]
async fn topcoat_answers_for_matched_endpoints() {
    let client = client(TopcoatPlugin::new().router(builder()));
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
    let client = client(TopcoatPlugin::new().router(builder().runtime()));
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
    // With `min_size(0)`, Topcoat compresses the empty tagged 404 too.
    let tagged =
        client(TopcoatPlugin::new().router(builder().compression(Compression::new().min_size(0))));
    tagged
        .get("/nope")
        .header("accept", "application/json")
        .header("accept-encoding", "gzip")
        .send()
        .await
        .assert_status(404)
        .assert_body_contains("No route matches /nope");
    // The same config compresses a Topcoat 404, so compression really runs.
    let owned = client(
        TopcoatPlugin::new()
            .router(builder().compression(Compression::new().min_size(0)))
            .not_found(NotFoundOwner::Topcoat),
    );
    let compressed = owned
        .get("/nope")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    compressed.assert_status(404);
    assert_eq!(compressed.header("content-encoding"), Some("gzip"));
}

#[tokio::test]
async fn topcoat_can_own_404() {
    let client = client(
        TopcoatPlugin::new()
            .router(builder())
            .not_found(NotFoundOwner::Topcoat),
    );
    let response = get(&client, "/nope", "application/json").await;
    response.assert_status(404).assert_body_eq("not found");
}

#[tokio::test]
async fn excluded_prefixes_never_reach_topcoat() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let plugin = TopcoatPlugin::new()
        .router(builder().layer(Counter(&CALLS)))
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

/// Regression: a matched route that returns a sub-request response keeps it.
#[tokio::test]
async fn sub_request_404_does_not_become_the_autumn_404() {
    let client = client(TopcoatPlugin::new().router(builder()));
    let response = get(&client, "/include", "application/json").await;
    response.assert_status(404).assert_body_eq("not found");
}

#[tokio::test]
async fn the_autumn_404_keeps_topcoat_cookies() {
    let client = client(TopcoatPlugin::new().router(builder().layer(SetCookie)));
    let response = get(&client, "/nope", "application/json").await;
    response
        .assert_status(404)
        .assert_body_contains("No route matches /nope");
    assert!(
        common::header_values(&response, "set-cookie").contains(&"seen=1".to_owned()),
        "{:?}",
        common::header_values(&response, "set-cookie")
    );
}

/// The Topcoat origin check runs before endpoint matching. So a cross-site
/// `POST` to an unknown path gets the Topcoat 403, not the Autumn 404.
#[tokio::test]
async fn a_cross_site_post_to_an_unknown_path_gets_the_topcoat_403() {
    let client = client(TopcoatPlugin::new().router(builder()));
    let response = client
        .post("/nope")
        .header("sec-fetch-site", "cross-site")
        .header("origin", "https://evil.example")
        .send()
        .await;
    response.assert_status(403);
    assert!(
        !response.text().contains("No route matches"),
        "{}",
        response.text()
    );
}

/// Regression: a sub-request made from copied parts keeps its own 404.
#[tokio::test]
async fn sub_request_from_copied_parts_keeps_its_404() {
    let client = client(TopcoatPlugin::new().router(builder()));
    let response = get(&client, "/include-parts", "application/json").await;
    response.assert_status(404).assert_body_eq("not found");
}
