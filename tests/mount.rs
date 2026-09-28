//! Mounting: typed routes, full-path forwarding and coexistence with Autumn routes.
//! Covers AC-2, AC-3, AC-4, AC-5 and AC-20.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use autumn_plugin_topcoat::TopcoatPlugin;
use autumn_web::prelude::*;
use autumn_web::test::TestApp;
use topcoat::context::Cx;
use topcoat::router::request::{method, uri};
use topcoat::router::{Router, href, page, route};
use topcoat::view::{View, view};

#[route(* "/")]
async fn topcoat_root(cx: &Cx) -> topcoat::Result<String> {
    Ok(format!("topcoat {} /", method(cx)))
}

#[route(* "/a/b/c")]
async fn deep(cx: &Cx) -> topcoat::Result<String> {
    let target = uri(cx)
        .path_and_query()
        .map_or("", |p| p.as_str())
        .to_owned();
    Ok(format!("topcoat {} {target}", method(cx)))
}

#[route(GET "/healthz")]
async fn healthz() -> topcoat::Result<&'static str> {
    Ok("topcoat healthz")
}

/// A Topcoat route under the Autumn static namespace. Autumn must win.
#[route(GET "/static/missing.css")]
async fn static_css() -> topcoat::Result<&'static str> {
    Ok("topcoat static")
}

#[route(GET "/staticfoo")]
async fn staticfoo() -> topcoat::Result<&'static str> {
    Ok("topcoat staticfoo")
}

#[page("/app")]
async fn app_home() -> topcoat::Result<impl View> {
    Ok(view! { <p>"app home"</p> })
}

#[page("/app/x")]
async fn app_x() -> topcoat::Result<impl View> {
    Ok(view! { <a href=(href!(app_x))>"self"</a> })
}

#[route(GET "/_topcoat/assets/app-0123456789abcdef.js")]
async fn asset() -> topcoat::Result<&'static str> {
    Ok("asset")
}

#[get("/api/users")]
async fn users() -> &'static str {
    "autumn users"
}

#[get("/")]
async fn host_root() -> &'static str {
    "autumn root"
}

#[get("/{slug}")]
async fn slug() -> &'static str {
    "autumn slug"
}

#[route(* "/")]
async fn second() -> topcoat::Result<&'static str> {
    Ok("second")
}

fn root_plugin() -> TopcoatPlugin {
    TopcoatPlugin::new().router(
        Router::builder()
            .route(topcoat_root)
            .route(deep)
            .route(healthz)
            .route(static_css)
            .route(staticfoo),
    )
}

#[tokio::test]
async fn serves_root_and_deep_paths_unmodified() {
    let client = TestApp::new().plugin(root_plugin()).build();
    client
        .get("/")
        .send()
        .await
        .assert_ok()
        .assert_body_eq("topcoat GET /");
    client
        .get("/a/b/c?x=1&y=%20")
        .send()
        .await
        .assert_ok()
        .assert_body_eq("topcoat GET /a/b/c?x=1&y=%20");
    client
        .post("/a/b/c?z=2")
        .send()
        .await
        .assert_ok()
        .assert_body_eq("topcoat POST /a/b/c?z=2");
    client
        .delete("/a/b/c")
        .send()
        .await
        .assert_ok()
        .assert_body_eq("topcoat DELETE /a/b/c");
}

#[tokio::test]
async fn framework_and_host_routes_win_over_the_catch_all() {
    let client = TestApp::new()
        .routes(routes![users])
        .plugin(root_plugin())
        .build();
    client.get("/health").send().await.assert_ok();
    client
        .get("/api/users")
        .send()
        .await
        .assert_body_eq("autumn users");
    let missing = client.get("/static/missing.css").send().await;
    missing.assert_status(404);
    assert_ne!(missing.text(), "topcoat static");
    client
        .get("/healthz")
        .send()
        .await
        .assert_body_eq("topcoat healthz");
    client
        .get("/staticfoo")
        .send()
        .await
        .assert_body_eq("topcoat staticfoo");
}

#[tokio::test]
async fn host_get_root_shares_the_root_path() {
    let client = TestApp::new()
        .routes(routes![host_root])
        .plugin(root_plugin())
        .build();
    client.get("/").send().await.assert_body_eq("autumn root");
    client
        .post("/")
        .send()
        .await
        .assert_body_eq("topcoat POST /");
}

#[tokio::test]
async fn root_capture_conflict_is_a_typed_autumn_error() {
    let app = TestApp::new().routes(routes![slug]).plugin(root_plugin());
    let panic = common::build_panic(app).expect("the build must fail");
    assert!(panic.contains("ConflictingRouteShape"), "{panic}");
    assert!(panic.contains("/{slug}"), "{panic}");
}

#[tokio::test]
async fn prefix_mount_escapes_the_root_capture() {
    let plugin = TopcoatPlugin::new()
        .mount_at("/app")
        .router(Router::builder().page(app_home).page(app_x).route(asset));
    let client = TestApp::new().routes(routes![slug]).plugin(plugin).build();
    client
        .get("/hello")
        .send()
        .await
        .assert_body_eq("autumn slug");
    client
        .get("/app/x")
        .send()
        .await
        .assert_ok()
        .assert_body_contains("href=\"/app/x\"");
    client
        .get("/app")
        .send()
        .await
        .assert_ok()
        .assert_body_contains("app home");
    let slash = client.get("/app/").send().await;
    slash.assert_status(308);
    assert_eq!(slash.header("location"), Some("/app"));
    client
        .get("/_topcoat/assets/app-0123456789abcdef.js")
        .send()
        .await
        .assert_body_eq("asset");
    // Outside the templates, under the mount and under `/_topcoat`, an
    // unknown path gets the Autumn 404.
    for path in ["/other/deep", "/app/nope", "/_topcoat/nope"] {
        let response = client.get(path).send().await;
        response.assert_status(404);
        assert!(
            response
                .text()
                .contains(&format!("No route matches {path}")),
            "{path}: {}",
            response.text()
        );
    }
}

/// An invalid config registers no routes, so no route conflict hides the
/// config error.
#[tokio::test]
async fn an_invalid_mount_registers_no_route() {
    let app = TestApp::new().routes(routes![slug]).plugin(
        TopcoatPlugin::new()
            .mount_at("/static")
            .router(Router::builder().route(topcoat_root)),
    );
    let panic = common::build_panic(app).expect("the startup must fail");
    assert!(panic.contains("invalid mount path"), "{panic}");
    assert!(!panic.contains("ConflictingRouteShape"), "{panic}");
}

/// The `/openapi.json` document does not show the plugin routes.
#[tokio::test]
async fn openapi_hides_the_plugin_routes() {
    let plugin = TopcoatPlugin::new()
        .mount_at("/app")
        .router(Router::builder().page(app_home).page(app_x).route(asset));
    let client = TestApp::new()
        .openapi(autumn_web::openapi::OpenApiConfig::new("test", "1"))
        .routes(routes![users])
        .plugin(plugin)
        .build();
    let response = client.get("/openapi.json").send().await;
    response.assert_ok();
    let document: serde_json::Value = serde_json::from_str(&response.text()).unwrap();
    let paths = document["paths"].as_object().expect("a paths object");
    assert!(paths.contains_key("/api/users"), "{paths:?}");
    for key in paths.keys() {
        assert!(
            !key.starts_with("/app") && !key.starts_with("/_topcoat"),
            "plugin path {key} is in the document"
        );
    }
}

#[tokio::test]
async fn a_second_registration_is_skipped() {
    let client = TestApp::new()
        .plugin(root_plugin())
        .plugin(TopcoatPlugin::new().router(Router::builder().route(second)))
        .build();
    client.get("/").send().await.assert_body_eq("topcoat GET /");
}

#[tokio::test]
async fn slash_mount_is_the_root_mount() {
    let plugin = TopcoatPlugin::new()
        .mount_at("/")
        .router(Router::builder().route(topcoat_root));
    let client = TestApp::new().plugin(plugin).build();
    client.get("/").send().await.assert_body_eq("topcoat GET /");
}
