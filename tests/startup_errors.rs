//! Configuration and startup errors. Covers AC-7 and AC-8.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use autumn_plugin_topcoat::TopcoatPlugin;
use autumn_web::test::TestApp;
use topcoat::router::{Router, route};

#[route(GET "/one")]
async fn one() -> topcoat::Result<&'static str> {
    Ok("one")
}

#[route(GET "/one")]
async fn one_again() -> topcoat::Result<&'static str> {
    Ok("again")
}

fn startup_panic(plugin: TopcoatPlugin) -> String {
    common::build_panic(TestApp::new().plugin(plugin)).expect("the startup must fail")
}

#[tokio::test]
async fn no_router_stops_the_startup() {
    let panic = startup_panic(TopcoatPlugin::new());
    assert!(panic.contains("no Topcoat router is set"), "{panic}");
}

#[tokio::test]
async fn each_invalid_option_is_named() {
    let panic = startup_panic(
        TopcoatPlugin::new()
            .router(Router::builder().route(one))
            .mount_at("/static")
            .exclude("bad")
            .runtime_prefix("/:x"),
    );
    assert!(panic.contains("invalid mount path"), "{panic}");
    assert!(panic.contains("reserved by Autumn static files"), "{panic}");
    assert!(panic.contains("invalid excluded prefix"), "{panic}");
    assert!(panic.contains("invalid runtime prefix"), "{panic}");
}

#[tokio::test]
async fn an_empty_router_stops_the_startup() {
    let panic = startup_panic(TopcoatPlugin::new().router(Router::builder()));
    assert!(
        panic.contains("the Topcoat router has no routes"),
        "{panic}"
    );
    let panic =
        startup_panic(TopcoatPlugin::new().router_with(|_| Ok::<_, String>(Router::builder())));
    assert!(
        panic.contains("the Topcoat router has no routes"),
        "{panic}"
    );
}

#[tokio::test]
async fn factory_errors_and_panics_stop_the_startup() {
    let panic = startup_panic(
        TopcoatPlugin::new().router_with(|_| Err::<topcoat::router::RouterBuilder, _>("no bundle")),
    );
    assert!(panic.contains("router factory failed"), "{panic}");
    assert!(panic.contains("no bundle"), "{panic}");

    let panic = startup_panic(
        TopcoatPlugin::new().router_with(|_| -> Result<_, String> { panic!("factory boom") }),
    );
    assert!(panic.contains("router factory failed"), "{panic}");
    assert!(panic.contains("factory boom"), "{panic}");
}

#[tokio::test]
async fn a_build_panic_stops_the_startup() {
    let panic =
        startup_panic(TopcoatPlugin::new().router(Router::builder().route(one).route(one_again)));
    assert!(panic.contains("RouterBuilder::build panicked"), "{panic}");
}

#[tokio::test]
async fn a_factory_can_read_the_app_state() {
    let client = TestApp::new()
        .plugin(TopcoatPlugin::new().router_with(|state| {
            assert_eq!(state.profile(), "test");
            Ok::<_, String>(Router::builder().route(one))
        }))
        .build();
    client.get("/one").send().await.assert_body_eq("one");
}
