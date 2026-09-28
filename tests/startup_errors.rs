//! Configuration and startup errors. Covers AC-7 and AC-8.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::await_holding_lock,
    missing_docs
)]

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
    let _serial = common::serial();
    let panic = startup_panic(TopcoatPlugin::new());
    assert!(
        panic.contains("the plugin has no Topcoat router"),
        "{panic}"
    );
}

#[tokio::test]
async fn each_invalid_option_is_named() {
    let _serial = common::serial();
    let panic = startup_panic(
        TopcoatPlugin::new()
            .router(Router::builder().route(one))
            .mount_at("/static")
            .exclude("bad")
            .runtime_prefix("/:x"),
    );
    assert!(panic.contains("invalid mount path"), "{panic}");
    assert!(panic.contains("belongs to Autumn static files"), "{panic}");
    assert!(panic.contains("invalid excluded prefix"), "{panic}");
    assert!(panic.contains("invalid runtime prefix"), "{panic}");
}

#[tokio::test]
async fn an_empty_router_stops_the_startup() {
    let _serial = common::serial();
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
    let _serial = common::serial();
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
    let _serial = common::serial();
    let panic =
        startup_panic(TopcoatPlugin::new().router(Router::builder().route(one).route(one_again)));
    assert!(panic.contains("RouterBuilder::build panicked"), "{panic}");
}

#[tokio::test]
async fn a_factory_can_read_the_app_state() {
    let _serial = common::serial();
    let client = TestApp::new()
        .plugin(TopcoatPlugin::new().router_with(|state| {
            assert_eq!(state.profile(), "test");
            Ok::<_, String>(Router::builder().route(one))
        }))
        .build();
    client.get("/one").send().await.assert_body_eq("one");
}

/// A cause that the error chain must keep.
#[derive(Debug)]
struct Root;

impl std::fmt::Display for Root {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("manifest.toml is missing")
    }
}

impl std::error::Error for Root {}

#[derive(Debug)]
struct Outer(Root);

impl std::fmt::Display for Outer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cannot load the asset bundle")
    }
}

impl std::error::Error for Outer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Regression: the startup error keeps the whole cause chain.
#[tokio::test]
async fn factory_error_keeps_the_cause_chain() {
    let _serial = common::serial();
    let panic = startup_panic(
        TopcoatPlugin::new().router_with(|_| Err::<topcoat::router::RouterBuilder, _>(Outer(Root))),
    );
    assert!(panic.contains("cannot load the asset bundle"), "{panic}");
    assert!(panic.contains("manifest.toml is missing"), "{panic}");
}

/// Regression: the hook names each startup problem, not only the first,
/// and the plugin writes one error event for each problem.
#[tokio::test]
async fn each_startup_problem_is_named() {
    let _serial = common::serial();
    let app = TestApp::new().plugin(
        TopcoatPlugin::new()
            .router_with(|_| Err::<topcoat::router::RouterBuilder, _>("no bundle"))
            .csp_check(autumn_plugin_topcoat::CspCheck::Deny),
    );
    let (panic, events) = common::capture(|| common::build_panic(app));
    let panic = panic.expect("the startup must fail");
    assert!(panic.contains("no bundle"), "{panic}");
    assert!(panic.contains("CspDenied"), "{panic}");
    let failures: Vec<String> = events
        .messages(tracing::Level::ERROR)
        .into_iter()
        .filter(|m| m.contains("failed to start"))
        .collect();
    assert_eq!(failures.len(), 2, "{failures:?}");
    assert!(failures[0].contains("no bundle"), "{failures:?}");
    assert!(failures[1].contains("CspDenied"), "{failures:?}");
}

/// Regression: a configuration error is also logged after telemetry starts.
#[tokio::test]
async fn configuration_errors_are_logged_during_startup() {
    let _serial = common::serial();
    let (panic, events) = common::capture(|| {
        common::build_panic(TestApp::new().plugin(TopcoatPlugin::new().mount_at("/static")))
    });
    assert!(panic.is_some());
    let errors = events.messages(tracing::Level::ERROR);
    assert_eq!(
        errors
            .iter()
            .filter(|m| m.contains("invalid mount path"))
            .count(),
        2,
        "{errors:?}"
    );
}

/// Regression: a process that serves no HTTP does not build the router.
#[tokio::test]
async fn worker_processes_skip_the_router() {
    let _serial = common::serial();
    let mut config = common::config();
    config.role = autumn_web::ProcessRole::Worker;
    let app = TestApp::new().config(config).plugin(
        TopcoatPlugin::new()
            .router_with(|_| Err::<topcoat::router::RouterBuilder, _>("no bundle"))
            .csp_check(autumn_plugin_topcoat::CspCheck::Deny),
    );
    let client = app.build();
    let diagnostics = client
        .state()
        .extension::<autumn_plugin_topcoat::TopcoatDiagnostics>()
        .unwrap();
    assert!(!diagnostics.serves_http);
    assert_eq!(diagnostics.startup_error, None);
}

/// The `AppState` that a failing factory saw.
static FAILED_STATE: std::sync::Mutex<Option<autumn_web::AppState>> = std::sync::Mutex::new(None);

/// Regression: the diagnostics record a failed startup.
#[tokio::test]
async fn diagnostics_record_the_startup_error() {
    let _serial = common::serial();
    let app = TestApp::new().plugin(TopcoatPlugin::new().router_with(|state| {
        *FAILED_STATE.lock().unwrap() = Some(state.clone());
        Err::<topcoat::router::RouterBuilder, _>("no bundle")
    }));
    let (panic, events) = common::capture(|| common::build_panic(app));
    assert!(panic.is_some());
    let state = FAILED_STATE
        .lock()
        .unwrap()
        .take()
        .expect("the factory ran");
    let diagnostics = state
        .extension::<autumn_plugin_topcoat::TopcoatDiagnostics>()
        .expect("the diagnostics exist after a failed startup");
    assert!(diagnostics.serves_http);
    let error = diagnostics.startup_error.as_ref().expect("the first error");
    assert!(
        matches!(error, autumn_plugin_topcoat::StartupError::Factory { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("no bundle"), "{error}");
    assert_eq!(
        events.count(tracing::Level::INFO),
        0,
        "no 'mounted' event after a failure"
    );
    assert!(
        events
            .messages(tracing::Level::ERROR)
            .iter()
            .any(|m| m.contains("failed to start")),
        "{:?}",
        events.messages(tracing::Level::ERROR)
    );
}
