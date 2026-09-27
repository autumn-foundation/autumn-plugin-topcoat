//! Startup diagnostics. Covers AC-19.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use autumn_plugin_topcoat::{
    BridgeStatus, CsrfBridge, MountPath, NotFoundOwner, TopcoatDiagnostics, TopcoatPlugin,
};
use autumn_web::test::{TestApp, TestClient};
use topcoat::router::{Router, route};

#[route(GET "/page")]
async fn page() -> topcoat::Result<&'static str> {
    Ok("page")
}

#[route(GET "/app")]
async fn app() -> topcoat::Result<&'static str> {
    Ok("app")
}

fn plugin() -> TopcoatPlugin {
    TopcoatPlugin::new().router(Router::builder().route(page))
}

fn diagnostics(client: &TestClient) -> TopcoatDiagnostics {
    (*client.state().extension::<TopcoatDiagnostics>().unwrap()).clone()
}

#[tokio::test]
async fn startup_writes_one_info_event_and_stores_the_facts() {
    let (client, events) = common::capture(|| TestApp::new().plugin(plugin()).build());
    assert_eq!(
        events.count(tracing::Level::INFO),
        1,
        "{:?}",
        events.messages(tracing::Level::INFO)
    );
    let info = &events.messages(tracing::Level::INFO)[0];
    assert!(info.contains("/{*path}"), "{info}");
    let stored = diagnostics(&client);
    assert_eq!(stored.mount, MountPath::root());
    assert_eq!(stored.templates, vec!["/", "/{*path}"]);
    assert_eq!(stored.csrf_bridge, BridgeStatus::InertCsrfDisabled);
    assert_eq!(stored.not_found, NotFoundOwner::Autumn);
    assert!(!stored.idempotency_fail_closed);
}

#[tokio::test]
async fn csrf_on_makes_the_bridge_active() {
    let client = TestApp::new()
        .config(common::csrf_config())
        .plugin(plugin())
        .build();
    assert_eq!(
        diagnostics(&client).csrf_bridge,
        BridgeStatus::Active {
            cookie: "autumn-csrf".into(),
            header: "x-csrf-token".into()
        }
    );
}

#[tokio::test]
async fn idempotency_side_effect_is_reported() {
    let mut config = common::config();
    config.idempotency.enabled = Some(true);
    let (client, events) = common::capture(|| {
        TestApp::new()
            .config(config.clone())
            .plugin(plugin())
            .build()
    });
    assert!(diagnostics(&client).idempotency_fail_closed);
    assert!(
        events
            .messages(tracing::Level::WARN)
            .iter()
            .any(|m| m.contains("idempotent")),
        "{:?}",
        events.messages(tracing::Level::WARN)
    );

    let off = TestApp::new()
        .config(config)
        .plugin(plugin().csrf_bridge(CsrfBridge::Off))
        .build();
    assert!(!diagnostics(&off).idempotency_fail_closed);
}

#[tokio::test]
async fn prefix_mount_is_recorded() {
    let client = TestApp::new()
        .plugin(
            TopcoatPlugin::new()
                .mount_at("/app")
                .exclude("/app/api")
                .router(Router::builder().route(app)),
        )
        .build();
    let stored = diagnostics(&client);
    assert_eq!(stored.mount.as_str(), "/app");
    assert_eq!(
        stored.templates,
        vec!["/app", "/app/", "/app/{*path}", "/_topcoat/{*path}"]
    );
    assert_eq!(stored.excluded.len(), 1);
}
