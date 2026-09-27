//! The CSP check at startup. Covers AC-15.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::await_holding_lock,
    missing_docs
)]

mod common;

use autumn_plugin_topcoat::csp::{CspFinding, InlineBlock, analyze, recommended_csp};
use autumn_plugin_topcoat::{CspCheck, TopcoatDiagnostics, TopcoatPlugin};
use autumn_web::config::AutumnConfig;
use autumn_web::test::{TestApp, TestClient};
use topcoat::router::{Router, route};

#[route(GET "/page")]
async fn page() -> topcoat::Result<&'static str> {
    Ok("page")
}

fn plugin() -> TopcoatPlugin {
    TopcoatPlugin::new().router(Router::builder().route(page))
}

fn client(config: AutumnConfig, plugin: TopcoatPlugin) -> TestClient {
    TestApp::new().config(config).plugin(plugin).build()
}

fn diagnostics(client: &TestClient) -> TopcoatDiagnostics {
    (*client.state().extension::<TopcoatDiagnostics>().unwrap()).clone()
}

/// Checks that the startup analysis agrees with the header that Autumn sends.
async fn assert_header_agrees(client: &TestClient) {
    let response = client.get("/page").send().await;
    response.assert_ok();
    let header = response
        .header("content-security-policy")
        .unwrap_or("")
        .to_owned();
    let stored = diagnostics(client).csp.expect("the check ran");
    assert_eq!(analyze(&header), stored, "header: {header}");
}

#[tokio::test]
async fn default_policy_is_reported_with_a_fix() {
    let _serial = common::serial();
    let (client, events) = common::capture(|| client(common::config(), plugin()));
    let stored = diagnostics(&client);
    let report = stored.csp.clone().unwrap();
    assert_eq!(
        report.findings,
        vec![
            CspFinding::EvalBlocked,
            CspFinding::InlineBlocked(InlineBlock::MissingUnsafeInline)
        ]
    );
    assert_eq!(
        stored.csp_suggestion.as_deref(),
        Some(recommended_csp().as_str())
    );
    assert_eq!(
        events.count(tracing::Level::WARN),
        2,
        "{:?}",
        events.messages(tracing::Level::WARN)
    );
    assert_header_agrees(&client).await;
}

#[tokio::test]
async fn recommended_policy_is_clean() {
    let _serial = common::serial();
    let mut config = common::config();
    config.security.headers.content_security_policy = recommended_csp();
    let client = client(config, plugin());
    let stored = diagnostics(&client);
    assert!(stored.csp.as_ref().unwrap().is_clean());
    assert_eq!(stored.csp_suggestion, None);
    assert_header_agrees(&client).await;
}

#[tokio::test]
async fn nonce_policy_neutralizes_inline_scripts() {
    let _serial = common::serial();
    let mut config = common::config();
    config.security.headers.csp_nonce.enabled = true;
    let client = client(config, plugin());
    let stored = diagnostics(&client);
    assert_eq!(
        stored.csp.as_ref().unwrap().findings,
        vec![
            CspFinding::EvalBlocked,
            CspFinding::InlineBlocked(InlineBlock::NeutralizedByNonceOrHash)
        ]
    );
    assert_eq!(stored.csp_suggestion, None, "a nonce blocks the patch");
    assert_header_agrees(&client).await;
}

#[tokio::test]
async fn custom_and_empty_policies_agree_with_the_header() {
    let _serial = common::serial();
    for policy in [
        "default-src 'self'",
        "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
        "",
    ] {
        let mut config = common::config();
        config.security.headers.content_security_policy = policy.into();
        let client = client(config, plugin());
        assert_header_agrees(&client).await;
        if policy.is_empty() {
            assert!(diagnostics(&client).csp.unwrap().disabled);
        }
    }
    let mut config = common::config();
    config.security.headers.content_security_policy = String::new();
    config.security.headers.csp_nonce.enabled = true;
    assert_header_agrees(&client(config, plugin())).await;
}

#[tokio::test]
async fn deny_stops_the_startup() {
    let _serial = common::serial();
    let app = TestApp::new()
        .config(common::config())
        .plugin(plugin().csp_check(CspCheck::Deny));
    let panic = common::build_panic(app).expect("the startup must fail");
    assert!(panic.contains("CspDenied"), "{panic}");
    assert!(panic.contains("unsafe-eval"), "{panic}");
}

#[tokio::test]
async fn deny_with_a_clean_policy_starts() {
    let _serial = common::serial();
    let mut config = common::config();
    config.security.headers.content_security_policy = recommended_csp();
    let client = client(config, plugin().csp_check(CspCheck::Deny));
    client.get("/page").send().await.assert_ok();
}

#[tokio::test]
async fn off_skips_the_analysis() {
    let _serial = common::serial();
    let (client, events) =
        common::capture(|| client(common::config(), plugin().csp_check(CspCheck::Off)));
    assert_eq!(diagnostics(&client).csp, None);
    assert_eq!(events.count(tracing::Level::WARN), 0);
}
