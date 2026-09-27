//! The CSRF bridge through the full Autumn stack. Covers AC-11, AC-12 and AC-13.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use autumn_plugin_topcoat::{BridgeStatus, CsrfBridge, TopcoatDiagnostics, TopcoatPlugin};
use autumn_web::prelude::*;
use autumn_web::test::{TestApp, TestClient, TestResponse};
use topcoat::context::Cx;
use topcoat::router::request::headers;
use topcoat::router::{Router, route};

/// Echoes whether Topcoat can see a CSRF header.
fn seen(cx: &Cx) -> String {
    let token = headers(cx)
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
        .to_owned();
    format!("topcoat token={token}")
}

#[route(POST "/page")]
async fn page(cx: &Cx) -> topcoat::Result<String> {
    Ok(seen(cx))
}

#[route(POST "/_topcoat/runtime/procedures/0123456789abcdef")]
async fn procedure(cx: &Cx) -> topcoat::Result<String> {
    Ok(seen(cx))
}

#[route(POST "/rpc/double")]
async fn custom_procedure(cx: &Cx) -> topcoat::Result<String> {
    Ok(seen(cx))
}

#[route(POST "/excluded/x")]
async fn excluded(cx: &Cx) -> topcoat::Result<String> {
    Ok(seen(cx))
}

#[post("/api/things")]
async fn things() -> &'static str {
    "autumn things"
}

fn plugin() -> TopcoatPlugin {
    TopcoatPlugin::new()
        .router(
            Router::builder()
                .route(page)
                .route(procedure)
                .route(custom_procedure)
                .route(excluded),
        )
        .runtime_prefix("/rpc")
        .exclude("/excluded")
}

fn client_with(config: autumn_web::config::AutumnConfig, plugin: TopcoatPlugin) -> TestClient {
    TestApp::new()
        .config(config)
        .routes(routes![things])
        .plugin(plugin)
        .build()
}

/// Sends a JSON `POST` with the given headers.
async fn post(client: &TestClient, path: &str, headers: &[(&str, &str)]) -> TestResponse {
    let mut request = client.post(path);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.body("{}").send().await
}

const JSON: (&str, &str) = ("content-type", "application/json");
const RERUN: (&str, &str) = ("x-topcoat-runtime", "true");
const SHARD: (&str, &str) = ("x-topcoat-identity", "unit-1");
const SAME: (&str, &str) = ("sec-fetch-site", "same-origin");
const COOKIE: (&str, &str) = ("cookie", "autumn-csrf=tok");

#[tokio::test]
async fn admits_same_origin_runtime_requests() {
    let client = client_with(common::csrf_config(), plugin());
    let cases: &[(&str, &[(&str, &str)])] = &[
        ("/page", &[JSON, RERUN, SAME, COOKIE]),
        ("/page", &[JSON, SHARD, SAME, COOKIE]),
        (
            "/_topcoat/runtime/procedures/0123456789abcdef",
            &[JSON, SAME, COOKIE],
        ),
        ("/rpc/double", &[JSON, SAME, COOKIE]),
        (
            "/page",
            &[
                JSON,
                RERUN,
                COOKIE,
                ("origin", "http://localhost"),
                ("host", "localhost"),
            ],
        ),
        (
            "/page",
            &[
                ("content-type", "application/json; charset=utf-8"),
                RERUN,
                SAME,
                COOKIE,
            ],
        ),
    ];
    for (index, (path, headers)) in cases.iter().enumerate() {
        let response = post(&client, path, headers).await;
        assert_eq!(response.status, 200, "case {index}: {}", response.text());
        // Topcoat never sees the copied header.
        assert_eq!(response.text(), "topcoat token=none", "case {index}");
    }
}

#[tokio::test]
async fn refuses_hostile_and_unmarked_requests() {
    let client = client_with(common::csrf_config(), plugin());
    let cases: &[(&str, &[(&str, &str)])] = &[
        (
            "/page",
            &[JSON, RERUN, ("sec-fetch-site", "cross-site"), COOKIE],
        ),
        (
            "/page",
            &[JSON, RERUN, ("sec-fetch-site", "same-site"), COOKIE],
        ),
        ("/page", &[JSON, RERUN, ("sec-fetch-site", "none"), COOKIE]),
        ("/page", &[JSON, RERUN, SAME, SAME, COOKIE]),
        (
            "/page",
            &[
                JSON,
                RERUN,
                ("origin", "http://evil.example"),
                ("host", "localhost"),
                COOKIE,
            ],
        ),
        (
            "/page",
            &[
                JSON,
                RERUN,
                ("origin", "http://localhost:8080"),
                ("host", "localhost"),
                COOKIE,
            ],
        ),
        (
            "/page",
            &[
                JSON,
                RERUN,
                ("origin", "null"),
                ("host", "localhost"),
                COOKIE,
            ],
        ),
        ("/page", &[JSON, RERUN, COOKIE]),
        (
            "/page",
            &[
                JSON,
                RERUN,
                SAME,
                ("cookie", "autumn-csrf=a; autumn-csrf=b"),
            ],
        ),
        ("/page", &[JSON, RERUN, SAME]),
        (
            "/page",
            &[("content-type", "text/plain"), RERUN, SAME, COOKIE],
        ),
        (
            "/page",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                RERUN,
                SAME,
                COOKIE,
            ],
        ),
        ("/page", &[JSON, SAME, COOKIE]),
        ("/api/things", &[JSON, RERUN, SAME, COOKIE]),
        (
            "/page",
            &[JSON, RERUN, SAME, COOKIE, ("x-csrf-token", "wrong")],
        ),
        ("/_topcoat/runtime/../page", &[JSON, SAME, COOKIE]),
        ("/excluded/x", &[JSON, RERUN, SAME, COOKIE]),
    ];
    for (index, (path, headers)) in cases.iter().enumerate() {
        let response = post(&client, path, headers).await;
        assert_eq!(response.status, 403, "case {index}: {}", response.text());
    }
}

#[tokio::test]
async fn custom_cookie_and_header_names_work() {
    let mut config = common::csrf_config();
    config.security.csrf.cookie_name = "my-csrf".into();
    config.security.csrf.token_header = "X-My-Token".into();
    let client = client_with(config, plugin());
    let response = post(
        &client,
        "/page",
        &[JSON, RERUN, SAME, ("cookie", "my-csrf=tok")],
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.text());
    let diagnostics = client.state().extension::<TopcoatDiagnostics>().unwrap();
    assert_eq!(
        diagnostics.csrf_bridge,
        BridgeStatus::Active {
            cookie: "my-csrf".into(),
            header: "x-my-token".into()
        }
    );
}

#[tokio::test]
async fn signed_cookies_pass_and_tampered_cookies_fail() {
    let mut config = common::csrf_config();
    config.security.signing_secret.secret =
        Some("0123456789abcdef0123456789abcdef0123456789abcdef".into());
    let client = client_with(config, plugin());
    let seed = client.get("/health").send().await;
    let signed = common::set_cookie(&seed, "autumn-csrf").expect("Autumn sets a signed cookie");
    assert!(signed.contains('.'), "a signed token has a MAC: {signed}");
    let cookie = format!("autumn-csrf={signed}");
    let ok = post(&client, "/page", &[JSON, RERUN, SAME, ("cookie", &cookie)]).await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    let tampered = post(
        &client,
        "/page",
        &[JSON, RERUN, SAME, ("cookie", "autumn-csrf=forged.mac")],
    )
    .await;
    assert_eq!(tampered.status, 403);
}

#[tokio::test]
async fn with_csrf_off_the_bridge_changes_nothing() {
    let client = client_with(common::config(), plugin());
    let response = post(
        &client,
        "/page",
        &[JSON, RERUN, SAME, COOKIE, ("x-csrf-token", "client")],
    )
    .await;
    assert_eq!(response.text(), "topcoat token=client");
    let diagnostics = client.state().extension::<TopcoatDiagnostics>().unwrap();
    assert_eq!(diagnostics.csrf_bridge, BridgeStatus::InertCsrfDisabled);
}

#[tokio::test]
async fn bridge_off_leaves_runtime_posts_to_autumn_csrf() {
    let client = client_with(common::csrf_config(), plugin().csrf_bridge(CsrfBridge::Off));
    let response = post(&client, "/page", &[JSON, RERUN, SAME, COOKIE]).await;
    assert_eq!(response.status, 403);
    let diagnostics = client.state().extension::<TopcoatDiagnostics>().unwrap();
    assert_eq!(diagnostics.csrf_bridge, BridgeStatus::Off);
}

#[tokio::test]
async fn topcoat_origin_policy_stays_active() {
    let client = client_with(common::config(), plugin());
    let response = post(
        &client,
        "/page",
        &[
            JSON,
            RERUN,
            ("sec-fetch-site", "cross-site"),
            ("origin", "https://evil.example"),
        ],
    )
    .await;
    assert_eq!(response.status, 403);
    assert!(response.text().contains("forbidden"), "{}", response.text());
}
