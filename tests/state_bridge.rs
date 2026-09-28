//! The Autumn state bridge and the request helpers. Covers AC-9 and AC-10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use autumn_plugin_topcoat::{RequestScopeError, TopcoatPlugin, autumn};
use autumn_web::test::TestApp;
use topcoat::context::Cx;
use topcoat::router::{Body, Router, route, router, to_bytes};

#[derive(Debug)]
struct Marker(u32);

#[route(GET "/state")]
async fn state_page(cx: &Cx) -> topcoat::Result<String> {
    let _state = autumn::state(cx)?;
    let marker = autumn::extension::<Marker>(cx)?;
    let profile = autumn::config(cx)?.profile.clone().unwrap_or_default();
    Ok(format!("marker={} profile={profile}", marker.0))
}

#[route(GET "/missing")]
async fn missing_extension(cx: &Cx) -> topcoat::Result<String> {
    Ok(format!("{:?}", autumn::extension::<String>(cx).err()))
}

#[route(GET "/detached")]
async fn detached(cx: &Cx) -> topcoat::Result<String> {
    // A synthetic request without Autumn extensions, as a WebSocket render makes.
    let synthetic = http::Request::get("/inner").body(Body::empty()).unwrap();
    let response = router(cx).handle(synthetic).await;
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[route(GET "/inner")]
async fn inner(cx: &Cx) -> topcoat::Result<String> {
    Ok(format!(
        "state={} csrf={:?} session={:?}",
        autumn::state(cx).is_ok(),
        autumn::csrf_token(cx).err(),
        autumn::session(cx).err(),
    ))
}

#[route(GET "/form")]
async fn form(cx: &Cx) -> topcoat::Result<String> {
    match autumn::csrf_token(cx) {
        Ok(info) => Ok(format!(
            "token={} header={} field={}",
            info.token, info.header, info.field
        )),
        Err(error) => Ok(format!("error={error:?}")),
    }
}

#[route(POST "/form")]
async fn form_post() -> topcoat::Result<&'static str> {
    Ok("posted")
}

#[route(POST "/session")]
async fn session_write(cx: &Cx) -> topcoat::Result<&'static str> {
    autumn::session(cx)?.insert("topcoat", "yes").await;
    Ok("written")
}

#[route(GET "/session")]
async fn session_read(cx: &Cx) -> topcoat::Result<String> {
    Ok(autumn::session(cx)?
        .get("topcoat")
        .await
        .unwrap_or_default())
}

fn plugin() -> TopcoatPlugin {
    TopcoatPlugin::new().router(
        Router::builder()
            .route(state_page)
            .route(missing_extension)
            .route(detached)
            .route(inner)
            .route(form)
            .route(form_post)
            .route(session_write)
            .route(session_read),
    )
}

#[tokio::test]
async fn pages_read_app_state_config_and_extensions() {
    let client = TestApp::new()
        .state_initializer(|state| state.insert_extension(Marker(42)))
        .plugin(plugin())
        .build();
    client
        .get("/state")
        .send()
        .await
        .assert_ok()
        .assert_body_eq("marker=42 profile=test");
    client
        .get("/missing")
        .send()
        .await
        .assert_body_contains("MissingExtension");
}

#[tokio::test]
async fn detached_renders_keep_app_state_but_not_request_data() {
    let client = TestApp::new().plugin(plugin()).build();
    let expected = format!(
        "state=true csrf={:?} session={:?}",
        Some(RequestScopeError::Detached),
        Some(RequestScopeError::Detached)
    );
    client
        .get("/detached")
        .send()
        .await
        .assert_ok()
        .assert_body_eq(&expected);
}

#[tokio::test]
async fn csrf_token_helper_feeds_plain_forms() {
    let client = TestApp::new()
        .config(common::csrf_config())
        .plugin(plugin())
        .build();
    let page = client.get("/form").send().await;
    page.assert_ok();
    let body = page.text();
    let token = body
        .strip_prefix("token=")
        .and_then(|rest| rest.split(' ').next())
        .expect("the page shows the token")
        .to_owned();
    assert!(body.ends_with("header=x-csrf-token field=_csrf"), "{body}");
    let cookie = common::set_cookie(&page, "autumn-csrf").expect("Autumn sets the CSRF cookie");
    assert_eq!(cookie, token);
    client
        .post("/form")
        .header("cookie", &format!("autumn-csrf={cookie}"))
        .form(&format!("_csrf={token}"))
        .send()
        .await
        .assert_ok()
        .assert_body_eq("posted");
}

#[tokio::test]
async fn csrf_token_is_unavailable_when_csrf_is_off() {
    let client = TestApp::new().plugin(plugin()).build();
    client
        .get("/form")
        .send()
        .await
        .assert_body_contains("Unavailable");
}

#[tokio::test]
async fn session_writes_persist() {
    let client = TestApp::new().plugin(plugin()).build();
    let write = client.post("/session").send().await;
    write.assert_ok().assert_body_eq("written");
    let cookie = common::set_cookie(&write, "autumn.sid").expect("Autumn sets the session cookie");
    client
        .get("/session")
        .header("cookie", &format!("autumn.sid={cookie}"))
        .send()
        .await
        .assert_body_eq("yes");
}
