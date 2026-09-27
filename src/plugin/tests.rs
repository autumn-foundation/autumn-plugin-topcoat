//! Tests for the `plugin` module.

use super::*;
use crate::error::ConfigError;
use topcoat::router::response::IntoResponse;
use topcoat::router::{Method, RouteFn, RouteFuture};

fn one(cx: &topcoat::context::Cx, _body: topcoat::router::Body) -> RouteFuture<'_> {
    Box::pin(async move { "one".into_response(cx) })
}

/// A route for tests that need a router with one route.
fn one_route() -> RouteFn {
    RouteFn::new(Method::GET, "/one", one)
}

fn assert_send_static<T: Send + 'static>() {}

#[test]
fn new_equals_default_and_has_the_documented_defaults() {
    let plugin = TopcoatPlugin::new();
    assert_eq!(
        format!("{plugin:?}"),
        format!("{:?}", TopcoatPlugin::default())
    );
    assert_eq!(plugin.name(), PLUGIN_NAME);
    assert!(plugin.source.is_none());
    assert!(plugin.mount.is_none());
    assert_eq!(plugin.csrf_bridge, CsrfBridge::SameOriginRuntime);
    assert_eq!(plugin.csp_check, CspCheck::Warn);
    assert_eq!(plugin.not_found, NotFoundOwner::Autumn);
}

#[test]
fn plugin_and_builder_are_send_and_static() {
    assert_send_static::<TopcoatPlugin>();
    assert_send_static::<RouterBuilder>();
    assert_send_static::<RouterSource>();
}

#[test]
fn setters_record_the_options() {
    let plugin = TopcoatPlugin::new()
        .router(Router::builder())
        .mount_at("/app")
        .exclude("/app/api")
        .runtime_prefix("/app/rpc")
        .csrf_bridge(CsrfBridge::Off)
        .csp_check(CspCheck::Deny)
        .not_found(NotFoundOwner::Topcoat);
    let debug = format!("{plugin:?}");
    assert!(debug.contains("builder"));
    assert_eq!(plugin.mount.as_deref(), Some("/app"));
    assert_eq!(plugin.excluded, vec!["/app/api"]);
    assert_eq!(plugin.runtime_prefixes, vec!["/app/rpc"]);
    assert_eq!(plugin.csrf_bridge, CsrfBridge::Off);
    assert_eq!(plugin.csp_check, CspCheck::Deny);
    assert_eq!(plugin.not_found, NotFoundOwner::Topcoat);
    let factory = TopcoatPlugin::new().router_with(|_| Ok::<_, String>(Router::builder()));
    assert!(format!("{factory:?}").contains("factory"));
}

#[test]
fn validate_reports_each_problem() {
    assert!(
        TopcoatPlugin::new()
            .router(Router::builder().route(one_route()))
            .validate()
            .is_ok()
    );
    let errors = TopcoatPlugin::new()
        .mount_at("/static")
        .exclude("bad")
        .validate()
        .unwrap_err();
    assert_eq!(errors.len(), 3);
    assert!(!errors.is_empty());
    assert!(matches!(errors.as_slice()[0], ConfigError::NoRouter));
    assert_eq!(errors.iter().count(), (&errors).into_iter().count());
    assert_eq!(errors.into_iter().count(), 3);
}

#[test]
fn plugin_claims_no_config_section() {
    let app = autumn_web::app().plugin(TopcoatPlugin::new().router(Router::builder()));
    assert!(app.has_plugin(PLUGIN_NAME));
    assert!(!app.has_config_section("topcoat"));
}
