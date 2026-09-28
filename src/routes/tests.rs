//! Tests for the `routes` module.

use super::*;
use autumn_web::route_listing::{RouteClassification, RouteSource, collect_route_infos};

fn routes_for(templates: &[&str]) -> Vec<Route> {
    let templates: Vec<String> = templates.iter().map(|t| (*t).to_owned()).collect();
    let handler = axum::routing::any(|| async { "topcoat" });
    mount_routes(&templates, &handler, &any_method().unwrap())
}

#[test]
fn any_token_is_valid() {
    assert_eq!(any_method().unwrap().as_str(), "ANY");
}

#[test]
fn root_routes_have_the_expected_shape() {
    let routes = routes_for(&["/", "/{*path}"]);
    let shape: Vec<(&str, &str, &str)> = routes
        .iter()
        .map(|r| (r.method.as_str(), r.path, r.name))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("ANY", "/", "topcoat_root"),
            ("ANY", "/{*path}", "topcoat_catch_all")
        ]
    );
    for route in &routes {
        assert!(route.api_doc.public);
        assert!(route.api_doc.hidden);
        assert!(route.api_doc.mcp_exclude);
        assert_eq!(route.api_doc.method, "ANY");
        assert_eq!(route.api_doc.path, route.path);
        assert_eq!(route.timeout, autumn_web::RouteTimeout::default());
        assert_eq!(route.idempotency, autumn_web::RouteIdempotency::default());
    }
}

#[test]
fn prefix_routes_have_distinct_names() {
    let routes = routes_for(&["/app", "/app/", "/app/{*path}", "/_topcoat/{*path}"]);
    let names: Vec<&str> = routes.iter().map(|r| r.name).collect();
    assert_eq!(
        names,
        vec![
            "topcoat_prefix",
            "topcoat_prefix_slash",
            "topcoat_prefix_catch_all",
            "topcoat_internal"
        ]
    );
    let paths: Vec<&str> = routes.iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        vec!["/app", "/app/", "/app/{*path}", "/_topcoat/{*path}"]
    );
}

#[test]
fn route_listing_classifies_the_routes_as_public() {
    let routes = routes_for(&["/", "/{*path}"]);
    let sources = vec![RouteSource::Plugin(crate::PLUGIN_NAME.to_owned()); routes.len()];
    let infos = collect_route_infos(&routes, &sources, &[], &[]).unwrap();
    assert_eq!(infos.len(), 2);
    for info in infos {
        assert_eq!(info.method, "ANY");
        assert_eq!(info.classification, RouteClassification::Public);
        assert_eq!(
            info.source,
            RouteSource::Plugin(crate::PLUGIN_NAME.to_owned())
        );
    }
}
