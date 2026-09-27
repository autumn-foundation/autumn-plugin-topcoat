//! The typed Autumn routes that send requests to Topcoat.

use autumn_web::openapi::ApiDoc;
use autumn_web::{AppState, Route, SeoRouteDefaults};
use axum::routing::MethodRouter;
use http::Method;

/// The route method token for a route that accepts each HTTP method.
pub(crate) const ANY_METHOD: &str = "ANY";

/// Returns the `ANY` method token.
pub(crate) fn any_method() -> Result<Method, http::method::InvalidMethod> {
    Method::from_bytes(ANY_METHOD.as_bytes())
}

/// Returns one typed route for each template, with the same handler.
///
/// Each route is public, hidden from `OpenAPI` and excluded from `MCP`. The
/// Autumn duplicate check keys on the method token and the path, so `ANY /`
/// can share `/` with a host `GET /`.
pub(crate) fn mount_routes(
    templates: &[String],
    handler: &MethodRouter<AppState>,
    method: &Method,
) -> Vec<Route> {
    templates
        .iter()
        .map(|template| {
            let (path, name) = path_and_name(template);
            Route {
                method: method.clone(),
                path,
                handler: handler.clone(),
                name,
                api_doc: ApiDoc {
                    method: ANY_METHOD,
                    path,
                    operation_id: name,
                    public: true,
                    hidden: true,
                    mcp_exclude: true,
                    ..ApiDoc::default()
                },
                api_version: None,
                sunset_opt_out: false,
                repository: None,
                idempotency: autumn_web::RouteIdempotency::default(),
                timeout: autumn_web::RouteTimeout::default(),
                seo: SeoRouteDefaults::EMPTY,
            }
        })
        .collect()
}

/// Returns the `'static` path and the route name for a template.
///
/// `Route` needs `&'static str` paths. The root templates are literals. A
/// prefix template is leaked once for each plugin build: at most three short
/// strings for each process.
fn path_and_name(template: &str) -> (&'static str, &'static str) {
    match template {
        "/" => ("/", "topcoat_root"),
        "/{*path}" => ("/{*path}", "topcoat_catch_all"),
        "/_topcoat/{*path}" => ("/_topcoat/{*path}", "topcoat_internal"),
        other => {
            let name = if other.ends_with("/{*path}") {
                "topcoat_prefix_catch_all"
            } else if other.ends_with('/') {
                "topcoat_prefix_slash"
            } else {
                "topcoat_prefix"
            };
            (Box::leak(other.to_owned().into_boxed_str()), name)
        }
    }
}

#[cfg(test)]
mod tests;
