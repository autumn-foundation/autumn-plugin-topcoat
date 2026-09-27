//! The axum handler that forwards requests to Topcoat.

use std::net::SocketAddr;

use autumn_web::AutumnError;
use axum::extract::{ConnectInfo, OriginalUri, Request};
use axum::response::{IntoResponse, Response};
use http::header::SET_COOKIE;
use topcoat::router::{Body, RemoteAddr};

use crate::autumn::ServedByAutumn;
use crate::fallthrough;
use crate::ingress::BridgedToken;
use crate::options::NotFoundOwner;
use crate::plugin::Shared;
use crate::tagger::Unmatched;

/// Forwards one request to Topcoat.
///
/// # Contract
///
/// 1. A path under an excluded prefix gets the Autumn fall-through answer.
///    Topcoat does not see it.
/// 2. After a failed startup, the answer is 500. Before the router is ready,
///    the answer is 503.
/// 3. Topcoat gets the original URI, without the copied CSRF header, with
///    `RemoteAddr` from `ConnectInfo` (the handler skips port 0) and with the
///    `ServedByAutumn` marker.
/// 4. With `NotFoundOwner::Autumn`, an unmatched Topcoat response becomes the
///    Autumn fall-through answer. Its `Set-Cookie` headers stay.
pub(crate) async fn forward(shared: &Shared, request: Request) -> Response {
    let mut request = request;
    if let Some(original) = request.extensions().get::<OriginalUri>() {
        *request.uri_mut() = original.0.clone();
    }
    let method = request.method().clone();
    // A `Uri` clone shares its buffer, so the path costs no copy.
    let uri = request.uri().clone();
    let path = uri.path();

    if shared
        .plan
        .excluded
        .iter()
        .any(|prefix| prefix.matches(path))
    {
        return fallthrough::respond(&method, path);
    }
    if let Some(error) = shared.startup_errors().first() {
        return AutumnError::internal_server_error_msg(error.to_string()).into_response();
    }
    let Some(router) = shared.router.get() else {
        return AutumnError::service_unavailable_msg("the Topcoat router is not ready")
            .into_response();
    };

    if let Some(BridgedToken(header)) = request.extensions_mut().remove::<BridgedToken>() {
        request.headers_mut().remove(header);
    }
    if request.extensions().get::<RemoteAddr>().is_none() {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0)
            .filter(|addr| addr.port() != 0);
        if let Some(peer) = peer {
            request.extensions_mut().insert(RemoteAddr(peer));
        }
    }
    request.extensions_mut().insert(ServedByAutumn);

    let response = router.handle(request.map(Body::new)).await;
    if shared.not_found == NotFoundOwner::Autumn
        && response.extensions().get::<Unmatched>().is_some()
    {
        let mut fallback = fallthrough::respond(&method, path);
        for cookie in response.headers().get_all(SET_COOKIE) {
            fallback.headers_mut().append(SET_COOKIE, cookie.clone());
        }
        return fallback;
    }
    response.map(axum::body::Body::new)
}

#[cfg(test)]
mod tests;
