//! A pathless Topcoat layer that marks requests with no Topcoat route.

use topcoat::context::{Cx, try_request_context};
use topcoat::router::error::NotFoundError;
use topcoat::router::response::Response;
use topcoat::router::{Body, Layer, LayerFuture, Next, Path, StatusCode, try_endpoint};

/// A response extension: Topcoat has no route for the request path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Unmatched;

/// A request context value: the forward handler sent this request.
///
/// The handler passes it with `Router::handle_with`. Topcoat keeps it across
/// rewrites. A route can dispatch a sub-request with `router(cx).handle(..)`.
/// The sub-request does not get the value, also when it copies the request
/// parts, so its 404 stays a Topcoat 404.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ForwardedByPlugin;

/// Returns `true` if the forward handler sent this request.
fn forwarded_by_plugin(cx: &Cx) -> bool {
    try_request_context::<ForwardedByPlugin>(cx).is_some()
}

/// Marks the 404 of an unmatched path with [`Unmatched`].
///
/// # Contract
///
/// - The layer tags a result only when all these conditions are true:
///   - The result is a `NotFoundError`.
///   - The request matched no endpoint.
///   - The forward handler sent the request.
/// - A tagged result becomes an empty 404 with the `Unmatched` extension.
/// - Each other result goes out unchanged: a page 404, a 405, a 308, a
///   rewrite, a sub-request of a route and each success.
pub(crate) struct UnmatchedTagger;

impl Layer for UnmatchedTagger {
    fn path(&self) -> Option<&Path> {
        None
    }

    fn handle<'a>(&'a self, cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
        Box::pin(async move {
            match next.run(cx, body).await {
                Err(error)
                    if error.is::<NotFoundError>()
                        && try_endpoint(cx).is_none()
                        && forwarded_by_plugin(cx) =>
                {
                    let mut response = Response::new(Body::empty());
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    response.extensions_mut().insert(Unmatched);
                    Ok(response)
                }
                other => other,
            }
        })
    }
}
