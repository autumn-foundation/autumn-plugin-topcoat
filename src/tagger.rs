//! A pathless Topcoat layer that marks requests with no Topcoat route.

use topcoat::context::Cx;
use topcoat::router::error::NotFoundError;
use topcoat::router::response::Response;
use topcoat::router::{Body, Layer, LayerFuture, Next, Path, StatusCode, try_endpoint};

/// A response extension: Topcoat has no route for the request path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Unmatched;

/// Marks the 404 of an unmatched path with [`Unmatched`].
///
/// # Contract
///
/// - When the inner result is a `NotFoundError` and the request matched no
///   endpoint, the layer returns an empty 404 with the `Unmatched` extension.
/// - Each other result goes out unchanged: a page 404, a 405, a 308, a
///   rewrite and each success.
pub(crate) struct UnmatchedTagger;

impl Layer for UnmatchedTagger {
    fn path(&self) -> Option<&Path> {
        None
    }

    fn handle<'a>(&'a self, cx: &'a Cx, body: Body, next: Next<'a>) -> LayerFuture<'a> {
        Box::pin(async move {
            match next.run(cx, body).await {
                Err(error) if error.is::<NotFoundError>() && try_endpoint(cx).is_none() => {
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
