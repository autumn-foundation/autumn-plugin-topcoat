//! The axum handler that forwards requests to Topcoat.

use axum::extract::Request;
use axum::response::Response;

use crate::plugin::Shared;

/// A request extension: the ingress layer copied the CSRF cookie into this header.
#[derive(Debug, Clone)]
pub(crate) struct BridgedToken(pub(crate) http::HeaderName);

/// Forwards one request to Topcoat.
///
/// # Contract
///
/// 1. A path under an excluded prefix gets the Autumn fall-through answer.
///    Topcoat does not see it.
/// 2. After a failed startup, the answer is 500. Before the router is ready,
///    the answer is 503.
/// 3. Topcoat gets the original URI, without the copied CSRF header, with
///    `RemoteAddr` from `ConnectInfo` (port 0 is skipped) and with the
///    `ServedByAutumn` marker.
/// 4. With `NotFoundOwner::Autumn`, an unmatched Topcoat response becomes the
///    Autumn fall-through answer. Its `Set-Cookie` headers stay.
pub(crate) async fn forward(shared: &Shared, request: Request) -> Response {
    let _ = (shared, request);
    unimplemented!("RED")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StartupError;
    use crate::options::{CspCheck, CsrfBridge, NotFoundOwner};
    use crate::plan::{PlanInput, RouterPresence, plan};
    use http::StatusCode;

    fn shared() -> Shared {
        let plan = plan(&PlanInput {
            mount: None,
            excluded: &["/api".to_owned()],
            runtime_prefixes: &[],
            router: RouterPresence::Present,
            csrf_bridge: CsrfBridge::SameOriginRuntime,
        })
        .unwrap();
        Shared::new(plan, NotFoundOwner::Autumn, CspCheck::Warn)
    }

    fn get(path: &str) -> Request {
        http::Request::get(path)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn before_startup_the_answer_is_503() {
        let response = forward(&shared(), get("/page")).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn after_a_failed_startup_the_answer_is_500() {
        let shared = shared();
        shared.record_failure(StartupError::Factory {
            message: "boom".into(),
        });
        let response = forward(&shared, get("/page")).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn excluded_paths_get_the_autumn_404_even_before_startup() {
        let response = forward(&shared(), get("/api/x")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
