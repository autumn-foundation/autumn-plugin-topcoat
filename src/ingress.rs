//! The ingress layer: the CSRF bridge in front of Autumn CSRF.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use http::HeaderName;

use crate::plugin::Shared;

/// The CSRF names that the bridge uses. Finalize sets them from the Autumn config.
#[derive(Debug, Clone)]
pub(crate) struct IngressSettings {
    pub(crate) cookie_name: String,
    pub(crate) token_header: HeaderName,
}

/// The Tower layer that Autumn runs before its CSRF layer.
#[derive(Clone)]
pub(crate) struct IngressLayer {
    shared: Arc<Shared>,
}

impl IngressLayer {
    pub(crate) const fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}

impl<S> tower::Layer<S> for IngressLayer {
    type Service = IngressService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IngressService {
            inner,
            shared: Arc::clone(&self.shared),
        }
    }
}

/// The service of [`IngressLayer`].
#[derive(Clone)]
pub(crate) struct IngressService<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S> tower::Service<Request> for IngressService<S>
where
    S: tower::Service<Request, Response = Response, Error = Infallible>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        bridge(&self.shared, &mut request);
        self.inner.call(request)
    }
}

/// Applies the CSRF bridge decision to one request.
///
/// Without settings (Autumn CSRF off, or startup not done), the request does
/// not change.
pub(crate) fn bridge(shared: &Shared, request: &mut Request) {
    let _ = (shared, request);
    unimplemented!("RED")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::{CspCheck, CsrfBridge, NotFoundOwner};
    use crate::plan::{PlanInput, RouterPresence, plan};
    use autumn_web::config::AutumnConfig;
    use autumn_web::security::CsrfLayer;
    use axum::extract::MatchedPath;
    use proptest::prelude::*;
    use tower::{Layer, ServiceExt};

    fn shared(with_settings: bool) -> Arc<Shared> {
        let plan = plan(&PlanInput {
            mount: None,
            excluded: &[],
            runtime_prefixes: &[],
            router: RouterPresence::Present,
            csrf_bridge: CsrfBridge::SameOriginRuntime,
        })
        .unwrap();
        let shared = Shared::new(plan, NotFoundOwner::Autumn, CspCheck::Warn);
        if with_settings {
            let _ = shared.ingress.set(IngressSettings {
                cookie_name: "autumn-csrf".into(),
                token_header: HeaderName::from_static("x-csrf-token"),
            });
        }
        Arc::new(shared)
    }

    /// Builds a request that axum routed to `matched`.
    fn request(method: &str, matched: Option<&str>, headers: &[(&str, &str)]) -> Request {
        let mut builder = http::Request::builder().method(method).uri("/page");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(axum::body::Body::empty()).unwrap();
        if let Some(matched) = matched {
            request.extensions_mut().insert(matched_path(matched));
        }
        request
    }

    /// Returns a real `MatchedPath` for `template`. It has no public
    /// constructor, so axum makes one when it routes a request.
    fn matched_path(template: &str) -> MatchedPath {
        let (tx, rx) = std::sync::mpsc::channel();
        let router = axum::Router::new().route(
            template,
            axum::routing::any(move |path: MatchedPath| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(path);
                    ""
                }
            }),
        );
        let uri = if template == "/{*path}" {
            "/page"
        } else {
            template
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let _ = router
                .oneshot(
                    http::Request::get(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await;
        });
        rx.recv().unwrap()
    }

    const RERUN: &[(&str, &str)] = &[
        ("content-type", "application/json"),
        ("x-topcoat-runtime", "true"),
        ("sec-fetch-site", "same-origin"),
        ("cookie", "autumn-csrf=tok"),
    ];

    #[test]
    fn without_settings_the_request_does_not_change() {
        let mut request = request("POST", Some("/{*path}"), RERUN);
        let before = request.headers().clone();
        bridge(&shared(false), &mut request);
        assert_eq!(request.headers(), &before);
        assert!(
            request
                .extensions()
                .get::<crate::handler::BridgedToken>()
                .is_none()
        );
    }

    #[test]
    fn with_settings_a_rerun_gets_the_token_and_the_marker() {
        let mut request = request("POST", Some("/{*path}"), RERUN);
        bridge(&shared(true), &mut request);
        assert_eq!(request.headers().get("x-csrf-token").unwrap(), "tok");
        assert!(
            request
                .extensions()
                .get::<crate::handler::BridgedToken>()
                .is_some()
        );
    }

    #[test]
    fn without_matched_path_the_request_does_not_change() {
        let mut request = request("POST", None, RERUN);
        bridge(&shared(true), &mut request);
        assert!(request.headers().get("x-csrf-token").is_none());
    }

    /// Runs the ingress layer in front of the real Autumn CSRF layer.
    async fn status_through_csrf(request: Request) -> u16 {
        let mut config = AutumnConfig::default();
        config.security.csrf.enabled = true;
        let echo = tower::service_fn(|_request: Request| async {
            Ok::<_, Infallible>(Response::new(axum::body::Body::from("ok")))
        });
        let service = IngressLayer::new(shared(true))
            .layer(CsrfLayer::from_config(&config.security.csrf).layer(echo));
        service.oneshot(request).await.unwrap().status().as_u16()
    }

    fn arb_headers() -> impl Strategy<Value = Vec<(&'static str, &'static str)>> {
        let pool: Vec<(&'static str, &'static str)> = vec![
            ("content-type", "application/json"),
            ("content-type", "text/plain"),
            ("x-topcoat-runtime", "true"),
            ("x-topcoat-identity", "id"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-site", "cross-site"),
            ("origin", "http://evil.example"),
            ("cookie", "autumn-csrf=tok"),
            ("cookie", "autumn-csrf=other"),
            ("x-csrf-token", "tok"),
            ("x-csrf-token", "wrong"),
        ];
        prop::collection::vec(prop::sample::select(pool), 0..8)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

        /// For non-safe requests without query or form tokens, Autumn CSRF
        /// admits the request if and only if the bridge injected the token or
        /// the client sent a header equal to the only CSRF cookie.
        #[test]
        fn bridge_and_autumn_csrf_agree(headers in arb_headers(), plugin_route in any::<bool>()) {
            let matched = if plugin_route { "/{*path}" } else { "/api/things" };
            let make = || request("POST", Some(matched), &headers);
            let mut probe = make();
            let before = probe.headers().get("x-csrf-token").cloned();
            bridge(&shared(true), &mut probe);
            let injected = before.is_none() && probe.headers().get("x-csrf-token").is_some();
            let cookie = crate::csrf::single_cookie(probe.headers(), "autumn-csrf").map(str::to_owned);
            let client_match = before.as_ref().zip(cookie.as_ref()).is_some_and(|(h, c)| h.as_bytes() == c.as_bytes());
            let expected = if cookie.as_deref().is_some_and(|c| !c.is_empty()) && (injected || client_match) { 200 } else { 403 };
            if !plugin_route {
                prop_assert!(!injected, "bridged a non-plugin route");
            }
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let status = runtime.block_on(status_through_csrf(make()));
            prop_assert_eq!(status, expected);
        }
    }
}
