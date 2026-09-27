//! The ingress layer: the CSRF bridge in front of Autumn CSRF.

use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use autumn_web::security::ResolvedClientIdentity;
use axum::extract::{MatchedPath, OriginalUri, Request};
use axum::response::Response;
use http::HeaderName;

use crate::csrf::{BridgePolicy, BridgeRequest, Decision, decide};
use crate::plugin::{Shared, TRACING_TARGET};

/// A request extension: the bridge copied the CSRF cookie into this header.
///
/// The forward handler removes the header before Topcoat gets the request.
#[derive(Debug, Clone)]
pub(crate) struct BridgedToken(pub(crate) HeaderName);

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
    let Some(settings) = shared.ingress.get() else {
        return;
    };
    let identity = request.extensions().get::<ResolvedClientIdentity>();
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map_or_else(|| request.uri().path(), |original| original.0.path());
    let facts = BridgeRequest {
        method: request.method(),
        matched_path: request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
        path,
        headers: request.headers(),
        identity_host: identity.and_then(|identity| identity.host.as_deref()),
        identity_scheme: identity.and_then(|identity| identity.scheme.as_deref()),
        uri_authority: request.uri().authority().map(http::uri::Authority::as_str),
    };
    let policy = BridgePolicy {
        cookie_name: &settings.cookie_name,
        token_header: &settings.token_header,
        templates: &shared.plan.templates,
        excluded: &shared.plan.excluded,
        runtime_prefixes: &shared.plan.runtime_prefixes,
    };
    match decide(&facts, &policy) {
        Decision::Inject(value) => {
            request
                .headers_mut()
                .insert(settings.token_header.clone(), value);
            request
                .extensions_mut()
                .insert(BridgedToken(settings.token_header.clone()));
        }
        Decision::Skip(reason) => {
            tracing::trace!(target: TRACING_TARGET, ?reason, "CSRF bridge skipped the request");
        }
    }
}

#[cfg(test)]
mod tests;
