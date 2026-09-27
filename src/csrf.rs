//! The pure CSRF bridge decision.
//!
//! The bridge copies the Autumn CSRF cookie into the CSRF header for
//! same-origin Topcoat runtime requests. Autumn CSRF then compares the two
//! values as usual.
//!
//! # Contract
//!
//! `decide(request, policy)` returns `Inject(v)` if and only if all these
//! rules are true, else `Skip(r)` where `r` is the first failed rule:
//!
//! 1. `NotPost`: the method is `POST`.
//! 2. `NotPluginRoute`: `matched_path` is one of `policy.templates`.
//! 3. `Excluded`: no excluded prefix matches the path.
//! 4. `TokenPresent`: the request has no CSRF header.
//! 5. `NotJson`: the request has one `Content-Type` with the media type
//!    `application/json`.
//! 6. `NoRuntimeMarker`: the request has one `x-topcoat-runtime: true`, or
//!    one non-empty `x-topcoat-identity`, or a canonical path under
//!    `/_topcoat/runtime/` or under a runtime prefix.
//! 7. `NotSameOrigin`: the request is same-origin.
//!    - With `Sec-Fetch-Site`, it has one value, and the value is `same-origin`.
//!    - Without `Sec-Fetch-Site`, the request has one `Origin` and at most
//!      one `Host`. The `Origin` matches the expected authority.
//!    - The expected authority is the identity host, else `Host`, else the
//!      URI authority.
//!    - A scheme signal that does not parse fails the rule. Without a scheme
//!      signal, the rule compares only the host and the port.
//! 8. `CookieUnusable`: [`single_cookie`] finds a non-empty cookie value that
//!    is a valid header value. Then `v` is that value.
//!
//! The decision is pure and total. A hostile change to the request never
//! changes `Skip` to `Inject`.

use http::{HeaderMap, HeaderName, HeaderValue, Method};

use crate::origin::{Authority, Origin, Scheme, same_origin};
use crate::path::PathPrefix;

/// The prefix of the default Topcoat shard and procedure endpoints.
pub(crate) const RUNTIME_PATH_PREFIX: &str = "/_topcoat/runtime/";
/// The header that the Topcoat runtime sends on page reruns.
pub(crate) const RUNTIME_HEADER: &str = "x-topcoat-runtime";
/// The header that the Topcoat runtime sends on shard renders.
pub(crate) const IDENTITY_HEADER: &str = "x-topcoat-identity";

/// The facts about one request that the decision reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BridgeRequest<'a> {
    pub(crate) method: &'a Method,
    pub(crate) matched_path: Option<&'a str>,
    pub(crate) path: &'a str,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) identity_host: Option<&'a str>,
    pub(crate) identity_scheme: Option<&'a str>,
    pub(crate) uri_authority: Option<&'a str>,
}

/// The configuration that the decision reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BridgePolicy<'a> {
    pub(crate) cookie_name: &'a str,
    pub(crate) token_header: &'a HeaderName,
    pub(crate) templates: &'a [String],
    pub(crate) excluded: &'a [PathPrefix],
    pub(crate) runtime_prefixes: &'a [PathPrefix],
}

/// The result of the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Insert the CSRF header with this value.
    Inject(HeaderValue),
    /// Do not change the request.
    Skip(Skip),
}

/// Why the bridge does not change a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Skip {
    NotPost,
    NotPluginRoute,
    Excluded,
    TokenPresent,
    NotJson,
    NoRuntimeMarker,
    NotSameOrigin,
    CookieUnusable,
}

/// Returns the value of the only cookie called `name`.
///
/// This is the same algorithm as the Autumn CSRF cookie parser: two cookies
/// with the same name give `None`, to stop cookie tossing.
pub(crate) fn single_cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut found = None;
    for header in headers.get_all(http::header::COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key.trim() != name {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(value.trim());
        }
    }
    found
}

/// Decides whether the bridge copies the CSRF cookie into the CSRF header.
pub(crate) fn decide(request: &BridgeRequest<'_>, policy: &BridgePolicy<'_>) -> Decision {
    match check(request, policy) {
        Ok(value) => Decision::Inject(value),
        Err(skip) => Decision::Skip(skip),
    }
}

/// Applies the rules in order. See the module contract.
fn check(request: &BridgeRequest<'_>, policy: &BridgePolicy<'_>) -> Result<HeaderValue, Skip> {
    let headers = request.headers;
    if request.method != Method::POST {
        return Err(Skip::NotPost);
    }
    let plugin_route = request
        .matched_path
        .is_some_and(|matched| policy.templates.iter().any(|t| t == matched));
    if !plugin_route {
        return Err(Skip::NotPluginRoute);
    }
    if policy.excluded.iter().any(|e| e.matches(request.path)) {
        return Err(Skip::Excluded);
    }
    if headers.contains_key(policy.token_header) {
        return Err(Skip::TokenPresent);
    }
    if !is_json(headers) {
        return Err(Skip::NotJson);
    }
    if !has_runtime_marker(request, policy) {
        return Err(Skip::NoRuntimeMarker);
    }
    if !is_same_origin(request) {
        return Err(Skip::NotSameOrigin);
    }
    single_cookie(headers, policy.cookie_name)
        .filter(|value| !value.is_empty())
        .and_then(|value| HeaderValue::from_str(value).ok())
        .ok_or(Skip::CookieUnusable)
}

/// Returns the only value of `name`, or `None` for zero or many values.
fn only<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

/// Rule 5: one `Content-Type` with the media type `application/json`.
fn is_json(headers: &HeaderMap) -> bool {
    only(headers, http::header::CONTENT_TYPE.as_str())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

/// Rule 6: a runtime header or a canonical runtime path.
fn has_runtime_marker(request: &BridgeRequest<'_>, policy: &BridgePolicy<'_>) -> bool {
    let headers = request.headers;
    let rerun = only(headers, RUNTIME_HEADER).is_some_and(|value| value.as_bytes() == b"true");
    let shard = only(headers, IDENTITY_HEADER).is_some_and(|value| !value.is_empty());
    let path = request.path;
    let runtime_path = is_canonical(path)
        && (path.starts_with(RUNTIME_PATH_PREFIX)
            || policy.runtime_prefixes.iter().any(|r| r.matches(path)));
    rerun || shard || runtime_path
}

/// Returns `true` if `path` has no empty inner segment, no dot segment, no
/// encoded dot and no backslash.
fn is_canonical(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && !path.to_ascii_lowercase().contains("%2e")
        && path
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

/// Rule 7: browser evidence that the request is same-origin.
fn is_same_origin(request: &BridgeRequest<'_>) -> bool {
    let headers = request.headers;
    if headers.contains_key("sec-fetch-site") {
        return only(headers, "sec-fetch-site")
            .is_some_and(|value| value.as_bytes() == b"same-origin");
    }
    let Some(origin) = only(headers, http::header::ORIGIN.as_str())
        .and_then(|value| value.to_str().ok())
        .and_then(Origin::parse)
    else {
        return false;
    };
    // Two `Host` headers make the expected origin ambiguous.
    if headers.get_all(http::header::HOST).iter().nth(1).is_some() {
        return false;
    }
    // A present `Host` header wins over the URI authority, even when it is bad.
    let authority = match request.identity_host {
        Some(host) => Some(host),
        None if headers.contains_key(http::header::HOST) => {
            only(headers, http::header::HOST.as_str()).and_then(|value| value.to_str().ok())
        }
        None => request.uri_authority,
    };
    let Some(expected) = authority.and_then(Authority::parse) else {
        return false;
    };
    // A scheme signal that does not parse cannot decide, so it fails closed.
    let scheme = match request.identity_scheme {
        Some(raw) => match Scheme::parse(raw) {
            Some(scheme) => Some(scheme),
            None => return false,
        },
        None => None,
    };
    same_origin(&origin, &expected, scheme)
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests;
