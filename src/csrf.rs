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
//! 7. `NotSameOrigin`: one `Sec-Fetch-Site` with the value `same-origin`;
//!    or, when `Sec-Fetch-Site` is absent, one `Origin` that is the origin of
//!    the expected authority (identity host, else `Host`, else URI
//!    authority).
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
    let scheme = request.identity_scheme.and_then(Scheme::parse);
    same_origin(&origin, &expected, scheme)
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A copy of `extract_cookie_token` from autumn-web 0.7.0 `security/csrf.rs`.
    fn reference_extract_cookie_token(
        req_headers: &HeaderMap,
        cookie_name: &str,
    ) -> Option<String> {
        let mut found_token = None;
        for cookie_header in &req_headers.get_all(http::header::COOKIE) {
            let Ok(cookie_str) = cookie_header.to_str() else {
                continue;
            };
            for pair in cookie_str.split(';') {
                let pair = pair.trim();
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                if name.trim() != cookie_name {
                    continue;
                }
                if found_token.is_some() {
                    return None;
                }
                found_token = Some(value.trim().to_owned());
            }
        }
        found_token
    }

    const TEMPLATES: &[&str] = &["/", "/{*path}"];

    #[derive(Debug)]
    struct Fixture {
        method: Method,
        matched: Option<String>,
        path: String,
        headers: HeaderMap,
        identity_host: Option<String>,
        identity_scheme: Option<String>,
        uri_authority: Option<String>,
        templates: Vec<String>,
        excluded: Vec<PathPrefix>,
        runtime: Vec<PathPrefix>,
        token_header: HeaderName,
    }

    impl Fixture {
        /// A same-origin page rerun that the bridge admits.
        fn rerun() -> Self {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            headers.insert(RUNTIME_HEADER, HeaderValue::from_static("true"));
            headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
            headers.insert(
                "cookie",
                HeaderValue::from_static("a=1; autumn-csrf=tok; b=2"),
            );
            headers.insert("host", HeaderValue::from_static("localhost"));
            Self {
                method: Method::POST,
                matched: Some("/{*path}".into()),
                path: "/page".into(),
                headers,
                identity_host: None,
                identity_scheme: None,
                uri_authority: None,
                templates: TEMPLATES.iter().map(|s| (*s).to_owned()).collect(),
                excluded: Vec::new(),
                runtime: Vec::new(),
                token_header: HeaderName::from_static("x-csrf-token"),
            }
        }

        fn decide(&self) -> Decision {
            decide(&self.request(), &self.policy())
        }

        fn request(&self) -> BridgeRequest<'_> {
            BridgeRequest {
                method: &self.method,
                matched_path: self.matched.as_deref(),
                path: &self.path,
                headers: &self.headers,
                identity_host: self.identity_host.as_deref(),
                identity_scheme: self.identity_scheme.as_deref(),
                uri_authority: self.uri_authority.as_deref(),
            }
        }

        fn policy(&self) -> BridgePolicy<'_> {
            BridgePolicy {
                cookie_name: "autumn-csrf",
                token_header: &self.token_header,
                templates: &self.templates,
                excluded: &self.excluded,
                runtime_prefixes: &self.runtime,
            }
        }

        fn set(&mut self, name: &'static str, value: &'static str) -> &mut Self {
            self.headers.insert(name, HeaderValue::from_static(value));
            self
        }

        fn add(&mut self, name: &'static str, value: &'static str) -> &mut Self {
            self.headers.append(name, HeaderValue::from_static(value));
            self
        }

        fn remove(&mut self, name: &'static str) -> &mut Self {
            self.headers.remove(name);
            self
        }
    }

    /// A change to a fixture.
    type Mutation = Box<dyn Fn(&mut Fixture)>;

    fn inject(value: &'static str) -> Decision {
        Decision::Inject(HeaderValue::from_static(value))
    }

    // ---------- cookie parser ----------

    #[test]
    fn single_cookie_examples() {
        let mut headers = HeaderMap::new();
        assert_eq!(single_cookie(&headers, "c"), None);
        headers.insert("cookie", HeaderValue::from_static(" a=1 ;  c = v ; d"));
        assert_eq!(single_cookie(&headers, "c"), Some("v"));
        headers.append("cookie", HeaderValue::from_static("c=w"));
        assert_eq!(
            single_cookie(&headers, "c"),
            None,
            "two cookies with one name"
        );
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("cc=1; c=; x=c"));
        assert_eq!(single_cookie(&headers, "c"), Some(""));
    }

    // ---------- decision examples ----------

    #[test]
    fn admits_same_origin_rerun() {
        assert_eq!(Fixture::rerun().decide(), inject("tok"));
    }

    #[test]
    fn admits_shard_and_default_procedure_and_runtime_prefix() {
        let mut shard = Fixture::rerun();
        shard.remove(RUNTIME_HEADER).set(IDENTITY_HEADER, "abc");
        assert_eq!(shard.decide(), inject("tok"));

        let mut procedure = Fixture::rerun();
        procedure.remove(RUNTIME_HEADER);
        procedure.path = "/_topcoat/runtime/procedures/0123abcd".into();
        assert_eq!(procedure.decide(), inject("tok"));

        let mut custom = Fixture::rerun();
        custom.remove(RUNTIME_HEADER);
        custom.path = "/rpc/double".into();
        custom.runtime = vec![PathPrefix::new("/rpc").unwrap()];
        assert_eq!(custom.decide(), inject("tok"));
    }

    #[test]
    fn admits_origin_fallback_from_each_authority_source() {
        let mut host = Fixture::rerun();
        host.remove("sec-fetch-site")
            .set("origin", "http://localhost");
        assert_eq!(host.decide(), inject("tok"));

        let mut identity = Fixture::rerun();
        identity
            .remove("sec-fetch-site")
            .remove("host")
            .set("origin", "https://app.example");
        identity.identity_host = Some("app.example".into());
        identity.identity_scheme = Some("https".into());
        assert_eq!(identity.decide(), inject("tok"));

        let mut uri = Fixture::rerun();
        uri.remove("sec-fetch-site")
            .remove("host")
            .set("origin", "http://h2.example:8080");
        uri.uri_authority = Some("h2.example:8080".into());
        assert_eq!(uri.decide(), inject("tok"));
    }

    #[test]
    fn content_type_parameters_and_case_are_accepted() {
        let mut fixture = Fixture::rerun();
        fixture.set("content-type", "Application/JSON; charset=utf-8");
        assert_eq!(fixture.decide(), inject("tok"));
    }

    #[test]
    fn skips_with_the_first_failed_rule() {
        let cases: Vec<(Skip, Mutation)> = vec![
            (Skip::NotPost, Box::new(|f| f.method = Method::PUT)),
            (Skip::NotPluginRoute, Box::new(|f| f.matched = None)),
            (
                Skip::NotPluginRoute,
                Box::new(|f| f.matched = Some("/api/things".into())),
            ),
            (
                Skip::Excluded,
                Box::new(|f| {
                    f.excluded = vec![PathPrefix::new("/page").unwrap()];
                }),
            ),
            (
                Skip::TokenPresent,
                Box::new(|f| {
                    f.set("x-csrf-token", "wrong");
                }),
            ),
            (
                Skip::NotJson,
                Box::new(|f| {
                    f.set("content-type", "text/plain");
                }),
            ),
            (
                Skip::NotJson,
                Box::new(|f| {
                    f.set("content-type", "application/x-www-form-urlencoded");
                }),
            ),
            (
                Skip::NotJson,
                Box::new(|f| {
                    f.remove("content-type");
                }),
            ),
            (
                Skip::NotJson,
                Box::new(|f| {
                    f.add("content-type", "application/json");
                }),
            ),
            (
                Skip::NoRuntimeMarker,
                Box::new(|f| {
                    f.remove(RUNTIME_HEADER);
                }),
            ),
            (
                Skip::NoRuntimeMarker,
                Box::new(|f| {
                    f.set(RUNTIME_HEADER, "1");
                }),
            ),
            (
                Skip::NoRuntimeMarker,
                Box::new(|f| {
                    f.add(RUNTIME_HEADER, "true");
                }),
            ),
            (
                Skip::NoRuntimeMarker,
                Box::new(|f| {
                    f.remove(RUNTIME_HEADER).set(IDENTITY_HEADER, "");
                }),
            ),
            (
                Skip::NoRuntimeMarker,
                Box::new(|f| {
                    f.remove(RUNTIME_HEADER);
                    f.path = "/_topcoat/runtime/../api".into();
                }),
            ),
            (
                Skip::NoRuntimeMarker,
                Box::new(|f| {
                    f.remove(RUNTIME_HEADER);
                    f.path = "/_topcoat/runtime/%2e%2e/x".into();
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.set("sec-fetch-site", "cross-site");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.set("sec-fetch-site", "same-site");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.set("sec-fetch-site", "none");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.add("sec-fetch-site", "same-origin");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site").set("origin", "null");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site")
                        .set("origin", "http://evil.example");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site")
                        .set("origin", "http://localhost:8080");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site").set("origin", "http://localhost");
                    f.identity_scheme = Some("https".into());
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site")
                        .set("origin", "http://localhost")
                        .add("origin", "http://localhost");
                }),
            ),
            (
                Skip::NotSameOrigin,
                Box::new(|f| {
                    f.remove("sec-fetch-site")
                        .remove("host")
                        .set("origin", "http://localhost");
                }),
            ),
            (
                Skip::CookieUnusable,
                Box::new(|f| {
                    f.remove("cookie");
                }),
            ),
            (
                Skip::CookieUnusable,
                Box::new(|f| {
                    f.set("cookie", "autumn-csrf=");
                }),
            ),
            (
                Skip::CookieUnusable,
                Box::new(|f| {
                    f.add("cookie", "autumn-csrf=other");
                }),
            ),
        ];
        for (index, (expected, mutate)) in cases.iter().enumerate() {
            let mut fixture = Fixture::rerun();
            mutate(&mut fixture);
            assert_eq!(fixture.decide(), Decision::Skip(*expected), "case {index}");
        }
    }

    #[test]
    fn custom_token_header_is_respected() {
        let mut fixture = Fixture::rerun();
        fixture.token_header = HeaderName::from_static("x-my-token");
        fixture.set("x-csrf-token", "ignored");
        assert_eq!(fixture.decide(), inject("tok"));
        fixture.set("x-my-token", "client");
        assert_eq!(fixture.decide(), Decision::Skip(Skip::TokenPresent));
    }

    // ---------- properties ----------

    /// An independent model of the rule table.
    fn model(fixture: &Fixture) -> Result<String, Skip> {
        let headers = &fixture.headers;
        let all = |name: &str| {
            headers
                .get_all(name)
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        if fixture.method != Method::POST {
            return Err(Skip::NotPost);
        }
        if !fixture
            .matched
            .as_ref()
            .is_some_and(|m| fixture.templates.contains(m))
        {
            return Err(Skip::NotPluginRoute);
        }
        if fixture.excluded.iter().any(|e| {
            fixture.path == e.as_str() || fixture.path.starts_with(&format!("{}/", e.as_str()))
        }) {
            return Err(Skip::Excluded);
        }
        if headers.contains_key(&fixture.token_header) {
            return Err(Skip::TokenPresent);
        }
        let ct = all("content-type");
        let json = ct.len() == 1
            && String::from_utf8_lossy(&ct[0])
                .split(';')
                .next()
                .unwrap()
                .trim()
                .eq_ignore_ascii_case("application/json");
        if !json {
            return Err(Skip::NotJson);
        }
        let runtime = all(RUNTIME_HEADER);
        let identity = all(IDENTITY_HEADER);
        let canonical = !fixture.path.contains("/./")
            && !fixture.path.contains("/../")
            && !fixture.path.ends_with("/.")
            && !fixture.path.ends_with("/..")
            && !fixture.path.contains("//")
            && !fixture.path.to_ascii_lowercase().contains("%2e")
            && !fixture.path.contains('\\');
        let marked = (runtime.len() == 1 && runtime[0] == b"true")
            || (identity.len() == 1 && !identity[0].is_empty())
            || (canonical
                && (fixture.path.starts_with(RUNTIME_PATH_PREFIX)
                    || fixture.runtime.iter().any(|r| {
                        fixture.path == r.as_str()
                            || fixture.path.starts_with(&format!("{}/", r.as_str()))
                    })));
        if !marked {
            return Err(Skip::NoRuntimeMarker);
        }
        let sfs = all("sec-fetch-site");
        let same = if sfs.is_empty() {
            let origins = all("origin");
            let expected = fixture.identity_host.clone().map_or_else(
                || {
                    let hosts = all("host");
                    if hosts.is_empty() {
                        fixture.uri_authority.clone()
                    } else {
                        (hosts.len() == 1).then(|| String::from_utf8_lossy(&hosts[0]).into_owned())
                    }
                },
                Some,
            );
            origins.len() == 1
                && expected.is_some_and(|e| {
                    let origin = Origin::parse(&String::from_utf8_lossy(&origins[0]));
                    let authority = Authority::parse(&e);
                    let scheme = fixture.identity_scheme.as_deref().and_then(Scheme::parse);
                    matches!((origin, authority), (Some(o), Some(a)) if same_origin(&o, &a, scheme))
                })
        } else {
            sfs.len() == 1 && sfs[0] == b"same-origin"
        };
        if !same {
            return Err(Skip::NotSameOrigin);
        }
        match reference_extract_cookie_token(headers, "autumn-csrf") {
            Some(v) if !v.is_empty() && HeaderValue::from_str(&v).is_ok() => Ok(v),
            _ => Err(Skip::CookieUnusable),
        }
    }

    fn arb_fixture() -> impl Strategy<Value = Fixture> {
        let method = prop_oneof![
            Just(Method::POST),
            Just(Method::POST),
            Just(Method::GET),
            Just(Method::DELETE)
        ];
        let matched = prop_oneof![
            Just(Some("/{*path}".to_owned())),
            Just(Some("/".to_owned())),
            Just(Some("/api/x".to_owned())),
            Just(None)
        ];
        let path = prop_oneof![
            Just("/page".to_owned()),
            Just("/_topcoat/runtime/procedures/ab".to_owned()),
            Just("/_topcoat/runtime/../x".to_owned()),
            Just("/_topcoat/runtime//x".to_owned()),
            Just("/rpc/x".to_owned()),
            Just("/api/x".to_owned()),
        ];
        let opt = |values: &'static [&'static str]| {
            prop::collection::vec(prop::sample::select(values), 0..3)
        };
        (
            method,
            matched,
            path,
            opt(&[
                "application/json",
                "application/json; charset=utf-8",
                "text/plain",
            ]),
            opt(&["true", "false"]),
            opt(&["id1", ""]),
            opt(&["same-origin", "same-site", "cross-site", "none"]),
            opt(&[
                "http://localhost",
                "https://localhost",
                "http://evil.example",
                "null",
                "http://localhost:81",
            ]),
            opt(&["localhost", "evil.example"]),
            opt(&[
                "autumn-csrf=tok",
                "autumn-csrf=",
                "other=1",
                "autumn-csrf=a b",
            ]),
            (
                any::<bool>(),
                prop::option::of(prop::sample::select(&["http", "https"][..])),
                any::<bool>(),
                any::<bool>(),
            ),
        )
            .prop_map(
                |(
                    method,
                    matched,
                    path,
                    ct,
                    rt,
                    id,
                    sfs,
                    origin,
                    host,
                    cookie,
                    (token, scheme, excl, rt_prefix),
                )| {
                    let mut f = Fixture::rerun();
                    f.method = method;
                    f.matched = matched;
                    f.path = path;
                    f.headers = HeaderMap::new();
                    for (name, values) in [
                        ("content-type", ct),
                        (RUNTIME_HEADER, rt),
                        (IDENTITY_HEADER, id),
                        ("sec-fetch-site", sfs),
                        ("origin", origin),
                        ("host", host),
                        ("cookie", cookie),
                    ] {
                        for value in values {
                            f.headers.append(
                                HeaderName::from_static(name),
                                HeaderValue::from_static(value),
                            );
                        }
                    }
                    if token {
                        f.headers
                            .insert("x-csrf-token", HeaderValue::from_static("client"));
                    }
                    f.identity_scheme = scheme.map(str::to_owned);
                    if excl {
                        f.excluded = vec![PathPrefix::new("/api").unwrap()];
                    }
                    if rt_prefix {
                        f.runtime = vec![PathPrefix::new("/rpc").unwrap()];
                    }
                    f
                },
            )
    }

    fn hostile(f: &mut Fixture, which: u8) {
        match which % 10 {
            0 => {
                f.headers
                    .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
            }
            1 => {
                f.headers
                    .append("sec-fetch-site", HeaderValue::from_static("same-origin"));
            }
            2 => {
                f.headers.remove("sec-fetch-site");
                f.headers
                    .insert("origin", HeaderValue::from_static("http://evil.example"));
            }
            3 => {
                f.headers.remove("sec-fetch-site");
                f.headers.remove("origin");
            }
            4 => {
                f.headers
                    .append("cookie", HeaderValue::from_static("autumn-csrf=tossed"));
            }
            5 => f.method = Method::GET,
            6 => {
                f.headers
                    .insert("content-type", HeaderValue::from_static("text/plain"));
            }
            7 => f.matched = Some("/api/not-plugin".into()),
            8 => {
                let first = f.path.split('/').nth(1).unwrap_or("x");
                f.excluded
                    .push(PathPrefix::new(&format!("/{first}")).unwrap());
            }
            _ => {
                f.headers
                    .insert("x-csrf-token", HeaderValue::from_static("client"));
            }
        }
    }

    proptest! {
        #[test]
        fn single_cookie_agrees_with_autumn(values in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..24), 0..4), name in prop::sample::select(&["c", "autumn-csrf", "a"][..])) {
            let mut headers = HeaderMap::new();
            for bytes in values {
                if let Ok(value) = HeaderValue::from_bytes(&bytes) {
                    headers.append("cookie", value);
                }
            }
            prop_assert_eq!(single_cookie(&headers, name).map(str::to_owned), reference_extract_cookie_token(&headers, name));
        }

        #[test]
        fn single_cookie_refuses_tossing(a in "[a-z0-9]{1,6}", b in "[a-z0-9]{1,6}", split in any::<bool>()) {
            let mut headers = HeaderMap::new();
            if split {
                headers.append("cookie", HeaderValue::from_str(&format!("autumn-csrf={a}")).unwrap());
                headers.append("cookie", HeaderValue::from_str(&format!("x=1; autumn-csrf={b}")).unwrap());
            } else {
                headers.append("cookie", HeaderValue::from_str(&format!("autumn-csrf={a}; autumn-csrf={b}")).unwrap());
            }
            prop_assert_eq!(single_cookie(&headers, "autumn-csrf"), None);
        }

        #[test]
        fn decide_agrees_with_model(f in arb_fixture()) {
            let expected = match model(&f) {
                Ok(v) => Decision::Inject(HeaderValue::from_str(&v).unwrap()),
                Err(skip) => Decision::Skip(skip),
            };
            prop_assert_eq!(f.decide(), expected);
        }

        #[test]
        fn hostile_changes_never_inject(mut f in arb_fixture(), which in any::<u8>()) {
            hostile(&mut f, which);
            prop_assert!(!matches!(f.decide(), Decision::Inject(_)), "hostile change {} injected", which % 10);
        }

        #[test]
        fn never_injects_when_token_header_is_present(mut f in arb_fixture()) {
            f.headers.insert("x-csrf-token", HeaderValue::from_static("client"));
            prop_assert_eq!(f.decide(), Decision::Skip(if f.method != Method::POST {
                Skip::NotPost
            } else if !f.matched.as_ref().is_some_and(|m| f.templates.contains(m)) {
                Skip::NotPluginRoute
            } else if f.excluded.iter().any(|e| e.matches(&f.path)) {
                Skip::Excluded
            } else {
                Skip::TokenPresent
            }));
        }

        #[test]
        fn unrelated_headers_do_not_change_the_decision(f in arb_fixture(), value in "[a-z]{0,8}") {
            let before = f.decide();
            let mut g = f;
            g.headers.append("x-unrelated", HeaderValue::from_str(&value).unwrap());
            prop_assert_eq!(g.decide(), before);
        }
    }
}
