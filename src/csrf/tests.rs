//! Tests for the `csrf` module.

use super::*;
use proptest::prelude::*;

/// A copy of `extract_cookie_token` from autumn-web 0.7.0 `security/csrf.rs`.
fn reference_extract_cookie_token(req_headers: &HeaderMap, cookie_name: &str) -> Option<String> {
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
            Skip::NoRuntimeMarker,
            Box::new(|f| {
                f.remove(RUNTIME_HEADER);
                f.path = "/_topcoat/runtime/%2E%2E/x".into();
            }),
        ),
        (
            Skip::NoRuntimeMarker,
            Box::new(|f| {
                f.remove(RUNTIME_HEADER);
                f.path = "/_topcoat/runtime/./x".into();
            }),
        ),
        (
            Skip::NoRuntimeMarker,
            Box::new(|f| {
                f.remove(RUNTIME_HEADER);
                f.path = "/_topcoat/runtime//x".into();
            }),
        ),
        (
            Skip::NoRuntimeMarker,
            Box::new(|f| {
                f.remove(RUNTIME_HEADER);
                f.path = "/_topcoat/runtime/a\\b".into();
            }),
        ),
        (
            Skip::NoRuntimeMarker,
            Box::new(|f| {
                f.remove(RUNTIME_HEADER);
                f.path = "/rpc/../api".into();
                f.runtime = vec![PathPrefix::new("/rpc").unwrap()];
            }),
        ),
        (
            Skip::NoRuntimeMarker,
            Box::new(|f| {
                f.remove(RUNTIME_HEADER);
                f.path = "/rpcx".into();
                f.runtime = vec![PathPrefix::new("/rpc").unwrap()];
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

/// Regression: two `Host` headers fail closed, also with an identity host.
#[test]
fn duplicate_host_headers_fail_closed() {
    let mut fixture = Fixture::rerun();
    fixture
        .remove("sec-fetch-site")
        .set("origin", "http://localhost")
        .add("host", "evil.example");
    fixture.identity_host = Some("localhost".into());
    assert_eq!(fixture.decide(), Decision::Skip(Skip::NotSameOrigin));
}

/// Regression: a scheme signal that does not parse fails closed.
#[test]
fn unparseable_scheme_fails_closed() {
    let mut fixture = Fixture::rerun();
    fixture
        .remove("sec-fetch-site")
        .set("origin", "http://localhost");
    fixture.identity_scheme = Some("junk".into());
    assert_eq!(fixture.decide(), Decision::Skip(Skip::NotSameOrigin));
}

/// The identity host wins over an internal `Host`.
#[test]
fn identity_host_wins_over_an_internal_host() {
    let mut fixture = Fixture::rerun();
    fixture
        .remove("sec-fetch-site")
        .set("host", "internal")
        .set("origin", "https://app.example");
    fixture.identity_host = Some("app.example".into());
    fixture.identity_scheme = Some("https".into());
    assert_eq!(fixture.decide(), inject("tok"));
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

/// An independent, string-level model of the origin comparison of rule 7.
///
/// It does not call `crate::origin`. `authority` is the expected
/// `host[:port]`, and `scheme` is the scheme signal of the request.
fn model_same_origin(origin: &str, authority: &str, scheme: Option<&str>) -> bool {
    fn valid_host(host: &str) -> bool {
        let name = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
        let ipv6 = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok());
        name || ipv6
    }
    fn split(text: &str) -> Option<(String, Option<u16>)> {
        let (host, port) = match text.rfind(':') {
            Some(i) if !text[i..].contains(']') => (&text[..i], Some(&text[i + 1..])),
            _ => (text, None),
        };
        let port = match port {
            None => None,
            Some(p)
                if !p.is_empty()
                    && !p.starts_with('0')
                    && p.bytes().all(|b| b.is_ascii_digit()) =>
            {
                Some(p.parse::<u16>().ok()?)
            }
            Some(_) => return None,
        };
        valid_host(host).then(|| (host.to_ascii_lowercase(), port))
    }
    let default_port = |scheme: &str| if scheme == "https" { 443 } else { 80 };
    let lower = origin.to_ascii_lowercase();
    let (origin_scheme, rest) = if let Some(rest) = lower.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = lower.strip_prefix("https://") {
        ("https", rest)
    } else {
        return false;
    };
    let signal = match scheme.map(str::to_ascii_lowercase).as_deref() {
        None => None,
        Some("http") => Some("http"),
        Some("https") => Some("https"),
        Some(_) => return false,
    };
    let (Some((origin_host, origin_port)), Some((host, port))) = (split(rest), split(authority))
    else {
        return false;
    };
    origin_host == host
        && origin_port.unwrap_or_else(|| default_port(origin_scheme))
            == port.unwrap_or_else(|| default_port(signal.unwrap_or(origin_scheme)))
        && signal.is_none_or(|s| s == origin_scheme)
}

/// An independent model of the rule table.
fn model(fixture: &Fixture) -> Result<String, Skip> {
    let headers = &fixture.headers;
    let all = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect::<Vec<_>>()
    };
    let under = |prefix: &PathPrefix| {
        fixture.path == prefix.as_str()
            || fixture.path.starts_with(&format!("{}/", prefix.as_str()))
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
    if fixture.excluded.iter().any(under) {
        return Err(Skip::Excluded);
    }
    if headers.contains_key(&fixture.token_header) {
        return Err(Skip::TokenPresent);
    }
    let ct = all("content-type");
    let json = ct.len() == 1
        && ct[0]
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
    let marked = (runtime.len() == 1 && runtime[0] == "true")
        || (identity.len() == 1 && !identity[0].is_empty())
        || (canonical
            && (fixture.path.starts_with(RUNTIME_PATH_PREFIX)
                || fixture.runtime.iter().any(under)));
    if !marked {
        return Err(Skip::NoRuntimeMarker);
    }
    let sfs = all("sec-fetch-site");
    let same = if sfs.is_empty() {
        let origins = all("origin");
        let hosts = all("host");
        let expected = match (&fixture.identity_host, hosts.as_slice()) {
            (Some(identity), _) => Some(identity.clone()),
            (None, []) => fixture.uri_authority.clone(),
            (None, [host]) => Some(host.clone()),
            (None, _) => None,
        };
        origins.len() == 1
            && hosts.len() <= 1
            && expected.is_some_and(|expected| {
                model_same_origin(&origins[0], &expected, fixture.identity_scheme.as_deref())
            })
    } else {
        sfs.len() == 1 && sfs[0] == "same-origin"
    };
    if !same {
        return Err(Skip::NotSameOrigin);
    }
    match reference_extract_cookie_token(headers, "autumn-csrf") {
        Some(v) if !v.is_empty() && HeaderValue::from_str(&v).is_ok() => Ok(v),
        _ => Err(Skip::CookieUnusable),
    }
}

/// A fixture with random values for each input of the rule table.
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
    let path = prop::sample::select(RUNTIME_PATHS).prop_map(str::to_owned);
    let opt =
        |values: &'static [&'static str]| prop::collection::vec(prop::sample::select(values), 0..3);
    let maybe = |values: &'static [&'static str]| prop::option::of(prop::sample::select(values));
    (
        (method, matched, path),
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
            "HTTP://LOCALHOST",
            "http://localhost:8080",
            "http://localhost:080",
            "http://[::1]",
            "http://evil.example",
            "null",
        ]),
        opt(&[
            "localhost",
            "LocalHost:80",
            "localhost:8080",
            "evil.example",
            "[::1]",
        ]),
        opt(&[
            "autumn-csrf=tok",
            "autumn-csrf=",
            "other=1",
            "autumn-csrf=a b",
        ]),
        (
            maybe(&[
                "localhost",
                "LOCALHOST:443",
                "localhost:8080",
                "evil.example",
                "bad host",
            ]),
            maybe(&["http", "https", "HTTPS", "junk"]),
            maybe(&["localhost", "localhost:8080", "[::1]", "h2.example"]),
        ),
        (any::<bool>(), any::<bool>(), any::<bool>()),
    )
        .prop_map(
            |(
                (method, matched, path),
                ct,
                rt,
                id,
                sfs,
                origin,
                host,
                cookie,
                (identity_host, identity_scheme, uri_authority),
                (token, excl, rt_prefix),
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
                f.identity_host = identity_host.map(str::to_owned);
                f.identity_scheme = identity_scheme.map(str::to_owned);
                f.uri_authority = uri_authority.map(str::to_owned);
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

/// Paths for the runtime-path branch of rule 6: canonical and not
/// canonical, under the default prefix, under `/rpc`, and near `/rpc`.
const RUNTIME_PATHS: &[&str] = &[
    "/page",
    "/api/x",
    "/_topcoat/runtime/procedures/ab",
    "/_topcoat/runtime/../x",
    "/_topcoat/runtime/./x",
    "/_topcoat/runtime//x",
    "/_topcoat/runtime/%2e%2e/x",
    "/_topcoat/runtime/%2E%2E/x",
    "/_topcoat/runtime/a\\b",
    "/rpc/x",
    "/rpc",
    "/rpc/../x",
    "/rpc/./x",
    "/rpc//x",
    "/rpcx",
];

/// One rule-targeted change. Some changes keep the request admissible.
fn tweak(f: &mut Fixture, which: u8) {
    match which % 20 {
        0 => {
            f.remove(RUNTIME_HEADER).set(IDENTITY_HEADER, "shard");
        }
        1 => {
            f.remove(RUNTIME_HEADER);
            f.path = "/_topcoat/runtime/procedures/ab".into();
        }
        2 => {
            f.remove("sec-fetch-site").set("origin", "http://localhost");
        }
        3 => {
            f.remove("sec-fetch-site")
                .set("origin", "https://app.example");
            f.identity_host = Some("app.example".into());
            f.identity_scheme = Some("https".into());
        }
        4 => {
            f.remove("sec-fetch-site")
                .remove("host")
                .set("origin", "http://h2.example:8080");
            f.uri_authority = Some("h2.example:8080".into());
        }
        5 => {
            f.set("content-type", "application/json; charset=utf-8");
        }
        6 => {
            f.matched = Some("/".into());
        }
        7 => {
            f.set("origin", "http://evil.example");
        }
        8 => {
            f.set("host", "localhost:8080");
        }
        9 => {
            f.identity_scheme = Some("https".into());
        }
        10 => {
            f.set("cookie", "autumn-csrf=");
        }
        11 => {
            f.set("sec-fetch-site", "same-site");
        }
        12 => {
            f.remove(RUNTIME_HEADER);
        }
        13 => {
            f.add("host", "localhost");
        }
        14 => {
            f.uri_authority = Some("evil.example".into());
        }
        // The runtime-path branch of rule 6: no marker header, a path under
        // the default prefix or under a runtime prefix.
        16 => {
            f.remove(RUNTIME_HEADER);
            f.path = "/rpc/x".into();
            f.runtime = vec![PathPrefix::new("/rpc").unwrap()];
        }
        17 => {
            f.remove(RUNTIME_HEADER);
            let index = usize::from(which) % RUNTIME_PATHS.len();
            f.path = RUNTIME_PATHS[index].to_owned();
            f.runtime = vec![PathPrefix::new("/rpc").unwrap()];
        }
        18 => {
            f.excluded = vec![PathPrefix::new("/page").unwrap()];
        }
        19 => {
            f.path = "/api/x".into();
            f.excluded = vec![PathPrefix::new("/api").unwrap()];
        }
        _ => {
            f.identity_host = Some("LOCALHOST".into());
        }
    }
}

/// The admitting rerun with up to three rule-targeted changes.
fn near_rerun() -> impl Strategy<Value = Fixture> {
    prop::collection::vec(any::<u8>(), 0..4).prop_map(|changes| {
        let mut f = Fixture::rerun();
        for which in changes {
            tweak(&mut f, which);
        }
        f
    })
}

fn any_fixture() -> impl Strategy<Value = Fixture> {
    prop_oneof![arb_fixture(), near_rerun()]
}

/// The number of hostile changes.
const HOSTILE: u8 = 12;

/// A change that no admissible request can make. Each change is hostile
/// for every fixture.
fn hostile(f: &mut Fixture, which: u8) {
    match which % HOSTILE {
        0 => {
            f.set("sec-fetch-site", "cross-site");
        }
        1 => {
            f.set("sec-fetch-site", "cross-site")
                .add("sec-fetch-site", "same-origin");
        }
        2 => {
            f.identity_host = None;
            f.remove("sec-fetch-site")
                .set("host", "localhost")
                .set("origin", "http://evil.example");
        }
        3 => {
            f.remove("sec-fetch-site").remove("origin");
        }
        4 => {
            f.add("cookie", "autumn-csrf=a; autumn-csrf=b");
        }
        5 => f.method = Method::GET,
        6 => {
            f.set("content-type", "text/plain");
        }
        7 => f.matched = Some("/api/not-plugin".into()),
        8 => {
            let first = f.path.split('/').nth(1).unwrap_or("x");
            f.excluded
                .push(PathPrefix::new(&format!("/{first}")).unwrap());
        }
        9 => {
            f.set("x-csrf-token", "client");
        }
        10 => {
            f.remove("sec-fetch-site")
                .set("origin", "http://localhost")
                .set("host", "localhost")
                .add("host", "evil.example");
        }
        _ => {
            f.remove("sec-fetch-site").set("origin", "http://localhost");
            f.identity_scheme = Some("junk".into());
        }
    }
}

/// Each hostile change turns the admitted rerun into a skip.
#[test]
fn hostile_changes_turn_inject_into_skip() {
    for which in 0..HOSTILE {
        let mut f = Fixture::rerun();
        assert_eq!(f.decide(), inject("tok"));
        hostile(&mut f, which);
        assert!(
            matches!(f.decide(), Decision::Skip(_)),
            "hostile change {which} injected"
        );
    }
}

/// Returns the rule 6 marker that admitted `fixture`.
fn marker_source(fixture: &Fixture) -> &'static str {
    if only(&fixture.headers, RUNTIME_HEADER).is_some_and(|v| v.as_bytes() == b"true") {
        "rerun"
    } else if fixture.headers.contains_key(IDENTITY_HEADER) {
        "shard"
    } else if fixture.path.starts_with(RUNTIME_PATH_PREFIX) {
        "default path"
    } else {
        "runtime prefix"
    }
}

/// The generators reach each rule, so the model property tests all rules.
#[test]
fn generators_reach_each_rule() {
    use proptest::strategy::ValueTree;

    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let strategy = any_fixture();
    let mut injects = 0;
    let mut sources = std::collections::HashSet::new();
    let mut skips = std::collections::HashSet::new();
    for _ in 0..512 {
        let fixture = strategy.new_tree(&mut runner).unwrap().current();
        match fixture.decide() {
            Decision::Inject(_) => {
                injects += 1;
                sources.insert(marker_source(&fixture));
            }
            Decision::Skip(skip) => {
                skips.insert(skip);
            }
        }
    }
    assert!(injects >= 50, "only {injects} injects");
    for source in ["rerun", "shard", "default path", "runtime prefix"] {
        assert!(sources.contains(source), "no inject through {source}");
    }
    for skip in [
        Skip::NotPost,
        Skip::NotPluginRoute,
        Skip::Excluded,
        Skip::TokenPresent,
        Skip::NotJson,
        Skip::NoRuntimeMarker,
        Skip::NotSameOrigin,
        Skip::CookieUnusable,
    ] {
        assert!(skips.contains(&skip), "no fixture reached {skip:?}");
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
    fn decide_agrees_with_model(f in any_fixture()) {
        let expected = match model(&f) {
            Ok(v) => Decision::Inject(HeaderValue::from_str(&v).unwrap()),
            Err(skip) => Decision::Skip(skip),
        };
        prop_assert_eq!(f.decide(), expected);
    }

    /// A hostile change never gives `Inject`, so a skip stays a skip.
    #[test]
    fn hostile_changes_are_monotone(mut f in any_fixture(), which in any::<u8>()) {
        let before = f.decide();
        hostile(&mut f, which);
        let after = f.decide();
        prop_assert!(matches!(after, Decision::Skip(_)), "hostile change {} injected", which % HOSTILE);
        if matches!(before, Decision::Skip(_)) {
            prop_assert!(matches!(after, Decision::Skip(_)));
        }
    }

    #[test]
    fn never_injects_when_token_header_is_present(mut f in any_fixture()) {
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
    fn unrelated_headers_do_not_change_the_decision(f in any_fixture(), value in "[a-z]{0,8}") {
        let before = f.decide();
        let mut g = f;
        g.headers.append("x-unrelated", HeaderValue::from_str(&value).unwrap());
        prop_assert_eq!(g.decide(), before);
    }

    /// The model origin check agrees with the parser on single values.
    #[test]
    fn origin_model_agrees_with_the_parser(
        origin in prop::sample::select(&["http://localhost", "https://LOCALHOST:443", "http://[::1]:8080", "http://[abc]", "http://localhost:080", "http://localhost:0", "http://a:b:c", "ftp://localhost", "http://user@localhost"][..]),
        authority in prop::sample::select(&["localhost", "LOCALHOST:80", "localhost:443", "[::1]:8080", "[1.2.3.4]", "localhost:", "a b"][..]),
        scheme in prop::option::of(prop::sample::select(&["http", "HTTPS", "junk"][..])),
    ) {
        let parsed = Origin::parse(origin).zip(Authority::parse(authority));
        let known = scheme.map(Scheme::parse);
        let expected = match (parsed, known) {
            (_, Some(None)) | (None, _) => false,
            (Some((o, a)), known) => same_origin(&o, &a, known.flatten()),
        };
        prop_assert_eq!(model_same_origin(origin, authority, scheme), expected);
    }
}
