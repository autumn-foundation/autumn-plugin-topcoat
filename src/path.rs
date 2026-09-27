//! Validated path prefixes and mount paths.

use std::fmt;
use std::str::FromStr;

use crate::error::PathError;

/// The Topcoat namespace for assets and runtime endpoints.
pub const INTERNAL_PREFIX: &str = "/_topcoat";

/// Namespaces that a mount path must not use, with their owners.
const RESERVED: &[(&str, &str)] = &[
    ("/static", "Autumn static files"),
    ("/_autumn", "Autumn"),
    ("/__autumn", "Autumn dev tools"),
    ("/_stories", "Autumn widget stories"),
    ("/actuator", "Autumn actuator"),
    ("/health", "Autumn probes"),
    ("/live", "Autumn probes"),
    ("/ready", "Autumn probes"),
    ("/startup", "Autumn probes"),
    ("/openapi.json", "Autumn OpenAPI"),
    ("/swagger-ui", "Autumn OpenAPI"),
    (INTERNAL_PREFIX, "Topcoat"),
];

/// A validated path prefix, for example `/api`.
///
/// A prefix matches a path at segment boundaries: `/api` matches `/api` and
/// `/api/users`, but not `/apix`. Matching uses the raw path, as axum does.
///
/// # Contract
///
/// - `new` never panics. It accepts `s` if and only if all these rules are
///   true: `s` starts with `/`; `s` is not `/`; `s` does not end with `/`;
///   no segment is empty, `.` or `..`; each character is an ASCII letter, a
///   digit, `-`, `.`, `_` or `~`.
/// - When `new` refuses `s`, the error is the first failed rule in this order:
///   `Empty`, `Root`, `MissingLeadingSlash`, `TrailingSlash`, `EmptySegment`,
///   `DotSegment`, `ForbiddenChar`.
/// - `new(p.as_str()) == Ok(p)` for each valid `p`.
/// - `matches(path) == (path == p || path.starts_with(p + "/"))`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathPrefix(Box<str>);

impl PathPrefix {
    /// Validates `prefix`.
    ///
    /// # Errors
    ///
    /// Returns the [`PathError`] for the first rule that `prefix` breaks.
    pub fn new(prefix: &str) -> Result<Self, PathError> {
        validate(prefix)?;
        Ok(Self(prefix.into()))
    }

    /// Returns the prefix as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if `path` is equal to the prefix or is under it.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        is_under(path, &self.0)
    }

    /// Returns `true` if the prefix is `/_topcoat` or is under it.
    pub(crate) fn overlaps_internal(&self) -> bool {
        is_under(&self.0, INTERNAL_PREFIX)
    }

    /// Returns `true` if the prefix is strictly under `parent`.
    pub(crate) fn is_strictly_under(&self, parent: &Self) -> bool {
        self.0 != parent.0 && is_under(&self.0, &parent.0)
    }
}

impl FromStr for PathPrefix {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<&str> for PathPrefix {
    type Error = PathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Display for PathPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PathPrefix {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The place where the plugin mounts Topcoat.
///
/// Topcoat always gets the full request path. The plugin never removes the
/// prefix, so declare the Topcoat pages under the prefix.
///
/// # Contract
///
/// - `prefix(s)` applies the [`PathPrefix`] rules, then refuses each
///   reserved namespace `r` (for example `/static`) with
///   [`PathError::Reserved`] when `s == r` or `s` is under `r`.
/// - `root().templates() == ["/", "/{*path}"]`.
/// - `prefix(P).templates() == [P, P + "/", P + "/{*path}", "/_topcoat/{*path}"]`.
/// - For each raw path `p`, `covers(p)` is `true` if and only if a matchit
///   0.8.4 router with `templates()` matches `p`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct MountPath(Repr);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
enum Repr {
    #[default]
    Root,
    Prefix(PathPrefix),
}

impl MountPath {
    /// Returns the root mount. Topcoat gets each path that Autumn does not route.
    #[must_use]
    pub const fn root() -> Self {
        Self(Repr::Root)
    }

    /// Returns a mount under `prefix`, for example `/app`.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] when `prefix` is not a valid prefix or is in a
    /// reserved namespace.
    pub fn prefix(prefix: &str) -> Result<Self, PathError> {
        let prefix = PathPrefix::new(prefix)?;
        if let Some((_, owner)) = RESERVED
            .iter()
            .find(|(reserved, _)| is_under(prefix.as_str(), reserved))
        {
            return Err(PathError::Reserved {
                path: prefix.as_str().to_owned(),
                owner,
            });
        }
        Ok(Self(Repr::Prefix(prefix)))
    }

    /// Returns `/` for the root mount, else the prefix.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Repr::Root => "/",
            Repr::Prefix(prefix) => prefix.as_str(),
        }
    }

    /// Returns `true` for the root mount.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        matches!(self.0, Repr::Root)
    }

    /// Returns the prefix, or `None` for the root mount.
    #[must_use]
    pub const fn as_prefix(&self) -> Option<&PathPrefix> {
        match &self.0 {
            Repr::Root => None,
            Repr::Prefix(prefix) => Some(prefix),
        }
    }

    /// Returns the axum route templates that the plugin registers, in order.
    #[must_use]
    pub fn templates(&self) -> Vec<String> {
        match &self.0 {
            Repr::Root => vec!["/".to_owned(), "/{*path}".to_owned()],
            Repr::Prefix(prefix) => {
                let p = prefix.as_str();
                vec![
                    p.to_owned(),
                    format!("{p}/"),
                    format!("{p}/{{*path}}"),
                    format!("{INTERNAL_PREFIX}/{{*path}}"),
                ]
            }
        }
    }

    /// Returns `true` if a request with the raw path `path` goes to Topcoat.
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        match &self.0 {
            Repr::Root => path.starts_with('/'),
            Repr::Prefix(prefix) => {
                is_under(path, prefix.as_str())
                    || path
                        .strip_prefix(INTERNAL_PREFIX)
                        .and_then(|rest| rest.strip_prefix('/'))
                        .is_some_and(|rest| !rest.is_empty())
            }
        }
    }
}

impl FromStr for MountPath {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "/" {
            Ok(Self::root())
        } else {
            Self::prefix(s)
        }
    }
}

impl TryFrom<&str> for MountPath {
    type Error = PathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for MountPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returns `true` if `path` is `prefix` or is under `prefix` at a segment boundary.
pub(crate) fn is_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Applies the prefix grammar. See the [`PathPrefix`] contract.
fn validate(prefix: &str) -> Result<(), PathError> {
    let owned = || prefix.to_owned();
    if prefix.is_empty() {
        return Err(PathError::Empty);
    }
    if prefix == "/" {
        return Err(PathError::Root);
    }
    let Some(rest) = prefix.strip_prefix('/') else {
        return Err(PathError::MissingLeadingSlash { path: owned() });
    };
    if rest.ends_with('/') {
        return Err(PathError::TrailingSlash { path: owned() });
    }
    let segments = || rest.split('/');
    if segments().any(str::is_empty) {
        return Err(PathError::EmptySegment { path: owned() });
    }
    if segments().any(|segment| segment == "." || segment == "..") {
        return Err(PathError::DotSegment { path: owned() });
    }
    if let Some(ch) = rest
        .chars()
        .find(|&c| c != '/' && !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')))
    {
        return Err(PathError::ForbiddenChar { path: owned(), ch });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---------- examples ----------

    #[test]
    fn prefix_accepts_simple_paths() {
        for ok in ["/api", "/a/b", "/v1.2", "/a-b_c~d", "/A9", "/..."] {
            let prefix = PathPrefix::new(ok).expect(ok);
            assert_eq!(prefix.as_str(), ok);
            assert_eq!(prefix.to_string(), ok);
        }
    }

    #[test]
    fn prefix_refuses_with_the_first_failed_rule() {
        let cases: &[(&str, PathError)] = &[
            ("", PathError::Empty),
            ("/", PathError::Root),
            ("api", PathError::MissingLeadingSlash { path: "api".into() }),
            (
                "/api/",
                PathError::TrailingSlash {
                    path: "/api/".into(),
                },
            ),
            (
                "/a//b/",
                PathError::TrailingSlash {
                    path: "/a//b/".into(),
                },
            ),
            (
                "/a//b",
                PathError::EmptySegment {
                    path: "/a//b".into(),
                },
            ),
            ("//a", PathError::EmptySegment { path: "//a".into() }),
            (
                "/a/./b",
                PathError::DotSegment {
                    path: "/a/./b".into(),
                },
            ),
            (
                "/a/..",
                PathError::DotSegment {
                    path: "/a/..".into(),
                },
            ),
            (
                "/a/{id}",
                PathError::ForbiddenChar {
                    path: "/a/{id}".into(),
                    ch: '{',
                },
            ),
            (
                "/:app",
                PathError::ForbiddenChar {
                    path: "/:app".into(),
                    ch: ':',
                },
            ),
            (
                "/*x",
                PathError::ForbiddenChar {
                    path: "/*x".into(),
                    ch: '*',
                },
            ),
            (
                "/a%2e",
                PathError::ForbiddenChar {
                    path: "/a%2e".into(),
                    ch: '%',
                },
            ),
            (
                "/a b",
                PathError::ForbiddenChar {
                    path: "/a b".into(),
                    ch: ' ',
                },
            ),
            (
                "/é",
                PathError::ForbiddenChar {
                    path: "/é".into(),
                    ch: 'é',
                },
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                PathPrefix::new(input).as_ref(),
                Err(expected),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn prefix_matches_at_segment_boundaries() {
        let api = PathPrefix::new("/api").unwrap();
        assert!(api.matches("/api"));
        assert!(api.matches("/api/"));
        assert!(api.matches("/api/x/y"));
        assert!(!api.matches("/apix"));
        assert!(!api.matches("/Api"));
        assert!(!api.matches("/"));
        assert!(!api.matches(""));
    }

    #[test]
    fn prefix_overlaps_internal_only_for_topcoat_namespace() {
        assert!(PathPrefix::new("/_topcoat").unwrap().overlaps_internal());
        assert!(
            PathPrefix::new("/_topcoat/assets")
                .unwrap()
                .overlaps_internal()
        );
        assert!(!PathPrefix::new("/_topcoatx").unwrap().overlaps_internal());
        assert!(!PathPrefix::new("/api").unwrap().overlaps_internal());
    }

    #[test]
    fn prefix_strictly_under() {
        let app = PathPrefix::new("/app").unwrap();
        assert!(PathPrefix::new("/app/api").unwrap().is_strictly_under(&app));
        assert!(!PathPrefix::new("/app").unwrap().is_strictly_under(&app));
        assert!(!PathPrefix::new("/apps/x").unwrap().is_strictly_under(&app));
    }

    #[test]
    fn mount_root_templates_and_str() {
        let root = MountPath::root();
        assert!(root.is_root());
        assert_eq!(root.as_str(), "/");
        assert_eq!(root.templates(), vec!["/", "/{*path}"]);
        assert_eq!(MountPath::default(), root);
        assert_eq!("/".parse::<MountPath>(), Ok(MountPath::root()));
        assert!(root.as_prefix().is_none());
    }

    #[test]
    fn mount_prefix_templates() {
        let app = MountPath::prefix("/app").unwrap();
        assert!(!app.is_root());
        assert_eq!(app.as_str(), "/app");
        assert_eq!(app.to_string(), "/app");
        assert_eq!(
            app.templates(),
            vec!["/app", "/app/", "/app/{*path}", "/_topcoat/{*path}"]
        );
        assert_eq!(app.as_prefix().map(PathPrefix::as_str), Some("/app"));
    }

    #[test]
    fn mount_refuses_reserved_namespaces() {
        for reserved in [
            "/static",
            "/static/x",
            "/_autumn",
            "/__autumn",
            "/_stories",
            "/actuator",
            "/actuator/health",
            "/health",
            "/live",
            "/ready",
            "/startup",
            "/openapi.json",
            "/swagger-ui",
            "/_topcoat",
            "/_topcoat/assets",
        ] {
            assert!(
                matches!(MountPath::prefix(reserved), Err(PathError::Reserved { .. })),
                "{reserved}"
            );
        }
        for allowed in ["/statics", "/healthz", "/app", "/_topcoatx"] {
            assert!(MountPath::prefix(allowed).is_ok(), "{allowed}");
        }
    }

    #[test]
    fn mount_covers_examples() {
        let root = MountPath::root();
        assert!(root.covers("/"));
        assert!(root.covers("/a/b"));
        assert!(!root.covers(""));
        assert!(!root.covers("a"));

        let app = MountPath::prefix("/app").unwrap();
        assert!(app.covers("/app"));
        assert!(app.covers("/app/"));
        assert!(app.covers("/app/x"));
        assert!(app.covers("/_topcoat/assets/a.js"));
        assert!(!app.covers("/apps"));
        assert!(!app.covers("/_topcoat"));
        assert!(!app.covers("/_topcoat/"));
        assert!(!app.covers("/"));
    }

    #[test]
    fn root_templates_conflict_with_root_capture_but_prefix_does_not() {
        let insert_all = |templates: &[String]| {
            let mut router = matchit::Router::new();
            router.insert("/{slug}", ()).unwrap();
            templates
                .iter()
                .try_for_each(|t| router.insert(t.as_str(), ()))
        };
        assert!(insert_all(&MountPath::root().templates()).is_err());
        assert!(insert_all(&MountPath::prefix("/app").unwrap().templates()).is_ok());
    }

    // ---------- properties ----------

    fn segment() -> impl Strategy<Value = String> {
        "[A-Za-z0-9._~-]{1,8}".prop_filter("dot segment", |s| s != "." && s != "..")
    }

    fn valid_prefix() -> impl Strategy<Value = String> {
        prop::collection::vec(segment(), 1..4)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    fn valid_mount() -> impl Strategy<Value = String> {
        valid_prefix().prop_filter("reserved", |p| {
            !RESERVED
                .iter()
                .any(|(r, _)| p == r || p.starts_with(&format!("{r}/")))
        })
    }

    /// An independent model of the prefix grammar.
    fn model_is_valid(s: &str) -> bool {
        let Some(rest) = s.strip_prefix('/') else {
            return false;
        };
        !rest.is_empty()
            && rest.split('/').all(|seg| {
                !seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
            })
    }

    fn raw_path() -> impl Strategy<Value = String> {
        let seg = prop_oneof![
            Just(String::new()),
            Just(".".to_owned()),
            Just("..".to_owned()),
            Just("app".to_owned()),
            Just("apix".to_owned()),
            Just("_topcoat".to_owned()),
            Just("assets".to_owned()),
            "[a-z%{}:*]{1,4}",
        ];
        (
            prop::collection::vec(seg, 0..5),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(segments, lead, trail)| {
                let mut path = if lead { "/".to_owned() } else { String::new() };
                path.push_str(&segments.join("/"));
                if trail {
                    path.push('/');
                }
                path
            })
    }

    proptest! {
        #[test]
        fn prefix_new_is_total(s in any::<String>()) {
            let _ = PathPrefix::new(&s);
            let _ = MountPath::prefix(&s);
        }

        #[test]
        fn prefix_new_agrees_with_model(s in prop_oneof![any::<String>(), valid_prefix(), "[/a-z.{}%:]{0,10}"]) {
            prop_assert_eq!(PathPrefix::new(&s).is_ok(), model_is_valid(&s));
        }

        #[test]
        fn prefix_round_trips(s in valid_prefix()) {
            let prefix = PathPrefix::new(&s).unwrap();
            prop_assert_eq!(PathPrefix::new(prefix.as_str()), Ok(prefix.clone()));
            prop_assert_eq!(prefix.to_string().parse::<PathPrefix>(), Ok(prefix));
        }

        #[test]
        fn prefix_matches_is_segment_prefix(p in valid_prefix(), path in raw_path(), extra in segment()) {
            let prefix = PathPrefix::new(&p).unwrap();
            let expected = path == p || path.starts_with(&format!("{p}/"));
            prop_assert_eq!(prefix.matches(&path), expected);
            // Boundary: a longer first segment never matches.
            let longer = format!("{p}{extra}");
            prop_assert!(!prefix.matches(&longer));
            // Upward closure.
            if prefix.matches(&path) {
                let deeper = format!("{path}/{extra}");
                prop_assert!(prefix.matches(&deeper));
            }
        }

        #[test]
        fn mount_round_trips(s in valid_mount()) {
            let mount = MountPath::prefix(&s).unwrap();
            prop_assert_eq!(mount.to_string().parse::<MountPath>(), Ok(mount.clone()));
            prop_assert_eq!(mount.as_str(), s.as_str());
        }

        #[test]
        fn covers_agrees_with_matchit(prefix in prop_oneof![Just(None), valid_mount().prop_map(Some)], path in raw_path()) {
            let mount = prefix.as_deref().map_or_else(MountPath::root, |p| MountPath::prefix(p).unwrap());
            let mut router = matchit::Router::new();
            for template in mount.templates() {
                router.insert(template, ()).unwrap();
            }
            prop_assert_eq!(mount.covers(&path), router.at(&path).is_ok(), "path {:?}", path);
        }

        #[test]
        fn templates_coexist_with_autumn_routes(prefix in valid_mount()) {
            let mount = MountPath::prefix(&prefix).unwrap();
            let mut router = matchit::Router::new();
            for fixed in ["/health", "/static", "/static/{*rest}", "/actuator/{name}", "/_autumn/jobs/{id}", "/{slug}"] {
                router.insert(fixed, ()).unwrap();
            }
            for template in mount.templates() {
                prop_assert!(router.insert(template.clone(), ()).is_ok(), "template {}", template);
            }
        }

        #[test]
        fn axum_accepts_the_templates(prefix in prop_oneof![Just(None), valid_mount().prop_map(Some)]) {
            let mount = prefix.as_deref().map_or_else(MountPath::root, |p| MountPath::prefix(p).unwrap());
            let result = std::panic::catch_unwind(|| {
                let mut router = axum::Router::<()>::new();
                for template in mount.templates() {
                    router = router.route(&template, axum::routing::any(|| async { "ok" }));
                }
                router
            });
            prop_assert!(result.is_ok());
        }
    }
}
