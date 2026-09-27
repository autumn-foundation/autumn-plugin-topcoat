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
///   true:
///   - `s` starts with `/`, is not `/` and does not end with `/`.
///   - No segment is empty, `.` or `..`.
///   - Each character is an ASCII letter, a digit, `-`, `.`, `_` or `~`.
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

    /// Returns `true` if one of the plugin route templates matches the raw
    /// path `path`. Autumn routes and excluded prefixes can still take the
    /// request.
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
mod tests;
