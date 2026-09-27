//! Error types.

use std::fmt;

/// A path prefix or mount path is not valid.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The path is empty.
    #[error("path is empty")]
    Empty,
    /// The path is `/`, which matches each path.
    #[error("`/` matches every path and cannot be a prefix")]
    Root,
    /// The path does not start with `/`.
    #[error("path {path:?} must start with '/'")]
    #[non_exhaustive]
    MissingLeadingSlash {
        /// The refused path.
        path: String,
    },
    /// The path ends with `/`.
    #[error("path {path:?} must not end with '/'")]
    #[non_exhaustive]
    TrailingSlash {
        /// The refused path.
        path: String,
    },
    /// The path has an empty segment (`//`).
    #[error("path {path:?} has an empty segment")]
    #[non_exhaustive]
    EmptySegment {
        /// The refused path.
        path: String,
    },
    /// The path has a `.` or `..` segment.
    #[error("path {path:?} has a '.' or '..' segment")]
    #[non_exhaustive]
    DotSegment {
        /// The refused path.
        path: String,
    },
    /// The path has a character that is not an ASCII letter, a digit, `-`, `.`, `_` or `~`.
    #[error("path {path:?} contains forbidden character {ch:?}")]
    #[non_exhaustive]
    ForbiddenChar {
        /// The refused path.
        path: String,
        /// The first forbidden character.
        ch: char,
    },
    /// The path is in a namespace that Autumn or Topcoat owns.
    #[error("path {path:?} is reserved by {owner}")]
    #[non_exhaustive]
    Reserved {
        /// The refused path.
        path: String,
        /// The owner of the namespace.
        owner: &'static str,
    },
}

/// One problem in the plugin configuration.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// No Topcoat router is set.
    #[error("no Topcoat router is set; call TopcoatPlugin::router or TopcoatPlugin::router_with")]
    NoRouter,
    /// The Topcoat router has no routes.
    #[error("the Topcoat router has no routes")]
    EmptyRouter,
    /// The mount path is not valid.
    #[error("invalid mount path {input:?}: {cause}")]
    #[non_exhaustive]
    InvalidMount {
        /// The input string.
        input: String,
        /// The cause.
        cause: PathError,
    },
    /// An excluded prefix is not valid.
    #[error("invalid excluded prefix {input:?}: {cause}")]
    #[non_exhaustive]
    InvalidExclude {
        /// The input string.
        input: String,
        /// The cause.
        cause: PathError,
    },
    /// A runtime prefix is not valid.
    #[error("invalid runtime prefix {input:?}: {cause}")]
    #[non_exhaustive]
    InvalidRuntimePrefix {
        /// The input string.
        input: String,
        /// The cause.
        cause: PathError,
    },
    /// An excluded prefix is not strictly inside the mount path.
    #[error("excluded prefix {prefix} must be strictly inside the mount {mount}")]
    #[non_exhaustive]
    ExcludedOutsideMount {
        /// The excluded prefix.
        prefix: String,
        /// The mount path.
        mount: String,
    },
    /// An excluded prefix overlaps the Topcoat namespace `/_topcoat`.
    #[error("excluded prefix {prefix} overlaps the Topcoat namespace /_topcoat")]
    #[non_exhaustive]
    ExcludedOverlapsInternal {
        /// The excluded prefix.
        prefix: String,
    },
    /// A runtime prefix is not inside the mount path.
    #[error("runtime prefix {prefix} must be inside the mount {mount}")]
    #[non_exhaustive]
    RuntimePrefixOutsideMount {
        /// The runtime prefix.
        prefix: String,
        /// The mount path.
        mount: String,
    },
    /// A runtime prefix is under an excluded prefix.
    #[error("runtime prefix {prefix} is under the excluded prefix {excluded}")]
    #[non_exhaustive]
    RuntimePrefixExcluded {
        /// The runtime prefix.
        prefix: String,
        /// The excluded prefix.
        excluded: String,
    },
}

/// All problems in the plugin configuration.
///
/// [`TopcoatPlugin::validate`](crate::TopcoatPlugin::validate) returns this
/// value. The list is never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors(pub(crate) Vec<ConfigError>);

impl ConfigErrors {
    /// Returns the problems in the order the plugin found them.
    #[must_use]
    pub const fn as_slice(&self) -> &[ConfigError] {
        self.0.as_slice()
    }

    /// Returns an iterator over the problems.
    pub fn iter(&self) -> std::slice::Iter<'_, ConfigError> {
        self.0.iter()
    }

    /// Returns the number of problems.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the list has no problem. A value from the plugin is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl IntoIterator for ConfigErrors {
    type Item = ConfigError;
    type IntoIter = std::vec::IntoIter<ConfigError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a ConfigErrors {
    type Item = &'a ConfigError;
    type IntoIter = std::slice::Iter<'a, ConfigError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// An error that stops the startup of the app.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupError {
    /// The plugin configuration is not valid.
    #[error("invalid TopcoatPlugin configuration: {0}")]
    Config(ConfigErrors),
    /// The router closure returned an error or panicked.
    #[error("the Topcoat router factory failed: {message}")]
    #[non_exhaustive]
    Factory {
        /// The error text.
        message: String,
    },
    /// `RouterBuilder::build` panicked.
    #[error("the Topcoat RouterBuilder::build panicked: {message}")]
    #[non_exhaustive]
    RouterBuild {
        /// The panic text.
        message: String,
    },
    /// The Content-Security-Policy blocks Topcoat and the check is `Deny`.
    #[error("CspDenied: the Content-Security-Policy blocks Topcoat ({findings}); {advice}")]
    #[non_exhaustive]
    CspDenied {
        /// The problems, separated by commas.
        findings: String,
        /// What to change.
        advice: String,
    },
}

/// A page cannot get Autumn app data.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppDataError {
    /// The page is not served by this plugin.
    #[error("this render is not served by autumn-plugin-topcoat")]
    NotMounted,
    /// `AppState` has no extension of this type.
    #[error("AppState has no extension of type {type_name}")]
    #[non_exhaustive]
    MissingExtension {
        /// The type name.
        type_name: &'static str,
    },
}

/// A page cannot get Autumn request data.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestScopeError {
    /// No Autumn HTTP request backs this render, for example a WebSocket render.
    #[error("no Autumn HTTP request backs this render")]
    Detached,
    /// The value is not on this request.
    #[error("{what} is not available on this request")]
    #[non_exhaustive]
    Unavailable {
        /// The name of the value.
        what: &'static str,
    },
}
