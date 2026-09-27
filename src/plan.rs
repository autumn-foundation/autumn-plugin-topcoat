//! The pure build plan: it validates the plugin options.
//!
//! # Contract
//!
//! `plan(input)` returns `Ok` if and only if the input has no problem. Else it
//! returns each problem once, in this order:
//!
//! 1. `NoRouter` when no router is set, `EmptyRouter` when the builder has no
//!    routes.
//! 2. `InvalidMount` when the mount string is not a valid [`MountPath`].
//!    The string `/` is the root mount.
//! 3. `InvalidExclude` and `InvalidRuntimePrefix` for each invalid prefix
//!    string, in input order.
//! 4. For each valid excluded prefix `e`: `ExcludedOverlapsInternal` when `e`
//!    is `/_topcoat` or under it; `ExcludedOutsideMount` when the mount is a
//!    prefix `P` and `e` is not strictly under `P`.
//! 5. For each valid runtime prefix `r`: `RuntimePrefixOutsideMount` when the
//!    mount is a prefix `P` and `r` is not `P`, not under `P` and not under
//!    `/_topcoat`; `RuntimePrefixExcluded` for each excluded prefix that matches `r`.
//!
//! Duplicate prefix strings count once. The root mount never gives an
//! `*OutsideMount` problem. `register_ingress` is `true` if and only if the
//! CSRF bridge is not `Off`.

use crate::error::{ConfigError, ConfigErrors};
use crate::options::CsrfBridge;
use crate::path::{MountPath, PathPrefix};

/// What the plugin knows about the router when it builds the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouterPresence {
    /// No router is set.
    Missing,
    /// A builder with no routes is set.
    Empty,
    /// A builder with routes is set.
    Present,
    /// A closure makes the builder at startup.
    Factory,
}

/// The input of [`plan`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct PlanInput<'a> {
    pub(crate) mount: Option<&'a str>,
    pub(crate) excluded: &'a [String],
    pub(crate) runtime_prefixes: &'a [String],
    pub(crate) router: RouterPresence,
    pub(crate) csrf_bridge: CsrfBridge,
}

/// A valid plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) mount: MountPath,
    pub(crate) templates: Vec<String>,
    pub(crate) excluded: Vec<PathPrefix>,
    pub(crate) runtime_prefixes: Vec<PathPrefix>,
    pub(crate) register_ingress: bool,
}

/// Validates the plugin options.
pub(crate) fn plan(input: &PlanInput<'_>) -> Result<Plan, ConfigErrors> {
    let mut errors = Vec::new();
    match input.router {
        RouterPresence::Missing => errors.push(ConfigError::NoRouter),
        RouterPresence::Empty => errors.push(ConfigError::EmptyRouter),
        RouterPresence::Present | RouterPresence::Factory => {}
    }

    let mount = match input.mount.map(str::parse::<MountPath>).transpose() {
        Ok(mount) => Some(mount.unwrap_or_default()),
        Err(source) => {
            errors.push(ConfigError::InvalidMount {
                input: input.mount.unwrap_or_default().to_owned(),
                cause: source,
            });
            None
        }
    };

    let excluded = parse_prefixes(input.excluded, &mut errors, |input, cause| {
        ConfigError::InvalidExclude { input, cause }
    });
    let runtime_prefixes = parse_prefixes(input.runtime_prefixes, &mut errors, |input, cause| {
        ConfigError::InvalidRuntimePrefix { input, cause }
    });

    let mount_prefix = mount.as_ref().and_then(MountPath::as_prefix);
    for prefix in &excluded {
        if prefix.overlaps_internal() {
            errors.push(ConfigError::ExcludedOverlapsInternal {
                prefix: prefix.to_string(),
            });
        }
        if let Some(parent) = mount_prefix
            && !prefix.is_strictly_under(parent)
        {
            errors.push(ConfigError::ExcludedOutsideMount {
                prefix: prefix.to_string(),
                mount: parent.to_string(),
            });
        }
    }
    for prefix in &runtime_prefixes {
        if let Some(parent) = mount_prefix
            && !parent.matches(prefix.as_str())
            && !prefix.overlaps_internal()
        {
            errors.push(ConfigError::RuntimePrefixOutsideMount {
                prefix: prefix.to_string(),
                mount: parent.to_string(),
            });
        }
        for excluded in excluded.iter().filter(|e| e.matches(prefix.as_str())) {
            errors.push(ConfigError::RuntimePrefixExcluded {
                prefix: prefix.to_string(),
                excluded: excluded.to_string(),
            });
        }
    }

    match mount {
        Some(mount) if errors.is_empty() => Ok(Plan {
            templates: mount.templates(),
            mount,
            excluded,
            runtime_prefixes,
            register_ingress: input.csrf_bridge != CsrfBridge::Off,
        }),
        _ => Err(ConfigErrors(errors)),
    }
}

/// Parses each distinct prefix string once. It records each invalid string.
fn parse_prefixes(
    inputs: &[String],
    errors: &mut Vec<ConfigError>,
    invalid: impl Fn(String, crate::error::PathError) -> ConfigError,
) -> Vec<PathPrefix> {
    let mut seen: Vec<&str> = Vec::new();
    let mut prefixes = Vec::new();
    for input in inputs {
        if seen.contains(&input.as_str()) {
            continue;
        }
        seen.push(input);
        match PathPrefix::new(input) {
            Ok(prefix) => prefixes.push(prefix),
            Err(source) => errors.push(invalid(input.clone(), source)),
        }
    }
    prefixes
}

#[cfg(test)]
mod tests;
