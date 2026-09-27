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

    let mount = match input.mount.map(MountPath::prefix).transpose() {
        Ok(mount) => Some(mount.unwrap_or_default()),
        Err(source) => {
            errors.push(ConfigError::InvalidMount {
                input: input.mount.unwrap_or_default().to_owned(),
                source,
            });
            None
        }
    };

    let excluded = parse_prefixes(input.excluded, &mut errors, |input, source| {
        ConfigError::InvalidExclude { input, source }
    });
    let runtime_prefixes = parse_prefixes(input.runtime_prefixes, &mut errors, |input, source| {
        ConfigError::InvalidRuntimePrefix { input, source }
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
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn input<'a>(
        mount: Option<&'a str>,
        excluded: &'a [String],
        runtime: &'a [String],
    ) -> PlanInput<'a> {
        PlanInput {
            mount,
            excluded,
            runtime_prefixes: runtime,
            router: RouterPresence::Present,
            csrf_bridge: CsrfBridge::SameOriginRuntime,
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn root_plan_defaults() {
        let plan = plan(&input(None, &[], &[])).unwrap();
        assert!(plan.mount.is_root());
        assert_eq!(plan.templates, vec!["/", "/{*path}"]);
        assert!(plan.register_ingress);
        assert!(plan.excluded.is_empty());
    }

    #[test]
    fn prefix_plan_with_prefixes() {
        let excluded = strings(&["/app/api", "/app/api"]);
        let runtime = strings(&["/app/rpc", "/_topcoat/runtime/x"]);
        let plan = plan(&input(Some("/app"), &excluded, &runtime)).unwrap();
        assert_eq!(plan.mount.as_str(), "/app");
        assert_eq!(plan.templates.len(), 4);
        assert_eq!(plan.excluded.len(), 1, "duplicates count once");
        assert_eq!(plan.runtime_prefixes.len(), 2);
    }

    #[test]
    fn bridge_off_registers_no_ingress() {
        let mut i = input(None, &[], &[]);
        i.csrf_bridge = CsrfBridge::Off;
        assert!(!plan(&i).unwrap().register_ingress);
    }

    #[test]
    fn collects_every_problem_in_order() {
        let excluded = strings(&["/app", "bad", "/_topcoat/x", "/other"]);
        let runtime = strings(&["/rpc", "/app/api/rpc", "/:x"]);
        let mut i = input(Some("/app"), &excluded, &runtime);
        i.router = RouterPresence::Missing;
        let errors = plan(&i).unwrap_err();
        let kinds: Vec<&str> = errors
            .0
            .iter()
            .map(|e| match e {
                ConfigError::NoRouter => "NoRouter",
                ConfigError::EmptyRouter => "EmptyRouter",
                ConfigError::InvalidMount { .. } => "InvalidMount",
                ConfigError::InvalidExclude { .. } => "InvalidExclude",
                ConfigError::InvalidRuntimePrefix { .. } => "InvalidRuntimePrefix",
                ConfigError::ExcludedOutsideMount { .. } => "ExcludedOutsideMount",
                ConfigError::ExcludedOverlapsInternal { .. } => "ExcludedOverlapsInternal",
                ConfigError::RuntimePrefixOutsideMount { .. } => "RuntimePrefixOutsideMount",
                ConfigError::RuntimePrefixExcluded { .. } => "RuntimePrefixExcluded",
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                "NoRouter",
                "InvalidExclude",
                "InvalidRuntimePrefix",
                "ExcludedOutsideMount",
                "ExcludedOverlapsInternal",
                "ExcludedOutsideMount",
                "ExcludedOutsideMount",
                "RuntimePrefixOutsideMount",
                "RuntimePrefixExcluded",
            ]
        );
        assert!(errors.to_string().contains("; "));
    }

    #[test]
    fn invalid_mount_and_empty_router() {
        let mut i = input(Some("/static"), &[], &[]);
        i.router = RouterPresence::Empty;
        let errors = plan(&i).unwrap_err();
        assert!(matches!(errors.0[0], ConfigError::EmptyRouter));
        assert!(matches!(errors.0[1], ConfigError::InvalidMount { .. }));
        assert_eq!(errors.0.len(), 2);
    }

    #[test]
    fn runtime_prefix_under_excluded_prefix() {
        let excluded = strings(&["/api"]);
        let runtime = strings(&["/api/rpc"]);
        let errors = plan(&input(None, &excluded, &runtime)).unwrap_err();
        assert_eq!(
            errors.0,
            vec![ConfigError::RuntimePrefixExcluded {
                prefix: "/api/rpc".into(),
                excluded: "/api".into()
            }]
        );
    }

    #[test]
    fn factory_presence_is_valid() {
        let mut i = input(None, &[], &[]);
        i.router = RouterPresence::Factory;
        assert!(plan(&i).is_ok());
    }

    fn prefix_string() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "/api",
            "/app/api",
            "/app",
            "/_topcoat",
            "/_topcoat/x",
            "/rpc",
            "/app/rpc",
            "bad",
            "/a/",
            "/x/y",
        ])
        .prop_map(str::to_owned)
    }

    fn error_set(result: &Result<Plan, ConfigErrors>) -> Vec<String> {
        let mut set: Vec<String> = result
            .as_ref()
            .err()
            .map(|e| e.0.iter().map(ToString::to_string).collect())
            .unwrap_or_default();
        set.sort();
        set
    }

    proptest! {
        #[test]
        fn errors_do_not_depend_on_order(
            mount in prop::option::of(prop::sample::select(vec!["/app", "/x"])),
            excluded in prop::collection::vec(prefix_string(), 0..4),
            runtime in prop::collection::vec(prefix_string(), 0..4),
        ) {
            let mut reversed_excluded = excluded.clone();
            reversed_excluded.reverse();
            let mut reversed_runtime = runtime.clone();
            reversed_runtime.reverse();
            let a = plan(&input(mount, &excluded, &runtime));
            let b = plan(&input(mount, &reversed_excluded, &reversed_runtime));
            prop_assert_eq!(error_set(&a), error_set(&b));
        }

        #[test]
        fn root_mount_never_reports_outside_mount(
            excluded in prop::collection::vec(prefix_string(), 0..4),
            runtime in prop::collection::vec(prefix_string(), 0..4),
        ) {
            if let Err(errors) = plan(&input(None, &excluded, &runtime)) {
                for error in errors.0 {
                    let outside = matches!(error, ConfigError::ExcludedOutsideMount { .. } | ConfigError::RuntimePrefixOutsideMount { .. });
                    prop_assert!(!outside);
                }
            }
        }

        #[test]
        fn more_prefixes_never_remove_errors(
            mount in prop::option::of(prop::sample::select(vec!["/app", "/x"])),
            excluded in prop::collection::vec(prefix_string(), 0..3),
            extra in prefix_string(),
        ) {
            let before = error_set(&plan(&input(mount, &excluded, &[])));
            let mut more = excluded;
            more.push(extra);
            let after = error_set(&plan(&input(mount, &more, &[])));
            for error in before {
                prop_assert!(after.contains(&error), "lost {}", error);
            }
        }
    }
}
