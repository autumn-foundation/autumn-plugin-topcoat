//! Tests for the `plan` module.

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
