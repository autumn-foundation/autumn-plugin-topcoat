//! Startup work: build the Topcoat router and check the Autumn config.
//!
//! Finalize runs as an Autumn state initializer, so `AppState` exists and
//! Autumn has not built its router yet.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

use autumn_web::config::AutumnConfig;
use autumn_web::{AppState, ProcessRole};
use http::HeaderName;
use topcoat::router::{Router, RouterBuilder};

use crate::autumn::AutumnApp;
use crate::csp::{self, CspReport, PatchBlocker};
use crate::diagnostics::{CsrfBridgeStatus, TopcoatDiagnostics};
use crate::error::{ConfigError, ConfigErrors, StartupError};
use crate::ingress::IngressSettings;
use crate::options::{CspCheck, NotFoundOwner};
use crate::plugin::{RouterSource, Shared, TRACING_TARGET};
use crate::tagger::UnmatchedTagger;

/// The CSRF header that Autumn uses when the configured name is not valid.
const DEFAULT_TOKEN_HEADER: &str = "x-csrf-token";

/// The variable that makes an Autumn binary run one task and exit.
/// `autumn task` sets it.
const TASK_ENV: &str = "AUTUMN_RUN_TASK";

/// Builds the router, reads the CSRF names, checks the CSP and stores the
/// diagnostics.
///
/// # Contract
///
/// - A panic or an error in the closure or in `build()` becomes a recorded
///   [`StartupError`]. No panic leaves this function.
/// - The router gets `AppState` in its app context, and the tagger when Autumn
///   owns 404.
/// - With `CspCheck::Deny`, a CSP finding is a recorded `CspDenied` error.
/// - A process that serves no HTTP does not call the closure, does not build
///   the router and does not check the CSP. A worker role and a one-off task
///   run (`AUTUMN_RUN_TASK`) serve no HTTP.
/// - The function records all startup errors once, and writes one `error`
///   event for each error.
/// - The function stores one `TopcoatDiagnostics` extension. It writes one
///   `info` event only after a good startup.
pub(crate) fn finalize(shared: &Shared, source: RouterSource, state: &AppState) {
    let config = state.config_arc();
    let task = std::env::var(TASK_ENV).ok();
    let serves_http = serves_http(state.role(), task.as_deref());
    let mut failures = Vec::new();

    if serves_http {
        match build_router(source, state, shared.not_found) {
            Ok(router) => {
                let _ = shared.router.set(router);
            }
            Err(error) => failures.push(error),
        }
    }

    let csrf_bridge = if !shared.plan.register_ingress {
        CsrfBridgeStatus::Off
    } else if let Some(settings) = ingress_settings(&config) {
        let status = CsrfBridgeStatus::Active {
            cookie: settings.cookie_name.clone(),
            header: settings.token_header.as_str().to_owned(),
        };
        let _ = shared.ingress.set(settings);
        status
    } else {
        CsrfBridgeStatus::InertCsrfDisabled
    };

    let (csp, csp_suggestion, denied) = if serves_http {
        check_csp(shared.csp_check, &config)
    } else {
        (None, None, None)
    };
    failures.extend(denied);

    let idempotency_fail_closed =
        shared.plan.register_ingress && config.idempotency.enabled == Some(true);
    if idempotency_fail_closed {
        tracing::warn!(
            target: TRACING_TARGET,
            "the Topcoat ingress layer makes Autumn idempotent replay fail closed; \
             use TopcoatPlugin::csrf_bridge(CsrfBridge::Off) to remove the layer"
        );
    }

    let diagnostics = TopcoatDiagnostics {
        mount: shared.plan.mount.clone(),
        templates: shared.plan.templates.clone(),
        excluded: shared.plan.excluded.clone(),
        runtime_prefixes: shared.plan.runtime_prefixes.clone(),
        csrf_bridge,
        csp,
        csp_suggestion,
        not_found: shared.not_found,
        idempotency_fail_closed,
        serves_http,
        startup_error: failures.first().cloned(),
    };
    if failures.is_empty() {
        tracing::info!(
            target: TRACING_TARGET,
            mount = %diagnostics.mount,
            templates = ?diagnostics.templates,
            excluded = ?diagnostics.excluded,
            csrf_bridge = ?diagnostics.csrf_bridge,
            csp_findings = ?diagnostics.csp.as_ref().map(|report| &report.findings),
            not_found = ?diagnostics.not_found,
            serves_http,
            "Topcoat mounted in Autumn"
        );
    }
    for error in &failures {
        tracing::error!(target: TRACING_TARGET, %error, "Topcoat failed to start");
    }
    let _ = shared.failures.set(failures);
    state.insert_extension(diagnostics);
}

/// Returns `true` if this process serves HTTP.
///
/// A worker role serves no HTTP. A one-off task run keeps its role, but it
/// serves no HTTP either. Autumn starts a task run when the task variable is
/// not blank.
fn serves_http(role: ProcessRole, task: Option<&str>) -> bool {
    role.serves_http() && task.is_none_or(|name| name.trim().is_empty())
}

/// Makes the builder, adds the Autumn parts and builds the router.
fn build_router(
    source: RouterSource,
    state: &AppState,
    not_found: NotFoundOwner,
) -> Result<Router, StartupError> {
    let builder = match source {
        RouterSource::Builder(builder) => *builder,
        RouterSource::Factory(factory) => match catch_unwind(AssertUnwindSafe(|| factory(state))) {
            Ok(Ok(builder)) => builder,
            Ok(Err(message)) => return Err(StartupError::Factory { message }),
            Err(payload) => {
                return Err(StartupError::Factory {
                    message: panic_text(payload.as_ref()),
                });
            }
        },
    };
    if builder.is_empty() {
        return Err(StartupError::Config(ConfigErrors(vec![
            ConfigError::EmptyRouter,
        ])));
    }
    let builder = add_autumn_parts(builder, state, not_found);
    catch_unwind(AssertUnwindSafe(|| builder.build())).map_err(|payload| {
        StartupError::RouterBuild {
            message: format!(
                "RouterBuilder::build panicked: {}",
                panic_text(payload.as_ref())
            ),
        }
    })
}

/// Adds `AppState` to the app context and, when Autumn owns 404, the tagger.
fn add_autumn_parts(
    builder: RouterBuilder,
    state: &AppState,
    not_found: NotFoundOwner,
) -> RouterBuilder {
    let builder = builder.app_context(AutumnApp(state.clone()));
    match not_found {
        NotFoundOwner::Autumn => builder.layer(UnmatchedTagger),
        NotFoundOwner::Topcoat => builder,
    }
}

/// Returns the CSRF names when Autumn CSRF is on.
fn ingress_settings(config: &AutumnConfig) -> Option<IngressSettings> {
    let csrf = &config.security.csrf;
    csrf.enabled.then(|| IngressSettings {
        cookie_name: csrf.cookie_name.clone(),
        token_header: HeaderName::from_bytes(csrf.token_header.as_bytes())
            .unwrap_or_else(|_| HeaderName::from_static(DEFAULT_TOKEN_HEADER)),
    })
}

/// The result of the CSP check: the report, the suggested policy and the
/// `Deny` error.
type CspOutcome = (Option<CspReport>, Option<String>, Option<StartupError>);

/// Runs the CSP check. It writes the warnings and returns a `Deny` error.
fn check_csp(check: CspCheck, config: &AutumnConfig) -> CspOutcome {
    if check == CspCheck::Off {
        return (None, None, None);
    }
    let policy = csp::effective_policy(&config.security.headers);
    if policy.is_empty()
        && !config
            .security
            .headers
            .content_security_policy
            .trim()
            .is_empty()
    {
        tracing::warn!(
            target: TRACING_TARGET,
            "Autumn sends no Content-Security-Policy header, because the configured \
             policy is not a valid header value"
        );
    }
    let report = csp::analyze(&policy);
    if report.is_clean() {
        return (Some(report), None, None);
    }
    let patched = csp::patch(&policy);
    let suggestion = patched.blockers.is_empty().then_some(patched.policy);
    let advice = suggestion.as_ref().map_or_else(
        || blocker_advice(&patched.blockers),
        |policy| format!("set security.headers.content_security_policy = \"{policy}\""),
    );
    for finding in &report.findings {
        tracing::warn!(
            target: TRACING_TARGET,
            finding = %finding,
            advice = %advice,
            "the Content-Security-Policy blocks Topcoat"
        );
    }
    let denied = (check == CspCheck::Deny).then(|| {
        let findings: Vec<String> = report.findings.iter().map(ToString::to_string).collect();
        StartupError::CspDenied {
            findings: findings.join(", "),
            advice,
        }
    });
    (Some(report), suggestion, denied)
}

/// Returns the advice when the patch cannot fix the policy.
fn blocker_advice(blockers: &[PatchBlocker]) -> String {
    let names: Vec<&str> = blockers
        .iter()
        .map(|blocker| match blocker {
            PatchBlocker::StrictDynamic => "'strict-dynamic'",
            PatchBlocker::NonceOrHash => "nonce or hash sources (or security.headers.csp_nonce)",
            PatchBlocker::TrustedTypes => "require-trusted-types-for 'script'",
            PatchBlocker::Sandbox => "the sandbox directive",
        })
        .collect();
    format!(
        "remove {} from the policy, then add 'unsafe-inline' and 'unsafe-eval' to script-src",
        names.join(" and ")
    )
}

/// Returns the text of a panic payload.
fn panic_text(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with no text".to_owned())
}

#[cfg(test)]
mod tests;
