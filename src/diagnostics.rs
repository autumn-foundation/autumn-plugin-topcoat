//! Startup facts about the plugin.

use crate::csp::CspReport;
use crate::options::NotFoundOwner;
use crate::path::{MountPath, PathPrefix};

/// What the plugin did at startup.
///
/// The plugin writes these facts as one `info` event with the target
/// `autumn_plugin_topcoat`. It also stores them as an `AppState` extension:
///
/// ```rust,no_run
/// # fn show(state: &autumn_web::AppState) {
/// use autumn_plugin_topcoat::TopcoatDiagnostics;
///
/// if let Some(diagnostics) = state.extension::<TopcoatDiagnostics>() {
///     println!("Topcoat routes: {:?}", diagnostics.templates);
/// }
/// # }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopcoatDiagnostics {
    /// The mount path.
    pub mount: MountPath,
    /// The axum route templates that the plugin registered.
    pub templates: Vec<String>,
    /// The excluded prefixes.
    pub excluded: Vec<PathPrefix>,
    /// The runtime prefixes.
    pub runtime_prefixes: Vec<PathPrefix>,
    /// The state of the CSRF bridge.
    pub csrf_bridge: CsrfBridgeStatus,
    /// The CSP analysis, or `None` when the check is `Off`.
    pub csp: Option<CspReport>,
    /// A policy that fixes the CSP findings, when the plugin can make one.
    pub csp_suggestion: Option<String>,
    /// The framework that answers unknown paths.
    pub not_found: NotFoundOwner,
    /// `true` when the ingress layer makes Autumn idempotent replay fail closed.
    pub idempotency_fail_closed: bool,
}

/// The state of the CSRF bridge at startup.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsrfBridgeStatus {
    /// The bridge copies the cookie `cookie` into the header `header`.
    #[non_exhaustive]
    Active {
        /// The CSRF cookie name.
        cookie: String,
        /// The CSRF header name, in lowercase.
        header: String,
    },
    /// The bridge is registered, but Autumn CSRF is off, so it does nothing.
    InertCsrfDisabled,
    /// The bridge is off. The plugin registered no ingress layer.
    Off,
}
