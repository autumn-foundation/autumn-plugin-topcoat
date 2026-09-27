//! Options that change how the plugin behaves.

/// Sets how the plugin helps Topcoat runtime requests pass Autumn CSRF.
///
/// The Topcoat runtime sends JSON `POST` requests without the Autumn CSRF
/// header. With [`CsrfBridge::SameOriginRuntime`], the plugin copies the CSRF
/// cookie into the CSRF header for same-origin runtime requests only. The
/// crate docs give the full rule list.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CsrfBridge {
    /// Copy the CSRF cookie into the CSRF header for same-origin runtime
    /// requests.
    ///
    /// When Autumn CSRF is off, the layer changes no request. It stays in the
    /// stack and adds a small cost to each request. Use `Off` to remove it.
    #[default]
    SameOriginRuntime,
    /// Never change requests. Autumn CSRF rejects runtime `POST` requests.
    Off,
}

/// Sets what the plugin does when the Content-Security-Policy blocks Topcoat.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CspCheck {
    /// Do not analyze the policy.
    Off,
    /// Write one warning for each problem. The warning gives a policy that
    /// fixes it, when the plugin can make one.
    #[default]
    Warn,
    /// Stop the startup when the policy blocks Topcoat.
    Deny,
}

/// Sets which framework answers a path that Topcoat does not know.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum NotFoundOwner {
    /// Autumn answers: an HTML error page or Problem Details JSON.
    #[default]
    Autumn,
    /// Topcoat answers with its own 404 response.
    Topcoat,
}
