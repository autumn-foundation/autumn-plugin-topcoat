//! Startup work: build the Topcoat router and check the Autumn config.
//!
//! Finalize runs as an Autumn state initializer, so `AppState` exists and
//! Autumn has not built its router yet.

use autumn_web::AppState;

use crate::plugin::{RouterSource, Shared};

/// Builds the router, reads the CSRF names, checks the CSP and stores the
/// diagnostics.
///
/// # Contract
///
/// - A panic or an error in the closure or in `build()` becomes a recorded
///   [`StartupError`](crate::StartupError). No panic leaves this function.
/// - The router gets `AppState` in its app context, and the tagger when Autumn
///   owns 404.
/// - With `CspCheck::Deny`, a CSP finding is a recorded `CspDenied` error.
/// - The function stores one `TopcoatDiagnostics` extension and writes one
///   `info` event.
pub(crate) fn finalize(shared: &Shared, source: RouterSource, state: &AppState) {
    let _ = (shared, source, state);
    unimplemented!("RED")
}
