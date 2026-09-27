//! Autumn plugin for Topcoat: Autumn serves the backend, Topcoat renders the frontend.

// Items in private modules use `pub(crate)` to show that they stay in the crate.
#![allow(clippy::redundant_pub_crate)]

mod csrf;
mod diagnostics;
mod error;
mod fallthrough;
mod finalize;
mod handler;
mod ingress;
mod options;
mod origin;
mod path;
mod plan;
mod plugin;
mod routes;
mod tagger;

pub mod autumn;
pub mod csp;

pub use crate::diagnostics::{BridgeStatus, TopcoatDiagnostics};
pub use crate::error::{
    BridgeError, ConfigError, ConfigErrors, PathError, RequestScopeError, StartupError,
};
pub use crate::options::{CspCheck, CsrfBridge, NotFoundOwner};
pub use crate::path::{INTERNAL_PREFIX, MountPath, PathPrefix};
pub use crate::plugin::{PLUGIN_NAME, TopcoatPlugin};
