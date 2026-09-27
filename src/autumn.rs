//! Autumn data for Topcoat pages.
//!
//! Use these functions in Topcoat pages, components and routes that the
//! plugin serves.
//!
//! - App data ([`state`], [`config`], [`extension`]) comes from the Topcoat
//!   app context. It is available in each render, also in WebSocket renders.
//! - Request data ([`csrf_token`], [`session`]) comes from the Autumn HTTP
//!   request. A WebSocket render has no Autumn HTTP request, so these
//!   functions return [`RequestScopeError::Detached`] there.
//!
//! ```rust,no_run
//! use autumn_plugin_topcoat::autumn;
//! use topcoat::{Result, context::Cx, router::page, view::{View, view}};
//!
//! #[page("/profile")]
//! async fn profile(cx: &Cx) -> Result<impl View> {
//!     let profile = autumn::config(cx)?.profile.clone().unwrap_or_default();
//!     Ok(view! { <p>"Profile: " (profile)</p> })
//! }
//! ```

use std::any::Any;
use std::sync::Arc;

use autumn_web::AppState;
use autumn_web::config::AutumnConfig;
use autumn_web::security::{CsrfFormField, CsrfToken, CsrfTokenHeader};
use autumn_web::session::Session;
use topcoat::context::{Cx, try_app_context, try_request_context};

use crate::error::{BridgeError, RequestScopeError};

/// The Autumn state in the Topcoat app context.
#[derive(Clone)]
pub(crate) struct AutumnApp(pub(crate) AppState);

/// A marker in the request extensions: this plugin forwarded the request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServedByAutumn;

/// The Autumn CSRF values for a plain HTML form or a custom `fetch` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfTokenInfo {
    /// The token value.
    pub token: String,
    /// The header name for the token, in lowercase, for example `x-csrf-token`.
    pub header: String,
    /// The form field name for the token, for example `_csrf`.
    pub field: String,
}

/// Returns the Autumn [`AppState`].
///
/// # Errors
///
/// Returns [`BridgeError::NotMounted`] if this plugin does not serve the render.
pub fn state(cx: &Cx) -> Result<&AppState, BridgeError> {
    try_app_context::<AutumnApp>(cx)
        .map(|app| &app.0)
        .ok_or(BridgeError::NotMounted)
}

/// Returns the Autumn config. The value is current at the time of the call.
///
/// # Errors
///
/// Returns [`BridgeError::NotMounted`] if this plugin does not serve the render.
pub fn config(cx: &Cx) -> Result<Arc<AutumnConfig>, BridgeError> {
    Ok(state(cx)?.config_arc())
}

/// Returns the `AppState` extension of type `T`.
///
/// # Errors
///
/// Returns [`BridgeError::NotMounted`] if this plugin does not serve the
/// render, or [`BridgeError::MissingExtension`] if `AppState` has no `T`.
pub fn extension<T: Any + Send + Sync>(cx: &Cx) -> Result<Arc<T>, BridgeError> {
    state(cx)?
        .extension::<T>()
        .ok_or_else(|| BridgeError::MissingExtension {
            type_name: std::any::type_name::<T>(),
        })
}

/// Returns the Autumn CSRF values of this HTTP request.
///
/// Put the token in plain HTML forms as the hidden field `field`. The CSRF
/// bridge covers only JSON runtime requests.
///
/// # Errors
///
/// Returns [`RequestScopeError::Detached`] in a WebSocket render, or
/// [`RequestScopeError::Unavailable`] when Autumn CSRF is off.
pub fn csrf_token(cx: &Cx) -> Result<CsrfTokenInfo, RequestScopeError> {
    let extensions = request_extensions(cx)?;
    let token = extensions
        .get::<CsrfToken>()
        .ok_or(RequestScopeError::Unavailable {
            what: "the Autumn CSRF token",
        })?;
    Ok(CsrfTokenInfo {
        token: token.token().to_owned(),
        header: extensions
            .get::<CsrfTokenHeader>()
            .map_or_else(|| "x-csrf-token".to_owned(), |header| header.0.clone()),
        field: extensions
            .get::<CsrfFormField>()
            .map_or_else(|| "_csrf".to_owned(), |field| field.0.clone()),
    })
}

/// Returns the Autumn session of this HTTP request.
///
/// Autumn saves the session when it sends the response head. Write to the
/// session before the first streamed chunk, or the change does not persist.
///
/// # Errors
///
/// Returns [`RequestScopeError::Detached`] in a WebSocket render, or
/// [`RequestScopeError::Unavailable`] when the request has no session.
pub fn session(cx: &Cx) -> Result<Session, RequestScopeError> {
    request_extensions(cx)?
        .get::<Session>()
        .cloned()
        .ok_or(RequestScopeError::Unavailable {
            what: "the Autumn session",
        })
}

/// Returns the request extensions of a render that this plugin forwarded.
fn request_extensions(cx: &Cx) -> Result<&http::Extensions, RequestScopeError> {
    try_request_context::<http::request::Parts>(cx)
        .map(|parts| &parts.extensions)
        .filter(|extensions| extensions.get::<ServedByAutumn>().is_some())
        .ok_or(RequestScopeError::Detached)
}

#[cfg(test)]
mod tests {
    use super::*;
    use topcoat::context::CxTestBuilder;

    #[test]
    fn helpers_outside_the_plugin_return_errors() {
        let cx = CxTestBuilder::new().build();
        assert!(matches!(state(&cx), Err(BridgeError::NotMounted)));
        assert!(matches!(config(&cx), Err(BridgeError::NotMounted)));
        assert!(matches!(extension::<u8>(&cx), Err(BridgeError::NotMounted)));
        assert_eq!(csrf_token(&cx), Err(RequestScopeError::Detached));
        assert!(matches!(session(&cx), Err(RequestScopeError::Detached)));
    }

    #[test]
    fn helpers_with_state_but_no_request() {
        let cx = CxTestBuilder::new()
            .app_context(AutumnApp(AppState::for_test()))
            .build();
        assert!(state(&cx).is_ok());
        assert!(config(&cx).is_ok());
        assert_eq!(
            extension::<u8>(&cx).err(),
            Some(BridgeError::MissingExtension { type_name: "u8" })
        );
        assert_eq!(csrf_token(&cx), Err(RequestScopeError::Detached));
    }

    #[test]
    fn request_helpers_need_the_marker_and_the_values() {
        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.extensions.insert(ServedByAutumn);
        let cx = CxTestBuilder::new().request_context(parts).build();
        assert_eq!(
            csrf_token(&cx),
            Err(RequestScopeError::Unavailable {
                what: "the Autumn CSRF token"
            })
        );
        assert!(matches!(
            session(&cx),
            Err(RequestScopeError::Unavailable {
                what: "the Autumn session"
            })
        ));
    }
}
