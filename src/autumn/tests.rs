//! Tests for the `autumn` module.

use super::*;
use topcoat::context::CxTestBuilder;

#[test]
fn helpers_outside_the_plugin_return_errors() {
    let cx = CxTestBuilder::new().build();
    assert!(matches!(state(&cx), Err(AppDataError::NotMounted)));
    assert!(matches!(config(&cx), Err(AppDataError::NotMounted)));
    assert!(matches!(
        extension::<u8>(&cx),
        Err(AppDataError::NotMounted)
    ));
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
        Some(AppDataError::MissingExtension { type_name: "u8" })
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
