//! Tests for the `fallthrough` module.

use super::*;

#[test]
fn classify_table() {
    let cases = [
        (Method::GET, "/favicon.ico", Fallthrough::NoContent),
        (Method::HEAD, "/favicon.ico", Fallthrough::NoContent),
        (Method::POST, "/favicon.ico", Fallthrough::NotFound),
        (Method::PUT, "/favicon.ico", Fallthrough::NotFound),
        (Method::GET, "/favicon.ico/", Fallthrough::NotFound),
        (Method::GET, "/nope", Fallthrough::NotFound),
        (Method::GET, "/", Fallthrough::NotFound),
    ];
    for (method, path, expected) in cases {
        assert_eq!(classify(&method, path), expected, "{method} {path}");
    }
}

#[test]
fn respond_gives_204_or_autumn_404() {
    let icon = respond(&Method::GET, "/favicon.ico");
    assert_eq!(icon.status(), StatusCode::NO_CONTENT);

    let missing = respond(&Method::GET, "/nope");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let expected = AutumnError::not_found_msg("No route matches /nope").into_response();
    assert_eq!(
        missing.headers().get("content-type"),
        expected.headers().get("content-type")
    );
}
