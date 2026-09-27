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

proptest::proptest! {
    #[test]
    fn classify_agrees_with_the_contract(
        method in proptest::sample::select(&["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "get"][..]),
        path in proptest::prop_oneof![
            proptest::strategy::Just("/favicon.ico".to_owned()),
            "/[a-z.]{0,12}",
            "/favicon\\.ico[/a-z]{0,3}",
        ],
    ) {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let icon = (method == Method::GET || method == Method::HEAD) && path == "/favicon.ico";
        let expected = if icon { Fallthrough::NoContent } else { Fallthrough::NotFound };
        proptest::prop_assert_eq!(classify(&method, &path), expected);
        let status = respond(&method, &path).status();
        proptest::prop_assert_eq!(status == StatusCode::NO_CONTENT, icon);
        proptest::prop_assert_eq!(status == StatusCode::NOT_FOUND, !icon);
    }
}
