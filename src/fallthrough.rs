//! The Autumn answer for paths that Topcoat does not serve.
//!
//! # Contract
//!
//! - `classify(m, p)` is `NoContent` if and only if `m` is `GET` or `HEAD`
//!   and `p` is `/favicon.ico`. Else it is `NotFound`.
//! - `respond` gives a 204 with an empty body for `NoContent`. For
//!   `NotFound` it gives `AutumnError::not_found_msg("No route matches {p}")`,
//!   which Autumn renders as an HTML page or as Problem Details JSON.
//!
//! This copies the private Autumn 404 fallback of autumn-web 0.7.

use autumn_web::AutumnError;
use axum::response::{IntoResponse, Response};
use http::{Method, StatusCode};

/// The path that Autumn answers with 204 when no route matches.
pub(crate) const FAVICON_PATH: &str = "/favicon.ico";

/// The kind of Autumn answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fallthrough {
    /// 204 No Content.
    NoContent,
    /// The Autumn 404.
    NotFound,
}

/// Classifies a request that Topcoat does not serve.
pub(crate) fn classify(method: &Method, path: &str) -> Fallthrough {
    if (method == Method::GET || method == Method::HEAD) && path == FAVICON_PATH {
        Fallthrough::NoContent
    } else {
        Fallthrough::NotFound
    }
}

/// Returns the Autumn answer for a request that Topcoat does not serve.
pub(crate) fn respond(method: &Method, path: &str) -> Response {
    match classify(method, path) {
        Fallthrough::NoContent => StatusCode::NO_CONTENT.into_response(),
        Fallthrough::NotFound => {
            AutumnError::not_found_msg(format!("No route matches {path}")).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
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
}
