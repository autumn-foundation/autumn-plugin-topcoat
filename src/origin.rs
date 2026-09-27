//! Parsing of `Origin` and `Host` values and the same-origin check.
//!
//! # Contract
//!
//! - `Origin::parse(s)` returns `Some` if and only if `s` is exactly
//!   `scheme "://" host [":" port]`: the scheme is `http` or `https` (any
//!   ASCII case); the host is a non-empty name of ASCII letters, digits, `-`,
//!   `.`, `_` and `~`, or a bracketed IPv6 address; the port is a decimal
//!   number from 1 to 65535. There is no user info, path, query or fragment.
//!   `null` gives `None`.
//! - The parsed host is in ASCII lowercase. The parsed port is the explicit
//!   port, or the default port of the scheme (80 or 443).
//! - `Authority::parse(s)` accepts `host [":" port]` with the same rules.
//! - `same_origin(o, a, s)` is `true` if and only if the hosts are equal, the
//!   ports are equal (a missing authority port is the default port of the
//!   known scheme `s`, else of `o`), and `s` is `None` or equal to the scheme
//!   of `o`.
//! - No function panics.

/// A URL scheme that can make an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Scheme {
    /// Parses `http` or `https` in any ASCII case.
    pub(crate) const fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("http") {
            Some(Self::Http)
        } else if value.eq_ignore_ascii_case("https") {
            Some(Self::Https)
        } else {
            None
        }
    }

    /// Returns the default port of the scheme.
    pub(crate) const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A serialized origin, for example `https://example.com:8443`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Origin {
    pub(crate) scheme: Scheme,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Origin {
    /// Parses an `Origin` header value.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let (scheme, authority) = value.split_once("://")?;
        let scheme = Scheme::parse(scheme)?;
        let authority = Authority::parse(authority)?;
        Some(Self {
            scheme,
            host: authority.host,
            port: authority.port.unwrap_or_else(|| scheme.default_port()),
        })
    }
}

/// A `host[:port]` authority, for example the value of the `Host` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Authority {
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl Authority {
    /// Parses a `Host` header value or a URI authority.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let (host, port) = if value.starts_with('[') {
            let end = value.find(']')?;
            let (host, rest) = value.split_at(end + 1);
            let inner = &host[1..host.len() - 1];
            if inner.is_empty()
                || !inner
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            {
                return None;
            }
            (host, rest)
        } else {
            let end = value.find(':').unwrap_or(value.len());
            let (host, rest) = value.split_at(end);
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
            {
                return None;
            }
            (host, rest)
        };
        let port = match port.strip_prefix(':') {
            None if port.is_empty() => None,
            None => return None,
            Some(digits) => Some(parse_port(digits)?),
        };
        Some(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Returns `true` if `origin` is the origin of a server at `expected`.
pub(crate) fn same_origin(origin: &Origin, expected: &Authority, scheme: Option<Scheme>) -> bool {
    let expected_port = expected
        .port
        .unwrap_or_else(|| scheme.unwrap_or(origin.scheme).default_port());
    origin.host == expected.host
        && origin.port == expected_port
        && scheme.is_none_or(|scheme| scheme == origin.scheme)
}

/// Parses a decimal port from 1 to 65535.
fn parse_port(digits: &str) -> Option<u16> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u16>().ok().filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn origin(scheme: Scheme, host: &str, port: u16) -> Origin {
        Origin {
            scheme,
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn scheme_parse() {
        assert_eq!(Scheme::parse("http"), Some(Scheme::Http));
        assert_eq!(Scheme::parse("HTTPS"), Some(Scheme::Https));
        assert_eq!(Scheme::parse("ws"), None);
        assert_eq!(Scheme::parse(""), None);
    }

    #[test]
    fn origin_parse_accepts_valid_values() {
        assert_eq!(
            Origin::parse("http://localhost"),
            Some(origin(Scheme::Http, "localhost", 80))
        );
        assert_eq!(
            Origin::parse("HTTPS://Example.COM"),
            Some(origin(Scheme::Https, "example.com", 443))
        );
        assert_eq!(
            Origin::parse("https://a.b:8443"),
            Some(origin(Scheme::Https, "a.b", 8443))
        );
        assert_eq!(
            Origin::parse("http://127.0.0.1:3000"),
            Some(origin(Scheme::Http, "127.0.0.1", 3000))
        );
        assert_eq!(
            Origin::parse("http://[::1]:8080"),
            Some(origin(Scheme::Http, "[::1]", 8080))
        );
        assert_eq!(
            Origin::parse("https://a:443"),
            Some(origin(Scheme::Https, "a", 443))
        );
    }

    #[test]
    fn origin_parse_refuses_invalid_values() {
        for bad in [
            "",
            "null",
            "localhost",
            "ftp://a",
            "http://",
            "http://a/",
            "http://a/b",
            "http://u@a",
            "http://a:0",
            "http://a:65536",
            "http://a:",
            "http://a:x",
            "http://a?q",
            "http://a#f",
            "http://a b",
            "http://[::1",
            "http://a:+80",
            "http:/a",
            " http://a",
        ] {
            assert_eq!(Origin::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn authority_parse() {
        assert_eq!(
            Authority::parse("localhost"),
            Some(Authority {
                host: "localhost".into(),
                port: None
            })
        );
        assert_eq!(
            Authority::parse("Example.com:8080"),
            Some(Authority {
                host: "example.com".into(),
                port: Some(8080)
            })
        );
        assert_eq!(
            Authority::parse("[::1]:3000"),
            Some(Authority {
                host: "[::1]".into(),
                port: Some(3000)
            })
        );
        for bad in ["", ":80", "a:", "a:0", "a/b", "u@a", "a b", "[::1"] {
            assert_eq!(Authority::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn same_origin_table() {
        let host = |s: &str| Authority::parse(s).unwrap();
        let o = |s: &str| Origin::parse(s).unwrap();
        assert!(same_origin(
            &o("http://localhost"),
            &host("localhost"),
            None
        ));
        assert!(same_origin(
            &o("https://a.com"),
            &host("a.com"),
            Some(Scheme::Https)
        ));
        assert!(same_origin(
            &o("https://a.com"),
            &host("a.com:443"),
            Some(Scheme::Https)
        ));
        assert!(same_origin(
            &o("http://a.com:8080"),
            &host("A.com:8080"),
            None
        ));
        // Host mismatch.
        assert!(!same_origin(&o("https://evil.com"), &host("a.com"), None));
        assert!(!same_origin(&o("https://sub.a.com"), &host("a.com"), None));
        // Port mismatch.
        assert!(!same_origin(&o("http://a.com:8080"), &host("a.com"), None));
        assert!(!same_origin(&o("http://a.com"), &host("a.com:8080"), None));
        // Known scheme mismatch.
        assert!(!same_origin(
            &o("http://a.com"),
            &host("a.com"),
            Some(Scheme::Https)
        ));
        assert!(!same_origin(
            &o("https://a.com"),
            &host("a.com"),
            Some(Scheme::Http)
        ));
    }

    fn host_name() -> impl Strategy<Value = String> {
        prop_oneof!["[a-z0-9][a-z0-9.-]{0,10}", Just("[::1]".to_owned())]
    }

    proptest! {
        #[test]
        fn parsers_are_total(s in any::<String>()) {
            let _ = Origin::parse(&s);
            let _ = Authority::parse(&s);
            let _ = Scheme::parse(&s);
        }

        #[test]
        fn origin_is_case_insensitive_and_normalises_default_ports(
            https in any::<bool>(), host in host_name(), upper in any::<bool>(), explicit in any::<bool>()
        ) {
            let scheme = if https { Scheme::Https } else { Scheme::Http };
            let name = if https { "https" } else { "http" };
            let port = scheme.default_port();
            let mut text = format!("{name}://{host}");
            if explicit {
                use std::fmt::Write;
                let _ = write!(text, ":{port}");
            }
            if upper {
                text = text.to_ascii_uppercase();
            }
            let parsed = Origin::parse(&text).unwrap();
            prop_assert_eq!(parsed.scheme, scheme);
            prop_assert_eq!(parsed.port, port);
            prop_assert_eq!(&parsed.host, &host.to_ascii_lowercase());
            let authority = Authority::parse(&host).unwrap();
            prop_assert!(same_origin(&parsed, &authority, Some(scheme)));
            prop_assert!(same_origin(&parsed, &authority, None));
        }

        #[test]
        fn origin_mutations_are_refused(host in host_name(), suffix in prop_oneof![
            Just("/".to_owned()), Just("/x".to_owned()), Just("?q".to_owned()), Just("#f".to_owned()),
            Just(":0".to_owned()), Just(":65536".to_owned()), Just(":".to_owned())
        ]) {
            let text = format!("https://{host}{suffix}");
            prop_assert_eq!(Origin::parse(&text), None);
            let with_user = format!("https://user@{host}");
            prop_assert_eq!(Origin::parse(&with_user), None);
        }

        #[test]
        fn port_changes_break_same_origin(host in host_name(), a in 1u16.., b in 1u16..) {
            let parsed = Origin::parse(&format!("http://{host}:{a}")).unwrap();
            let authority = Authority::parse(&format!("{host}:{b}")).unwrap();
            prop_assert_eq!(same_origin(&parsed, &authority, None), a == b);
        }
    }
}
