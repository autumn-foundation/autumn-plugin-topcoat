//! Tests for the `origin` module.

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

/// Regression: brackets must hold an IPv6 address, and ports have no leading zero.
#[test]
fn brackets_hold_ipv6_and_ports_have_no_leading_zero() {
    for bad in [
        "http://[abc]",
        "http://[.]",
        "http://[:::::]",
        "http://[1.2.3.4]",
        "http://a:0080",
        "http://a:00",
    ] {
        assert_eq!(Origin::parse(bad), None, "{bad:?}");
    }
    assert!(Origin::parse("https://[2001:db8::1]:443").is_some());
    assert!(Origin::parse("http://[::ffff:1.2.3.4]").is_some());
    assert_eq!(Authority::parse("[abc]:80"), None);
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
