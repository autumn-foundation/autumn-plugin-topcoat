//! Parsing of `Origin` and `Host` values and the same-origin check.
//!
//! # Contract
//!
//! - `Origin::parse(s)` returns `Some` if and only if `s` is exactly
//!   `scheme "://" host [":" port]`, with these rules:
//!   - The scheme is `http` or `https`, in any ASCII case.
//!   - The host is a non-empty name of ASCII letters, digits, `-`, `.`, `_`
//!     and `~`, or an IPv6 address in brackets.
//!   - The port is a decimal number from 1 to 65535 with no leading zero.
//!   - There is no user info, path, query or fragment. `null` gives `None`.
//! - The parsed host is in ASCII lowercase. The parsed port is the explicit
//!   port, or the default port of the scheme (80 or 443).
//! - `Authority::parse(s)` accepts `host [":" port]` with the same rules.
//! - `same_origin(o, a, s)` is `true` if and only if all these are true:
//!   - The hosts are equal.
//!   - The ports are equal. A missing authority port is the default port of
//!     the known scheme `s`, else of `o`.
//!   - `s` is `None` or equal to the scheme of `o`.
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
            if inner.parse::<std::net::Ipv6Addr>().is_err() {
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

/// Parses a decimal port from 1 to 65535, with no leading zero.
fn parse_port(digits: &str) -> Option<u16> {
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u16>().ok().filter(|port| *port != 0)
}

#[cfg(test)]
mod tests;
