use cybermesh_protocol::domain::is_normalized_domain;

/// Why an input could not be normalised into a domain name.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NormalizeError {
    #[error("empty input")]
    Empty,
    #[error("input too long")]
    TooLong,
    #[error("IDNA conversion failed")]
    Idna,
    #[error("not a valid domain name (IP literals and single labels are not accepted)")]
    Invalid,
}

/// Maximum accepted raw input length (URLs may be longer than domains).
const MAX_INPUT: usize = 2048;

/// Normalises a domain or URL into the protocol's canonical form: host only, IDNA ASCII
/// (punycode), lowercase, no trailing dot, no port or credentials.
pub fn normalize_domain(input: &str) -> Result<String, NormalizeError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(NormalizeError::Empty);
    }
    if s.len() > MAX_INPUT {
        return Err(NormalizeError::TooLong);
    }
    let host = extract_host(s);
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err(NormalizeError::Invalid);
    }
    let ascii = idna::domain_to_ascii(host).map_err(|_| NormalizeError::Idna)?;
    if is_normalized_domain(&ascii) {
        Ok(ascii)
    } else {
        Err(NormalizeError::Invalid)
    }
}

/// True when `s` is a URL scheme per RFC 3986: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_scheme(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

/// Extracts the host from `scheme://user@host:port/path?q#f`, or returns the input. A `://`
/// only starts an authority when everything before it is a valid scheme, so inputs such as
/// `evil.example/redirect?u=http://good.example` resolve to `evil.example`.
fn extract_host(s: &str) -> &str {
    let rest = match s.find("://") {
        Some(i) if is_scheme(&s[..i]) => &s[i + 3..],
        _ => s,
    };
    let end = rest
        .find(['/', '?', '#', '\\'])
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if host_port.starts_with('[') {
        // IPv6 literal: return as-is so that validation rejects it.
        return host_port;
    }
    match host_port.rfind(':') {
        Some(i) => &host_port[..i],
        None => host_port,
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn normalises_urls_and_idn() {
        assert_eq!(normalize_domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://user:pw@Login.Example.com:8443/a?b#c").unwrap(),
            "login.example.com"
        );
        // Cyrillic 'а' (U+0430) in "pаypal" becomes punycode.
        assert_eq!(normalize_domain("pаypal.com").unwrap(), "xn--pypal-4ve.com");
        assert_eq!(normalize_domain("  www.example.org  ").unwrap(), "www.example.org");
    }

    #[test]
    fn embedded_urls_do_not_change_the_host() {
        for (input, host) in [
            ("evil.example.com/redirect?u=http://good.example.com", "evil.example.com"),
            ("evil.example.com?next=https://good.example.com", "evil.example.com"),
            ("evil.example.com#http://good.example.com", "evil.example.com"),
            ("hxxp://evil.example.com", "evil.example.com"),
            ("HTTPS://Evil.Example.com/x", "evil.example.com"),
        ] {
            assert_eq!(normalize_domain(input).unwrap(), host, "{input}");
        }
        // Not a scheme: the part before :// contains a dot-free path character.
        assert!(normalize_domain("evil.example.com/a://b").is_ok_and(|h| h == "evil.example.com"));
    }

    #[test]
    fn rejects_non_domains() {
        for bad in ["", "localhost", "10.0.0.1", "http://[::1]/", "a b.com", "ex_ample.com", "http://", "..."] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn idempotent_and_never_panics(s in ".{0,120}") {
            if let Ok(n) = normalize_domain(&s) {
                prop_assert_eq!(normalize_domain(&n).unwrap(), n.clone());
                prop_assert!(is_normalized_domain(&n));
            }
        }
    }
}
