//! Syntax rules for domain names carried in protocol messages.
//!
//! Messages carry domains in normalised form only: ASCII (IDNA/punycode already applied),
//! lowercase, no trailing dot, letters/digits/hyphens, 2+ labels, and a non-numeric
//! top-level label (so IPv4 literals are rejected). Normalisation from user input happens in
//! `cybermesh-analysis`; the protocol only checks that input is already normalised.

/// Maximum total length of a domain name.
pub const MAX_DOMAIN_LEN: usize = 253;
/// Maximum length of one label.
pub const MAX_LABEL_LEN: usize = 63;

/// Returns true when `s` is a syntactically valid, normalised domain name.
#[must_use]
pub fn is_normalized_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_DOMAIN_LEN || s.ends_with('.') {
        return false;
    }
    let mut labels = 0usize;
    let mut last = "";
    for label in s.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
        labels += 1;
        last = label;
    }
    labels >= 2 && !last.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn accepts_and_rejects() {
        for ok in [
            "example.com",
            "a.b.c.example.co.uk",
            "xn--pypal-4ve.com",
            "login-secure.example.test",
            "examplebank-secure-login.phish.localhost",
        ] {
            assert!(is_normalized_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "com",
            "Example.com",
            "example.com.",
            "-a.com",
            "a-.com",
            "a..com",
            "192.168.1.1",
            "exa mple.com",
            "ex_ample.com",
            "пример.рф",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}com", "a.".repeat(130)),
        ] {
            assert!(!is_normalized_domain(bad), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn never_panics(s in ".{0,300}") {
            let _ = is_normalized_domain(&s);
        }
    }
}
