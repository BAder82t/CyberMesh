//! Pure, deterministic feature extractors. Integer arithmetic only.

/// Parts of a normalised host name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostParts<'a> {
    pub host: &'a str,
    /// Registrable domain per the Public Suffix List (ICANN + private sections).
    pub registrable: &'a str,
    /// Public suffix, e.g. `co.uk`, `github.io`.
    pub suffix: &'a str,
    /// The label immediately left of the suffix, e.g. `example` in `example.co.uk`.
    pub registrable_label: &'a str,
    /// Labels left of the registrable domain, e.g. `["login", "secure"]`.
    pub subdomain_labels: Vec<&'a str>,
}

/// Splits a normalised host using the compiled-in Public Suffix List.
#[must_use]
pub fn host_parts(host: &str) -> Option<HostParts<'_>> {
    let registrable = psl::domain_str(host)?;
    let suffix = psl::suffix_str(host)?;
    let label_end = registrable.len().checked_sub(suffix.len() + 1)?;
    let registrable_label = &registrable[..label_end];
    let prefix_len = host.len() - registrable.len();
    let subdomain_labels = if prefix_len == 0 {
        Vec::new()
    } else {
        host[..prefix_len - 1].split('.').collect()
    };
    Some(HostParts {
        host,
        registrable,
        suffix,
        registrable_label,
        subdomain_labels,
    })
}

/// `log2(x)` in Q16 fixed point (x >= 1), computed with integer squaring so the result
/// is bit-identical on every platform.
#[must_use]
pub fn log2_q16(x: u64) -> u64 {
    if x <= 1 {
        return 0;
    }
    let n = u64::from(63 - x.leading_zeros());
    // y = x / 2^n in Q32, within [1, 2).
    let mut y: u128 = (u128::from(x) << 32) >> n;
    let mut frac: u64 = 0;
    for i in 1..=16u32 {
        y = (y * y) >> 32;
        if y >= (2u128 << 32) {
            y >>= 1;
            frac |= 1 << (16 - i);
        }
    }
    (n << 16) | frac
}

/// Shannon entropy of the bytes of `s` in Q16 bits per character.
#[must_use]
pub fn entropy_q16(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let n = bytes.len() as u64;
    if n == 0 {
        return 0;
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        counts[usize::from(*b)] += 1;
    }
    let sum: u64 = counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| c * log2_q16(*c))
        .sum();
    log2_q16(n).saturating_sub(sum / n)
}

/// Optimal string alignment (restricted Damerau-Levenshtein) distance on bytes.
#[must_use]
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let w = m + 1;
    let mut d = vec![0usize; (n + 1) * w];
    for i in 0..=n {
        d[i * w] = i;
    }
    for (j, cell) in d.iter_mut().enumerate().take(m + 1) {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[(i - 1) * w + j] + 1)
                .min(d[i * w + j - 1] + 1)
                .min(d[(i - 1) * w + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[(i - 2) * w + j - 2] + 1);
            }
            d[i * w + j] = v;
        }
    }
    d[n * w + m]
}

/// Undoes common character substitutions used in lookalike domains
/// (`0->o 1->l 3->e 4->a 5->s 7->t 8->b`, `rn->m`, `vv->w`).
#[must_use]
pub fn deleet(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            other => other,
        })
        .collect();
    mapped.replace("rn", "m").replace("vv", "w")
}

/// Script classes relevant to homograph detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Other,
    Common,
}

#[must_use]
pub fn script_of(c: char) -> Script {
    match c {
        'a'..='z' | 'A'..='Z' => Script::Latin,
        '0'..='9' | '-' | '.' => Script::Common,
        '\u{00C0}'..='\u{024F}' => Script::Latin,
        '\u{0370}'..='\u{03FF}' => Script::Greek,
        '\u{0400}'..='\u{052F}' => Script::Cyrillic,
        '\u{0530}'..='\u{058F}' => Script::Armenian,
        _ => Script::Other,
    }
}

/// True when a label mixes Latin with Cyrillic, Greek or Armenian, or mixes two of those.
#[must_use]
pub fn is_mixed_script(label: &str) -> bool {
    let mut latin = false;
    let mut confusable_scripts = 0u8;
    let (mut cy, mut gr, mut ar) = (false, false, false);
    for c in label.chars() {
        match script_of(c) {
            Script::Latin => latin = true,
            Script::Cyrillic => cy = true,
            Script::Greek => gr = true,
            Script::Armenian => ar = true,
            Script::Other | Script::Common => {}
        }
    }
    for f in [cy, gr, ar] {
        confusable_scripts += u8::from(f);
    }
    (latin && confusable_scripts > 0) || confusable_scripts > 1
}

/// Maps visually confusable characters to Latin look-alikes and strips common diacritics.
/// Characters without a mapping are kept. This is a small, reviewed subset of Unicode
/// TR39 confusables, not the full table.
#[must_use]
pub fn skeleton(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // Cyrillic
            'а' => 'a',
            'в' => 'b',
            'е' | 'ё' | 'є' => 'e',
            'к' => 'k',
            'м' => 'm',
            'н' => 'h',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'т' => 't',
            'у' => 'y',
            'х' => 'x',
            'ѕ' => 's',
            'і' | 'ї' => 'i',
            'ј' => 'j',
            'ԁ' => 'd',
            'ԛ' => 'q',
            'ԝ' => 'w',
            'һ' => 'h',
            'ӏ' => 'l',
            'ɡ' => 'g',
            // Greek
            'α' => 'a',
            'ο' | 'σ' => 'o',
            'ν' => 'v',
            'ρ' => 'p',
            'τ' => 't',
            'υ' => 'u',
            'ι' => 'i',
            'κ' => 'k',
            'χ' => 'x',
            'ε' => 'e',
            // Armenian
            'օ' => 'o',
            'ս' => 'u',
            'հ' => 'h',
            'ո' => 'n',
            // Latin with diacritics / variants
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' | 'ɑ' => 'a',
            'ç' | 'ć' | 'ĉ' | 'č' => 'c',
            'ď' | 'đ' => 'd',
            'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' | 'ě' => 'e',
            'ĝ' | 'ğ' | 'ġ' | 'ģ' => 'g',
            'ì' | 'í' | 'î' | 'ï' | 'ī' | 'į' | 'ı' => 'i',
            'ķ' => 'k',
            'ĺ' | 'ļ' | 'ľ' | 'ł' => 'l',
            'ñ' | 'ń' | 'ņ' | 'ň' => 'n',
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => 'o',
            'ŕ' | 'ř' => 'r',
            'ś' | 'ş' | 'š' => 's',
            'ţ' | 'ť' => 't',
            'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' | 'ų' => 'u',
            'ý' | 'ÿ' => 'y',
            'ź' | 'ż' | 'ž' => 'z',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn host_parts_uses_public_suffix_list() {
        let p = host_parts("login.secure.example.co.uk").unwrap();
        assert_eq!(p.registrable, "example.co.uk");
        assert_eq!(p.suffix, "co.uk");
        assert_eq!(p.registrable_label, "example");
        assert_eq!(p.subdomain_labels, vec!["login", "secure"]);
        let p = host_parts("evil.github.io").unwrap();
        assert_eq!(p.registrable, "evil.github.io");
        assert_eq!(p.registrable_label, "evil");
        assert!(p.subdomain_labels.is_empty());
        let p = host_parts("examplebank-secure-login.phish.localhost").unwrap();
        assert_eq!(p.registrable, "phish.localhost");
        assert_eq!(p.subdomain_labels, vec!["examplebank-secure-login"]);
    }

    #[test]
    fn fixed_point_log2() {
        assert_eq!(log2_q16(1), 0);
        assert_eq!(log2_q16(2), 1 << 16);
        assert_eq!(log2_q16(1024), 10 << 16);
        // Exact pinned values (integer algorithm, identical on every platform).
        assert_eq!(log2_q16(3), 103_872);
        assert_eq!(log2_q16(5), 152_169);
        assert_eq!(log2_q16(63), 391_727);
        assert_eq!(entropy_q16("paypal-login"), 202_176);
    }

    #[test]
    fn entropy_values() {
        assert_eq!(entropy_q16("aaaa"), 0);
        assert_eq!(entropy_q16("ab"), 1 << 16);
        assert_eq!(entropy_q16("abcd"), 2 << 16);
        assert!(entropy_q16("x7kq9zr2mw4tpl") > entropy_q16("mailservice"));
    }

    #[test]
    fn edit_distance_cases() {
        assert_eq!(edit_distance("paypal", "paypal"), 0);
        assert_eq!(edit_distance("paypa1", "paypal"), 1);
        assert_eq!(edit_distance("paypall", "paypal"), 1);
        assert_eq!(edit_distance("papyal", "paypal"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("micros0ft", "microsoft"), 1);
    }

    #[test]
    fn deleet_and_skeleton() {
        assert_eq!(deleet("paypa1"), "paypal");
        assert_eq!(deleet("rnicrosoft"), "microsoft");
        assert_eq!(skeleton("pаypal"), "paypal");
        assert!(is_mixed_script("pаypal"));
        assert!(!is_mixed_script("paypal"));
        assert!(!is_mixed_script("пример"));
    }

    proptest! {
        #[test]
        fn edit_distance_is_symmetric_and_bounded(a in "[a-z0-9]{0,20}", b in "[a-z0-9]{0,20}") {
            let d = edit_distance(&a, &b);
            prop_assert_eq!(d, edit_distance(&b, &a));
            prop_assert!(d <= a.len().max(b.len()));
            prop_assert_eq!(d == 0, a == b);
        }

        #[test]
        fn entropy_bounded_by_log2_len(s in "[a-z0-9-]{1,63}") {
            prop_assert!(entropy_q16(&s) <= log2_q16(s.len() as u64) + 1);
        }

        #[test]
        fn log2_monotonic(x in 1u64..1_000_000) {
            prop_assert!(log2_q16(x) <= log2_q16(x + 1));
        }
    }
}
