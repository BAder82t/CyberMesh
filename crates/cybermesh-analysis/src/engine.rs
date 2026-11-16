use cybermesh_protocol::domain::is_normalized_domain;
use cybermesh_protocol::{
    DomainAssessment, EngineSpec, Finding, FindingCode, TaskAnnouncement, TaskKind, Verdict,
};

use crate::evidence::{Brand, EvidenceBundle};
use crate::features::{
    HostParts, deleet, edit_distance, entropy_q16, host_parts, is_mixed_script, skeleton,
};
use crate::AnalysisError;

/// Engine identifier carried in tasks and results.
pub const ENGINE_NAME: &str = "cybermesh-lexical";
/// Bumped on any change that can alter output for the same input. The suffix records the
/// exact Public Suffix List and IDNA table versions compiled in (pinned with `=` in
/// `Cargo.toml`), because they also determine output.
pub const ENGINE_VERSION: &str = "0.2.0+psl.2.1.255+idna.1.1.0";

/// The engine spec of this build.
#[must_use]
pub fn engine_spec() -> EngineSpec {
    EngineSpec {
        name: ENGINE_NAME.into(),
        version: ENGINE_VERSION.into(),
    }
}

/// Scoring weights and thresholds (basis points). Part of the engine version: changing any
/// of these requires bumping [`ENGINE_VERSION`].
pub mod scoring {
    pub const FEED_MATCH: i32 = 9000;
    pub const POPULAR_DOMAIN: i32 = -9000;
    pub const BRAND_IMPERSONATION: i32 = 3500;
    pub const BRAND_LOOKALIKE: i32 = 4500;
    pub const IDN_HOMOGRAPH: i32 = 6000;
    pub const MIXED_SCRIPT: i32 = 2500;
    pub const KEYWORD_EACH: i32 = 700;
    pub const KEYWORD_MAX: usize = 3;
    pub const MANY_HYPHENS: i32 = 900;
    pub const HYPHEN_THRESHOLD: usize = 3;
    pub const DEEP_SUBDOMAIN: i32 = 800;
    pub const DEPTH_THRESHOLD: usize = 4;
    pub const LONG_HOSTNAME: i32 = 700;
    pub const LONG_THRESHOLD: usize = 60;
    pub const HIGH_ENTROPY: i32 = 1800;
    pub const ENTROPY_MIN_LEN: usize = 12;
    /// 3.6 bits per character in Q16.
    pub const ENTROPY_Q16_THRESHOLD: u64 = 235_930;
    pub const DIGIT_HEAVY: i32 = 700;
    pub const SUSPICIOUS_TLD: i32 = 900;
    pub const MALICIOUS_THRESHOLD: u16 = 7000;
    pub const SUSPICIOUS_THRESHOLD: u16 = 4000;

    /// Credential-phishing vocabulary (substring match, distinct words counted).
    pub const KEYWORDS: &[&str] = &[
        "account", "alert", "authenticate", "banking", "billing", "confirm", "credential",
        "invoice", "login", "logon", "password", "recover", "reset", "secure", "signin",
        "support", "suspend", "unlock", "update", "validate", "verify", "wallet", "webscr",
    ];

    /// TLDs repeatedly reported as disproportionately abused (e.g. Spamhaus and Interisle
    /// annual reports). A weak signal on its own.
    pub const SUSPICIOUS_TLDS: &[&str] = &[
        "bond", "buzz", "cf", "cfd", "click", "country", "cyou", "ga", "gq", "icu", "link",
        "lol", "ml", "monster", "mov", "quest", "rest", "sbs", "tk", "top", "work", "xyz",
        "zip",
    ];
}

const MAX_DETAIL: usize = 200;

fn truncate(mut s: String) -> String {
    if s.len() > MAX_DETAIL {
        let mut cut = MAX_DETAIL;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// The deterministic domain risk engine bound to one evidence bundle.
#[derive(Debug, Clone)]
pub struct Engine {
    evidence: EvidenceBundle,
}

impl Engine {
    #[must_use]
    pub fn new(evidence: EvidenceBundle) -> Self {
        Self { evidence }
    }

    #[must_use]
    pub fn evidence(&self) -> &EvidenceBundle {
        &self.evidence
    }

    /// Checks that a task asks for this engine and exactly the local evidence snapshots.
    pub fn check_task(&self, task: &TaskAnnouncement) -> Result<(), AnalysisError> {
        let TaskKind::DomainRiskAssessment = task.kind;
        let spec = engine_spec();
        if task.engine != spec {
            return Err(AnalysisError::EngineMismatch {
                required: task.engine.to_string(),
                actual: spec.to_string(),
            });
        }
        for (id, pinned) in &task.evidence {
            match self.evidence.pins.get(id) {
                None => return Err(AnalysisError::UnknownEvidence(id.clone())),
                Some(local) if local != pinned => {
                    return Err(AnalysisError::EvidenceMismatch {
                        source_id: id.clone(),
                        pinned: pinned.to_string(),
                        local: local.to_string(),
                    });
                }
                Some(_) => {}
            }
        }
        if task.evidence.len() != self.evidence.pins.len() {
            // Every local source influences scoring, so all must be pinned.
            let missing = self
                .evidence
                .pins
                .keys()
                .find(|k| !task.evidence.contains_key(*k))
                .cloned()
                .unwrap_or_default();
            return Err(AnalysisError::UnknownEvidence(format!("{missing} (not pinned by task)")));
        }
        Ok(())
    }

    /// Runs a validated task.
    pub fn assess_task(
        &self,
        task: &TaskAnnouncement,
    ) -> Result<Vec<DomainAssessment>, AnalysisError> {
        self.check_task(task)?;
        task.domains.iter().map(|d| self.assess(d)).collect()
    }

    /// Assesses one normalised domain.
    pub fn assess(&self, domain: &str) -> Result<DomainAssessment, AnalysisError> {
        if !is_normalized_domain(domain) {
            return Err(AnalysisError::InvalidDomain(domain.to_owned()));
        }
        let Some(parts) = host_parts(domain) else {
            return Ok(DomainAssessment {
                domain: domain.to_owned(),
                risk_score_bp: 0,
                confidence_bp: 1000,
                verdict: Verdict::NoSignal,
                findings: vec![],
            });
        };
        let mut findings = Vec::new();

        let feed_hits = self.evidence.blocklist_hits(parts.host, parts.registrable);
        if !feed_hits.is_empty() {
            findings.push(Finding {
                code: FindingCode::FeedMatch,
                points: scoring::FEED_MATCH,
                detail: truncate(format!("listed in reference feed: {}", feed_hits.join(", "))),
            });
        }
        let popular = self.evidence.popular.contains(parts.registrable);
        if popular {
            findings.push(Finding {
                code: FindingCode::PopularDomain,
                points: scoring::POPULAR_DOMAIN,
                detail: truncate(format!(
                    "{} is on the pinned popularity list",
                    parts.registrable
                )),
            });
        } else {
            self.lexical_findings(&parts, &mut findings);
        }

        findings.sort();
        let raw: i64 = findings.iter().map(|f| i64::from(f.points)).sum();
        let score = u16::try_from(raw.clamp(0, 10_000)).unwrap_or(0);
        let lexical_points: i64 = findings
            .iter()
            .filter(|f| f.code != FindingCode::FeedMatch && f.code != FindingCode::PopularDomain)
            .map(|f| i64::from(f.points))
            .sum();
        let feed = !feed_hits.is_empty();
        let verdict = if popular {
            Verdict::KnownBenign
        } else if score >= scoring::MALICIOUS_THRESHOLD {
            Verdict::Malicious
        } else if score >= scoring::SUSPICIOUS_THRESHOLD {
            Verdict::Suspicious
        } else {
            Verdict::NoSignal
        };
        let confidence: u16 = match verdict {
            Verdict::KnownBenign if feed => 3000, // conflicting evidence
            Verdict::KnownBenign => 9000,
            Verdict::Malicious if feed && lexical_points >= 2000 => 9800,
            Verdict::Malicious if feed => 9500,
            Verdict::Malicious => 6000 + (score - scoring::MALICIOUS_THRESHOLD) / 3,
            Verdict::Suspicious => 4000 + (score - scoring::SUSPICIOUS_THRESHOLD) / 3,
            Verdict::NoSignal => 2000,
        };
        Ok(DomainAssessment {
            domain: domain.to_owned(),
            risk_score_bp: score,
            confidence_bp: confidence.min(10_000),
            verdict,
            findings,
        })
    }

    fn lexical_findings(&self, p: &HostParts<'_>, out: &mut Vec<Finding>) {
        // Labels that a registrant controls (everything left of the public suffix).
        // Punycode (xn--) labels are analysed separately in decoded form below; their ASCII
        // encoding carries no meaningful lexical signal.
        let mut all_labels: Vec<&str> = p.subdomain_labels.clone();
        all_labels.push(p.registrable_label);
        let labels: Vec<&str> = all_labels
            .iter()
            .copied()
            .filter(|l| !l.starts_with("xn--"))
            .collect();
        let parts: Vec<&str> = labels.iter().flat_map(|l| l.split('-')).collect();

        let mut impersonated = Vec::new();
        let mut lookalikes = Vec::new();
        for brand in &self.evidence.brands {
            if is_legitimate(brand, p.registrable) {
                continue;
            }
            if brand_tokens_in(brand, &labels, &parts) {
                impersonated.push(brand.name.as_str());
            } else if let Some(part) = lookalike_part(brand, &parts) {
                lookalikes.push(format!("{part}~{}", brand.name));
            }
        }
        if !impersonated.is_empty() {
            out.push(Finding {
                code: FindingCode::BrandImpersonation,
                points: scoring::BRAND_IMPERSONATION,
                detail: truncate(format!(
                    "brand name outside its legitimate domains: {}",
                    impersonated.join(", ")
                )),
            });
        }
        if !lookalikes.is_empty() {
            out.push(Finding {
                code: FindingCode::BrandLookalike,
                points: scoring::BRAND_LOOKALIKE,
                detail: truncate(format!("near-miss spelling of brand: {}", lookalikes.join(", "))),
            });
        }

        // Internationalised labels: mixed scripts and homographs of protected brands.
        if all_labels.iter().any(|l| l.starts_with("xn--")) {
            let (unicode, _) = idna::domain_to_unicode(p.host);
            let ulabels: Vec<&str> = unicode.split('.').collect();
            let controlled = ulabels.len().saturating_sub(p.suffix.split('.').count());
            let ulabels = &ulabels[..controlled];
            if ulabels.iter().any(|l| is_mixed_script(l)) {
                out.push(Finding {
                    code: FindingCode::MixedScript,
                    points: scoring::MIXED_SCRIPT,
                    detail: "label mixes Latin with Cyrillic, Greek or Armenian letters".into(),
                });
            }
            let skel: Vec<String> = ulabels
                .iter()
                .filter(|l| !l.is_ascii())
                .map(|l| skeleton(l))
                .collect();
            if !skel.is_empty() {
                let skel_refs: Vec<&str> = skel.iter().map(String::as_str).collect();
                let skel_parts: Vec<&str> = skel_refs.iter().flat_map(|l| l.split('-')).collect();
                let mut homographs = Vec::new();
                for brand in &self.evidence.brands {
                    if is_legitimate(brand, p.registrable) {
                        continue;
                    }
                    if brand_tokens_in(brand, &skel_refs, &skel_parts)
                        || skel_parts.iter().any(|s| brand.tokens.iter().any(|t| deleet(s) == *t))
                    {
                        homographs.push(brand.name.as_str());
                    }
                }
                if !homographs.is_empty() {
                    out.push(Finding {
                        code: FindingCode::IdnHomograph,
                        points: scoring::IDN_HOMOGRAPH,
                        detail: truncate(format!(
                            "internationalised name renders like: {}",
                            homographs.join(", ")
                        )),
                    });
                }
            }
        }

        let joined = labels.join(".");
        let mut kws: Vec<&str> = scoring::KEYWORDS
            .iter()
            .copied()
            .filter(|k| joined.contains(k))
            .collect();
        kws.sort_unstable();
        if !kws.is_empty() {
            let n = kws.len().min(scoring::KEYWORD_MAX);
            out.push(Finding {
                code: FindingCode::SuspiciousKeywords,
                points: scoring::KEYWORD_EACH * i32::try_from(n).unwrap_or(0),
                detail: truncate(format!("credential-phishing terms: {}", kws.join(", "))),
            });
        }

        // Hyphens inside punycode (xn--) labels are encoding artefacts, not signals.
        let hyphens: usize = p
            .host
            .split('.')
            .filter(|l| !l.starts_with("xn--"))
            .map(|l| l.bytes().filter(|b| *b == b'-').count())
            .sum();
        if hyphens >= scoring::HYPHEN_THRESHOLD {
            out.push(Finding {
                code: FindingCode::ManyHyphens,
                points: scoring::MANY_HYPHENS,
                detail: format!("{hyphens} hyphens in hostname"),
            });
        }
        if p.subdomain_labels.len() >= scoring::DEPTH_THRESHOLD {
            out.push(Finding {
                code: FindingCode::DeepSubdomain,
                points: scoring::DEEP_SUBDOMAIN,
                detail: format!("{} subdomain levels", p.subdomain_labels.len()),
            });
        }
        if p.host.len() > scoring::LONG_THRESHOLD {
            out.push(Finding {
                code: FindingCode::LongHostname,
                points: scoring::LONG_HOSTNAME,
                detail: format!("hostname is {} characters", p.host.len()),
            });
        }
        let label = p.registrable_label;
        if label.len() >= scoring::ENTROPY_MIN_LEN && !label.starts_with("xn--") {
            let h = entropy_q16(label);
            if h >= scoring::ENTROPY_Q16_THRESHOLD {
                out.push(Finding {
                    code: FindingCode::HighEntropy,
                    points: scoring::HIGH_ENTROPY,
                    detail: format!(
                        "label entropy {}.{:02} bits/char",
                        h >> 16,
                        ((h & 0xffff) * 100) >> 16
                    ),
                });
            }
        }
        let digits = label.bytes().filter(u8::is_ascii_digit).count();
        if !label.starts_with("xn--") && digits >= 4 && digits * 10 >= label.len() * 3 {
            out.push(Finding {
                code: FindingCode::DigitHeavy,
                points: scoring::DIGIT_HEAVY,
                detail: format!("{digits} digits in registrable label"),
            });
        }
        let tld = p.suffix.rsplit('.').next().unwrap_or(p.suffix);
        if scoring::SUSPICIOUS_TLDS.contains(&tld) {
            out.push(Finding {
                code: FindingCode::SuspiciousTld,
                points: scoring::SUSPICIOUS_TLD,
                detail: format!(".{tld} is frequently abused"),
            });
        }
    }
}

fn is_legitimate(brand: &Brand, registrable: &str) -> bool {
    brand.legitimate.iter().any(|d| d == registrable)
}

/// Whole hyphen-separated part equals a token, or (for tokens of 6+ chars) a label contains it.
fn brand_tokens_in(brand: &Brand, labels: &[&str], parts: &[&str]) -> bool {
    brand.tokens.iter().any(|t| {
        parts.iter().any(|p| p == t) || (t.len() >= 6 && labels.iter().any(|l| l.contains(t.as_str())))
    })
}

/// A part that is a near-miss of a brand token: de-leeted equality for any token, edit
/// distance 1 for tokens of 6+ chars, distance 2 for tokens of 9+ chars.
fn lookalike_part<'a>(brand: &Brand, parts: &[&'a str]) -> Option<&'a str> {
    for p in parts {
        if p.len() < 4 {
            continue;
        }
        for t in &brand.tokens {
            if *p == t {
                continue;
            }
            let d = deleet(p);
            if d == *t {
                return Some(p);
            }
            let dist = edit_distance(p, t);
            if (t.len() >= 6 && dist == 1) || (t.len() >= 9 && dist == 2) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use cybermesh_crypto::Digest;

    use super::*;

    pub(crate) fn test_engine() -> Engine {
        let brands = vec![
            Brand {
                name: "examplebank".into(),
                tokens: vec!["examplebank".into()],
                legitimate: vec!["examplebank.test".into()],
            },
            Brand {
                name: "paypal".into(),
                tokens: vec!["paypal".into()],
                legitimate: vec!["paypal.com".into(), "paypal.me".into()],
            },
            Brand {
                name: "apple".into(),
                tokens: vec!["apple".into(), "icloud".into()],
                legitimate: vec!["apple.com".into(), "icloud.com".into()],
            },
        ];
        let ev = EvidenceBundle {
            blocklists: vec![(
                "reference-feed".into(),
                HashSet::from([
                    "examplebank-secure-login.phish.localhost".to_owned(),
                    "drive.google.com".to_owned(),
                    "malware-drop.xyz".to_owned(),
                ]),
            )],
            popular: HashSet::from(["google.com".to_owned(), "wikipedia.org".to_owned()]),
            brands,
            pins: BTreeMap::from([("reference-feed".into(), Digest::of(b"f"))]),
            sources: vec![],
            skipped_lines: 0,
        };
        Engine::new(ev)
    }

    fn verdict(e: &Engine, d: &str) -> (Verdict, u16, Vec<FindingCode>) {
        let a = e.assess(d).unwrap();
        (
            a.verdict,
            a.risk_score_bp,
            a.findings.iter().map(|f| f.code).collect(),
        )
    }

    #[test]
    fn feed_listed_phishing_domain_is_malicious_with_high_confidence() {
        let e = test_engine();
        let a = e.assess("examplebank-secure-login.phish.localhost").unwrap();
        assert_eq!(a.verdict, Verdict::Malicious);
        assert_eq!(a.risk_score_bp, 10_000);
        assert!(a.confidence_bp >= 9500);
        let codes: Vec<_> = a.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&FindingCode::FeedMatch));
        assert!(codes.contains(&FindingCode::BrandImpersonation));
        // Subdomain of a listed host also matches.
        assert_eq!(verdict(&e, "cdn.malware-drop.xyz").0, Verdict::Malicious);
    }

    #[test]
    fn lexical_only_phishing_is_suspicious_not_malicious() {
        let e = test_engine();
        let (v, s, codes) = verdict(&e, "examplebank-account-verify.phish.localhost");
        assert_eq!(v, Verdict::Suspicious, "score {s}");
        assert!(codes.contains(&FindingCode::BrandImpersonation));
        assert!(codes.contains(&FindingCode::SuspiciousKeywords));
    }

    #[test]
    fn popular_domain_overrides_feed_listing() {
        // URL-hosting feeds list abused paths on large platforms; a domain-level block
        // of drive.google.com would be a severe false positive.
        let e = test_engine();
        let a = e.assess("drive.google.com").unwrap();
        assert_eq!(a.verdict, Verdict::KnownBenign);
        assert_eq!(a.confidence_bp, 3000);
        let codes: Vec<_> = a.findings.iter().map(|f| f.code).collect();
        assert_eq!(codes, vec![FindingCode::FeedMatch, FindingCode::PopularDomain]);
    }

    #[test]
    fn brand_on_legitimate_domain_is_clean() {
        let e = test_engine();
        assert_eq!(verdict(&e, "examplebank.test").0, Verdict::NoSignal);
        assert_eq!(verdict(&e, "www.paypal.com").0, Verdict::NoSignal);
        // Generic word that is also a short brand token: alone it stays below threshold.
        assert_eq!(verdict(&e, "apple-pie-recipes.com").0, Verdict::NoSignal);
    }

    #[test]
    fn lookalikes_and_homographs() {
        let e = test_engine();
        let (v, _, codes) = verdict(&e, "paypa1-secure.com");
        assert!(codes.contains(&FindingCode::BrandLookalike), "{codes:?}");
        assert_eq!(v, Verdict::Suspicious);
        // Cyrillic 'а' in "pаypal".
        let (v, _, codes) = verdict(&e, "xn--pypal-4ve.com");
        assert!(codes.contains(&FindingCode::IdnHomograph), "{codes:?}");
        assert!(codes.contains(&FindingCode::MixedScript));
        assert_eq!(v, Verdict::Malicious);
    }

    #[test]
    fn structural_signals() {
        let e = test_engine();
        let (_, _, codes) = verdict(&e, "a.b.c.d.e.example.com");
        assert!(codes.contains(&FindingCode::DeepSubdomain));
        let (_, _, codes) = verdict(&e, "x7kq9zr2mw4tplv.top");
        assert!(codes.contains(&FindingCode::HighEntropy), "{codes:?}");
        assert!(codes.contains(&FindingCode::SuspiciousTld));
        let (_, _, codes) = verdict(&e, "secure-login-account-update.example.com");
        assert!(codes.contains(&FindingCode::ManyHyphens));
        assert_eq!(verdict(&e, "wikipedia.org").0, Verdict::KnownBenign);
        assert_eq!(verdict(&e, "mailservice.example.com").0, Verdict::NoSignal);
    }

    #[test]
    fn deterministic_output() {
        let e = test_engine();
        for d in [
            "examplebank-secure-login.phish.localhost",
            "xn--pypal-4ve.com",
            "x7kq9zr2mw4tplv.top",
        ] {
            let a = cybermesh_crypto::canonical::to_vec(&e.assess(d).unwrap()).unwrap();
            let b = cybermesh_crypto::canonical::to_vec(&e.clone().assess(d).unwrap()).unwrap();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn legitimate_idns_get_no_structural_findings() {
        let e = test_engine();
        for d in ["xn--bcher-kva.de", "xn--e1afmkfd.xn--p1ai", "xn--mnchen-3ya.de", "xn--80aswg.xn--p1ai"] {
            let a = e.assess(d).unwrap();
            assert!(
                a.findings.is_empty(),
                "{d}: {:?}",
                a.findings.iter().map(|f| f.code).collect::<Vec<_>>()
            );
            assert_eq!(a.verdict, Verdict::NoSignal);
        }
    }

    #[test]
    fn whole_script_homograph_of_apple_is_detected() {
        // "аррӏе.com" written entirely in Cyrillic: the classic homograph demonstration.
        let e = test_engine();
        let a = e.assess("xn--80ak6aa92e.com").unwrap();
        assert!(a.findings.iter().any(|f| f.code == FindingCode::IdnHomograph));
        assert!(!a.findings.iter().any(|f| f.code == FindingCode::DigitHeavy));
    }

    /// Golden vectors: the exact canonical output for a fixed corpus. Any change to scoring,
    /// tables (PSL/IDNA) or encoding changes this digest and must bump ENGINE_VERSION.
    #[test]
    fn golden_vectors() {
        let e = test_engine();
        let corpus = [
            "examplebank-secure-login.phish.localhost",
            "examplebank-account-verify.phish.localhost",
            "drive.google.com",
            "xn--pypal-4ve.com",
            "xn--bcher-kva.de",
            "paypa1-secure.com",
            "x7kq9zr2mw4tplv.top",
            "a.b.c.d.e.example.com",
            "secure-login-account-update.example.com",
            "evil.github.io",
            "www.example.co.uk",
            "apple-pie-recipes.com",
        ];
        let out: Vec<_> = corpus.iter().map(|d| e.assess(d).unwrap()).collect();
        let bytes = cybermesh_crypto::canonical::to_vec(&out).unwrap();
        let summary: Vec<(u16, Verdict)> = out.iter().map(|a| (a.risk_score_bp, a.verdict)).collect();
        assert_eq!(
            summary,
            vec![
                (10_000, Verdict::Malicious),
                (4900, Verdict::Suspicious),
                (0, Verdict::KnownBenign),
                (8500, Verdict::Malicious),
                (0, Verdict::NoSignal),
                (5200, Verdict::Suspicious),
                (2700, Verdict::NoSignal),
                (800, Verdict::NoSignal),
                (3000, Verdict::NoSignal),
                (0, Verdict::NoSignal),
                (0, Verdict::NoSignal),
                (3500, Verdict::NoSignal),
            ]
        );
        assert_eq!(Digest::of(&bytes).to_string(), GOLDEN_DIGEST);
    }

    const GOLDEN_DIGEST: &str =
        "sha256:f81c8096736b55f8d8c54bd1ddfe9128b7936d169d85326a988b176e72405a7e";

    #[test]
    fn rejects_unnormalised_input() {
        let e = test_engine();
        assert!(e.assess("Example.COM").is_err());
        assert!(e.assess("1.2.3.4").is_err());
    }
}
