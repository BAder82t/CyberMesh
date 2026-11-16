//! Classification policy: which verified assessments may be published, and how strongly.

use cybermesh_protocol::{DomainAssessment, FindingCode, Verdict};
use serde::{Deserialize, Serialize};

/// What a release may do with a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Classification {
    /// High-confidence: eligible for automatic blocking where the user/admin opted in.
    Block,
    /// Advisory: show a dismissible warning.
    Warn,
    /// Not published.
    None,
}

/// Verifier policy. Defaults are conservative.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Distinct operators that must agree before anything is published.
    pub min_operators: usize,
    /// Seconds after task expiry during which results are still accepted.
    pub result_grace_secs: u64,
    /// Minimum score for an advisory warning.
    pub warn_min_score_bp: u16,
    /// Minimum score for a block (in addition to independent feed corroboration).
    pub block_min_score_bp: u16,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_operators: 3,
            result_grace_secs: 60,
            warn_min_score_bp: 4000,
            block_min_score_bp: 7000,
        }
    }
}

impl Policy {
    /// Rejects unsafe or inconsistent settings.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_operators == 0 {
            return Err("min_operators must be at least 1".into());
        }
        if self.warn_min_score_bp == 0
            || self.warn_min_score_bp > self.block_min_score_bp
            || self.block_min_score_bp > 10_000
        {
            return Err("require 0 < warn_min_score_bp <= block_min_score_bp <= 10000".into());
        }
        Ok(())
    }

    /// Classifies an assessment that `agreeing_operators` operators produced identically.
    ///
    /// `feed_corroborated` must come from the verifier's own evidence, never from the
    /// worker-supplied findings.
    #[must_use]
    pub fn classify(
        &self,
        a: &DomainAssessment,
        agreeing_operators: usize,
        feed_corroborated: bool,
    ) -> (Classification, &'static str) {
        if agreeing_operators < self.min_operators {
            return (Classification::None, "insufficient independent operators");
        }
        if a.verdict == Verdict::KnownBenign
            || a.findings
                .iter()
                .any(|f| f.code == FindingCode::PopularDomain)
        {
            return (Classification::None, "on popularity allowlist");
        }
        let risky = matches!(a.verdict, Verdict::Malicious | Verdict::Suspicious);
        if !risky || a.risk_score_bp < self.warn_min_score_bp {
            return (Classification::None, "no actionable risk");
        }
        let claims_feed = a.findings.iter().any(|f| f.code == FindingCode::FeedMatch);
        if a.verdict == Verdict::Malicious
            && a.risk_score_bp >= self.block_min_score_bp
            && claims_feed
            && feed_corroborated
        {
            return (
                Classification::Block,
                "malicious verdict corroborated by an independent reference feed",
            );
        }
        if claims_feed && !feed_corroborated {
            // Workers claim a feed listing the verifier cannot confirm: never escalate.
            return (
                Classification::Warn,
                "feed listing claimed by workers but not confirmed by verifier",
            );
        }
        (
            Classification::Warn,
            "lexical risk agreed by independent operators (advisory only)",
        )
    }
}

#[cfg(test)]
mod tests {
    use cybermesh_protocol::Finding;

    use super::*;

    fn a(verdict: Verdict, score: u16, codes: &[FindingCode]) -> DomainAssessment {
        DomainAssessment {
            domain: "x.example.com".into(),
            risk_score_bp: score,
            confidence_bp: 5000,
            verdict,
            findings: codes
                .iter()
                .map(|c| Finding {
                    code: *c,
                    points: 0,
                    detail: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn block_requires_independent_corroboration() {
        let p = Policy::default();
        let m = a(Verdict::Malicious, 10_000, &[FindingCode::FeedMatch]);
        assert_eq!(p.classify(&m, 3, true).0, Classification::Block);
        assert_eq!(p.classify(&m, 3, false).0, Classification::Warn);
        assert_eq!(p.classify(&m, 2, true).0, Classification::None);
        let lexical = a(Verdict::Malicious, 9000, &[FindingCode::IdnHomograph]);
        assert_eq!(p.classify(&lexical, 10, true).0, Classification::Warn);
    }

    #[test]
    fn benign_and_low_risk_are_never_published() {
        let p = Policy::default();
        let pop = a(
            Verdict::KnownBenign,
            9000,
            &[FindingCode::FeedMatch, FindingCode::PopularDomain],
        );
        assert_eq!(p.classify(&pop, 5, true).0, Classification::None);
        let low = a(Verdict::NoSignal, 3000, &[]);
        assert_eq!(p.classify(&low, 5, true).0, Classification::None);
    }
}
