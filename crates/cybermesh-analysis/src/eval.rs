//! Evaluation metrics for protection quality (precision, recall, false-positive rate).
//!
//! Floating point is used here for reporting only; it never feeds into signed protocol data.

use std::fmt;

use cybermesh_protocol::{DomainAssessment, FindingCode, Verdict};
use serde::Serialize;

/// Binary confusion matrix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Confusion {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    pub fn_: u64,
}

impl Confusion {
    pub fn record(&mut self, predicted_malicious: bool, actually_malicious: bool) {
        match (predicted_malicious, actually_malicious) {
            (true, true) => self.tp += 1,
            (true, false) => self.fp += 1,
            (false, false) => self.tn += 1,
            (false, true) => self.fn_ += 1,
        }
    }

    #[must_use]
    pub fn total(&self) -> u64 {
        self.tp + self.fp + self.tn + self.fn_
    }

    #[must_use]
    pub fn precision(&self) -> Option<f64> {
        ratio(self.tp, self.tp + self.fp)
    }

    #[must_use]
    pub fn recall(&self) -> Option<f64> {
        ratio(self.tp, self.tp + self.fn_)
    }

    #[must_use]
    pub fn false_positive_rate(&self) -> Option<f64> {
        ratio(self.fp, self.fp + self.tn)
    }

    #[must_use]
    pub fn f1(&self) -> Option<f64> {
        let p = self.precision()?;
        let r = self.recall()?;
        if p + r == 0.0 {
            return Some(0.0);
        }
        Some(2.0 * p * r / (p + r))
    }
}

#[allow(clippy::cast_precision_loss)]
fn ratio(a: u64, b: u64) -> Option<f64> {
    (b > 0).then(|| a as f64 / b as f64)
}

impl fmt::Display for Confusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = |o: Option<f64>| o.map_or_else(|| "n/a".to_owned(), |v| format!("{v:.3}"));
        write!(
            f,
            "tp={} fp={} tn={} fn={} precision={} recall={} fpr={} f1={}",
            self.tp,
            self.fp,
            self.tn,
            self.fn_,
            p(self.precision()),
            p(self.recall()),
            p(self.false_positive_rate()),
            p(self.f1())
        )
    }
}

/// Decision rules compared in the evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Detector {
    /// Baseline: flag exactly what the reference feed lists (domain-level).
    FeedOnly,
    /// Lexical signals only (feed ignored): verdict suspicious or worse.
    LexicalOnly,
    /// Full engine, verdict malicious (what CyberMesh may *block* given corroboration).
    EngineMalicious,
    /// Full engine, verdict suspicious or worse (what CyberMesh may *warn* on).
    EngineSuspicious,
}

impl Detector {
    pub const ALL: [Detector; 4] = [
        Detector::FeedOnly,
        Detector::LexicalOnly,
        Detector::EngineMalicious,
        Detector::EngineSuspicious,
    ];

    /// Applies the rule to an engine assessment.
    #[must_use]
    pub fn flags(self, a: &DomainAssessment) -> bool {
        let feed = a.findings.iter().any(|f| f.code == FindingCode::FeedMatch);
        match self {
            Detector::FeedOnly => feed,
            Detector::LexicalOnly => {
                let lexical: i64 = a
                    .findings
                    .iter()
                    .filter(|f| f.code != FindingCode::FeedMatch)
                    .map(|f| i64::from(f.points))
                    .sum();
                lexical >= i64::from(crate::scoring::SUSPICIOUS_THRESHOLD)
            }
            Detector::EngineMalicious => a.verdict == Verdict::Malicious,
            Detector::EngineSuspicious => {
                matches!(a.verdict, Verdict::Malicious | Verdict::Suspicious)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics() {
        let mut c = Confusion::default();
        for _ in 0..8 {
            c.record(true, true);
        }
        for _ in 0..2 {
            c.record(true, false);
        }
        for _ in 0..88 {
            c.record(false, false);
        }
        for _ in 0..2 {
            c.record(false, true);
        }
        assert_eq!(c.total(), 100);
        assert!((c.precision().unwrap() - 0.8).abs() < 1e-9);
        assert!((c.recall().unwrap() - 0.8).abs() < 1e-9);
        assert!((c.false_positive_rate().unwrap() - 2.0 / 90.0).abs() < 1e-9);
        assert!(Confusion::default().precision().is_none());
    }
}
