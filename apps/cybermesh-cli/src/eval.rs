use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Result, bail};
use clap::Args;
use cybermesh_analysis::eval::{Confusion, Detector};
use cybermesh_analysis::{Engine, EvidenceBundle, normalize_domain};
use serde::Serialize;

use crate::util::{read, write_json};

pub fn analyze(evidence: &Path, domains: &[String]) -> Result<()> {
    let engine = Engine::new(EvidenceBundle::load(evidence)?);
    for d in domains {
        match normalize_domain(d) {
            Ok(n) => println!("{}", serde_json::to_string_pretty(&engine.assess(&n)?)?),
            Err(e) => eprintln!("{d}: {e}"),
        }
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct EvalArgs {
    /// Evidence bundle used by the engine (its blocklist is the feed baseline).
    #[arg(long)]
    pub evidence: PathBuf,
    /// CSV: `domain,label[,split]` with label `malicious` or `benign`.
    #[arg(long)]
    pub dataset: PathBuf,
    /// Only rows whose split column equals this value.
    #[arg(long)]
    pub split: Option<String>,
    /// Write a JSON report here.
    #[arg(long)]
    pub json_out: Option<PathBuf>,
    /// Print up to N example errors per detector.
    #[arg(long, default_value_t = 10)]
    pub examples: usize,
}

#[derive(Serialize)]
struct DetectorReport {
    confusion: Confusion,
    precision: Option<f64>,
    recall: Option<f64>,
    false_positive_rate: Option<f64>,
    f1: Option<f64>,
    false_positive_examples: Vec<String>,
}

#[derive(Serialize)]
struct EvalReport {
    dataset: String,
    split: Option<String>,
    rows: usize,
    skipped_rows: usize,
    malicious: usize,
    benign: usize,
    engine_micros_per_domain: f64,
    evidence_pins: BTreeMap<String, String>,
    detectors: BTreeMap<String, DetectorReport>,
}

pub fn eval(a: &EvalArgs) -> Result<()> {
    let engine = Engine::new(EvidenceBundle::load(&a.evidence)?);
    let text = String::from_utf8_lossy(&read(&a.dataset)?).into_owned();
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("domain,") {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 2 {
            skipped += 1;
            continue;
        }
        if let Some(s) = &a.split
            && cols.get(2).copied() != Some(s.as_str())
        {
            continue;
        }
        let label = match cols[1] {
            "malicious" => true,
            "benign" => false,
            _ => {
                skipped += 1;
                continue;
            }
        };
        match normalize_domain(cols[0]) {
            Ok(d) => rows.push((d, label)),
            Err(_) => skipped += 1,
        }
    }
    if rows.is_empty() {
        bail!("no usable rows");
    }
    let mut conf: BTreeMap<&'static str, (Confusion, Vec<String>)> = BTreeMap::new();
    let names = [
        "feed-only",
        "lexical-only",
        "engine-malicious",
        "engine-suspicious",
    ];
    let start = Instant::now();
    let mut assessments = Vec::with_capacity(rows.len());
    for (d, _) in &rows {
        assessments.push(engine.assess(d)?);
    }
    let per = start.elapsed().as_secs_f64() * 1e6 / rows.len() as f64;
    for ((d, label), asmt) in rows.iter().zip(&assessments) {
        for (det, name) in Detector::ALL.iter().zip(names) {
            let flagged = det.flags(asmt);
            let e = conf.entry(name).or_default();
            e.0.record(flagged, *label);
            if flagged && !label && e.1.len() < a.examples {
                e.1.push(d.clone());
            }
        }
    }
    let malicious = rows.iter().filter(|r| r.1).count();
    println!(
        "dataset={} split={} rows={} (malicious={} benign={}) skipped={} engine={:.1}us/domain",
        a.dataset.display(),
        a.split.as_deref().unwrap_or("all"),
        rows.len(),
        malicious,
        rows.len() - malicious,
        skipped,
        per
    );
    let mut detectors = BTreeMap::new();
    for name in names {
        let (c, fps) = conf.remove(name).unwrap_or_default();
        println!("  {name:<18} {c}");
        detectors.insert(
            name.to_owned(),
            DetectorReport {
                precision: c.precision(),
                recall: c.recall(),
                false_positive_rate: c.false_positive_rate(),
                f1: c.f1(),
                confusion: c,
                false_positive_examples: fps,
            },
        );
    }
    if let Some(p) = &a.json_out {
        write_json(
            p,
            &EvalReport {
                dataset: a.dataset.display().to_string(),
                split: a.split.clone(),
                rows: rows.len(),
                skipped_rows: skipped,
                malicious,
                benign: rows.len() - malicious,
                engine_micros_per_domain: per,
                evidence_pins: engine
                    .evidence()
                    .pins
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_string()))
                    .collect(),
                detectors,
            },
        )?;
    }
    Ok(())
}

pub fn bench(evidence: &Path, n: usize) -> Result<()> {
    let engine = Engine::new(EvidenceBundle::load(evidence)?);
    let samples = [
        "examplebank-secure-login.phish.localhost",
        "www.wikipedia.org",
        "x7kq9zr2mw4tplv.top",
        "xn--pypal-4ve.com",
        "login.microsoft-account-verify.example.net",
        "mail.example.co.uk",
    ];
    let cpu0 = cybermesh_node::governor::process_cpu();
    let t0 = Instant::now();
    let mut sink = 0u64;
    for i in 0..n {
        let a = engine.assess(samples[i % samples.len()])?;
        sink = sink.wrapping_add(u64::from(a.risk_score_bp));
    }
    let wall = t0.elapsed();
    let cpu = cybermesh_node::governor::process_cpu().saturating_sub(cpu0);
    std::hint::black_box(sink);
    println!(
        "{n} assessments in {:.3}s wall / {:.3}s CPU: {:.0} domains/s, {:.2} us/domain CPU",
        wall.as_secs_f64(),
        cpu.as_secs_f64(),
        n as f64 / wall.as_secs_f64(),
        cpu.as_secs_f64() * 1e6 / n as f64
    );
    println!(
        "at a 1% CPU budget one worker can assess about {:.0} domains/hour",
        3600.0 * 0.01 / (cpu.as_secs_f64() / n as f64)
    );
    Ok(())
}
