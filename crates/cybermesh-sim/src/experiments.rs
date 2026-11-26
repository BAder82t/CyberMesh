//! The named experiments. Each takes a base scenario, varies one thing and returns a table. Every
//! number comes from the deterministic simulation: **simulated, not measured on real infrastructure**.

use crate::engine::{drain_bound, simulate};
use crate::report::Table;
use crate::scenario::{AdversaryCfg, Scenario, SimError};

/// Secure delivery and breaches against the number of corrupt domains, for a plan that assumes
/// `base.requirement.corrupt_domains`. Breaches **through the paths** must be zero while the
/// corruption stays within the assumption (a theorem of domain-disjoint planning when the router
/// knows the domains); endpoint breaches grow with corruption whatever the plan.
///
/// # Errors
/// As [`simulate`].
pub fn corruption_sweep(base: &Scenario, corrupt: &[usize]) -> Result<Table, SimError> {
    let mut rows = Vec::new();
    for &c in corrupt {
        let sc = Scenario {
            adversary: AdversaryCfg::Static { corrupt_domains: c },
            detect_ticks: u32::MAX, // the router never learns: the worst case for the plan
            ..base.clone()
        };
        let r = simulate(&sc)?;
        rows.push(vec![
            c as f64,
            base.requirement.corrupt_domains as f64,
            r.availability(),
            r.breach_rate_paths(),
            r.breach_rate_endpoint(),
            r.secret_per_payload(),
        ]);
    }
    Ok(Table {
        columns: vec![
            "corrupt_domains",
            "assumed_t",
            "availability",
            "breach_via_paths",
            "breach_endpoint",
            "secret_per_payload",
        ],
        rows,
    })
}

/// Availability against administrative diversity: the same participants spread over more or
/// fewer domains, with random link failures and domain outages.
///
/// # Errors
/// As [`simulate`].
pub fn diversity_sweep(base: &Scenario, domain_counts: &[usize]) -> Result<Table, SimError> {
    let mut rows = Vec::new();
    for &d in domain_counts {
        let r = simulate(&Scenario {
            domains: d,
            ..base.clone()
        })?;
        rows.push(vec![
            d as f64,
            r.availability(),
            r.no_plan_rate(),
            r.lost_rate(),
            r.mean_recovery_ticks(),
        ]);
    }
    Ok(Table {
        columns: vec![
            "domains",
            "availability",
            "no_plan",
            "lost",
            "mean_recovery_ticks",
        ],
        rows,
    })
}

/// Cost and availability against the assumed number of corrupt domains `t`: the plan needs more
/// disjoint paths (shares) as `t` grows, and so more wire and secret per payload byte.
///
/// # Errors
/// As [`simulate`].
pub fn threshold_sweep(base: &Scenario, ts: &[usize]) -> Result<Table, SimError> {
    let mut rows = Vec::new();
    for &t in ts {
        let mut sc = base.clone();
        sc.requirement.corrupt_domains = t;
        let r = simulate(&sc)?;
        rows.push(vec![
            t as f64,
            r.paths_per_message as f64,
            r.wire_per_payload(),
            r.secret_per_payload(),
            r.availability(),
            r.no_plan_rate(),
        ]);
    }
    Ok(Table {
        columns: vec![
            "t",
            "paths_n",
            "wire_per_payload",
            "secret_per_payload",
            "availability",
            "no_plan",
        ],
        rows,
    })
}

/// A mobile adversary holding `corrupt_domains` domains at a time, moving with probability
/// `move_prob` per tick, against the router's detection delay: breaches through the paths and the
/// time to recover.
///
/// # Errors
/// As [`simulate`].
pub fn mobile_sweep(
    base: &Scenario,
    corrupt_domains: usize,
    move_probs: &[f64],
) -> Result<Table, SimError> {
    let mut rows = Vec::new();
    for &p in move_probs {
        let sc = Scenario {
            adversary: AdversaryCfg::Mobile {
                corrupt_domains,
                move_prob: p,
            },
            ..base.clone()
        };
        let r = simulate(&sc)?;
        rows.push(vec![
            p,
            r.availability(),
            r.breach_rate_paths(),
            r.breach_rate_endpoint(),
            r.mean_recovery_ticks(),
            f64::from(r.recovery_max_ticks),
        ]);
    }
    Ok(Table {
        columns: vec![
            "move_prob",
            "availability",
            "breach_via_paths",
            "breach_endpoint",
            "mean_recovery_ticks",
            "max_recovery_ticks",
        ],
        rows,
    })
}

/// Share bytes a pair can send before running out of secret, against the max-flow bound, over
/// several seeds. The ratio must never exceed 1.
///
/// # Errors
/// As [`drain_bound`].
pub fn drain_sweep(base: &Scenario, seeds: &[u64]) -> Result<Table, SimError> {
    let mut rows = Vec::new();
    for &seed in seeds {
        let d = drain_bound(&Scenario {
            seed,
            replenish_per_tick: 0,
            ..base.clone()
        })?;
        rows.push(vec![
            seed as f64,
            d.paths as f64,
            d.bound as f64,
            d.measured as f64,
            d.ratio(),
            d.sends as f64,
        ]);
    }
    Ok(Table {
        columns: vec![
            "seed",
            "paths_n",
            "flow_bound_bytes",
            "measured_bytes",
            "ratio",
            "sends",
        ],
        rows,
    })
}
