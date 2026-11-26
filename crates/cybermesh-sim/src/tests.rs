#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::experiments as exp;

fn base() -> Scenario {
    Scenario {
        participants: 120,
        domains: 20,
        sessions: 10,
        ticks: 20,
        ..Scenario::default()
    }
}

fn with_adversary(a: AdversaryCfg, detect: u32, seed: u64) -> Scenario {
    Scenario {
        adversary: a,
        detect_ticks: detect,
        seed,
        ..base()
    }
}

// ---- the generator ----------------------------------------------------------------------------

#[test]
fn the_generator_is_deterministic_bounded_and_forkable() {
    let (mut a, mut b) = (SimRng::new(42), SimRng::new(42));
    assert!((0..100).all(|_| a.next_u64() == b.next_u64()));
    assert_ne!(SimRng::new(1).next_u64(), SimRng::new(2).next_u64());
    let mut r = SimRng::new(7);
    assert!((0..2000).all(|_| r.below(7) < 7));
    assert!((0..2000).all(|_| (3..=9).contains(&r.range(3, 9))));
    assert!(!r.chance(0.0) && (0..50).all(|_| r.chance(1.0)));
    let heads = (0..20_000).filter(|_| r.chance(0.5)).count();
    assert!((9_600..10_400).contains(&heads), "{heads}");
    // Forks are independent streams.
    let mut parent = SimRng::new(9);
    let (mut f1, mut f2) = (parent.fork(1), parent.fork(1));
    assert_ne!(f1.next_u64(), f2.next_u64());
}

// ---- reproducibility and scenarios ------------------------------------------------------------

#[test]
fn the_same_scenario_gives_the_same_report_and_another_seed_a_different_one() {
    let sc = Scenario {
        adversary: AdversaryCfg::Mobile {
            corrupt_domains: 3,
            move_prob: 0.3,
        },
        link_failure_prob: 0.02,
        domain_outage_prob: 0.01,
        ..base()
    };
    let a = simulate(&sc).unwrap();
    assert_eq!(a, simulate(&sc).unwrap());
    assert_ne!(a, simulate(&Scenario { seed: 2, ..sc }).unwrap());
}

#[test]
fn scenarios_round_trip_through_toml_and_bad_ones_are_rejected() {
    let sc = Scenario {
        adversary: AdversaryCfg::Mobile {
            corrupt_domains: 2,
            move_prob: 0.25,
        },
        ..base()
    };
    let text = sc.to_toml().unwrap();
    assert!(text.contains("kind = \"mobile\""));
    assert_eq!(Scenario::from_toml(&text).unwrap(), sc);
    assert_eq!(
        Scenario::from_toml(&Scenario::default().to_toml().unwrap()).unwrap(),
        Scenario::default()
    );
    // Unknown fields and values out of range fail instead of being ignored.
    assert!(matches!(
        Scenario::from_toml(&format!("bogus = 1\n{text}")),
        Err(SimError::Parse(_))
    ));
    for bad in [
        Scenario {
            participants: 3,
            ..base()
        },
        Scenario {
            domains: 2,
            ..base()
        },
        Scenario {
            domains: 500,
            ..base()
        },
        Scenario {
            latency_min_ms: 0,
            ..base()
        },
        Scenario {
            sessions: 0,
            ..base()
        },
        Scenario {
            link_failure_prob: 1.5,
            ..base()
        },
        Scenario {
            adversary: AdversaryCfg::Static {
                corrupt_domains: 99,
            },
            ..base()
        },
        Scenario {
            adversary: AdversaryCfg::Mobile {
                corrupt_domains: 1,
                move_prob: 2.0,
            },
            ..base()
        },
    ] {
        assert!(
            matches!(simulate(&bad), Err(SimError::Invalid(_))),
            "{bad:?}"
        );
    }
    // Tampering assumed with no protection cannot even be planned.
    let mut unprotected = base();
    unprotected.requirement.protection = ProtectionCfg::None;
    assert!(matches!(simulate(&unprotected), Err(SimError::Routing(_))));
}

// ---- behaviour --------------------------------------------------------------------------------

#[test]
fn without_adversary_or_failures_everything_is_delivered_and_the_books_balance() {
    let sc = base();
    let r = simulate(&sc).unwrap();
    assert_eq!(r.attempted, 10 * 20);
    assert_eq!(r.delivered, r.attempted);
    assert_eq!(
        (
            r.breached_paths,
            r.breached_endpoint,
            r.no_plan,
            r.starved,
            r.lost
        ),
        (0, 0, 0, 0, 0)
    );
    assert_eq!(
        r.paths_per_message, 3,
        "t = 1 with authenticated shares needs 2t + 1 paths"
    );
    let per_path = sc.msg_bytes + RECORD_OVERHEAD;
    assert_eq!(r.wire_bytes, r.attempted * 3 * per_path);
    assert_eq!(r.payload_bytes, r.attempted * sc.msg_bytes);
    // Every share crosses at least one hop, so the secret spent is at least the wire bytes.
    assert!(r.secret_consumed >= r.wire_bytes);
    assert!((r.wire_per_payload() - 3.0 * per_path as f64 / sc.msg_bytes as f64).abs() < 1e-9);
    assert_eq!(r.delivered_by_tick, vec![10; 20]);
    assert_eq!(r.recoveries, 0);
}

#[test]
fn corruption_within_the_assumption_never_breaches_through_the_paths() {
    // t = 1: with the router never learning of the corruption, one corrupt domain still cannot
    // hold the two shares the threshold needs, because the paths are domain-disjoint.
    for seed in 1..=8 {
        let r = simulate(&with_adversary(
            AdversaryCfg::Static { corrupt_domains: 1 },
            u32::MAX,
            seed,
        ))
        .unwrap();
        assert_eq!(r.breached_paths, 0, "seed {seed}");
    }
    // Beyond the assumption it can: several corrupt domains do get two shares on some messages.
    let breached: u64 = (1..=6)
        .map(|seed| {
            simulate(&with_adversary(
                AdversaryCfg::Static { corrupt_domains: 8 },
                u32::MAX,
                seed,
            ))
            .unwrap()
            .breached_paths
        })
        .sum();
    assert!(breached > 0);
}

#[test]
fn knowing_the_corrupt_domains_turns_breaches_into_refusals() {
    let (mut refused, mut endpoint_unknown, mut paths_unknown) = (0, 0, 0);
    for seed in 1..=6 {
        let a = AdversaryCfg::Static { corrupt_domains: 5 };
        // The router excludes corrupt domains from the start: nothing corrupt is ever on a path,
        // and it will not even talk to an endpoint it knows is corrupt, so nothing is breached.
        let known = simulate(&with_adversary(a, 0, seed)).unwrap();
        assert_eq!(
            (known.breached_paths, known.breached_endpoint),
            (0, 0),
            "seed {seed}"
        );
        refused += known.no_plan;
        // A router that never learns is breached, through the paths and at the endpoints.
        let blind = simulate(&with_adversary(a, u32::MAX, seed)).unwrap();
        endpoint_unknown += blind.breached_endpoint;
        paths_unknown += blind.breached_paths;
    }
    assert!(
        refused > 0,
        "sessions with a known-corrupt endpoint are refused, not served"
    );
    assert!(endpoint_unknown > 0 && paths_unknown > 0);
}

#[test]
fn a_mobile_adversary_is_caught_more_slowly_than_it_moves() {
    let (mut fast, mut slow) = (0, 0);
    for seed in 1..=4 {
        let a = AdversaryCfg::Mobile {
            corrupt_domains: 5,
            move_prob: 1.0,
        }; // moves every tick
        // Detection after 3 ticks never sees a domain that stays corrupt for one tick.
        fast += simulate(&with_adversary(a, 3, seed))
            .unwrap()
            .breached_paths;
        let a = AdversaryCfg::Mobile {
            corrupt_domains: 5,
            move_prob: 0.0,
        }; // never moves
        slow += simulate(&with_adversary(a, 3, seed))
            .unwrap()
            .breached_paths;
    }
    assert!(
        fast > slow,
        "moving faster than detection costs breaches: {fast} vs {slow}"
    );
}

#[test]
fn secret_runs_out_without_provisioning_and_provisioning_restores_service() {
    let drained = Scenario {
        initial_secret: 5_000,
        replenish_per_tick: 0,
        ticks: 40,
        ..base()
    };
    let r = simulate(&drained).unwrap();
    let first = r.delivered_by_tick[0];
    let last = *r.delivered_by_tick.last().unwrap();
    assert!(first > 0 && last < first, "{first} -> {last}");
    assert!(r.starved + r.no_plan > 0);
    // Total spending can never exceed what was provisioned: 2 directions per link.
    let links_upper_bound = 120u64 * 10; // far above any link count here
    assert!(r.secret_consumed <= links_upper_bound * 2 * 5_000);
    // The same network with enough provisioning keeps delivering.
    let fed = Scenario {
        replenish_per_tick: 200_000,
        ..drained
    };
    assert!(simulate(&fed).unwrap().availability() > r.availability());
}

#[test]
fn spare_paths_absorb_failures_and_correlated_outages_cost_availability() {
    let flaky = Scenario {
        link_failure_prob: 0.02,
        ..base()
    };
    let bare = simulate(&flaky).unwrap();
    let spare = simulate(&Scenario {
        requirement: RequirementCfg {
            path_failures: 2,
            ..flaky.requirement
        },
        ..flaky.clone()
    })
    .unwrap();
    assert!(bare.lost > 0, "unannounced failures lose shares");
    assert!(spare.availability() >= bare.availability());
    assert!(
        spare.wire_per_payload() > bare.wire_per_payload(),
        "redundancy costs wire"
    );
    // A whole-domain outage is a correlated failure.
    let calm = simulate(&base()).unwrap();
    let outages = simulate(&Scenario {
        domain_outage_prob: 0.05,
        ..base()
    })
    .unwrap();
    assert!(outages.availability() < calm.availability());
    assert!(outages.recoveries > 0 && outages.mean_recovery_ticks() > 0.0);
}

#[test]
fn it_runs_thousands_of_participants() {
    let sc = Scenario {
        participants: 2000,
        domains: 120,
        sessions: 4,
        ticks: 2,
        link_failure_prob: 0.01,
        adversary: AdversaryCfg::Static { corrupt_domains: 5 },
        ..Scenario::default()
    };
    let r = simulate(&sc).unwrap();
    assert_eq!(r.attempted, 8);
    assert_eq!(r.delivered_by_tick.len(), 2);
}

// ---- measured against the bound ---------------------------------------------------------------

#[test]
fn bytes_sent_before_running_dry_never_exceed_the_flow_bound() {
    for seed in 1..=5 {
        let d = drain_bound(&Scenario {
            seed,
            replenish_per_tick: 0,
            initial_secret: 1 << 14,
            ..base()
        })
        .unwrap();
        assert!(d.bound > 0 && d.measured > 0, "seed {seed}");
        assert!(
            d.measured <= d.bound,
            "seed {seed}: {} > {}",
            d.measured,
            d.bound
        );
        assert!(
            d.ratio() > 0.3,
            "the planner should use a good share of the cut: {}",
            d.ratio()
        );
        assert_eq!(
            d.measured,
            d.sends * d.paths as u64 * (512 + RECORD_OVERHEAD)
        );
    }
}

// ---- experiments and tables -------------------------------------------------------------------

#[test]
fn experiments_produce_well_formed_tables() {
    let b = Scenario {
        ticks: 8,
        sessions: 6,
        ..base()
    };
    let t = exp::corruption_sweep(&b, &[0, 1, 4]).unwrap();
    assert_eq!(t.columns.len(), 6);
    assert_eq!(t.rows.len(), 3);
    assert!(t.rows.iter().all(|r| r.len() == 6));
    assert_eq!(
        t.rows[0][3], 0.0,
        "no breach through the paths without corruption"
    );
    let th = exp::threshold_sweep(&b, &[0, 1, 2]).unwrap();
    let paths: Vec<f64> = th.rows.iter().map(|r| r[1]).collect();
    assert_eq!(
        paths,
        vec![1.0, 3.0, 5.0],
        "n = 2t + 1 with authenticated shares"
    );
    let wire: Vec<f64> = th.rows.iter().map(|r| r[2]).collect();
    assert!(
        wire.windows(2).all(|w| w[0] < w[1]),
        "communication grows with the threshold"
    );
    assert_eq!(exp::diversity_sweep(&b, &[6, 20]).unwrap().rows.len(), 2);
    assert_eq!(exp::mobile_sweep(&b, 2, &[0.0, 1.0]).unwrap().rows.len(), 2);
    let dr = exp::drain_sweep(
        &Scenario {
            initial_secret: 1 << 14,
            ..b.clone()
        },
        &[1, 2],
    )
    .unwrap();
    assert!(dr.rows.iter().all(|r| r[4] <= 1.0 && r[4] > 0.0));
    let csv = t.to_csv();
    assert!(csv.starts_with("corrupt_domains,assumed_t,"));
    assert_eq!(csv.lines().count(), 4);
    let md = t.to_markdown();
    assert!(md.starts_with("| corrupt_domains |") && md.contains("|---|"));
}

#[test]
fn averaging_keeps_the_swept_parameter_and_rejects_mismatched_tables() {
    let t = |a: f64, b: f64| Table {
        columns: vec!["x", "y"],
        rows: vec![vec![1.0, a], vec![2.0, b]],
    };
    let avg = Table::average(&[t(1.0, 10.0), t(3.0, 20.0)]).unwrap();
    assert_eq!(avg.rows, vec![vec![1.0, 2.0], vec![2.0, 15.0]]);
    assert!(Table::average(&[]).is_none());
    let other = Table {
        columns: vec!["x", "z"],
        rows: vec![vec![1.0, 0.0], vec![2.0, 0.0]],
    };
    assert!(Table::average(&[t(1.0, 1.0), other]).is_none());
    let short = Table {
        columns: vec!["x", "y"],
        rows: vec![vec![1.0, 0.0]],
    };
    assert!(Table::average(&[t(1.0, 1.0), short]).is_none());
}
