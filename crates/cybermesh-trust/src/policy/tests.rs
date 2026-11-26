#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use cybermesh_entropy::{Pool, PoolId, Provenance, Purpose, Reservation};
use std::collections::BTreeSet;

fn p(n: u32) -> ParticipantId {
    ParticipantId(n)
}
fn d(n: u32) -> DomainId {
    DomainId(n)
}
fn set(v: &[u32]) -> BTreeSet<DomainId> {
    v.iter().map(|&n| DomainId(n)).collect()
}
const ACT: [u8; 16] = [0xA1; 16];
const SES: [u8; 16] = [0x51; 16];

/// Registry with domains 1..=3, two participants each: (1,2) in domain 1, (3,4) in 2, (5,6) in 3.
fn registry() -> Registry {
    let mut r = Registry::new();
    for (pid, dom) in [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3), (6, 3)] {
        r.register(p(pid), d(dom)).unwrap();
    }
    r
}

fn threshold(k: usize, per: usize) -> Policy {
    Policy::new(Structure::Threshold { min_domains: k }, per).unwrap()
}

// ---- registry ---------------------------------------------------------------------------------

#[test]
fn registry_rules_and_epochs() {
    let mut r = registry();
    assert_eq!(r.epoch(), 0, "registration does not advance the epoch");
    assert_eq!(
        r.register(p(1), d(9)),
        Err(PolicyError::AlreadyRegistered(p(1)))
    );
    assert_eq!(r.revoke(p(99)), Err(PolicyError::UnknownParticipant(p(99))));
    r.revoke(p(1)).unwrap();
    assert_eq!(r.epoch(), 1);
    assert_eq!(r.revoke(p(1)), Err(PolicyError::AlreadyRevoked(p(1))));
    assert_eq!(
        r.register(p(1), d(1)),
        Err(PolicyError::AlreadyRegistered(p(1))),
        "ids are not reused"
    );
    assert_eq!(
        r.mark_domain_compromised(d(9)),
        Err(PolicyError::UnknownDomain(d(9)))
    );
    r.mark_domain_compromised(d(2)).unwrap();
    assert_eq!(r.epoch(), 2);
    assert_eq!(
        r.mark_domain_compromised(d(2)),
        Err(PolicyError::AlreadyCompromised(d(2)))
    );
    assert_eq!(
        r.readmit_domain(d(3)),
        Err(PolicyError::NotCompromised(d(3)))
    );
    let s = r.standing(p(3)).unwrap();
    assert!(s.domain_compromised && s.status == Status::Active && s.domain == d(2));
    assert_eq!(r.standing(p(1)).unwrap().status, Status::Revoked);
    assert!(r.standing(p(42)).is_none());
    r.readmit_domain(d(2)).unwrap();
    assert_eq!(r.epoch(), 3);
    assert!(!r.standing(p(3)).unwrap().domain_compromised);
    // Eligibility: domain 1 lost p1 (revoked) and so has one active participant.
    assert_eq!(r.eligible_domains(1), set(&[1, 2, 3]));
    assert_eq!(r.eligible_domains(2), set(&[2, 3]));
    r.mark_domain_compromised(d(3)).unwrap();
    assert_eq!(r.eligible_domains(1), set(&[1, 2]));
    assert_eq!(r.domains(), set(&[1, 2, 3]));
}

#[test]
fn invalid_policies_are_refused() {
    for bad in [
        Policy::new(Structure::Threshold { min_domains: 0 }, 1),
        Policy::new(Structure::Threshold { min_domains: 1 }, 0),
        Policy::new(Structure::Minimal(vec![]), 1),
        Policy::new(Structure::Minimal(vec![BTreeSet::new()]), 1),
    ] {
        assert!(matches!(bad, Err(PolicyError::InvalidPolicy(_))));
    }
}

// ---- policy evaluation ------------------------------------------------------------------------

#[test]
fn many_participants_of_one_domain_are_one_vote() {
    let r = registry();
    let pol = threshold(2, 1);
    let d1 = pol.authorise(&r, &[p(1), p(2)]);
    assert!(!d1.authorised);
    assert_eq!(d1.counted_domains, set(&[1]));
    let d2 = pol.authorise(&r, &[p(1), p(3)]);
    assert!(d2.authorised);
    assert_eq!(d2.counted_domains, set(&[1, 2]));
    // Six approvals from one domain's two participants twice over still count once.
    assert!(!pol.authorise(&r, &[p(1), p(2), p(1), p(2)]).authorised);
}

#[test]
fn per_domain_minimum_and_ignored_approvals() {
    let mut r = registry();
    let pol = threshold(2, 2);
    let short = pol.authorise(&r, &[p(1), p(2), p(3)]);
    assert!(!short.authorised);
    assert_eq!(short.short_domains, set(&[2]));
    assert!(pol.authorise(&r, &[p(1), p(2), p(3), p(4)]).authorised);
    // Ignored: duplicate, unknown, revoked, compromised domain.
    r.revoke(p(6)).unwrap();
    r.mark_domain_compromised(d(2)).unwrap();
    let dec = pol.authorise(&r, &[p(1), p(1), p(99), p(6), p(3), p(5), p(2)]);
    let why: BTreeSet<String> = dec
        .ignored
        .iter()
        .map(|(i, w)| format!("{}:{w:?}", i.0))
        .collect();
    for want in [
        "1:Duplicate",
        "99:Unknown",
        "6:Revoked",
        "3:DomainCompromised",
    ] {
        assert!(why.contains(want), "{want} in {why:?}");
    }
    assert!(
        !dec.authorised,
        "domain 3 now has one active participant, domain 2 is compromised"
    );
    assert_eq!(dec.counted_domains, set(&[1]));
}

#[test]
fn minimal_structures() {
    let r = registry();
    // Either domains 1 and 2 together, or domain 3 alone.
    let pol = Policy::new(Structure::Minimal(vec![set(&[1, 2]), set(&[3])]), 1).unwrap();
    assert!(pol.authorise(&r, &[p(5)]).authorised);
    assert!(!pol.authorise(&r, &[p(1)]).authorised);
    assert!(!pol.authorise(&r, &[p(3)]).authorised);
    assert!(pol.authorise(&r, &[p(1), p(3)]).authorised);
    assert!(
        pol.qualified(&set(&[1, 2, 3])) && !pol.qualified(&set(&[1])) && !pol.qualified(&set(&[]))
    );
}

// ---- analysis ---------------------------------------------------------------------------------

#[test]
fn threshold_tolerances_match_the_closed_form() {
    for n in 1..=6u32 {
        let mut r = Registry::new();
        for i in 1..=n {
            r.register(p(i), d(i)).unwrap();
        }
        for k in 1..=n as usize {
            let pol = threshold(k, 1);
            assert_eq!(max_safe_corruption(&pol, &r).unwrap(), k - 1, "n={n} k={k}");
            assert_eq!(
                max_tolerable_loss(&pol, &r).unwrap(),
                n as usize - k,
                "n={n} k={k}"
            );
        }
    }
}

#[test]
fn safety_and_liveness_report_counterexamples() {
    let mut r = Registry::new();
    for i in 1..=5 {
        r.register(p(i), d(i)).unwrap();
    }
    let pol = threshold(3, 1);
    let all = r.domains();
    assert!(check_safety(&pol, &r, &Adversary::any_up_to(&all, 2).unwrap()).is_ok());
    let bad = check_safety(&pol, &r, &Adversary::any_up_to(&all, 3).unwrap()).unwrap_err();
    assert_eq!(bad.len(), 3);
    assert!(check_liveness(&pol, &r, &Adversary::any_up_to(&all, 2).unwrap()).is_ok());
    assert_eq!(
        check_liveness(&pol, &r, &Adversary::any_up_to(&all, 3).unwrap())
            .unwrap_err()
            .len(),
        3
    );
    // A named adversary: domains 1 and 2 collude, 3 and 4 collude, never across.
    let named = Adversary(vec![set(&[1, 2]), set(&[3, 4])]);
    assert!(check_safety(&pol, &r, &named).is_ok());
    // A compromised domain is lost to the honest side: liveness tolerance drops.
    r.mark_domain_compromised(d(5)).unwrap();
    assert_eq!(max_tolerable_loss(&pol, &r).unwrap(), 1);
    // Capacity: with min_per_domain = 2 a one-participant domain gives the adversary nothing.
    let mut r2 = Registry::new();
    for (pid, dom) in [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3)] {
        r2.register(p(pid), d(dom)).unwrap();
    }
    let pol2 = threshold(2, 2);
    // Domains 1 and 2 both have two participants: colluding they can authorise.
    assert_eq!(
        check_safety(&pol2, &r2, &Adversary(vec![set(&[1, 2])])).unwrap_err(),
        set(&[1, 2])
    );
    // Domain 3 has one participant, so it cannot supply the two approvals the policy needs and
    // corrupting it gives the adversary nothing.
    assert!(check_safety(&pol2, &r2, &Adversary(vec![set(&[1, 3])])).is_ok());
    // Structures that are not thresholds.
    let m = Policy::new(Structure::Minimal(vec![set(&[1, 2]), set(&[3])]), 1).unwrap();
    assert_eq!(
        check_safety(&m, &registry(), &Adversary(vec![set(&[3])])).unwrap_err(),
        set(&[3])
    );
}

#[test]
fn q_conditions_match_the_threshold_arithmetic() {
    let dom = |n: u32| (1..=n).map(DomainId).collect::<BTreeSet<_>>();
    // Q^k holds for "any t of n" exactly when k*t < n.
    for n in 2..=8u32 {
        for t in 1..=3usize {
            let adv = Adversary::any_up_to(&dom(n), t).unwrap();
            for k in [2usize, 3] {
                let holds = q_condition(&adv, &dom(n), k).is_ok();
                assert_eq!(holds, k * t < n as usize, "n={n} t={t} k={k}");
            }
        }
    }
    let adv = Adversary::any_up_to(&dom(6), 2).unwrap();
    let cover = q_condition(&adv, &dom(6), 3).unwrap_err();
    assert_eq!(cover.len(), 3);
    assert_eq!(
        cover.iter().flatten().copied().collect::<BTreeSet<_>>(),
        dom(6)
    );
}

#[test]
fn analysis_refuses_huge_domain_sets() {
    let mut r = Registry::new();
    for i in 1..=21 {
        r.register(p(i), d(i)).unwrap();
    }
    assert!(matches!(
        max_safe_corruption(&threshold(2, 1), &r),
        Err(PolicyError::TooManyDomains(20))
    ));
    assert!(Adversary::any_up_to(&r.domains(), 1).is_err());
}

// ---- authenticated approvals ------------------------------------------------------------------

/// Key block for one participant: the participant's copy and the verifier's copy.
fn block(pid: u32, slots: usize, purpose: Purpose) -> (Reservation, Reservation) {
    let material: Vec<u8> = {
        let mut s = 0x9e37_79b9_7f4a_7c15u64 ^ (u64::from(pid) << 24);
        (0..16 * (1 + slots) * 2)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8 | 1
            })
            .collect()
    };
    let mk = || {
        let dir = tempfile::tempdir().unwrap();
        let pool = Pool::create(
            dir.path(),
            PoolId([pid as u8; 16]),
            purpose,
            Provenance::ProvisionedShared,
            &material,
        )
        .unwrap();
        pool.reserve(16 * (1 + slots)).unwrap()
    };
    (mk(), mk())
}

struct World {
    reg: Registry,
    auth: Authoriser,
    issuers: std::collections::BTreeMap<ParticipantId, ApprovalIssuer>,
}

fn world(policy: Policy, max_failures: u32, slots: usize) -> World {
    let reg = registry();
    let mut auth = Authoriser::new(policy, max_failures);
    let mut issuers = std::collections::BTreeMap::new();
    for pid in 1..=6 {
        let (mine, theirs) = block(pid, slots, Purpose::Authentication);
        issuers.insert(p(pid), ApprovalIssuer::new(p(pid), mine).unwrap());
        auth.add_channel(p(pid), theirs).unwrap();
    }
    World { reg, auth, issuers }
}

impl World {
    fn approve(&mut self, pid: u32) -> TaggedApproval {
        let e = self.reg.epoch();
        self.issuers
            .get_mut(&p(pid))
            .unwrap()
            .issue(ACT, SES, e)
            .unwrap()
    }
}

fn why(d: &Decision, pid: u32) -> Option<Ignored> {
    d.ignored.iter().find(|(i, _)| i.0 == pid).map(|&(_, w)| w)
}

#[test]
fn approvals_authorise_once_and_only_across_domains() {
    let mut w = world(threshold(2, 1), 5, 4);
    let a = vec![w.approve(1), w.approve(2)];
    let dec = w.auth.authorise(&w.reg, ACT, SES, &a);
    assert!(!dec.authorised, "one domain, two approvals");
    // Unspent approvals stay usable: add a second domain's and present them all.
    let mut all = a;
    all.push(w.approve(3));
    let dec = w.auth.authorise(&w.reg, ACT, SES, &all);
    assert!(dec.authorised, "{dec:?}");
    assert_eq!(dec.counted_domains, set(&[1, 2]));
    // The same action cannot be authorised twice, even with fresh approvals.
    let fresh = vec![w.approve(4), w.approve(5)];
    let again = w.auth.authorise(&w.reg, ACT, SES, &fresh);
    assert!(!again.authorised);
    assert!(
        again
            .ignored
            .iter()
            .all(|&(_, i)| i == Ignored::AlreadyAuthorised)
    );
    assert!(
        format!("{:?}", w.auth).contains("Authoriser")
            && !format!("{:?}", w.issuers[&p(1)]).contains("pads")
    );
}

#[test]
fn approvals_are_bound_to_action_session_block_and_epoch() {
    let mut w = world(threshold(1, 1), 5, 6);
    let good = w.approve(1);
    let other_action = [0xB2; 16];
    let d = w.auth.authorise(&w.reg, other_action, SES, &[good]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::WrongAction))
    );
    let d = w.auth.authorise(&w.reg, ACT, [0x99; 16], &[good]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::WrongSession))
    );
    let mut moved = good;
    moved.approval.block_offset += 16;
    let d = w.auth.authorise(&w.reg, ACT, SES, &[moved]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::WrongBlock))
    );
    // A different participant's tag on someone else's approval does not verify.
    let mut forged = w.approve(2);
    forged.approval.participant = p(1);
    forged.approval.seq = 1;
    let d = w.auth.authorise(&w.reg, ACT, SES, &[forged]);
    assert_eq!(why(&d, 1), Some(Ignored::Rejected(ApprovalError::BadTag)));
    // Sequence beyond the block.
    let mut far = good;
    far.approval.seq = 200;
    let d = w.auth.authorise(&w.reg, ACT, SES, &[far]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::BadSequence))
    );
    // The genuine approval still works, then a revocation elsewhere makes new approvals stale.
    assert!(w.auth.authorise(&w.reg, ACT, SES, &[good]).authorised);
    let mut w = world(threshold(1, 1), 5, 6);
    let before = w.approve(1);
    w.reg.revoke(p(6)).unwrap();
    let d = w.auth.authorise(&w.reg, ACT, SES, &[before]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::Stale { got: 0, now: 1 }))
    );
    let renewed = w.approve(1);
    assert!(w.auth.authorise(&w.reg, ACT, SES, &[renewed]).authorised);
}

#[test]
fn forged_tags_are_counted_and_retire_the_channel() {
    let mut w = world(threshold(1, 1), 2, 8);
    let good = w.approve(1);
    let mut bad = good;
    bad.approval.session = SES; // unchanged fields...
    let flip = |t: &TaggedApproval| {
        let mut b = t.tag_bytes();
        b[3] ^= 1;
        TaggedApproval::with_tag(t.approval, b)
    };
    for n in 1..=2 {
        let d = w.auth.authorise(&w.reg, ACT, SES, &[flip(&good)]);
        assert_eq!(why(&d, 1), Some(Ignored::Rejected(ApprovalError::BadTag)));
        assert_eq!(w.auth.failures(p(1)), n);
    }
    // Budget spent: even the genuine approval is refused until the channel is replaced.
    let d = w.auth.authorise(&w.reg, ACT, SES, &[good]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::ChannelRetired))
    );
    assert!(!d.authorised);
    // Other participants are unaffected.
    let other = w.approve(3);
    assert!(w.auth.authorise(&w.reg, ACT, SES, &[other]).authorised);
    let _ = bad;
}

#[test]
fn revoked_unknown_and_compromised_participants_are_ignored_without_costing_budget() {
    let mut w = world(threshold(2, 1), 5, 6);
    let a1 = w.approve(1);
    let a3 = w.approve(3);
    let a5 = w.approve(5);
    let mut r = w.reg.clone();
    // Same epoch for the approvals: do the registry changes first, then issue.
    r.revoke(p(1)).unwrap();
    r.mark_domain_compromised(d(2)).unwrap();
    w.reg = r;
    let (b1, b3, b5, b6) = (w.approve(1), w.approve(3), w.approve(5), w.approve(6));
    let d = w.auth.authorise(&w.reg, ACT, SES, &[b1, b3, b5]);
    assert_eq!(why(&d, 1), Some(Ignored::Revoked));
    assert_eq!(why(&d, 3), Some(Ignored::DomainCompromised));
    assert!(!d.authorised, "only domain 3 counts");
    assert_eq!(d.counted_domains, set(&[3]));
    assert_eq!(w.auth.failures(p(1)) + w.auth.failures(p(3)), 0);
    // Approvals from before the changes are stale for the participant still standing.
    let d = w.auth.authorise(&w.reg, ACT, SES, &[a5, a1, a3]);
    assert_eq!(
        why(&d, 5),
        Some(Ignored::Rejected(ApprovalError::Stale { got: 0, now: 2 }))
    );
    // Domain 1 still has p2; with domain 3 that is two domains once re-issued at this epoch.
    let b2 = w.approve(2);
    assert!(w.auth.authorise(&w.reg, ACT, SES, &[b2, b5, b6]).authorised);
}

#[test]
fn issuer_and_channel_material_checks() {
    let (mine, _) = block(7, 2, Purpose::Authentication);
    let mut iss = ApprovalIssuer::new(p(7), mine).unwrap();
    assert_eq!(iss.remaining(), 2);
    iss.issue(ACT, SES, 0).unwrap();
    iss.issue(ACT, SES, 0).unwrap();
    assert_eq!(
        iss.issue(ACT, SES, 0).unwrap_err(),
        ApprovalError::Exhausted(2)
    );
    assert_eq!(iss.remaining(), 0);
    let (enc, _) = block(8, 2, Purpose::Encryption);
    assert_eq!(
        ApprovalIssuer::new(p(8), enc).unwrap_err(),
        ApprovalError::BadMaterial
    );
    let mut a = Authoriser::new(threshold(1, 1), 1);
    let (enc, _) = block(9, 2, Purpose::Encryption);
    assert_eq!(
        a.add_channel(p(9), enc).unwrap_err(),
        ApprovalError::BadMaterial
    );
    // A registered participant with no channel, and an unregistered one.
    let reg = registry();
    let (mine, _) = block(1, 2, Purpose::Authentication);
    let mut lone = ApprovalIssuer::new(p(1), mine).unwrap();
    let t = lone.issue(ACT, SES, 0).unwrap();
    let d = a.authorise(&reg, ACT, SES, &[t]);
    assert_eq!(
        why(&d, 1),
        Some(Ignored::Rejected(ApprovalError::NoChannel))
    );
    let mut stranger = t;
    stranger.approval.participant = p(77);
    assert_eq!(
        why(&a.authorise(&reg, ACT, SES, &[stranger]), 77),
        Some(Ignored::Unknown)
    );
}
