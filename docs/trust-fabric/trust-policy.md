# Trust Fabric: trust policy

Status: experimental, unaudited. Implemented in `crates/cybermesh-trust` (`policy` module).
No signatures are used: approvals are authenticated with the pairwise Wegman-Carter MAC.

## Model

* **Participants** belong to **administrative domains** (an organisation, a legal and
  operational boundary). A **registry** tracks them with an **epoch** that advances on every
  revocation, domain compromise and readmission (not on registration).
* A **policy** says which sets of *domains* are qualified to authorise: a threshold (any `k`
  domains) or explicit minimal qualified sets, plus how many active approvals one domain must
  supply for its vote to count. **Many participants of one domain are one vote.**
* **Revocation** is permanent for a participant id. **Domain compromise** makes every participant
  of the domain count for nothing; readmission needs the operator to have re-provisioned the
  domain's pairwise key material (the registry cannot check that).

## Analysis against a stated adversary

The adversary is a list of domain sets that may be corrupt (or unavailable); each stands for
itself and its subsets.

* `check_safety`: can any corruptible set authorise alone? An adversary can approve only for
  domains that have enough registered active participants. `Err` returns the offending set.
* `check_liveness`: if these sets become unavailable, can the rest still authorise? Only
  eligible domains (not compromised, enough active participants) count. `Err` returns the set.
* `max_safe_corruption`, `max_tolerable_loss`: the largest number of simultaneously corrupt or
  lost domains the policy tolerates; for "any `k` of `n`" they are `k - 1` and `n - k`
  (checked for `n <= 6`). Exhaustive over subsets, so limited to 20 domains.
* `q_condition(k)`: no `k` corruptible sets cover all domains, the `Q^k` conditions of the
  general-adversary multiparty-computation literature. Per Hirt and Maurer's abstract, `k = 2`
  characterises passive adversaries and active adversaries **with** a broadcast channel, and `k = 3`
  active adversaries **without** broadcast (`literature-review.md`: `hirtmaurer1997` V1, `cdm2000`
  V2). For "any `t` of `n`" it holds exactly when `k * t < n` (checked).

## Authenticated approvals

A participant's `ApprovalIssuer` and the verifier's `Authoriser` hold copies of one pairwise key
block (`cybermesh-entropy`, purpose `Authentication`, `16 * (1 + n)` bytes: a hash key and one pad
per approval). An approval names the participant, the **action**, the **session**, the registry
**epoch**, a sequence number and the block offset; the tag covers all of them and the pool id.

The verifier counts an approval only if: the participant is registered, active and not in a
compromised domain; a channel exists; the block offset, action and session match; the epoch equals
the registry's current epoch (anything older is stale); the sequence number is in the block and
unused; and the tag verifies. Bad tags are counted per participant and retire the participant's
channel at a budget. Approvals used in an authorised decision are spent; others stay usable, so
approvals can be collected over several calls. An action authorised once is never authorised
again.

## Limits

* **The decision is private to the verifier.** Tags are pairwise and symmetric, so nobody else can
  check them and the verifier could fabricate them: no public verifiability, no non-repudiation,
  no certificate to show a third party.
* **The registry is in-memory state.** No persistence, no protection against rollback, no
  agreement between several verifiers. A verifier with a stale registry may honour a revoked
  participant until it learns of the revocation.
* **Domains are an assumption.** Counting domains gives isolation only if the operator drew the
  domains so that their members really are independent (shared infrastructure, common owners and
  legal compulsion are not modelled). The analysis proves nothing about that.
* **Thresholds, not general secret-sharing schemes.** The structures are evaluated over domains;
  nothing here yet derives a sharing scheme from a general structure or ties the policy to the
  transport or the sharing crates.
* Adaptive and mobile corruption are tracked only through `mark_domain_compromised` and epochs;
  there is no automatic detection and no proactive re-keying.
* Epoch advance also makes all approvals gathered earlier stale, by design: collecting and
  using approvals must happen between registry changes.
