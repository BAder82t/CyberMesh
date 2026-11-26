# Trust Fabric: formal model of pool use and resynchronisation

Status: experimental. A TLA+ model checked with TLC over a **small bounded state space**. It is a
model of the protocol as written in `transport-protocol.md`, **not** of the Rust code, and it is
**not a proof**: a pass means no violation was found within the bounds, a counterexample is a
concrete trace. It covers pool cursors, records, hello-style messages and the authenticated sync
message. It does **not** model the handshake's transcript binding, the key schedule inside a
session, timing, or cryptography (the MAC is ideal, see below). Issue #3 in `known-issues.md`
(no composable security proof, no machine-checked model of the whole handshake) stays open.

The nonce challenge described below is **implemented** in `cybermesh-transport` (`SyncRequest`,
`sync_response`, `resync`). The implementation was written from the model's description and checked by
its own tests; **the model was not re-derived from the code**, so the two can drift.

Files: `formal/tla/TrustFabricResync.tla`, twenty-four `.cfg` files, and `formal/tla/run.sh`, which runs
every configuration and checks each gives the **expected** result (needs Java and `tla2tools.jar`;
run with TLC 2.19 from the tlaplus v1.7.4 release, a file whose checksum I did not compare with an
upstream value).

```sh
TLA2TOOLS=/path/to/tla2tools.jar formal/tla/run.sh
```

## What is modelled

Two parties, A and B. Each holds four cursors counted in **slots** (one slot is one use of
authentication material, 32 bytes, or one encryption pad): its own send-authentication and
send-encryption cursors, and its copies of the peer's two. Actions: send a record (spends one
authentication and one encryption slot), send a hello (authentication only, **spent before the sender
knows whether the peer's cursors agree**), send a sync message (one authentication slot, cursors
reported after spending), deliver any message ever sent (delivery does not remove it, so replay is free),
lose a message, take a backup and restore one party from it, and an adversary that builds a sync
message of its own choosing.

The MAC is **ideal**: a message verifies only if an honest party made it for exactly that content, with
**one assumption added**: the adversary can forge for any slot whose key and pad were used for two
different messages. That is the weakest form of the one-time-MAC reuse failure and it is an
assumption of the model, not something it derives. A receiver accepts a record or hello only if its
offsets equal its copies; it accepts a sync message only if the message's slot is not below its copy
(otherwise stale), and then burns each of its four cursors forward to the larger value.

## What was checked, and the result

| Config | Bounds | Property | Result |
|---|---|---|---|
| `safe` | no restore; sync authenticated | no slot reused (authentication and encryption), no forgery accepted, no copy of a peer's cursor ahead of the peer's own | **holds** (133,033 states, depth 13) |
| `unauth` / `unauth_overrun` | the sync message has no MAC (the design before #65) | no forgery accepted; no cursor overrun | **violated**: a forged sync burns the receiver's copy past the sender's own cursor, 3 steps |
| `restore` / `restore_pad` | one restore from an earlier backup | no authentication slot reused; no encryption pad reused | **violated**: a party that sends, is restored, and sends again reuses both |
| `discipline` / `discipline_pad` | as above, but a restored party sends nothing until it has **applied a peer sync** | same | **violated**, see the finding below |
| `instep_discipline` / `_pad` | as `discipline`, restore only when the peer has seen everything the party sent, no loss, `MaxSends = 3` | same | **violated**: the stale-sync finding below, without any loss involved |
| `fresh_instep_discipline` | as above, **plus a nonce challenge** (a sync is accepted only as the answer to a nonce the receiver chose after restarting) | no slot reuse, no forgery | **holds** (316,665 states, depth 14) |
| `fresh_instep_nodiscipline` | nonce challenge, but a restored party may send before it has synced | same | **violated**: the restored party speaks first |
| `fresh_discipline` | nonce challenge, restore allowed while a message of the party's is lost or in flight | same | **violated**: see "What freshness does not fix" |
| `fresh_safe`, `fresh_reach`, `fresh_instep_recovers` | nonce challenge, no restore / recovery reachability | holds / reachable | as expected |
| `reach` | no restore | "lose a message, apply a sync, end in step" is reachable | reachable (the property is expected to be violated, which shows the healing state exists) |

The bounds are `MaxC = 3` slots per pool and `MaxSends = 4` messages, one restore. TLC finishes the
safe configuration; the others stop at the first violation, so they say a violation exists, not that
no other kind does. The "no overrun" property is violated by any restore (a restored sender is behind
its peer's copy), so it is not asserted in the restore configurations.

## Finding: a stale genuine sync lifts the restore precaution without healing

`known-issues.md` says a restored party should **apply the peer's sync message first**. The model
gives a concrete counterexample to the procedure being enough: B restored from an earlier backup applies
A's sync message that A made **before** B's later traffic. The message is genuine, and its slot is
unspent on B's side (B's copy was rolled back too), so B accepts it. Its cursors are old, so it burns
nothing past what B had already used, and B's next message reuses encryption and authentication
slots.

The Rust code does the same. `a_stale_genuine_sync_is_accepted_by_a_restored_side_and_does_not_heal_it`
(`cybermesh-transport`, `resync/tests.rs`) makes the responder's sync message while the pair is
fresh, runs a session, restores the initiator and applies that message: it is accepted and the
initiator's send cursors stay behind what it had already used. The cause is that the message
authenticates the sender's cursors but **not that they are current**, and the stale check only
compares the message's offset with the receiver's own (possibly rolled-back) copy. An attacker who
replays an old message from the peer, or an ordinary delay, produces the same state. **This is not
fixed in code here.** An earlier version of this page, and the register, said a fix needs a counter a
restore cannot roll back. **That was too strong**, and is corrected: the model shows that a **nonce
challenge** closes this particular hole (next section).

The discipline configurations also assume an oracle that tells a party it was restored. The real
code has none, so even the procedure that the model shows to be insufficient cannot be followed
reliably.

## The fix: a nonce challenge (implemented in `cybermesh-transport`)

A party about to resynchronise picks a fresh random **nonce** (public, needs uniqueness, not secrecy)
and sends it; the peer's sync message covers the nonce in its one-time tag; the requester accepts
only a message that echoes the nonce it is waiting for, and forgets the nonce when it restarts. An old
genuine message cannot match a nonce chosen after the restore. Under the bounds above, with the nonce,
a restore from an in-step state, no loss, and a restored party that sends nothing until it has
applied a fresh sync, **no slot is reused and no forgery is accepted** (`fresh_instep_discipline`,
exhaustive for those bounds). Removing the nonce (`instep_discipline`) or the discipline
(`fresh_instep_nodiscipline`) each brings a violation back, so both are needed.

Because the discipline here is "send nothing until a fresh sync has been applied", a party would run
the request and response **at every start**, before any record, hello or sync of its own, so that it
needs no way of knowing it was restored. The model gives a restored party an oracle (it is
quarantined by the restore action); the start-up rule above is the proposal for removing the oracle and
**is not itself modelled**: how two parties that both restart and both wait for the other are
sequenced is not settled.

### What freshness does not fix

* **A message of the restored party's that was lost or still in flight.** Its slot was used and seen on
  the wire, but the peer never accepted it, so the peer's copy cannot tell the restored party. It reuses
  that slot after the restore (`fresh_discipline`). No message exchange can fix this: it needs durable
  local state the restore cannot undo, which is the open part of #1.
* **Both parties restored to the same moment.** Both give old cursors; nothing differs.
* **Nonce uniqueness is an assumption.** Restoring a whole virtual machine can also restore the random
  number generator's state and a nonce already chosen; the model assumes the restart gives a new,
  never-used nonce.
* **A restored party's first attempt before it knows** (a hello or sync made from reused material)
  is not prevented by the start-up rule if the party was not yet started that way.
* **A forged request** makes the peer spend 32 authentication bytes: a small denial of service that needs
  a rate limit or a policy.

Bounds for the restore pair: `MaxSends = 3`, `MaxNonce = 2`, no loss; with four messages the search did
not finish in the time I gave it (about 2.1 million states and a growing queue), so it is a bound, not a
proof for larger ones.

## Start-up sequencing: a rule that needs no oracle (modelled, not implemented)

The restore configurations above give a restored party an oracle: the restore action quarantines it. The
real code has none, so the rule has to apply to **every start**: a party sends no record and no hello
until it has applied a fresh response to a request of its own. The model (`Startup = TRUE`: both parties
start quarantined) asks how the first response can then be produced.

| Config | What is checked | Result |
|---|---|---|
| `startup_none_cold` | nobody may answer a request while quarantined | **deadlock**: both parties request, nobody answers, and the pair is stuck (7 states in all) |
| `startup_both_cold`, `startup_responder_cold` | a quarantined party may answer (both parties, or only the responder) | the pair comes out of its quarantine (the property `NeverSequenced` is violated, which is the reachability we want) |
| `startup_both_safe`, `startup_responder_safe` | as above, one restore from an in-step state, no loss | no pad reused and no forgery accepted: **holds**, exhaustive (32,539 and 10,969 states) |
| `startup_both_hygiene`, `startup_responder_hygiene` | the same, but asking that no authentication slot is reused | **violated**: see below |
| `startup_both_recovers` | a restored party can recover | reachable |

**What this says.** A rule that lets nobody answer while quarantined deadlocks two parties that start together, so
somebody has to answer. Letting a quarantined party answer has a price: a restored party that answers
uses a slot it used before the restore. In the model that is **harmless** (a hygiene failure, not a
break): the peer was in step with the restored party at the restore, so it already spent that slot, and a
message at a spent slot is refused as stale; a quarantined party sends no record, so no pad is reused. The
trace is short: the responder answers during the cold start, is restored, then answers a request made
by anyone (the nonce is public) and reuses slot 0. A role-based tie-break (only the responder may answer
while quarantined) is enough to break the symmetry and exposes one party's answers instead of both.

**What this does not show.**
* **A message lost or in flight at the restore.** The reused slot may then be unspent at the peer, and a
  forgery at that slot becomes possible. The start-up configurations require an in-step restore and no loss;
  the case without them was shown to fail earlier (`fresh_discipline`) and was not repeated with the start-up
  rule.
* **The code does not enforce the rule.** `Initiator::start` and `Responder::accept` do not check that a
  sync has been applied since the endpoint was opened; enforcing it (an endpoint that knows whether it
  has synced since it was opened, and refuses to start a handshake before then) is a design change that is
  **not made**. Until it is made, the start-up rule is a procedure.
* Bounds as before: `MaxSends = 3`, `MaxNonce = 2`, one restore. Both parties restored to the same moment
  is not modelled and is still not detected.

## What this does not show

* The model is not the code: the code was checked against the finding by a test, not by the model.
* Bounded: 3 slots, 4 messages, one restore. Larger bounds were not run.
* The handshake's transcript binding, the encryption of records, and cryptographic security of the MAC
  are not modelled. The sync check against a **role** (reflection) is not modelled either.
* Adversary-injected records and hellos are not modelled, only forged sync messages.
* Properties checked are safety properties. No liveness property (that resync terminates, or that the
  pair always recovers) was checked.
* Mutation checking of the model was limited to switching the MAC off and the restore on; removing the
  stale check, for instance, was not tried.
