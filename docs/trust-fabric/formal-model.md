# Trust Fabric: formal model of pool use and resynchronisation

Status: experimental. A TLA+ model checked with TLC over a **small bounded state space**. It is a
model of the protocol as written in `transport-protocol.md`, **not** of the Rust code, and it is
**not a proof**: a pass means no violation was found within the bounds, a counterexample is a
concrete trace. It covers pool cursors, records, hello-style messages and the authenticated sync
message. It does **not** model the handshake's transcript binding, the key schedule inside a
session, timing, or cryptography (the MAC is ideal, see below). Issue #3 in `known-issues.md`
(no composable security proof, no machine-checked model of the whole handshake) stays open.

Files: `formal/tla/TrustFabricResync.tla`, eight `.cfg` files, and `formal/tla/run.sh`, which runs
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
fixed here.** A fix needs a freshness input (a counter the restore cannot roll back, which is the
open part of #1), not a tweak to the message. The register and `transport-protocol.md` now say so.

The discipline configurations also assume an oracle that tells a party it was restored. The real
code has none, so even the procedure that the model shows to be insufficient cannot be followed
reliably.

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
