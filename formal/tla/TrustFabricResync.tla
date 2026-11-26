---------------------------- MODULE TrustFabricResync ----------------------------
(***************************************************************************)
(* Abstract model of pool use, records, handshake-style messages and the   *)
(* authenticated resynchronisation message of cybermesh-transport.         *)
(*                                                                         *)
(* This is a model of the PROTOCOL as documented in                        *)
(* docs/trust-fabric/transport-protocol.md, not of the Rust code, and it   *)
(* is checked by TLC over a small bounded state space. A pass is not a     *)
(* proof; a counterexample is a concrete trace worth testing in the code.  *)
(*                                                                         *)
(* One "slot" stands for one use of pool material: 32 authentication bytes *)
(* (hash key and pad) or one encryption pad. Cursors count slots.          *)
(*                                                                         *)
(* The MAC is ideal: a tag verifies only if an honest party made it for    *)
(* exactly that message, EXCEPT that the adversary can forge for any slot  *)
(* whose key and pad were used for two different messages (a reused slot). *)
(* That is the weakest form of the one-time-MAC reuse failure, and it is   *)
(* an assumption of the model, not something it derives.                   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxC,        \* pool size in slots
    MaxSends,    \* bound on total honest messages sent
    AuthSync,    \* TRUE: sync message carries a one-time MAC (PR #65); FALSE: it does not
    Fresh,       \* TRUE: a sync is accepted only as the answer to a fresh nonce the receiver chose
    MaxNonce,    \* bound on nonces issued
    Restore,     \* TRUE: a party's state may be rolled back to an earlier backup
    NoLoss,      \* TRUE: messages are never lost (they may still be replayed or delayed)
    InStepOnly,  \* TRUE: a restore happens only when the peer has seen everything the party sent
                 \* (no message of the party's is lost or in flight): the quiescent case
    Startup,     \* TRUE: every party starts quarantined (the rule needs no oracle), not only a restored one
    Answerers,   \* parties that may answer a sync request while quarantined
    Discipline   \* TRUE: a restored party sends nothing until it has applied a peer sync
                 \* (assumes an oracle that tells it it was restored; the real code has none)

Parties == {"A", "B"}
Peer(p) == IF p = "A" THEN "B" ELSE "A"
Max(x, y) == IF x >= y THEN x ELSE y

VARIABLES
    cur,        \* cur[p] = [sa, se, ra, re]: p's send-auth, send-enc, and its copies of the
                \* peer's send-auth and send-enc cursors
    backup,     \* backup[p] = an earlier value of cur[p]
    net,        \* honest messages ever sent and not lost (delivery does not remove: replay is free)
    uses,       \* {<<sender, auth offset, message id>>}
    encUses,    \* {<<sender, enc offset, message id>>}
    sends,      \* honest messages sent so far
    restores,   \* number of restore actions taken
    quarantine, \* quarantine[p]: p was restored and has not yet applied a peer sync
    lost,       \* a message was lost
    synced,     \* a sync message was applied
    forgedOk,   \* the adversary got a forged message accepted
    pending,    \* pending[p]: the nonce p is waiting for a sync to answer (0 = none)
    nonces      \* nonces issued so far (a nonce is never reused, even after a restore)

vars == <<cur, backup, net, uses, encUses, sends, restores, quarantine, lost, synced, forgedOk, pending, nonces>>

Zero == [sa |-> 0, se |-> 0, ra |-> 0, re |-> 0]

Init ==
    /\ cur = [p \in Parties |-> Zero]
    /\ backup = [p \in Parties |-> Zero]
    /\ net = {}
    /\ uses = {}
    /\ encUses = {}
    /\ sends = 0
    /\ restores = 0
    /\ quarantine = [p \in Parties |-> Startup]
    /\ lost = FALSE
    /\ synced = FALSE
    /\ forgedOk = FALSE
    /\ pending = [p \in Parties |-> 0]
    /\ nonces = 0

CanSpeak(p) == ~(Discipline /\ quarantine[p])

(* --- honest sending ------------------------------------------------------ *)

SendRecord(p) ==
    /\ CanSpeak(p) /\ sends < MaxSends
    /\ cur[p].sa < MaxC /\ cur[p].se < MaxC
    /\ LET c == cur[p]
           m == [kind |-> "rec", from |-> p, off |-> c.sa, eoff |-> c.se, id |-> sends + 1]
       IN /\ cur' = [cur EXCEPT ![p].sa = c.sa + 1, ![p].se = c.se + 1]
          /\ net' = net \cup {m}
          /\ uses' = uses \cup {<<p, c.sa, sends + 1>>}
          /\ encUses' = encUses \cup {<<p, c.se, sends + 1>>}
          /\ sends' = sends + 1
    /\ UNCHANGED <<backup, restores, quarantine, lost, synced, forgedOk, pending, nonces>>

\* A hello (or finished) message: spends authentication material, not encryption material.
\* The sender spends BEFORE it knows whether the peer's cursors agree.
SendHello(p) ==
    /\ CanSpeak(p) /\ sends < MaxSends
    /\ cur[p].sa < MaxC
    /\ LET c == cur[p]
           m == [kind |-> "hello", from |-> p, off |-> c.sa, eoff |-> c.se, id |-> sends + 1]
       IN /\ cur' = [cur EXCEPT ![p].sa = c.sa + 1]
          /\ net' = net \cup {m}
          /\ uses' = uses \cup {<<p, c.sa, sends + 1>>}
          /\ sends' = sends + 1
    /\ UNCHANGED <<backup, encUses, restores, quarantine, lost, synced, forgedOk, pending, nonces>>

\* The sync message: spends one authentication slot, reports its cursors AFTER spending.
\* Under Fresh the message answers a nonce the peer issued (n is public: the adversary can relay it);
\* otherwise it is unsolicited (nonce 0) as in the shipped protocol.
SendSync(p, n) ==
    /\ (CanSpeak(p) \/ p \in Answerers) /\ sends < MaxSends
    /\ cur[p].sa < MaxC
    /\ IF Fresh THEN n \in 1..nonces ELSE n = 0
    /\ LET c == cur[p]
           m == [kind |-> "sync", from |-> p, off |-> c.sa, csa |-> c.sa + 1, cse |-> c.se,
                 cra |-> c.ra, cre |-> c.re, nonce |-> n, id |-> sends + 1]
       IN /\ cur' = [cur EXCEPT ![p].sa = c.sa + 1]
          /\ net' = net \cup {m}
          /\ uses' = uses \cup {<<p, c.sa, sends + 1>>}
          /\ sends' = sends + 1
    /\ UNCHANGED <<backup, encUses, restores, quarantine, lost, synced, forgedOk, pending, nonces>>

(* --- delivery ------------------------------------------------------------ *)

\* Receiver q accepts a record or hello only if the offsets agree with its copies.
\* A record also spends encryption material at the receiver.
RecvData(q, m) ==
    /\ m \in net /\ m.from = Peer(q) /\ m.kind \in {"rec", "hello"}
    /\ m.off = cur[q].ra /\ m.eoff = cur[q].re
    /\ cur' = [cur EXCEPT ![q].ra = cur[q].ra + 1,
                          ![q].re = IF m.kind = "rec" THEN cur[q].re + 1 ELSE cur[q].re]
    /\ UNCHANGED <<backup, net, uses, encUses, sends, restores, quarantine, lost, synced, forgedOk, pending, nonces>>

\* Burn forward to the larger cursor in all four directions of pool use.
Burn(q, csa, cse, cra, cre) ==
    [cur[q] EXCEPT !.ra = Max(cur[q].ra, csa), !.re = Max(cur[q].re, cse),
                   !.sa = Max(cur[q].sa, cra), !.se = Max(cur[q].se, cre)]

\* A genuine sync is refused as stale if its slot is below the receiver's copy (already spent).
RecvSync(q, m) ==
    /\ m \in net /\ m.from = Peer(q) /\ m.kind = "sync"
    /\ m.off >= cur[q].ra
    /\ (Fresh => (pending[q] # 0 /\ m.nonce = pending[q]))
    /\ cur' = [cur EXCEPT ![q] = Burn(q, m.csa, m.cse, m.cra, m.cre)]
    /\ synced' = TRUE
    /\ quarantine' = [quarantine EXCEPT ![q] = FALSE]
    /\ pending' = [pending EXCEPT ![q] = 0]
    /\ UNCHANGED <<backup, net, uses, encUses, sends, restores, lost, forgedOk, nonces>>

Reused(d, o) ==
    \E u1 \in uses : \E u2 \in uses :
        u1[1] = d /\ u1[2] = o /\ u2[1] = d /\ u2[2] = o /\ u1[3] # u2[3]

\* The adversary builds a sync message of its own choosing and delivers it. It is accepted only if
\* the sync carries no MAC (AuthSync = FALSE) or the adversary knows the slot's key and pad.
ForgedSync(q) ==
    /\ \E off \in 0..MaxC : \E csa \in 0..MaxC : \E cse \in 0..MaxC :
       \E cra \in 0..MaxC : \E cre \in 0..MaxC :
         /\ off >= cur[q].ra
         /\ (~AuthSync \/ Reused(Peer(q), off))
         /\ cur' = [cur EXCEPT ![q] = Burn(q, csa, cse, cra, cre)]
         /\ cur'[q] # cur[q]
    /\ forgedOk' = TRUE
    /\ UNCHANGED <<backup, net, uses, encUses, sends, restores, quarantine, lost, synced, pending, nonces>>

\* A party chooses a nonce no earlier request used. Choosing one spends no pool material.
Request(p) ==
    /\ Fresh /\ nonces < MaxNonce
    /\ nonces' = nonces + 1
    /\ pending' = [pending EXCEPT ![p] = nonces + 1]
    /\ UNCHANGED <<cur, backup, net, uses, encUses, sends, restores, quarantine, lost, synced, forgedOk>>

Lose(m) ==
    /\ ~NoLoss /\ m \in net
    /\ net' = net \ {m}
    /\ lost' = TRUE
    /\ UNCHANGED <<cur, backup, uses, encUses, sends, restores, quarantine, synced, forgedOk, pending, nonces>>

(* --- backup and restore -------------------------------------------------- *)

TakeBackup(p) ==
    /\ Restore /\ backup[p] # cur[p]
    /\ backup' = [backup EXCEPT ![p] = cur[p]]
    /\ UNCHANGED <<cur, net, uses, encUses, sends, restores, quarantine, lost, synced, forgedOk, pending, nonces>>

RestoreOne(p) ==
    /\ Restore /\ restores < 1 /\ backup[p] # cur[p]
    /\ (InStepOnly => (cur[p].sa = cur[Peer(p)].ra /\ cur[p].se = cur[Peer(p)].re))
    /\ cur' = [cur EXCEPT ![p] = backup[p]]
    /\ quarantine' = [quarantine EXCEPT ![p] = TRUE]
    \* the restored party starts a new process: a nonce it was waiting for is forgotten
    /\ pending' = [pending EXCEPT ![p] = 0]
    /\ restores' = restores + 1
    /\ UNCHANGED <<backup, net, uses, encUses, sends, lost, synced, forgedOk, nonces>>

Next ==
    \/ \E p \in Parties : SendRecord(p) \/ SendHello(p) \/ (\E n \in 0..MaxNonce : SendSync(p, n)) \/ Request(p)
    \/ \E q \in Parties : \E m \in net : RecvData(q, m) \/ RecvSync(q, m)
    \/ \E q \in Parties : ForgedSync(q)
    \/ \E m \in net : Lose(m)
    \/ \E p \in Parties : TakeBackup(p) \/ RestoreOne(p)

Spec == Init /\ [][Next]_vars

(* --- properties ---------------------------------------------------------- *)

\* No authentication slot is used for two different messages.
NoAuthReuse == \A d \in Parties : \A o \in 0..MaxC : ~Reused(d, o)

\* No encryption pad is used for two different messages (a two-time pad).
NoPadReuse ==
    \A u1 \in encUses : \A u2 \in encUses :
        (u1[1] = u2[1] /\ u1[2] = u2[2]) => u1[3] = u2[3]

\* A forged message is never accepted.
NoForgery == ~forgedOk

\* A party's copy of its peer's cursor never runs ahead of the peer's own cursor:
\* nothing has been burned that the peer did not itself spend.
NoOverrun ==
    \A p \in Parties : cur[p].ra <= cur[Peer(p)].sa /\ cur[p].re <= cur[Peer(p)].se

InStep == \A p \in Parties : cur[p].sa = cur[Peer(p)].ra /\ cur[p].se = cur[Peer(p)].re

\* Reachability checks (expected to be VIOLATED, which shows the state can be reached):
\* the pair loses a message, applies a sync, and ends up back in step.
NotHealed == ~(lost /\ synced /\ InStep /\ sends > 0 /\ ~forgedOk)

\* Reachability check (expected to be VIOLATED): a restored party applies a fresh sync, which lifts
\* its quarantine, and messages go on afterwards.
\* With Startup, the pair can come out of its start-up quarantine (expected to be VIOLATED when it can,
\* and to HOLD when the parties deadlock): both parties have applied a fresh sync.
NeverSequenced == ~(synced /\ \A p \in Parties : ~quarantine[p])

NotRecovered == ~(restores = 1 /\ synced /\ \A p \in Parties : ~quarantine[p]) \/ sends < 3

=============================================================================
