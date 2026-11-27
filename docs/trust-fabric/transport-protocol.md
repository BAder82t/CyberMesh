# Trust Fabric: transport protocol

Status: experimental, unaudited. Implemented in `crates/cybermesh-transport`. Inspired by the
shape of TLS 1.3 (now specified by RFC 9846, which obsoletes RFC 8446; the key schedule uses HKDF
and authentication uses a signature and a MAC, so TLS 1.3 is computational throughout);
**not TLS and not wire-compatible with it**. The existing CyberMesh libp2p
transport (Noise, computational) may carry these messages, but its protection is never counted
towards the guarantees here.

## Profiles

`SecurityProfile` names `Standard`, `PostQuantum` and `InformationTheoretic`. Only the last is
implemented. There is no negotiation: asking for another profile fails with
`ProfileUnsupported`, and a peer announcing another profile in its hello is refused as a
`Downgrade` before anything else is looked at. This crate uses no cipher, hash, KDF or
public-key primitive.

## Model and assumptions

* Each pair of parties holds four pools of shared secret material, identical on both sides:
  encryption and authentication for each direction (`cybermesh-entropy`; provenance must be
  provisioned or QKD, local randomness is refused; the four pools must be distinct).
* A sender consumes its direction's pools, the receiver its copy of the same pools, in the same
  order. Sessions run over a reliable, in-order byte transport that delivers every record.
* The material is uniform, secret, known only to the two parties, and erased when spent.

## Messages

```text
Hello    'H' ver profile role session_id[16] auth_start[8] enc_start[8] tag[16]
Finished 'F' ver session_id[16] tag[16]
Record   ver session_id[16] dir seq[8] ctlen[4] ciphertext tag[16]
Frame    type[1] len[4] data zero-padding        (at least 8 bytes, encrypted whole)
```

Each direction's authentication stream is: one 16-byte hash key, a pad for the hello,
(initiator only) a pad for the finished message, then one pad per record. The encryption stream
is one pad per record, as long as its frame. Tags are Wegman-Carter (`authentication.md`).

## State machine

```text
Initiator: start -> [send Hello] -> finish(Responder Hello) -> [send Finished] -> Session
Responder: accept(Initiator Hello) -> [send Hello] -> finish(Finished) -> Session
Session:   Open -- any failure --> Terminated        close() / peer close: per direction
```

1. `I -> R: Hello`, tagged over its header. `auth_start` and `enc_start` are I's pool cursors.
2. R compares those cursors with its own copies **before consuming anything** (`OutOfStep` on
   mismatch), verifies the tag, then `R -> I: Hello`, tagged over R's header **and I's complete
   hello**.
3. I checks R's cursors the same way, verifies R's hello, then `I -> R: Finished`, tagged over
   **both complete hellos**. R verifies it.

Each side thereby proves it saw the other's hello unchanged: transcript binding without a hash.
The profile, role, session id and cursors are inside authenticated bytes.

## Records

Encrypt-then-MAC. The frame (`type`, length, data, zero padding) is XORed with a fresh pad of
the same length; the tag covers a domain string, the header (version, session id, direction,
sequence number, length) and the ciphertext. The receiver spends the authentication pad first,
verifies, and only then spends the encryption pad. Types are data and close. Maximum data per
record is 65,536 bytes; frames are at least 8 bytes (the pool's minimum reservation), so very
short messages are padded.

## Guarantees (in the model)

| Property | How |
|---|---|
| Confidentiality | ciphertext = frame XOR a fresh uniform pad used once; independent of the plaintext except its length. Length is the permitted leakage |
| Integrity, authenticity | forgery probability at most `(blocks+1)/2^128` per attempt, against unbounded computation; the first failure ends the session, so one attempt per session |
| Order, replay | strictly increasing sequence number inside the authenticated bytes; a repeat, gap or reorder ends the session |
| Reflection, cross-session replay | direction and session id inside the authenticated bytes |
| Truncation | an authenticated close record per direction; a stream that stops without one is not a clean close |
| Downgrade | no negotiation; another announced profile is refused first |
| No pad reuse | pools advance durably before bytes are used; `Reservation` is consumed by use; a crash burns material |
| Past traffic after later state compromise | spent pad bytes are erased (relies on the erasure holding) |

## Failure behaviour

* **Fail closed.** Any authentication, order, session, malformed or entropy failure ends the
  session; later calls return `Terminated`. Nothing falls back to another profile.
* **Exhaustion** (`KeyExhausted`) is checked on both pools before anything is spent, so it
  leaves the session and the pools untouched. Both parties provision the same new bytes
  (`Pool::replenish`) and continue. If a pool fails between the two reservations, the session
  ends because the pair would be desynchronised.
* **Crash.** Session state (sequence numbers, keys in memory) is lost. The pools survive and
  are never reissued. A new handshake works only if both sides' cursors still agree.

## Resynchronisation

A lost record, or a crash with undelivered records in flight, leaves one party's cursor ahead of
the other's copy of the same pool; the next handshake reports `OutOfStep` and consumes nothing.
Resynchronisation is a **request and a response**. The party that wants to resync calls
`Endpoint::sync_request` (a fresh random nonce, no pool material spent) and sends the request; the
peer answers with `Endpoint::sync_response`; the requester passes the response and its `SyncRequest`
to `Endpoint::resync`, which, for each of the four pools, **burns forward to the larger of the two
cursors**. Cursors never move backwards, so after both parties have asked once the pair is in step and
a new handshake works. A session, even a terminated one, returns its pools with
`Session::into_endpoint`.

```text
Request   'Q' ver 3 role nonce[16]                                       (19 bytes)
Response  'S' ver 3 role nonce[16] cursors[4 x 8] tag[16]                (67 bytes)
```

**The response is authenticated.** Its tag is a **one-time MAC** (`cybermesh_trust::mac::tag_one_time`)
over the whole body, nonce included: the responder spends 32 fresh bytes from its send authentication
pool (a hash key, then a pad) and reports its cursors **after** spending them, so the message names
where its material is. The requester reads those 32 bytes at that offset in its own copy of the pool
**without consuming them** (`Pool::peek_unspent`, for verification only), verifies the tag, and only
then changes anything. Forged, tampered, reflected (wrong role) and replayed responses are refused
before any state changes: a forger has none of the material, so succeeds with probability at most
`(blocks + 1) / 2^128` per message and burns nothing. A response naming material the requester has
already spent is refused (`SyncStale`).

**The response is fresh.** `resync` accepts a response only if it echoes the nonce of the
`SyncRequest` it is given (`SyncNotRequested` otherwise), and a `SyncRequest` is used by one
successful resync. A genuine response that the peer made for an earlier request therefore cannot
be accepted by a party that has restarted since: its new request has a new nonce, and the old
request is gone with the old process. The nonce is public and needs uniqueness, not secrecy. This
closes the hole the TLA+ model found, where a restored party accepted a genuine but old message that
burned nothing past what it had used (`formal-model.md`); the test
`a_stale_genuine_response_is_refused_by_a_restored_side_which_then_heals_properly` pins it.

After authentication, burning forward is safe as before: every byte below a party's cursor is
already spent or erased on that side, so burning can only waste material. It is bounded by the pool
size (`ResyncExceedsPool`), the caller's `max_burn` per pool (`ResyncExceedsPolicy`), and a gap no
sequence of records can produce, under 8 bytes (`Misaligned`). All four targets are validated
before anything is burned. The 32 bytes the response spent are spent, not burned, and are not
counted in the report. A refused response leaves the `SyncRequest` usable.

**The start-up rule.** A party that might have been restored should **request first and answer only
after it has applied a fresh response**: answering spends 32 bytes at the responder's own cursor,
which on a restored party are bytes it already used (the peer refuses such an answer as stale, and
its tag reuses a key and pad; `known-issues.md`, #1). Nothing local tells a party that it was
restored, so the rule applies to **every start**, and the code enforces the part that matters for a
session: an `Endpoint` is unsynced when it is opened, and `Initiator::start` and `Responder::accept`
return `NotSynced` until `Endpoint::resync` has applied a fresh response to a request of its own
(`is_synced`; an in-step response counts and burns nothing). Answering is allowed while unsynced, because
two parties that start together would otherwise both wait for the other; the model shows that
answering reuses at most an authentication slot the in-step peer has already spent. Each party
therefore runs one request and response before the first hello, in both directions. The flag is in
memory only (a restart or restore clears it), the endpoint a `Session` hands back stays synced, and
the code was tested against the rule, not re-modelled. An endpoint kept in memory across a rollback of
its disk keeps its flag, and nothing stops a caller using the pools without an `Endpoint`.

**What it does not fix.** A message of the restored party's that was lost or in flight at the restore:
its slot was used and seen on the wire, but the peer never accepted it, so the restored party reuses
it and no exchange can tell it (needs durable local state, #1). Both parties restored to the same
moment is not detected. Nonce uniqueness is assumed (a whole-VM restore can also restore the random
number generator), and so is that a `SyncRequest` does not outlive the restore: a process that keeps a
request while only its disk is rolled back could still accept a response made for that request. **A forged request costs the responder 32 authentication bytes** and leaves the pair
out of step until a resync; this is pinned by a test as a known cost and is in line with availability not
being protected.

Tested: a lost record, losses in both directions and a crash with records in flight, a session
terminated by tampering, an in-step exchange that burns nothing, replays and stale responses,
a response accepted once and only for its own request, forged responses (right shape and wrong tag,
at and far ahead of the right offset; every body byte flipped; the tag flipped; a reflected
message; one byte of the receiver's material changed; beyond the pool) with the pools unchanged
afterwards and 300 further forgeries leaving them unchanged, a genuine response beyond the policy,
erased bytes on disk, a property test over random loss patterns, the restore scenarios, and the
cost of a forged request. Mutation checks: skipping the nonce comparison, the used-request check,
the request-role check, or the marking of a used request each fail a test.

## Limitations

* **No post-compromise recovery.** Whoever copies the unspent pools can read and forge all
  future traffic until they are replaced.
* **Availability is not protected.** An active attacker can end any session by injecting or
  altering one record.
* **Resynchronisation is manual and burns material** (previous section). It is authenticated
  but not automatic; it needs a quiescent pair, and after a restore the order of the two
  messages matters.
* **Cost.** One secret byte per plaintext byte (at least 8 per record) plus 16 authentication
  bytes per record, and 48 / 32 bytes per handshake. Throughput is bounded by provisioning.
* The pools are provisioned out of band: this crate does not establish keys. ITSAKE (IACR ePrint
  2026/222, Jacqmin and Lienardy, February 2026) is a two-message protocol from a pre-shared secret
  with entity authentication and forward secrecy, proven without computational assumptions; it is a
  preprint with no peer-reviewed venue found, only its abstract was read, and it is **not
  implemented**. Other information-theoretic key establishment was not evaluated
  (`literature-review.md`).
* Variable-time record handling on secret data is not claimed constant time; no timing review.
* Wire formats are versioned (`ver = 1`) but not frozen.
