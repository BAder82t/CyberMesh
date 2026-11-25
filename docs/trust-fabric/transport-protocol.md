# Trust Fabric: transport protocol

Status: experimental, unaudited. Implemented in `crates/cybermesh-transport`. Inspired by the
shape of TLS 1.3; **not TLS and not wire-compatible with it**. The existing CyberMesh libp2p
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
`Endpoint::sync_message` gives the party's four cursors (no secrets) and `Endpoint::resync`
takes the peer's message and, for each of the four pools, **burns forward to the larger of the
two cursors**. Cursors never move backwards, so after both parties apply it the pair is in step
and a new handshake works. A session, even a terminated one, returns its pools with
`Session::into_endpoint`.

Why it needs no authentication for safety: every byte below a party's cursor is already spent or
erased on that side, so burning forward can only waste material; it cannot make a pad usable
twice or reveal anything. A forged or replayed sync message can only persuade a party to burn
material (denial of service), bounded by: a target beyond the pool's provisioned size is refused
(`ResyncExceedsPool`), the caller's `max_burn` per pool (`ResyncExceedsPolicy`), and a gap no
sequence of records can produce (under 8 bytes) is refused (`Misaligned`). All four targets are
validated before anything is burned. A stale message moves nothing; applying the same exchange
twice is a no-op. If a lie leaves the pair out of step, the next authenticated handshake detects
it and another honest exchange heals it; the cost is only burned material. Run it with no
session active.

Tested: a lost record, losses in both directions and a crash with records in flight, a session
terminated by tampering, idempotence, stale messages, forged claims (beyond the pool, over
policy, misaligned, within policy then healed), erased bytes on disk, and a property test over
random loss patterns.

## Limitations

* **No post-compromise recovery.** Whoever copies the unspent pools can read and forge all
  future traffic until they are replaced.
* **Availability is not protected.** An active attacker can end any session by injecting or
  altering one record.
* **Resynchronisation is manual and burns material** (next section). It is not automatic and
  not authenticated; it needs a quiescent pair.
* **Cost.** One secret byte per plaintext byte (at least 8 per record) plus 16 authentication
  bytes per record, and 48 / 32 bytes per handshake. Throughput is bounded by provisioning.
* The pools are provisioned out of band: this crate does not establish keys. ITSAKE and other
  information-theoretic key establishment were considered and are not implemented.
* Variable-time record handling on secret data is not claimed constant time; no timing review.
* Wire formats are versioned (`ver = 1`) but not frozen.
