# Trust Fabric: literature review

Status: first verified pass. This review exists to put evidence under the claims the Trust Fabric
documents and code comments make about prior work, to say which of them the sources support,
and to correct the ones they do not. It does **not** establish novelty, and it is not a survey of
the field.

## 1. How it was done, and what that does and does not show

**Method.** The references the repository's claims lean on, plus the sources behind its open
issues, were each checked by an independent checker working from a written protocol
(`data/literature/PROTOCOL.md`) that forbids filling any field from memory. The checkers matched
each reference to an authoritative record (Crossref, a publisher or standards-body page, ePrint,
arXiv, an author's own copy) and answered neutral questions about what the source states, quoting
the text. The hints given to the checkers were written from memory and were treated as search
keys only. The author spot-checked four points independently (the ITSAKE record, RFC 9846, NIST
SP 800-88 Rev. 2, and the message-transmission bound through restatements).

**Levels.**

| Level | Meaning |
|---|---|
| V2 | the bibliographic record matches an authoritative record **and** every claim question asked was answered from source text that was read |
| V1 | the record matches; claim questions were answered only partly, from an abstract or a mirror of the abstract, or from a secondary source, or not at all |
| V0 | no authoritative record matched |
| MISMATCH | a record exists but differs from the hint |

**What a level does not mean.** V2 says the *questions asked* were answered from source text. It
does not say the whole paper was read, understood or found correct. The checkers could not
read many primary papers: publishers' pages, DBLP and ePrint PDFs blocked automated access, some
scans did not decode, and the checkers did not circumvent paywalls. Where a primary text was not
read, the entry says so. **No human domain expert has reviewed this.** It should be reread by one
before any of it goes into a paper.

**Totals:** 73 records: 36 at V2, 34 at V1, 1 at V0, 2 flagged MISMATCH (both minor, explained in the bibliography). The raw records, with the quoted evidence, the URLs fetched and every
discrepancy, are in `data/literature/`.

## 2. Claims the repository makes, and what the sources say

Keys refer to the bibliography in section 8.

### Secret sharing and multiparty computation

| Claim in the repo | What the sources say | Status |
|---|---|---|
| Fewer than `k` Shamir shares reveal nothing (`cybermesh-sharing`) | Shamir 1979 is the source; read at the source | **supported** (`shamir1979`, V2) |
| BGW-style degree reduction is private against `t` passive parties when `n >= 2t + 1` (`cybermesh-private-compute`) | The BGW proceedings text states unconditional security for fewer than `n/2` passive and fewer than `n/3` active corruptions, and reduces the degree of the degree-`2t` product polynomial | **supported** (`bgw1988`, V2). Gennaro–Rabin–Rabin do degree reduction and randomisation in one step against a passive adversary (`grr1998`, V1: the submission text was read and gives no explicit sentence on `n` and `t`) |
| Active security needs more (`n >= 3t + 1`, verifiable sharing) | BGW: fewer than `n/3` active corruptions. Chaum–Crépeau–Damgård: at least `2n/3` of the participants honest. Rabin–Ben-Or: majority honest, but with a broadcast channel and pairwise secret channels | **supported**, with a broadcast caveat: Rabin–Ben-Or's honest-majority result uses a broadcast channel, and Hirt–Maurer's active condition *without* broadcast is the `Q3` (no three sets cover) one, so the threshold depends on the channel model (`bgw1988`, `ccd1988` V2; `rabinbenor1989` V1, abstract only) |
| Information checking as the model for authenticated shares (`cybermesh_trust::shares`) | The Rabin–Ben-Or abstract names "Information Checking" | **name supported at abstract level**; the construction there was not read (`rabinbenor1989`, V1). Our scheme is a **pairwise-MAC** version, not a reproduction of theirs |
| `Q2` / `Q3` conditions on the adversary structure (`cybermesh_trust::policy::q_condition`) | Hirt–Maurer's abstract states, in words, that no two sets covering the player set characterises **passive** adversaries **and active adversaries with a broadcast channel**, and that no three characterises **active adversaries without broadcast**. Cramer–Damgård–Maurer, Theorem 2, require `Q2` for passive security | **corrected**: earlier text said `Q2` for passive and `Q3` for active, leaving out the broadcast case (`hirtmaurer1997`, V1: abstract through a mirror; the names `Q2`, `Q3` are CDM's, `cdm2000` V2) |
| Beaver-style preprocessing is not used | Beaver 1991 precomputes random products ("one-time table"), without using the word "triple" | **consistent** (`beaver1991`, V2) |
| Packed (multi-secret) sharing is a research item, not built | Franklin–Yung: "polynomial-based multi-secret sharing" (abstract); DIKNS 2008: resilience is **computational** against an active adaptive adversary corrupting `1/2 - epsilon`; packing not read | **consistent** (`franklinyung1992` V1, `dikns2008` V1) |
| Algebraic-geometry codes give strong multiplication | CCCX 2009's abstract states ideal linear secret sharing with strong multiplication over any fixed finite field from algebraic geometry | **consistent as a pointer**; nothing implemented (`cccx2009`, V2) |
| Homomorphic secret sharing is computational | Boyle–Gilboa–Ishai 2016: DDH, inverse-polynomial correctness error | **supported** (`bgi2016`, V2): no information-theoretic construction there |
| General access structures are realisable | Ito–Saito–Nishizeki: "any access structure can be realized"; Karchmer–Wigderson: monotone span programs tied to secret sharing (Section 8, Theorem 13) | **supported** (`itosaito1987` V1, `karchmerwigderson1993` V2) |

### Proactive refresh, redistribution, robust sharing

| Claim | What the sources say | Status |
|---|---|---|
| Refresh by sharing a zero-constant polynomial (`refresh.rs`) | Herzberg et al. §3.3: each server picks a degree-`k` polynomial with free coefficient zero, sends sub-shares, and each adds what it receives to its old share, then erases | **mechanism supported** (`herzberg1995proactive`, V2) |
| That refresh is information-theoretic (`refresh.rs`, `limitations.md`) | **Only the bare renewal step is**, and only if sub-shares are delivered perfectly secretly. The paper's full scheme is **computational**: it assumes a broadcast channel, a synchronous clock, a computationally bounded adversary, encryption and signatures, a Feldman or Pedersen VSS, erasure, secure re-initialisation, and `k < n/2` per period | **corrected**: our crate implements the bare renewal only, with none of the detection or recovery of Section 4 |
| Mobile adversary model | Ostrovsky–Yung: the adversary corrupts "a constant fraction of the machines" per round (abstract); no exact constant read | **supported at abstract level** (`ostrovskyyung1991`, V1) |
| Redistribution to a new threshold or membership is a known technique | Desmedt–Jajodia read in full: redistributing shares to a new access structure without recovering the secret | **supported**; not implemented here (`desmedtjajodia1997`, V1; the report number and year are unconfirmed) |
| `2e + s <= n - k` for Reed-Solomon with `e` wrong and `s` missing shares (`robust.rs`) | Guruswami–Rudra–Sudan: Reed-Solomon minimum distance `n - k + 1` (Claim 5.2.3), MDS, and Theorem 14.2.2: `e` errors and `s` erasures are corrected whenever `2e + s < N - K + 1` | **supported** (`guruswami2025ect`, V1: a self-published open textbook with no Crossref record). `reedsolomon1960` V2 for the codes; the patent `welchberlekamp1986` describes remainder and rational-function decoding and corrects errors when `2t < d` (minor title difference "for" vs "of") |
| Robust sharing against wrong shares is only possible below `n/3` with Reed-Solomon | **Not what the literature shows.** Cevallos–Fehr–Ostrovsky–Rabani achieve unconditionally secure robust sharing for `n/3 <= t < n/2` with exponentially small failure and share overhead `O~(kappa + n)`; Bishop et al. reach `n = 2t + 1` with shares `m + O~(k)` bits, against a lower bound `m + k` | **the repo is behind the literature here** (`cevallos2012`, `bishop2016`, V2, abstracts). Our authenticated shares reach `t < n/2` by using pairwise keys, a different model |

### Authentication

| Claim | What the sources say | Status |
|---|---|---|
| The hash (Horner over GF(2^128), length block) is almost-XOR-universal with bound `(n+1)/2^128` | McGrew–Viega Lemma 2: GHASH is `ceil(l/w + 1) 2^-t` almost-XOR-universal; Bernstein Theorem 3.3: polynomial evaluation modulo a prime, collision bound `8 ceil(L/16)/2^106`. The same degree argument gives ours | **supported by analogy and by our own short argument**; wording corrected from "almost-universal" to **almost-XOR-universal** (`mcgrewviega2004`, `bernstein2005poly`, V2). The test now checks every difference, not only collisions |
| An almost-universal family gives an authentication code | Stinson Theorem 3.2: an `epsilon`-almost-**strongly**-universal class gives an authentication code with `P_d1 <= epsilon`; Theorem 6.4 gives a construction and key length | **supported**, and it is the strongly-universal property, not the one we use (`stinson1994`, V2 for the CRYPTO '91 text) |
| The same hash key can be reused across messages when each tag is masked by a fresh one-time pad | Credited in the repo to Wegman–Carter 1981. **That paper's text was not read** (paywalled) | **not verified in the primary source** (`wegmancarter1981`, V1). The reasoning that supports it for an almost-XOR-universal hash is in `authentication.md`; it is ours and has had no review |
| Wegman–Carter MACs are information-theoretically secure; Poly1305 and GCM are not | Bernstein: Poly1305-AES masks the hash with AES of a nonce (computational); McGrew–Viega: security in the PRP model | **supported** |
| Perfect secrecy needs a key at least as long as the message | Shannon Section 10: the number of keys is at least the number of messages; for long messages `R_M L_M <= R_K L_K`. The entropy form `H(K) >= H(M)` was not found in the passage read | **supported in the key-count form** (`shannon1949`, V2) |
| Authentication also costs secret key | Gilbert–MacWilliams–Sloane: an opponent's best substitution probability is at least `K^(-1/2)` for `K` keys (the exponent came from an OCR of the abstract and should be confirmed on a clean scan); Stinson gives key-length bounds; Simmons's abstract does not state key bounds | **supported with a caveat** (`gms1974` V2, `stinson1994` V2, `simmons1985` V1) |
| Pairwise key predistribution | Blom: storage per user "the least possible"; Blundo et al.: each user's piece must be at least `C(k+t-1, t-1)` times the key, tight; an interactive scheme needs `k + t - 1` times the key | **supported** (`blom1984` V1, `blundo1998` V2). We use pairwise pools, which need `n - 1` pools per party |
| Publicly verifiable unconditional authentication is not provided | Swanson–Stinson: unconditionally secure signature schemes need different signing and verification algorithms per user and a security model with explicit dispute-resolution trust assumptions; Chaum–Roijakkers: only "for a finite set of participants" (abstract, truncated); Hanaoka et al.: a model for a group, with transferability | **supported** (`swansonstinson2011` V2, `chaumroijakkers1990` V1, `hanaoka2000` V1). Pfitzmann–Waidner: the hinted report could **not** be found (V0); do not cite it |

### Transport

| Claim | What the sources say | Status |
|---|---|---|
| The transport is shaped like TLS 1.3 but is not TLS | RFC 8446 uses HKDF for key derivation and a signature (CertificateVerify) and a MAC (Finished) for authentication, so TLS 1.3 is computational throughout. **RFC 8446 is now obsoleted by RFC 9846 (July 2026)**, a minor backward-compatible revision | **supported**; cite RFC 9846 as current (`rfc8446` V2; the author confirmed the RFC 9846 status independently, its text unread) |
| ITSAKE was considered and not implemented (`transport-protocol.md`) | ITSAKE exists as IACR ePrint 2026/222, Jacqmin and Liénardy (Royal Military Academy, Belgium), February 2026: a two-message protocol from a **pre-shared secret** with entity authentication and perfect forward secrecy, proven without computational assumptions; the authors name the key length as the main drawback | **exists, unreviewed**: a preprint with no peer-reviewed venue found, abstract read only, security model unread (`itsake`, V2 for existence) |
| The wire is `n - 1` pools per party, one byte of pad per byte of data | Follows from Shannon's bound and the per-pair key cost; Blundo's bound for conferences | **consistent** |

### Routing and capacity

| Claim | What the sources say | Status |
|---|---|---|
| One-way perfectly secure message transmission needs `3t + 1` paths, two or more rounds need `2t + 1` | Desmedt–Wang (EUROCRYPT 2002, arXiv preprint, read in full): for a `k`-active adversary, "(3k + 1)-connectivity is necessary and sufficient" if all channels are one-way, "(2k + 1)" for two-way; Spini–Zémor read in full: Dolev et al. showed one round needs `n >= 3t + 1` and two or more need `n >= 2t + 1`. Both attribute it to Dolev–Dwork–Waarts–Yung | **supported through restatements only**: the original paper could not be read (`ddwy1993`, V1; `desmedt_wang_2002`, `spini_zemor_2016`, V1). "Connectivity" in Desmedt–Wang means `k` node-disjoint paths |
| Our `2t + 1` with authenticated shares in **one** round does not contradict that | The `3t + 1` one-way bound is for a model with **no pre-shared secrets**. Ours assumes sender and receiver already share pairwise MAC material, a different model, in which wrong shares are rejected rather than corrected | **a different theorem, argued by us**; it is not in the literature we read and has had no review |
| Max-flow equals min-cut; vertex-disjoint paths equal the minimum vertex cut | Ford–Fulkerson Theorem 1 (read): the maximal flow value equals the minimum cut; Elias–Feinstein–Shannon's abstract states the same cut theorem; Menger's record is verified but its German text was not read | **supported** (`fordfulkerson1956` V2; `eliasfeinsteinshannon1956`, `menger1927` V1) |
| Min-cost flow by successive shortest paths | Edmonds–Karp: the abstract is garbled and truncated before the minimum-cost result | **record only** (`edmondskarp1972`, V1); no claim is made from it |

## 3. Corrections this review forced on the repository

1. **`Q2` / `Q3`** (`policy::q_condition` docs, `trust-policy.md`): `Q2` covers passive adversaries and active adversaries *with* broadcast; `Q3` covers active adversaries *without* broadcast.
2. **Message-transmission figures** (`plan.rs`, `secure-routing.md`): attributed to Dolev et al. through verified restatements, with the pre-shared-keys difference stated.
3. **Herzberg et al.** (`refresh.rs`, `limitations.md`): our refresh is the bare, information-theoretic renewal step only; the paper's full scheme is computational.
4. **Wegman–Carter wording** (`mac.rs`, `authentication.md`): "almost-XOR-universal", citing McGrew–Viega Lemma 2 and Bernstein Theorem 3.3; the key-reuse composition is marked as not verified in the primary text; the exhaustive small-field test now checks every difference.
5. **BGW privacy reference** (`private-computation.md`, `lib.rs`): now cites the verified thresholds instead of "from memory".
6. **Open-issue citations** (`known-issues.md`): references added for erasure, rollback, provenance, side channels and signatures; `Gutmann 1996` is **not** cited for flash erasure (it covers magnetic media and volatile memory only).
7. **TLS and NIST** (`transport-protocol.md`, `known-issues.md`): RFC 9846 and SP 800-88 Rev. 2 are the current documents.

## 4. Sources behind the open issues

| Issue (`known-issues.md`) | Evidence found |
|---|---|
| 1. Backup restore resurrects consumed secrets | Rollback and state-continuity work addresses this **for trusted-execution environments**: ROTE keeps state integrity through a distributed set of enrolled platforms; Ariadne needs one bit flip of non-volatile memory per update; Memoir uses a summary of the request history in protected NVRAM and a deterministic module. All assume protected hardware or modules; a pool of plain files has none. The direction (a protected monotonic counter or a quorum of witnesses) is known; none is built here (`matetic2017`, `strackxpiessens2016`, `parno2011`, V2, abstracts) |
| 4. Provenance cannot be verified | NIST SP 800-90B: estimation methods rely on statistical assumptions and "should not replace in-depth analysis" of the noise source (`nist80090b`, V2, full text) |
| 5. Erasure on SSDs | Wei et al.: overwriting the whole visible address space twice is usually, not always, sufficient; no file-level technique designed for hard drives is effective on SSDs; built-in sanitise commands are sometimes implemented incorrectly (`wei2011`, V2). Gutmann 1996 does **not** address flash. NIST SP 800-88 Rev. 1 was withdrawn on 2025-09-26 and replaced by Rev. 2 (`nist80088`) |
| 7. Side channels | Kocher 1996 (timing) and Bernstein 2005 (data-dependent table lookups leak through the cache) (`kocher1996`, `bernstein2005cache`, V2). Supports the design choice of avoiding secret-dependent tables, not any claim of resistance |

## 5. What the literature offers that the repository does not use

* **Robust secret sharing below `n/2` without pre-shared keys** (Cevallos et al.; Bishop et al.), instead of Reed-Solomon below `n/3` or pairwise MACs.
* **Verifiable secret sharing** with honest majority (Rabin–Ben-Or; the Feldman and Pedersen constructions the Herzberg paper uses): the dishonest-dealer gap in `known-issues.md` #3.
* **General-adversary MPC** (Hirt–Maurer; Cramer–Damgård–Maurer) in place of the threshold-only BGW baseline.
* **State-continuity techniques** for the rollback problem.
* **Composable frameworks**: Canetti's UC (the composition theorem was read in a 2018 revision, not the 2001 text, and the paper says its text changed substantially across 15 revisions), Maurer–Renner's abstract cryptography (abstract only), and the quantum-side-information treatments of Renner, Portmann–Renner, König–Renner–Schaffner and Ben-Or et al., all read at the abstract level or better. None is applied to the transport.

## 6. The capacity question, and what is not claimed

The secret-key capacity literature (Maurer 1993; Ahlswede–Csiszár 1993; Csiszár–Narayan 2004) defines and bounds the rate of a shared secret key obtainable from **correlated random sources with public discussion**; secure network coding (Cai–Yeung; Feldman et al.) studies a wiretapper on a bounded set of links. The Trust Fabric's setting is different: secret material is **pre-provisioned**, consumed by use, authenticated and replenished, and the adversary is a set of domains. These abstracts say the formulas exist for those other models; they do not cover this one.

Nothing in this repository defines `C_secure(G, A, R)` rigorously, and **no result about it is
claimed**. `wire_secret_flow` bounds one scheme (per-hop one-time-pad forwarding) and is only a
max-flow. Whether a nontrivial characterisation exists, and whether it is new, requires reading
the full texts above and was not done.

## 7. Not checked

* The full text of Wegman–Carter 1981 (the key-reuse composition), Dolev et al. 1993, Menger 1927, Rabin–Ben-Or 1989, Hirt–Maurer 1997, Franklin–Wright 2000, Srinathan et al. 2004, Kurosawa–Suzuki 2008 (not read).
* The ITSAKE security model; RFC 9846 and SP 800-88 Rev. 2 (existence only).
* Several V1 entries are verified only to the abstract or its mirror: see each entry.
* Whether any result in the secret-sharing literature already contains the authenticated-share, resync or restore behaviour reported here. No search for novelty was done.
* Human expert review of everything above.

## 8. Bibliography

Entries are generated from the verification records in `data/literature/`. `[V2]` etc. is the
verification level; text after the dash is the checker's qualifier. Two superseded duplicates were
dropped (`herzberg1995` V1 in favour of `herzberg1995proactive` V2; `dolev1993_psmt` in favour of
`ddwy1993`).

- **ahlswede2000** [V1] Ahlswede, R.; Cai, N.; Li, S.-Y. R.; Yeung, R. W. "Network information flow". IEEE Transactions on Information Theory 46(4), 1204-1216, July 2000. DOI 10.1109/18.850663. (A short ISIT 1998 abstract "Network information flow theory", p. 186, is a separate record.)
- **ahlswedecsiszar1993** [V1] Ahlswede, R.; Csiszar, I. "Common randomness in information theory and cryptography. I. Secret sharing". IEEE Transactions on Information Theory 39(4), 1121-1132, July 1993. DOI 10.1109/18.243431.
- **bb84** [V1] Charles H. Bennett, Gilles Brassard. "Quantum cryptography: Public key distribution and coin tossing". Proceedings of the IEEE International Conference on Computers, Systems and Signal Processing, Bangalore, India, December 1984, pp. 175-179 (venue and pages as stated by the authors' own arXiv scan record). No DOI for the 1984 original.
- **beaver1991** [V2] Donald Beaver. "Efficient multiparty protocols using circuit randomization". Advances in Cryptology - CRYPTO '91, LNCS 576, pp. 420-432. https://doi.org/10.1007/3-540-46766-1_34
- **benor2005** [V2] M. Ben-Or, M. Horodecki, D. W. Leung, D. Mayers, J. Oppenheim. "The Universal Composable Security of Quantum Key Distribution". Theory of Cryptography (TCC 2005), LNCS 3378, pp. 386-406, Springer, 2005. DOI 10.1007/978-3-540-30576-7_21. arXiv quant-ph/0409078.
- **bernstein2005cache** [V2] Daniel J. Bernstein. "Cache-timing attacks on AES". Preprint dated 2005-04-14, University of Illinois at Chicago. https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
- **bernstein2005poly** [V2] Daniel J. Bernstein. "The Poly1305-AES Message-Authentication Code". Fast Software Encryption (FSE 2005), LNCS 3557, pp. 32-49. DOI 10.1007/11502760_3.
- **bernstein2005wcs** [V1] Daniel J. Bernstein. "Stronger Security Bounds for Wegman-Carter-Shoup Authenticators". Advances in Cryptology - EUROCRYPT 2005, LNCS 3494, pp. 164-180. DOI 10.1007/11426639_10. — abstract read; the specific "attempts and message length" aspect is only partly addressed by the abstract
- **bgi2016** [V2] Elette Boyle, Niv Gilboa, Yuval Ishai. "Breaking the Circuit Size Barrier for Secure Computation Under DDH". Advances in Cryptology, CRYPTO 2016, LNCS 9814, pp. 509-539. DOI 10.1007/978-3-662-53018-4_19. ePrint 2016/585.
- **bgw1988** [V2] Michael Ben-Or, Shafi Goldwasser, Avi Wigderson. "Completeness theorems for non-cryptographic fault-tolerant distributed computation (extended abstract)". Proceedings of the 20th Annual ACM Symposium on Theory of Computing (STOC '88), pp. 1-10, 1988. https://doi.org/10.1145/62212.62213
- **bishop2016** [V2] Allison Bishop, Valerio Pastro, Rajmohan Rajaraman, Daniel Wichs. "Essentially Optimal Robust Secret Sharing with Maximal Corruptions". EUROCRYPT 2016 (LNCS 9665), pp. 58-86. DOI 10.1007/978-3-662-49890-3_3. ePrint 2015/1032.
- **blakley1979** [V1] G. R. Blakley. "Safeguarding cryptographic keys". Proceedings of the AFIPS 1979 National Computer Conference, Vol. 48, Arlington, Va., June 1979, pp. 313-317 (as cited by Shamir). Crossref has the IEEE-hosted record at pp. 313-318: https://doi.org/10.1109/MARK.1979.8817296
- **blom1984** [V1] Rolf Blom. "An Optimal Class of Symmetric Key Generation Systems". Advances in Cryptology - EUROCRYPT '84, LNCS 209, pp. 335-338, Springer, 1985. DOI 10.1007/3-540-39757-4_22.
- **blundo1998** [V2] Carlo Blundo, Alfredo De Santis, Amir Herzberg, Shay Kutten, Ugo Vaccaro, Moti Yung. "Perfectly Secure Key Distribution for Dynamic Conferences". Information and Computation 146(1), 1-23, October 1998. DOI 10.1006/inco.1998.2717. Conference: "Perfectly-Secure Key Distribution for Dynamic Conferences", CRYPTO '92, LNCS 740, pp. 471-486, DOI 10.1007/3-540-48071-4_33 (proceedings 1993). — claim read in the CRYPTO '92 abstract; the journal text was not read
- **caiyeung** [V1] Two records exist.
- **canetti2001** [V1] Ran Canetti. "Universally Composable Security: A New Paradigm for Cryptographic Protocols". Proceedings 42nd IEEE Symposium on Foundations of Computer Science (FOCS 2001), pp. 136-145, 2001. DOI 10.1109/SFCS.2001.959888. Preprint: IACR ePrint 2000/067 (= ECCC TR01-016). Later journal-style rewrite: "Universally Composable Security", J. ACM 67(5), 2020, DOI 10.1145/3402457 (different title).
- **cartermegman1979** [V2] J. Lawrence Carter, Mark N. Wegman. "Universal classes of hash functions". Journal of Computer and System Sciences 18(2), 143-154, April 1979. DOI 10.1016/0022-0000(79)90044-8. Conference version: "Universal classes of hash functions (Extended Abstract)", STOC '77, pp. 106-112, DOI 10.1145/800105.803400.
- **cccx2009** [V2] Ignacio Cascudo, Hao Chen, Ronald Cramer, Chaoping Xing. "Asymptotically Good Ideal Linear Secret Sharing with Strong Multiplication over Any Fixed Finite Field". Advances in Cryptology, CRYPTO 2009, LNCS 5677, pp. 466-486. DOI 10.1007/978-3-642-03356-8_28 — abstract text obtained via the fetch tool's extraction of the Springer page; see notes
- **ccd1988** [V2] David Chaum, Claude Crepeau, Ivan Damgard. "Multiparty unconditionally secure protocols (extended abstract)". Proceedings of the 20th Annual ACM Symposium on Theory of Computing (STOC '88), pp. 11-19, 1988. https://doi.org/10.1145/62212.62214
- **cdm2000** [V2] Ronald Cramer, Ivan Damgard, Ueli Maurer. "General secure multi-party computation from any linear secret-sharing scheme". Advances in Cryptology - EUROCRYPT 2000, LNCS (vol. 1807), pp. 316-334, 2000. https://doi.org/10.1007/3-540-45539-6_22 ; full version IACR ePrint 2000/037.
- **cdn2015** [V2] Ronald Cramer, Ivan Bjerre Damgard, Jesper Buus Nielsen. "Secure Multiparty Computation and Secret Sharing". Cambridge University Press, 2015. DOI 10.1017/CBO9781107337756. ISBN 9781107043053 (hardback, as listed on the Cambridge page; assignment of format inferred by the fetch tool) and 9781107337756 (online).
- **cevallos2012** [V2] Alfonso Cevallos, Serge Fehr, Rafail Ostrovsky, Yuval Rabani. "Unconditionally-Secure Robust Secret Sharing with Compact Shares". EUROCRYPT 2012 (LNCS 7237), pp. 195-208. DOI 10.1007/978-3-642-29011-4_13.
- **chaumroijakkers1990** [V1] David Chaum, Sandra Roijakkers. "Unconditionally-Secure Digital Signatures". Advances in Cryptology - CRYPTO '90, LNCS 537, pp. 206-214, Springer. DOI 10.1007/3-540-38424-3_15.
- **csiszarnarayan2004** [V1] Csiszar, I.; Narayan, P. "Secrecy Capacities for Multiple Terminals". IEEE Transactions on Information Theory 50(12), 3047-3061, December 2004. DOI 10.1109/tit.2004.838380.
- **ddwy1993** [V1] Dolev, D.; Dwork, C.; Waarts, O.; Yung, M. "Perfectly secure message transmission". Journal of the ACM 40(1), 17-47, January 1993. DOI 10.1145/138027.138036. FOCS version: Proc. 31st Annual Symposium on Foundations of Computer Science (1990), pp. 36-45, DOI 10.1109/fscs.1990.89522.
- **desmedt_wang_2002** [V1] Desmedt, Wang. "Perfectly Secure Message Transmission Revisited". EUROCRYPT 2002, LNCS 2332, pp. 502-517 (venue/pages from the paper's own reference [3], truncated "...rocrypt '02, pages 502-517, LNCS 2332"); arXiv cs/0208041 (26 Aug 2002); ePrint 2002/128 (page says "Published elsewhere"). — arXiv/ePrint records matched; Springer/Crossref record for the EUROCRYPT version not fetched
- **desmedtjajodia1997** [V1] Yvo Desmedt, Sushil Jajodia. "Redistributing secret shares to new access structures and its applications". Technical report (George Mason University, Dept. of Information and Software Systems Engineering), 1997. Copy at https://csis.gmu.edu/jajodia/desmedt25-7-1997.pdf
- **dikns2008** [V1] Ivan Damgard, Yuval Ishai, Mikkel Kroigaard, Jesper Buus Nielsen, Adam Smith. "Scalable Multiparty Computation with Nearly Optimal Work and Resilience". Advances in Cryptology, CRYPTO 2008, LNCS 5157, pp. 241-261. DOI 10.1007/978-3-540-85174-5_14
- **edmondskarp1972** [V1] Edmonds, J.; Karp, R. M. "Theoretical Improvements in Algorithmic Efficiency for Network Flow Problems". Journal of the ACM 19(2), 248-264, April 1972. DOI 10.1145/321694.321699.
- **eliasfeinsteinshannon1956** [V1] Elias, P.; Feinstein, A.; Shannon, C. E. "A note on the maximum flow through a network". IRE Transactions on Information Theory 2(4), 117-119, December 1956. DOI 10.1109/tit.1956.1056816.
- **fmss2004** [V1] Feldman, J.; Malkin, T.; Servedio, R.; Stein, C. "On the Capacity of Secure Network Coding". 42nd Annual Allerton Conference on Communication, Control, and Computing, 2004. Author copy: https://www.cs.columbia.edu/~rocco/papers/allerton04.html (PDF at https://www.cs.columbia.edu/~rocco/Public/sflow_allerton_final.pdf).
- **fordfulkerson1956** [V2] Ford, L. R., Jr.; Fulkerson, D. R. "Maximal Flow Through a Network". Canadian Journal of Mathematics 8, 399-404, 1956. DOI 10.4153/cjm-1956-045-5. Reprinted in Classic Papers in Combinatorics (Birkhauser, 2009), pp 243-248.
- **franklinwright2000** [V1] Franklin, M.; Wright, R. "Secure Communication in Minimal Connectivity Models". Journal of Cryptology 13(1), 9-30, January 2000. DOI 10.1007/s001459910002. Preliminary version: EUROCRYPT 1998, LNCS, pp. 346-360, DOI 10.1007/bfb0054138.
- **franklinyung1992** [V1] Matthew K. Franklin, Moti Yung. "Communication complexity of secure computation (extended abstract)". Proceedings of the 24th Annual ACM Symposium on Theory of Computing (STOC '92), pp. 699-710, 1992. https://doi.org/10.1145/129712.129780
- **gms1974** [V2] E. N. Gilbert, F. J. MacWilliams, N. J. A. Sloane. "Codes which detect deception". Bell System Technical Journal 53(3), 405-424, March 1974. DOI 10.1002/j.1538-7305.1974.tb02751.x.
- **grr1998** [V1] Rosario Gennaro, Michael O. Rabin, Tal Rabin. "Simplified VSS and fast-track multiparty computations with applications to threshold cryptography". Proceedings of the 17th Annual ACM Symposium on Principles of Distributed Computing (PODC '98), pp. 101-111, 1998. https://doi.org/10.1145/277697.277716
- **guruswami2025ect** [V1] Venkatesan Guruswami, Atri Rudra, Madhu Sudan. "Essential Coding Theory". Open textbook, version dated August 26, 2025 (566 pp.). http://www.cse.buffalo.edu/faculty/atri/courses/coding-theory/book/ (PDF fetched: https://cse.buffalo.edu/faculty/atri/courses/coding-theory/book/web-coding-book.pdf) — no Crossref/DBLP record: it is a self-published book; text read at the authors' institutional host, but this is an unpublished web book, not a peer-reviewed record
- **gutmann1996** [V2] Peter Gutmann. "Secure Deletion of Data from Magnetic and Solid-State Memory". 6th USENIX Security Symposium, San Jose, CA, 1996. https://www.usenix.org/conference/6th-usenix-security-symposium/secure-deletion-data-magnetic-and-solid-state-memory — bibliographic record matches; the claim presumption in the question does not hold, see below
- **hanaoka2000** [V1] Goichiro Hanaoka, Junji Shikata, Yuliang Zheng, Hideki Imai. "Unconditionally Secure Digital Signature Schemes Admitting Transferability". Advances in Cryptology - ASIACRYPT 2000, LNCS 1976, pp. 130-142. DOI 10.1007/3-540-44448-3_11.
- **herzberg1995proactive** [V2] Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, Moti Yung. "Proactive Secret Sharing Or: How to Cope With Perpetual Leakage". CRYPTO '95 (LNCS 963), pp. 339-352, Springer 1995. DOI 10.1007/3-540-44750-4_27.
- **hirtmaurer1997** [V1] Martin Hirt, Ueli Maurer. "Complete characterization of adversaries tolerable in secure multi-party computation (extended abstract)". Proceedings of the 16th Annual ACM Symposium on Principles of Distributed Computing (PODC '97), pp. 25-34, 1997. https://doi.org/10.1145/259380.259412
- **itosaito1987** [V1] Mitsuru Ito, Akira Saito, Takao Nishizeki. "Secret sharing scheme realizing general access structure". Electronics and Communications in Japan (Part III: Fundamental Electronic Science) 72(9), pp. 56-64, 1989. DOI 10.1002/ecjc.4430720906. (Conference version: IEEE GLOBECOM '87, Tokyo, 1987, per secondary listings only.)
- **itsake** [V2] Pierre-Alain Jacqmin, Jean Lienardy (Royal Military Academy, Belgium). "ITSAKE: an unconditionally secure authenticated key establishment protocol". Cryptology ePrint Archive, Paper 2026/222, received 2026-02-10, approved 2026-02-12. https://eprint.iacr.org/2026/222 — for the existence of an authoritative record (IACR ePrint). It is a preprint with no peer-reviewed venue. The claim answer rests on the abstract only.
- **karchmerwigderson1993** [V2] Mauricio Karchmer, Avi Wigderson. "On span programs". Proceedings of the Eighth Annual Structure in Complexity Theory Conference, 1993, pp. 102-111. DOI 10.1109/SCT.1993.336536.
- **kocher1996** [V2] Paul C. Kocher. "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems". Advances in Cryptology, CRYPTO '96, LNCS 1109, pp. 104-113, 1996. DOI 10.1007/3-540-68697-5_9
- **koenigrennerschaffner2009** [V2] Robert Konig, Renato Renner, Christian Schaffner. "The Operational Meaning of Min- and Max-Entropy". IEEE Transactions on Information Theory 55(9), pp. 4337-4347, Sept 2009. DOI 10.1109/TIT.2009.2025545. arXiv:0807.1338.
- **macwilliamssloane1977** [V1] F. J. MacWilliams, N. J. A. Sloane. "The Theory of Error-Correcting Codes". North-Holland Mathematical Library, vol. 16, North-Holland (Amsterdam / New York), 1977, xv + 762 pp., ISBN 0-444-85193-3 (as given by library catalogue search listings; see Notes).
- **matetic2017** [V2] Sinisa Matetic, Mansoor Ahmed, Kari Kostiainen, Aritra Dhar, David Sommer, Arthur Gervais, Ari Juels, Srdjan Capkun. "ROTE: Rollback Protection for Trusted Execution". 26th USENIX Security Symposium, Vancouver, 2017, pp. 1289-1306. https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic
- **maurer1993** [V1] Maurer, U. M. "Secret key agreement by public discussion from common information". IEEE Transactions on Information Theory 39(3), 733-742, May 1993. DOI 10.1109/18.256484.
- **maurerrenner2011** [V1] Ueli Maurer, Renato Renner. "Abstract Cryptography". Innovations in Computer Science (ICS 2011), Tsinghua University Press, 2011 (pp. 1-21 per secondary citation, not checked at an authoritative record). Proceedings PDF: https://conference.iiis.tsinghua.edu.cn/ICS2011/content/paper/14.pdf (first page header "Innovations in Computer Science 2011").
- **mcgrewviega2004** [V2] David A. McGrew, John Viega. "The Security and Performance of the Galois/Counter Mode (GCM) of Operation". Progress in Cryptology - INDOCRYPT 2004, LNCS 3348, pp. 343-355. DOI 10.1007/978-3-540-30556-9_27. ePrint 2004/193 (title there ends "(Full Version)").
- **menger1927** [V1] Menger, K. "Zur allgemeinen Kurventheorie". Fundamenta Mathematicae 10, 96-115, 1927. DOI 10.4064/fm-10-1-96-115. EuDML: http://eudml.org/doc/211191.
- **nist80088** [MISMATCH] Authors not verified (not read from the text). "Guidelines for Media Sanitization". NIST SP 800-88 Rev. 1, December 2014. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf. — status only
- **nist80090b** [V2] Meltem Sonmez Turan, Elaine Barker, John Kelsey, Kerry A. McKay, Mary L. Baish, Mike Boyle. "Recommendation for the Entropy Sources Used for Random Bit Generation". NIST SP 800-90B, 84 pages, January 2018. DOI 10.6028/NIST.SP.800-90B. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf
- **ostrovskyyung1991** [V1] Rafail Ostrovsky, Moti Yung. "How to withstand mobile virus attacks (extended abstract)". Proceedings of the 10th ACM Symposium on Principles of Distributed Computing (PODC '91), pp. 51-59, 1991. DOI 10.1145/112600.112605.
- **parno2011** [V2] Bryan Parno, Jacob R. Lorch, John R. Douceur, James Mickens, Jonathan M. McCune. "Memoir: Practical State Continuity for Protected Modules". 2011 IEEE Symposium on Security and Privacy, May 2011, pp. 379-394. DOI 10.1109/SP.2011.38
- **pfitzmannwaidner** [V0] Not verified as hinted. The only authoritative record found for Pfitzmann/Waidner on this topic: Birgit Pfitzmann, Michael Waidner. "Unconditional Byzantine agreement for any number of faulty processors". STACS 92, LNCS 577, pp. 337-350, 1992. DOI 10.1007/3-540-55210-3_195 (Crossref). Also: Baum-Waidner, Pfitzmann, Waidner, "Unconditional Byzantine Agreement with good majority", STACS 91, pp. 285-295, DOI 10.1007/BFb0020806. — for the hinted IBM report (RZ 2882, 1996, "Information-theoretic pseudosignatures and Byzantine agreement for t >= n/3"). The STACS 92 paper is a different, verified reco
- **portmannrenner2014** [V2] Christopher Portmann, Renato Renner. "Cryptographic security of quantum key distribution". arXiv:1409.3525 [quant-ph], 11 Sep 2014 (v1; "31+23 pages"). DOI 10.48550/arXiv.1409.3525. No journal reference listed on arXiv.
- **rabinbenor1989** [V1] Tal Rabin, Michael Ben-Or. "Verifiable secret sharing and multiparty protocols with honest majority". Proceedings of the 21st Annual ACM Symposium on Theory of Computing (STOC '89), pp. 73-85, 1989. https://doi.org/10.1145/73007.73014
- **reedsolomon1960** [V2] I. S. Reed, G. Solomon. "Polynomial Codes Over Certain Finite Fields". Journal of the Society for Industrial and Applied Mathematics 8(2), pp. 300-304, June 1960. DOI 10.1137/0108018. JSTOR 2098968.
- **renner2005** [V2] Renato Renner. "Security of Quantum Key Distribution". PhD thesis, ETH Zurich, Diss. ETH No. 16242, 2005. arXiv:quant-ph/0512258 (v1 30 Dec 2005, v2 11 Jan 2006 "index added"). No journal version (later published in Int. J. Quantum Inf. 6, 2008, not checked here).
- **rfc8446** [V2] E. Rescorla. "The Transport Layer Security (TLS) Protocol Version 1.3". RFC 8446, IETF, Proposed Standard, August 2018. DOI 10.17487/RFC8446. https://www.rfc-editor.org/rfc/rfc8446
- **shamir1979** [V2] Adi Shamir. "How to share a secret". Communications of the ACM, 22(11), pp. 612-613, November 1979. https://doi.org/10.1145/359168.359176
- **shannon1949** [V2] Claude E. Shannon. "Communication Theory of Secrecy Systems". Bell System Technical Journal 28(4), 656-715, October 1949. DOI 10.1002/j.1538-7305.1949.tb00928.x.
- **simmons1985** [V1] Gustavus J. Simmons. "Authentication Theory/Coding Theory". In Advances in Cryptology (CRYPTO '84), LNCS 196, pp. 411-431, Springer, 1985. DOI 10.1007/3-540-39568-7_32.
- **spini_zemor_2016** [V1] Spini, Zemor. "Perfectly Secure Message Transmission in Two Rounds". arXiv:1608.01909v1 (5 Aug 2016); footnote says a shorter version is scheduled for TCC 2016-B. TCC proceedings record NOT fetched. — arXiv only; peer-reviewed version not matched
- **stinson1994** [V2] Douglas R. Stinson. "Universal hashing and authentication codes". Designs, Codes and Cryptography 4(3), 369-380, 1994 (July). DOI 10.1007/BF01388651. Conference version: CRYPTO '91, LNCS 576, pp. 74-85, DOI 10.1007/3-540-46766-1_5 (proceedings published 1992). — for the CRYPTO '91 text; the DCC 1994 text itself was not read
- **strackxpiessens2016** [V2] Raoul Strackx, Frank Piessens. "Ariadne: A Minimal Approach to State Continuity". 25th USENIX Security Symposium, Austin, 2016, pp. 875-892. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/strackx
- **swansonstinson2011** [V2] Colleen M. Swanson, Douglas R. Stinson. "Unconditionally Secure Signature Schemes Revisited". Information Theoretic Security (ICITS 2011), LNCS 6673, pp. 100-116. DOI 10.1007/978-3-642-20728-0_10. ePrint 2011/104. Extended journal version: Journal of Mathematical Cryptology 10(1), 35-67, 2016, DOI 10.1515/jmc-2016-0002.
- **wegmancarter1981** [V1] Mark N. Wegman, J. Lawrence Carter. "New hash functions and their use in authentication and set equality". Journal of Computer and System Sciences 22(3), 265-279, June 1981. DOI 10.1016/0022-0000(81)90033-7. (Earlier FOCS 1979 version: "New classes and applications of hash functions", pp. 175-182, DOI 10.1109/SFCS.1979.26.)
- **wei2011** [V2] Michael Wei, Laura M. Grupp, Frederick E. Spada, Steven Swanson. "Reliably Erasing Data From Flash-Based Solid State Drives". 9th USENIX Conference on File and Storage Technologies (FAST '11), San Jose, 2011. https://www.usenix.org/conference/fast11/reliably-erasing-data-flash-based-solid-state-drives
- **welchberlekamp1986** [MISMATCH] Lloyd R. Welch, Elwyn R. Berlekamp. "Error correction for algebraic block codes". US Patent 4,633,470, assignee Cyclotomics, Inc.; filed 27 Sep 1983, granted 30 Dec 1986. https://patents.google.com/patent/US4633470A/en — minor
- **wyner1975** [V1] Wyner, A. D. "The Wire-Tap Channel". Bell System Technical Journal 54(8), 1355-1387, October 1975. DOI 10.1002/j.1538-7305.1975.tb02040.x.
