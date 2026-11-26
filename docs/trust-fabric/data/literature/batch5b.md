### wei2011
- **Citation (as verified):** Michael Wei, Laura M. Grupp, Frederick E. Spada, Steven Swanson. "Reliably Erasing Data From Flash-Based Solid State Drives". 9th USENIX Conference on File and Storage Technologies (FAST '11), San Jose, 2011. https://www.usenix.org/conference/fast11/reliably-erasing-data-flash-based-solid-state-drives
- **Level:** V2
- **Sources fetched:** USENIX FAST'11 page -> authors, title, venue, year (no abstract on page); https://www.usenix.org/legacy/events/fast11/tech/full_papers/Wei.pdf (downloaded, pdftotext) -> full abstract and introduction.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What does the abstract say about overwriting individual files and built-in drive-level sanitization? -> A: Built-in commands are effective but manufacturers sometimes implement them incorrectly. Overwriting the whole visible address space twice is usually, not always, sufficient. None of the existing hard-drive-oriented techniques for individual file sanitization are effective on SSDs. | read: abstract (full text PDF) | evidence: "none of the existing hard drive-oriented techniques for individual file sanitization are effective on SSDs." https://www.usenix.org/legacy/events/fast11/tech/full_papers/Wei.pdf
- **Notes:** The abstract also concludes that reliable SSD sanitization requires built-in, verifiable sanitize operations, and the authors propose FTL extensions for file sanitization. Pages not recorded (not read from a metadata record).

### gutmann1996
- **Citation (as verified):** Peter Gutmann. "Secure Deletion of Data from Magnetic and Solid-State Memory". 6th USENIX Security Symposium, San Jose, CA, 1996. https://www.usenix.org/conference/6th-usenix-security-symposium/secure-deletion-data-magnetic-and-solid-state-memory
- **Level:** V2 (bibliographic record matches; the claim presumption in the question does not hold, see below)
- **Sources fetched:** USENIX conference page -> authors, title, venue, year, abstract; https://www.usenix.org/legacy/publications/library/proceedings/sec96/full_papers/gutmann/index.html (downloaded, full text, grepped and read sections 7-9) -> full text.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What does it state about erasing data from solid-state memory? -> A: The paper's "solid-state" content is only volatile semiconductor RAM (SRAM/DRAM) in sections 7 and 8. Flash, EEPROM and SSDs do not appear in the text (grep for "flash", "EEPROM", "non-volatile", "erasable" found nothing relevant). The abstract does not mention solid-state memory; "solid-state" occurs only in the title. On DRAM erasure it says overwriting is much less effective than for magnetic media and recommends constantly flipping bits for small amounts of sensitive data such as keys. Its conclusion: "effectively impossible to sanitise storage locations by simple overwriting". | read: full text | evidence: "Simply repeatedly overwriting the data held in DRAM with new data isn't nearly as effective as it is for magnetic media." https://www.usenix.org/legacy/publications/library/proceedings/sec96/full_papers/gutmann/index.html
- **Notes:** Do not cite Gutmann 1996 for flash/SSD erasure. It does not address NAND flash at all. The conclusion's "no matter how many overwrite passes" applies to magnetic media and RAM as analysed there.

### kocher1996
- **Citation (as verified):** Paul C. Kocher. "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems". Advances in Cryptology, CRYPTO '96, LNCS 1109, pp. 104-113, 1996. DOI 10.1007/3-540-68697-5_9
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works/10.1007/3-540-68697-5_9 -> title, author, CRYPTO '96, 1996, pp. 104-113, DOI; https://www.paulkocher.com/doc/TimingAttacks.pdf (author's copy, downloaded, pdftotext) -> abstract and introduction. Springer landing page was blocked by redirect.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What does the abstract say about the attack? -> A: Carefully measuring the time of private-key operations may let attackers find fixed Diffie-Hellman exponents, factor RSA keys and break other systems. The attack is computationally inexpensive and often needs only known ciphertext. Countermeasures for RSA and DH are presented. | read: abstract (author's PDF copy) | evidence: "By carefully measuring the amount of time required to perform private key operations, attackers may be able to find fixed Diffie-Hellman exponents" https://www.paulkocher.com/doc/TimingAttacks.pdf
- **Notes:** The abstract text was read from the author's copy, not the Springer page. The paper says the attack does not work if a new secret exponent is chosen for each operation.

### bernstein2005cache
- **Citation (as verified):** Daniel J. Bernstein. "Cache-timing attacks on AES". Preprint dated 2005-04-14, University of Illinois at Chicago. https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
- **Level:** V2
- **Sources fetched:** https://cr.yp.to/antiforgery/cachetiming-20050414.pdf (downloaded, pdftotext, 37 pages) -> abstract, introduction, terminology note.
- **Hint vs found:** none. The document is a self-published preliminary version; no formal venue.
- **Claim checks:**
  - Q: What does it say about data-dependent table lookups? -> A: It defines S-box lookups as table lookups with input-dependent indices (loads from input-dependent addresses). It says it is extremely difficult to load an array entry in time independent of the index, so constant-time high-speed AES is hard. It warns against using secret data as an array index. | read: full text (introduction and terminology note) | evidence: "Using secret data as an array index is a recipe for disaster." https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
- **Notes:** The document says it is a preliminary version meant to be replaced by a final version. Its abstract says the AES design is to blame, not the library. The attack target was OpenSSL AES on a Pentium III, timed over a network. A later workshop version exists (not fetched).

### matetic2017
- **Citation (as verified):** Sinisa Matetic, Mansoor Ahmed, Kari Kostiainen, Aritra Dhar, David Sommer, Arthur Gervais, Ari Juels, Srdjan Capkun. "ROTE: Rollback Protection for Trusted Execution". 26th USENIX Security Symposium, Vancouver, 2017, pp. 1289-1306. https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic
- **Level:** V2
- **Sources fetched:** USENIX presentation page -> authors, title, venue, year, pages, abstract.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What problem does it address and what does it use to protect state from rollback? -> A: Rollback attacks on SGX, where an adversary replays old persistently stored data or starts multiple instances. It uses a distributed system in which multiple enrolled processors/platforms assist each other (not local non-volatile memory or hardware counters). Stated property: the only way to violate integrity is to reset all participating platforms to their initial state. | read: abstract | evidence: "multiple processors can be enrolled to assist each other." https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic
- **Notes:** Abstract also claims better performance than prior solutions based on local non-volatile memory. Security is relative to an adversary model the paper defines; not assessed here.

### strackxpiessens2016
- **Citation (as verified):** Raoul Strackx, Frank Piessens. "Ariadne: A Minimal Approach to State Continuity". 25th USENIX Security Symposium, Austin, 2016, pp. 875-892. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/strackx
- **Level:** V2
- **Sources fetched:** USENIX presentation page -> authors, title, venue, year, pages, abstract.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What does the abstract say about state continuity and hardware counters? -> A: State continuity requires (1) rollback protection, (2) a module that accepted an input continues on it or never advances, and (3) a liveness guarantee after power loss. Ariadne needs only one bit flip of non-volatile memory per state update, which it calls the theoretical lower limit. The abstract does not mention "hardware counters"; it speaks of non-volatile memory. | read: abstract | evidence: "requiring only a single bit flip of non-volatile memory per state update." https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/strackx
- **Notes:** Calling Ariadne a "hardware counter" scheme is not supported by the abstract. Full text not read, so the body may discuss counters.

### parno2011
- **Citation (as verified):** Bryan Parno, Jacob R. Lorch, John R. Douceur, James Mickens, Jonathan M. McCune. "Memoir: Practical State Continuity for Protected Modules". 2011 IEEE Symposium on Security and Privacy, May 2011, pp. 379-394. DOI 10.1109/SP.2011.38
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works/10.1109/SP.2011.38 -> five authors, venue, pp. 379-394, May 2011; https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/memoir.pdf (downloaded, pdftotext) -> abstract; MSR publication page -> authors, venue.
- **Hint vs found:** none. The Microsoft-hosted PDF lists four authors on the title page (Parno, Lorch, Douceur, Mickens); Crossref and the MSR page list McCune as fifth.
- **Claim checks:**
  - Q: What does the abstract say about the problem and the hardware it needs? -> A: Problem: preserving a protected module's state beyond confidentiality and integrity, since rolled-back stale state can make software err. Memoir ensures continuity using a deterministic module, a concise summary of request history in protected NVRAM, and safe replays only after crashes. Because frequent NVRAM writes are impractical, it uses limited trusted hardware to minimize them. Formal machine-verified safety proofs and an implementation are reported. | read: abstract | evidence: "we present a novel way to leverage limited trusted hardware to minimize such writes." https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/memoir.pdf
- **Notes:** The abstract does not name the hardware (TPM or otherwise); the body was not read.

### itsake
- **Citation (as verified):** Pierre-Alain Jacqmin, Jean Lienardy (Royal Military Academy, Belgium). "ITSAKE: an unconditionally secure authenticated key establishment protocol". Cryptology ePrint Archive, Paper 2026/222, received 2026-02-10, approved 2026-02-12. https://eprint.iacr.org/2026/222
- **Level:** V2 for the existence of an authoritative record (IACR ePrint). It is a preprint with no peer-reviewed venue. The claim answer rests on the abstract only.
- **Sources fetched:** https://eprint.iacr.org/2026/222 -> metadata and abstract; https://researchportal.rma.ac.be/de/publications/itsake-an-unconditionally-secure-authenticated-key-establishment-/ -> institutional record, preprint, same authors, 2026. The PDF could not be retrieved (bot check returned HTML). DBLP and Crossref were not usable (DBLP blocked; Crossref query returned no usable JSON).
- **Hint vs found:** The hint's expansion "information-theoretically secure authenticated key exchange" is close; the title says "Information-Theoretic Secure Authenticated Key Establishment". Venue and year: ePrint preprint, 2026. No journal or conference version found.
- **Claim checks:**
  - Q: What does it assume to achieve information-theoretic security? -> A: A pre-shared secret (symmetric master key) held by both parties; the main drawback is the length of those pre-shared keys. It is a 2-message protocol with entity authentication, perfect forward secrecy and weak synchronization robustness, proved in a multi-party model for symmetric-key authenticated key establishment with concurrent runs and a fully controlling network adversary. No unproven assumptions or adversary computational limits. An instantiation has a master key only slightly longer than the total keying material that can be established. Trusted dealer or key predistribution are not named in the abstract. | read: abstract | evidence: "establish keys between two parties from a pre-shared secret." https://eprint.iacr.org/2026/222
  - The authors position it as an alternative to QKD where physical key exchanges are done occasionally.
- **Notes:** Preprint, not peer reviewed as far as found. Not an earlier protocol from before 2026. Full text and security model details were not read.

### bgi2016
- **Citation (as verified):** Elette Boyle, Niv Gilboa, Yuval Ishai. "Breaking the Circuit Size Barrier for Secure Computation Under DDH". Advances in Cryptology, CRYPTO 2016, LNCS 9814, pp. 509-539. DOI 10.1007/978-3-662-53018-4_19. ePrint 2016/585.
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works?query.bibliographic=... -> title, authors, CRYPTO 2016, pp. 509-539, DOI; https://eprint.iacr.org/2016/585 -> abstract (marked "Preliminary full version of the Crypto 2016 paper"; published by IACR in CRYPTO 2016).
- **Hint vs found:** none
- **Claim checks:**
  - Q: What assumption does it use and what does it achieve for HSS? -> A: Decisional Diffie-Hellman (DDH). A 2-out-of-2 secret sharing scheme supporting compact evaluation of branching programs on the shares: Eval(P,w0) XOR Eval(P,w1) = P(w) except with failure probability at most delta. Eval runs in time polynomial in S, lambda and 1/delta. Also a public-key variant for multiple clients. Applications: 2-party computation with communication linear in input size, a function-secret-sharing scheme for general branching programs, and 2-server PIR. | read: abstract (ePrint) | evidence: "Under the Decisional Diffie-Hellman (DDH) assumption, we present a 2-out-of-2 secret sharing scheme" https://eprint.iacr.org/2016/585
- **Notes:** The scheme has a nonzero correctness error (inverse-polynomial delta); it is computational, not information-theoretic. The volume number LNCS 9814 comes from the DOI prefix 978-3-662-53018-4 and was not read from a page; treat the volume as unverified (pages and DOI verified in Crossref).

### dikns2008
- **Citation (as verified):** Ivan Damgard, Yuval Ishai, Mikkel Kroigaard, Jesper Buus Nielsen, Adam Smith. "Scalable Multiparty Computation with Nearly Optimal Work and Resilience". Advances in Cryptology, CRYPTO 2008, LNCS 5157, pp. 241-261. DOI 10.1007/978-3-540-85174-5_14
- **Level:** V1
- **Sources fetched:** Crossref -> title, five authors, CRYPTO 2008, pp. 241-261, DOI (issued year missing in Crossref record); Springer chapter page (via fetch tool) -> authors, pages, LNCS 5157, abstract.
- **Hint vs found:** none
- **Claim checks:**
  - Q: Does it use packed secret sharing? -> A: Not answered. The abstract does not mention packed secret sharing and the full text was not read. | read: not read (abstract only) | evidence: none
  - Q: What resilience does it state? -> A: Computational security against an active, adaptive adversary corrupting a (1/2 - epsilon) fraction of the players, for arbitrary epsilon > 0. Total work grows only polylogarithmically with n (ignoring an additive term depending on n but not on the complexity of f). | read: abstract | evidence: "corrupting a (1/2 − ε) fraction of the players, for an arbitrary ε > 0." https://link.springer.com/chapter/10.1007/978-3-540-85174-5_14
- **Notes:** The resilience is computational, not information-theoretic. The abstract quote was extracted by the fetch tool from the Springer page, not read directly in a browser. The IACR archive PDF was blocked.

### cccx2009
- **Citation (as verified):** Ignacio Cascudo, Hao Chen, Ronald Cramer, Chaoping Xing. "Asymptotically Good Ideal Linear Secret Sharing with Strong Multiplication over Any Fixed Finite Field". Advances in Cryptology, CRYPTO 2009, LNCS 5677, pp. 466-486. DOI 10.1007/978-3-642-03356-8_28
- **Level:** V2 (abstract text obtained via the fetch tool's extraction of the Springer page; see notes)
- **Sources fetched:** Crossref -> title, four authors, CRYPTO 2009, pp. 466-486, DOI; https://link.springer.com/chapter/10.1007/978-3-642-03356-8_28 -> authors, pages, LNCS 5677, abstract sentences. The IACR archive PDF was blocked (403 / bot check).
- **Hint vs found:** none
- **Claim checks:**
  - Q: What tools and what property does the abstract state? -> A: Tools: Chen and Cramer's algebraic-geometry-based schemes, combined with a dedicated field-descent method. Property: t-strong multiplication on n players, in ideal schemes (one field element per share), over every finite field. A further family of ideal schemes with t-strong multiplication is presented that does not rely on algebraic geometry. | read: abstract | evidence: "combining the results of Chen and Cramer with a dedicated field-descent method." https://link.springer.com/chapter/10.1007/978-3-642-03356-8_28
- **Notes:** The quotes came from a small-model extraction of the Springer page. One earlier extraction returned a loosely paraphrased list of excerpts, so the quoted sentences were re-queried specifically; re-check the wording against the printed abstract before quoting verbatim.
