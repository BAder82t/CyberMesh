# Batch 5a verification

Tooling notes: DBLP (Anubis bot wall) and eprint.iacr.org PDFs (Cloudflare/403) were not retrievable; no workaround attempted. Crossref API, arXiv, rfc-editor.org, NIST nvlpubs and the ECCC mirror were retrievable.

### canetti2001
- **Citation (as verified):** Ran Canetti. "Universally Composable Security: A New Paradigm for Cryptographic Protocols". Proceedings 42nd IEEE Symposium on Foundations of Computer Science (FOCS 2001), pp. 136-145, 2001. DOI 10.1109/SFCS.2001.959888. Preprint: IACR ePrint 2000/067 (= ECCC TR01-016). Later journal-style rewrite: "Universally Composable Security", J. ACM 67(5), 2020, DOI 10.1145/3402457 (different title).
- **Level:** V1
- **Sources fetched:** https://api.crossref.org/works?query.bibliographic=... -> FOCS 2001 record, pp. 136-145, DOI 10.1109/sfcs.2001.959888; https://eprint.iacr.org/2000/067 -> 15 revisions, received 2000-12-23, last 2020-02-12, "extended abstract appeared at FOCS 2001", earlier version Dec 2000 titled "A unified framework for analyzing security of protocols", earlier versions listed Oct 2001, 2005, 2013, 2018, 2019; https://eccc.weizmann.ac.il/report/2001/016/ and /revision/6/download -> ECCC revision 6 PDF dated December 30, 2018, text read
- **Hint vs found:** Hint matches (FOCS 2001, ePrint 2000/067). The hint's own caveat holds: the ePrint text has been revised 15 times and ePrint says "many important details differ" from earlier versions.
- **Claim checks:**
  - Q: What does the composition theorem state? -> A: If pi UC-emulates phi, and phi is a subroutine of rho, and pi is identity-compatible with rho and phi, then the composed protocol rho^{phi->pi} UC-emulates rho. Consequently, if rho UC-realizes an ideal functionality G, so does the composed protocol. | read: theorem statement (Section 2.3 simplified-model theorem, ECCC revision 6, dated 30 Dec 2018; NOT the 2001 FOCS text and NOT the 2020 ePrint revision) | evidence: "if π UC-emulates φ, then the composed protocol ρφ→π UC-emulates the original protocol ρ" https://eccc.weizmann.ac.il/report/2001/016/revision/6/download
- **Notes:** Version read is the Dec 2018 revision, so the exact theorem wording and the model (simplified vs general) may differ from the 2001 FOCS paper and from the 2020 revision. The 2001 FOCS full text and the 2020 ePrint revision were not read (eprint PDF blocked, 403). Cite which version if the exact statement matters. The ePrint abstract (read) claims security is preserved under "universal composition" and that protocols keep security in any context with unbounded concurrent instances.

### maurerrenner2011
- **Citation (as verified):** Ueli Maurer, Renato Renner. "Abstract Cryptography". Innovations in Computer Science (ICS 2011), Tsinghua University Press, 2011 (pp. 1-21 per secondary citation, not checked at an authoritative record). Proceedings PDF: https://conference.iiis.tsinghua.edu.cn/ICS2011/content/paper/14.pdf (first page header "Innovations in Computer Science 2011").
- **Level:** V1
- **Sources fetched:** https://conference.iiis.tsinghua.edu.cn/ICS2011/content/paper/14.pdf -> conference-site PDF; fetched copy was 2 pages only (title/abstract and start of introduction), authors and venue header confirmed, abstract read; Crossref -> no record for this ICS paper (returned only other Maurer/Renner works); DBLP blocked.
- **Hint vs found:** none on authors, title, venue, year. Page range and publisher not confirmed from an authoritative catalogue (page count of 21 comes from a search snippet citing another paper).
- **Claim checks:**
  - Q: What framework does it propose, in one sentence from the abstract? -> A: "a general framework for defining and proving that a system satisfying an (abstract or ideal) specification is constructed from some systems satisfying certain (concrete or real) specifications." | read: abstract | evidence: "we propose a general framework for defining and proving that a system satisfying an (abstract or ideal) specification is constructed" https://conference.iiis.tsinghua.edu.cn/ICS2011/content/paper/14.pdf
- **Notes:** Abstract also states existing frameworks for composable security are special cases and a single common composition theorem is proved. Page numbers / publisher record should be taken from DBLP when reachable. Related later work: Maurer-Renner TCC 2016 (10.1007/978-3-662-53641-4_1), a different paper.

### benor2005
- **Citation (as verified):** M. Ben-Or, M. Horodecki, D. W. Leung, D. Mayers, J. Oppenheim. "The Universal Composable Security of Quantum Key Distribution". Theory of Cryptography (TCC 2005), LNCS 3378, pp. 386-406, Springer, 2005. DOI 10.1007/978-3-540-30576-7_21. arXiv quant-ph/0409078.
- **Level:** V2
- **Sources fetched:** Crossref -> LNCS record, pp. 386-406, 2005, five authors; arXiv abs quant-ph/0409078 -> journal ref TCC 2005 LNCS 3378 pp. 386-406; arXiv API -> verbatim abstract.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What does the abstract claim? -> A: Existing unconditional QKD security definitions do not cover joint attacks over QKD and later use of the key; the paper derives a composable security definition for QKD using a quantum universal composability theorem and proves the usual security definition implies it; also proposes two other sufficient conditions and shows keys from repeated QKD runs degrade slowly. | read: abstract | evidence: "we prove that the usual security definition of QKD still implies the composable security definition" http://export.arxiv.org/api/query?id_list=quant-ph/0409078 (abstract text: "We then prove that the usual security definition of QKD still implies the composable security definition.")
- **Notes:** arXiv v1 dated 14 Sep 2004. Claim read from the abstract only, not the full text.

### renner2005
- **Citation (as verified):** Renato Renner. "Security of Quantum Key Distribution". PhD thesis, ETH Zurich, Diss. ETH No. 16242, 2005. arXiv:quant-ph/0512258 (v1 30 Dec 2005, v2 11 Jan 2006 "index added"). No journal version (later published in Int. J. Quantum Inf. 6, 2008, not checked here).
- **Level:** V2
- **Sources fetched:** https://arxiv.org/abs/quant-ph/0512258 -> title, author, report number Diss. ETH No. 16242, comments "PhD thesis; index added", abstract; arXiv PDF (v2, 148 pages) -> full text, Section 2.2.
- **Hint vs found:** Hint says 2005; the arXiv posting is 30 Dec 2005 / v2 Jan 2006; thesis year 2005 matches the Diss. number. Hint otherwise correct.
- **Claim checks:**
  - Q: How is security defined with quantum side information (trace distance)? -> A: A key S with joint state rho_SE is epsilon-secure with respect to H_E if (1/2)||rho_SE - rho_U (x) rho_E||_1 <= epsilon, where rho_U is the fully mixed state on H_S (half the L1/trace distance to a perfect key independent of the adversary). The thesis notes the older mutual-information criterion max_W I(S;W) <= epsilon is not universal. | read: full text (Section 2.2, Eq. 2.6) | evidence: "S is ε-secure with respect to HE if ½‖ρSE − ρU ⊗ ρE‖1 ≤ ε" https://arxiv.org/pdf/quant-ph/0512258
- **Notes:** The thesis states Eq. 2.5 (mutual-information definition) "does not guarantee that the key S can safely be used in applications".

### portmannrenner2014
- **Citation (as verified):** Christopher Portmann, Renato Renner. "Cryptographic security of quantum key distribution". arXiv:1409.3525 [quant-ph], 11 Sep 2014 (v1; "31+23 pages"). DOI 10.48550/arXiv.1409.3525. No journal reference listed on arXiv.
- **Level:** V2
- **Sources fetched:** https://arxiv.org/abs/1409.3525 -> metadata, abstract; arXiv PDF -> full text, Definition 2.1 and Section 3.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What composable security definition does it present? -> A: Definition 2.1 (cryptographic security, taken from Maurer-Renner AC framework): a protocol pi_AB constructs ideal filtered resource S from real R within epsilon if (i) d(pi_AB R_filtered, S_filtered) <= epsilon (availability, no Eve) and (ii) there exists a simulator sigma_E with d(pi_AB R, S sigma_E) <= epsilon. If two protocols are epsilon- and epsilon'-secure their composition is (epsilon+epsilon')-secure. | read: full text (Section 2, Def. 2.1 and following text) | evidence: "if two protocols π and π′ are ε- and ε′-secure, the composition of the two is (ε + ε′)-secure" https://arxiv.org/pdf/1409.3525
- **Notes:** Abstract describes it as an introduction/motivation for the QKD security definition and discusses the operational meaning of the distance metric. Definition is in the Abstract Cryptography formalism, not UC.

### koenigrennerschaffner2009
- **Citation (as verified):** Robert Konig, Renato Renner, Christian Schaffner. "The Operational Meaning of Min- and Max-Entropy". IEEE Transactions on Information Theory 55(9), pp. 4337-4347, Sept 2009. DOI 10.1109/TIT.2009.2025545. arXiv:0807.1338.
- **Level:** V2
- **Sources fetched:** Crossref -> vol 55, issue 9, pp. 4337-4347, 2009-09; arXiv abs 0807.1338 -> IEEE ref confirmed (v2 revised 2015); arXiv API -> verbatim abstract.
- **Hint vs found:** none (the first author's surname is "König" with umlaut in the paper; Crossref spells "Konig").
- **Claim checks:**
  - Q: What operational meaning does the abstract give for min-entropy with quantum side information? -> A: Conditional min-entropy H_min(A|B) is directly related to the maximum achievable overlap with a maximally entangled state when only local actions on B are allowed; for classical A this overlap is the probability of guessing A given B. | read: abstract | evidence: "In the special case where A is classical, this overlap corresponds to the probability of guessing A given B." http://export.arxiv.org/api/query?id_list=0807.1338
- **Notes:** Abstract also states log of the guessing probability lower-bounds the number of uniform secret bits extractable relative to an adversary holding B. Full text not read.

### bb84
- **Citation (as verified):** Charles H. Bennett, Gilles Brassard. "Quantum cryptography: Public key distribution and coin tossing". Proceedings of the IEEE International Conference on Computers, Systems and Signal Processing, Bangalore, India, December 1984, pp. 175-179 (venue and pages as stated by the authors' own arXiv scan record). No DOI for the 1984 original.
- **Level:** V1
- **Sources fetched:** https://arxiv.org/abs/2003.06557 -> authors' arXiv posting (14 Mar 2020) of a scan of the original: "Proceedings of the International Conference on Computers, Systems & Signal Processing (Bangalore, India, December 1984, pp. 175-179)"; journal ref TCS 560(1), 2014, pp. 7-11; Crossref DOI 10.1016/j.tcs.2014.05.025 -> journal-article, Theoretical Computer Science vol 560, pp. 7-11, issued 2014-12, Elsevier, ISSN 0304-3975; DBLP and ScienceDirect: blocked (not read).
- **Hint vs found:** Hint matches. Venue name wording varies: hint says "IEEE International Conference on Computers, Systems and Signal Processing"; arXiv comment says "International Conference on Computers, Systems & Signal Processing". Pages 175-179 are not in the hint.
- **Claim checks:** none asked (bibliographic record only).
- **Notes:** The 2014 reprint exists: TCS 560 (Part 1), 7-11, DOI 10.1016/j.tcs.2014.05.025 (Crossref). No DBLP/library-catalogue record of the 1984 proceedings was retrievable, so the 1984 pages rest on the authors' arXiv comment (authoritative as an arXiv record, but not a catalogue). Page range of the TCS reprint (7-11) is 5 pages versus the original 175-179.

### rfc8446
- **Citation (as verified):** E. Rescorla. "The Transport Layer Security (TLS) Protocol Version 1.3". RFC 8446, IETF, Proposed Standard, August 2018. DOI 10.17487/RFC8446. https://www.rfc-editor.org/rfc/rfc8446
- **Level:** V2
- **Sources fetched:** https://www.rfc-editor.org/info/rfc8446 -> status page; https://www.rfc-editor.org/rfc/rfc8446.txt -> full text read; Crossref -> RFC 8446 (2018-08) plus a record 10.17487/rfc9846 "The Transport Layer Security (TLS) Protocol Version 1.3" dated 2026-07.
- **Hint vs found:** Record matches the hint. IMPORTANT: rfc-editor.org now shows "This RFC is now obsolete, see RFC 9846" for RFC 8446. RFC 9846 (July 2026 per Crossref) is the current TLS 1.3 specification. I did not read RFC 9846.
- **Claim checks:**
  - Q: What key-derivation primitive does the key schedule use? -> A: HKDF (HMAC-based Extract-and-Expand Key Derivation Function), using HKDF-Extract, HKDF-Expand, and HKDF-Expand-Label. | read: full text | evidence: "The HMAC-based Extract-and-Expand Key Derivation Function (HKDF) is used as an underlying primitive." https://www.rfc-editor.org/rfc/rfc8446.txt (Section 1.2, key schedule in Section 7.1)
  - Q: What primitives does the handshake rely on for authentication? -> A: CertificateVerify is a signature over the entire handshake using the certificate's private key; Finished is a MAC (HMAC, with the handshake hash) over the entire handshake. Authentication also via PSKs (binders are HMAC values), with Diffie-Hellman for key exchange. | read: full text (Section 2, 4.4) | evidence: "CertificateVerify: A signature over the entire handshake using the private key corresponding to the certificate" https://www.rfc-editor.org/rfc/rfc8446.txt
- **Notes:** The "signature over the entire handshake" and "MAC over the entire handshake" phrases are in Section 2 (lines ~694-699 of the txt). Cite RFC 9846 as the successor if the review targets current TLS.

### nist80090b
- **Citation (as verified):** Meltem Sonmez Turan, Elaine Barker, John Kelsey, Kerry A. McKay, Mary L. Baish, Mike Boyle. "Recommendation for the Entropy Sources Used for Random Bit Generation". NIST SP 800-90B, 84 pages, January 2018. DOI 10.6028/NIST.SP.800-90B. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf
- **Level:** V2
- **Sources fetched:** NIST nvlpubs PDF (full text read via pdftotext): cover "January 2018", citation line "Natl. Inst. Stand. Technol. Spec. Publ. 800-90B, 84 pages (January 2018)".
- **Hint vs found:** none. (No withdrawal notice found in the PDF; I did not check the CSRC page for later status.)
- **Claim checks:**
  - Q: What does it say entropy estimation by testing can and cannot establish about a noise source (statistical estimates and design analysis)? -> A: The document states the estimation methods rely on statistical assumptions that may not hold for all noise sources; they "should not replace in-depth analysis of noise sources" and are to "support the initial entropy estimate of the submitter", which is based on the submitter's analysis of the noise source. The IID tests are "designed to find evidence that the samples are not IID"; if none is found, IID is assumed (not proven). The text does not use the words "can establish / cannot establish". | read: full text (Section 6 intro, Section 3.1.3, Section 5 intro) | evidence: "The methods should not replace in-depth analysis of noise sources, but should be used to support the initial entropy estimate" https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf
- **Notes:** Related exact wording: "entropy estimation methods described in this section rely on some statistical assumptions that may not hold for all types of noise sources" (Section 6). Section 3.1.3: initial estimate "based on the submitter's analysis of the noise source". A paraphrase such as "testing cannot prove entropy" is the reader's inference, not a quote.

### nist80088
- **Citation (as verified):** Authors not verified (not read from the text). "Guidelines for Media Sanitization". NIST SP 800-88 Rev. 1, December 2014. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf.
- **Level:** MISMATCH (status only)
- **Sources fetched:** NIST nvlpubs PDF (full text read): the PDF begins with a "Withdrawn NIST Technical Series Publication" notice: SP 800-88r1, Publication date December 2014, Withdrawal date September 26, 2025, "withdrawn and superseded in its entirety by NIST SP 800-88r2" (Ron Ross, Victoria Pillitteri).
- **Hint vs found:** Title and date match. The document is now WITHDRAWN and superseded by SP 800-88 Rev. 2. I did not read Rev. 2.
- **Claim checks:**
  - Q: What does it say about overwriting as sanitization for flash-based (SSD) media? -> A: Overwriting may be infeasible/incomplete on flash: devices have spare cells and wear levelling and may not support addressing all areas where data was stored. Table A-8 allows overwrite for Clear on ATA SSDs but notes it may not sanitize unmapped physical media. | read: full text (Section 2.3/Clear definition and Table A-8) | evidence: "overwrite on flash-based media ... may not sanitize the data in unmapped physical media (i.e., the old data may still remain" https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
  - Q: What does it say about cryptographic erase? -> A: Section 2.6: CE sanitizes the target data's encryption key, leaving only ciphertext; without the key the data is unrecoverable; effort to recover is the lesser of the key strength or the algorithm strength; the document calls CE "an emerging sanitization technique"; applies when data is encrypted as stored. | read: full text (Sections 2.5/2.6) | evidence: "Cryptographic Erase (CE) leverages the encryption of target data by enabling sanitization of the target data's encryption key." https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
- **Notes:** Label MISMATCH reflects withdrawal and supersession, not wrong bibliographic data. The claims above are accurate for Rev. 1 only; Rev. 2 may differ. Also the overwrite passage: "flash memory-based storage devices may contain spare cells and perform wear levelling, making it infeasible for a user to sanitize all previous data using this approach."
