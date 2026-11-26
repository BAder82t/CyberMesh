### dolev1993_psmt
- **Citation (as verified):** Dolev, Dwork, Waarts, Yung. "Perfectly secure message transmission". J. ACM 40(1):17-47, 1993. DOI 10.1145/138027.138036. FOCS 1990 version: pp. 36-45, DOI 10.1109/FSCS.1990.89522.
- **Level:** V1 (metadata matches Crossref; the paper text was NOT read; claims answered only from peer-reviewed restatements)
- **Sources fetched:**
  - https://api.crossref.org/works?query.bibliographic=... -> JACM record (40, 1, 17-47, 1993) and FOCS record (pp. 36-45) both found
  - https://dl.acm.org/doi/10.1145/138027.138036 -> HTTP 403, not read
  - https://cris.huji.ac.il/en/publications/perfectly-secure-message-transmission-2/ -> abstract (excerpt only, via summarizer); the page labels the venue oddly (IEEE Trans. Ind. Appl. 1991, pp. 36-45), a catalogue error for the FOCS 1990 paper
- **Hint vs found:** none for JACM/FOCS.
- **Claim checks:**
  - Q1 exact condition -> A: NOT read from the paper. Abstract (Huji page) says only "lower bounds on the connectivity needed for secure communication"; no number. | read: abstract only (partial excerpt) | evidence: "Efficient algorithms that operate with this connectivity and rely on no complexity theoretic assumptions are derived." https://cris.huji.ac.il/en/publications/perfectly-secure-message-transmission-2/
- **Notes:** Original text unread. See restatements below; they are secondary to this paper.

### desmedt_wang_2002
- **Citation (as verified):** Desmedt, Wang. "Perfectly Secure Message Transmission Revisited". EUROCRYPT 2002, LNCS 2332, pp. 502-517 (venue/pages from the paper's own reference [3], truncated "...rocrypt '02, pages 502-517, LNCS 2332"); arXiv cs/0208041 (26 Aug 2002); ePrint 2002/128 (page says "Published elsewhere").
- **Level:** V1 (arXiv/ePrint records matched; Springer/Crossref record for the EUROCRYPT version not fetched)
- **Sources fetched:** https://arxiv.org/pdf/cs/0208041 -> full text read (pdftotext of downloaded PDF); https://eprint.iacr.org/2002/128 -> title/authors/date only (PDF 403); Springer PDF -> auth redirect, not read.
- **Hint vs found:** none.
- **Claim checks:**
  - Q1/Q2 -> A: Restates Dolev et al.: one-way channels need (3k+1)-connectivity; two-way need (2k+1)-connectivity, k-active adversary, "(0,0)-secure". | read: full text (Sec. 3) | evidence: "if all channels from A to B are one-way, then (3k + 1)-connectivity is necessary and sufficient" https://arxiv.org/pdf/cs/0208041
  - "if all channels between A and B are two-way, then (2k + 1)-connectivity is necessary and sufficient for (0,0)-secure message transmissions" (same, Sec. 3; quote is 22 words of the original sentence)
  - Q3 -> A: Yes, it conflates in wording but defines precisely: "A and B are k-connected in G(V, E) if there are k node disjoint paths between A and B". Intro: "reliable communication is achievable only if the system's network is 2k + 1 connected" (reliable only, citing Dolev 1982 and Dolev et al.). Sec. 3 uses "2k + 1 directed node disjoint paths". | read: full text | https://arxiv.org/pdf/cs/0208041
- **Notes:** Preprint of the conference paper, not the proceedings text. Model: general directed graph between A and B, node-disjoint paths, k-active (Byzantine) adversary, unbounded.

### spini_zemor_2016
- **Citation (as verified):** Spini, Zemor. "Perfectly Secure Message Transmission in Two Rounds". arXiv:1608.01909v1 (5 Aug 2016); footnote says a shorter version is scheduled for TCC 2016-B. TCC proceedings record NOT fetched.
- **Level:** V1 (arXiv only; peer-reviewed version not matched)
- **Sources fetched:** https://arxiv.org/pdf/1608.01909 -> full text read
- **Claim checks:**
  - Q1/Q2 -> A: Model: sender connected to receiver by n parallel two-way channels, computationally unbounded Eve controls t of them. One round (r=1, Alice to Bob only): PSMT iff n >= 3t+1. Two or more rounds (r>=2): iff n >= 2t+1. | read: full text (Intro) | evidence: "for r = 1 ... PSMT is possible if and only if n ≥ 3t + 1" ; "for r ≥ 2 ... if and only if n ≥ 2t + 1" https://arxiv.org/pdf/1608.01909
  - Also states Dolev et al. gave an r=3 protocol for n=2t+1 with rate O(n^5) and a non-polynomial-rate r=2 protocol.
  - Q3 -> A: Speaks only of n parallel channels (wires); no network connectivity claim. | read: full text
- **Notes:** Attributes both bounds to Dolev et al.'s original paper [4]. Tight at n=2t+1 even for two rounds only with an inefficient protocol, per this text.

### srinathan_2004 / kurosawa_suzuki_2008 / franklin_wright_2000
- **Level:** V0 for claim checks (not read). Records only seen via search snippets, not authoritative fetches.
- Srinathan, Narayanan, Rangan, CRYPTO 2004, LNCS 3152 pp. 545-561, DOI 10.1007/978-3-540-28628-8_33: Springer PDF -> auth redirect/Cloudflare, not read.
- Kurosawa, Suzuki, EUROCRYPT 2008, LNCS 4965 pp. 324-340, DOI 10.1007/978-3-540-78967-3_19; ePrint 2008/421: iacr.org PDF and ePrint PDF blocked (bot challenge), not read.
- Franklin, Wright, J. Cryptology 2000: not fetched.
- ePrint 2008/086 (Patra, Choudhary, Gayatri, Rangan) abstract page read: no 3t+1/2t+1 statement on the page, only that the connectivity requirement is same for static and mobile adversaries.

### Summary answers
- Q1: Not obtained from the paper itself. Peer-reviewed/arXiv restatements (Desmedt-Wang; Spini-Zemor) say one-way: 3t+1; two-way (two or more rounds): 2t+1.
- Q3: Yes, they are used interchangeably in wording ("(2k+1)-connectivity" vs "n >= 2t+1 channels"), but the definition read (Desmedt-Wang) equates k-connected with k node-disjoint A-B paths. Network-wide (2t+1)-connectedness is the A-B vertex connectivity; Desmedt-Wang's intro applies "2k+1 connected" to reliable communication.
