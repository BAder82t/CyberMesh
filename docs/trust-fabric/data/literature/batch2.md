# Batch 2 verification

Access notes: Springer, ACM DL, IEEE Xplore, Wiley, DBLP (Anubis), and iacr.org PDFs returned 403/bot walls to direct fetches. Springer abstracts were read through a WebFetch redirect hop. Crossref was used for DOI-registered metadata (and publisher-deposited abstract where present).

### ostrovskyyung1991
- **Citation (as verified):** Rafail Ostrovsky, Moti Yung. "How to withstand mobile virus attacks (extended abstract)". Proceedings of the 10th ACM Symposium on Principles of Distributed Computing (PODC '91), pp. 51-59, 1991. DOI 10.1145/112600.112605.
- **Level:** V1
- **Sources fetched:**
  - Crossref works query (api.crossref.org) -> authors, title with "(extended abstract)", PODC '91, pp. 51-59, 1991, DOI 10.1145/112600.112605
  - https://web.cs.ucla.edu/~rafail/PUBLIC/05.html (author's own page) -> abstract text and "PODC-91 August 1991, Montreal, pp. 51-59"
  - https://dl.acm.org/doi/10.1145/112600.112605 -> 403, not read
- **Hint vs found:** Only difference: the official title carries the suffix "(extended abstract)".
- **Claim checks:**
  - Q: What adversary model does it define (which parties can be corrupted over time, and the bound per period)? -> A: Abstract only: a synchronous network with a malicious, infinitely powerful adversary whose faults are non-stationary and move through the network, infecting at a certain rate each round. Detection of infected sites keeps the same rate. Up to a constant fraction of machines may be infected in any single round, and every machine may eventually be infected at different rounds. The abstract gives no exact constant; the exact bound is not read. | read: abstract | evidence: "we allow up to a constant fraction of the machines to be infected at any single round" https://web.cs.ucla.edu/~rafail/PUBLIC/05.html
- **Notes:** Full text not read (the ACM PDF was blocked and the mirror host was unreachable). The UCLA page links a PDF/PS of the paper. The exact fraction (for example 1/3 or 1/2) must come from the paper body.

### herzberg1995
- **Citation (as verified):** Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, Moti Yung. "Proactive Secret Sharing Or: How to Cope With Perpetual Leakage". CRYPTO '95 (LNCS 963, ed. D. Coppersmith), pp. 339-352, 1995. DOI 10.1007/3-540-44750-4_27.
- **Level:** V1
- **Sources fetched:**
  - Crossref -> authors, title, "Advances in Cryptology - CRYPTO' 95", pp. 339-352, 1995, DOI
  - https://link.springer.com/chapter/10.1007/3-540-44750-4_27 (via redirect hop) -> abstract only
  - https://research.google/pubs/proactive-secret-sharing-or-how-to-cope-with-perpetual-leakage -> metadata (CRYPTO '95, pp. 339-352), empty abstract
- **Hint vs found:** none.
- **Claim checks:**
  - Q: How are shares renewed each period? -> A: Abstract states only that shares are renewed periodically without changing the secret. The renewal mechanism is not described in the abstract. | read: abstract | evidence: "shares are renewed periodically without changing the secret" (paraphrase of the abstract; Springer page) https://link.springer.com/chapter/10.1007/3-540-44750-4_27
  - Q: What assumptions does it need (authenticated channels, broadcast, honest majority, secure erasure, computational assumptions)? -> A: not read. The abstract does not list them.  | read: not read | evidence: none
  - Q: Information-theoretic or computational primitives? -> A: not read. The abstract also says the authors add mechanisms to detect corrupted shares and recover correct ones, but does not state the security type. | read: not read | evidence: none
- **Notes:** The full paper PDF was not obtainable (Springer paywall; MIT thesis host rate-limited). One secondary source gave pages 457-469, which is wrong; Springer/Crossref/Google Research all say 339-352. No claim answers beyond the abstract.

### desmedtjajodia1997
- **Citation (as verified):** Yvo Desmedt, Sushil Jajodia. "Redistributing secret shares to new access structures and its applications". Technical report (George Mason University, Dept. of Information and Software Systems Engineering), 1997. Copy at https://csis.gmu.edu/jajodia/desmedt25-7-1997.pdf
- **Level:** V1
- **Sources fetched:**
  - https://csis.gmu.edu/jajodia/desmedt25-7-1997.pdf (downloaded, 14 pages, full text) -> title, authors (Desmedt, Univ. of Wisconsin-Milwaukee; Jajodia, GMU ISSE), abstract
  - Crossref title search -> no record for this report
- **Hint vs found:** The report number "ISSE-TR-97-01" and the date 1997 appear nowhere in the PDF text I read (grep for "ISSE", "TR-97", "1997" found nothing in the header or footer). The file name contains "25-7-1997". The number and year are NOT confirmed. The authors' acknowledgement says the work was done at the Newton Institute; NSF NCR-9508528.
- **Claim checks:**
  - Q: What does it describe? -> A: Redistributing shares of a secret from an old access structure to a new access structure (for example 4-out-of-8 to 2-out-of-4) without recovering the secret; an adaptation to threshold cryptography; applications to secure databases. | read: full text (abstract and introduction) | evidence: "redistribute the secret, without recovering it, in such a way that those specified in the new access structure" https://csis.gmu.edu/jajodia/desmedt25-7-1997.pdf
- **Notes:** The record exists only as the GMU-hosted PDF (and citations in later papers). It cites Ostrovsky-Yung PODC '91 and Herzberg et al. CRYPTO '95 and contrasts itself with proactive refresh (same access structure). Cite the report number only if confirmed from the GMU technical report series.

### cevallos2012
- **Citation (as verified):** Alfonso Cevallos, Serge Fehr, Rafail Ostrovsky, Yuval Rabani. "Unconditionally-Secure Robust Secret Sharing with Compact Shares". EUROCRYPT 2012 (LNCS 7237), pp. 195-208. DOI 10.1007/978-3-642-29011-4_13.
- **Level:** V2
- **Sources fetched:**
  - Crossref -> authors, title, venue, pp. 195-208, 2012
  - https://link.springer.com/chapter/10.1007/978-3-642-29011-4_13 (via redirect hop) -> abstract
  - https://ir.cwi.nl/pub/20687 -> CWI record, EUROCRYPT, pp. 195-208, 2012
  - https://web.cs.ucla.edu/~rafail/PUBLIC/136.html -> citation and abstract
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What setting (corruption bound, error probability) and what share size? -> A: Any t shares give no information; reconstruction works even if up to t of n shares are incorrect, in the range n/3 <= t < n/2. Failure probability is exponentially small in the security parameter kappa. Share-size overhead is O~(kappa + n) with polynomial running time, against earlier Omega(kappa n) overhead or exponential-time near-optimal schemes. | read: abstract | evidence: "reconstruction is possible even if up to t out of the n shares are incorrect" https://link.springer.com/chapter/10.1007/978-3-642-29011-4_13
- **Notes:** Abstract only, not the theorem statement. Bishop et al. (see below) cite this result as m + O~(k + n) for message length m. Free full text via the CWI repository.

### bishop2016
- **Citation (as verified):** Allison Bishop, Valerio Pastro, Rajmohan Rajaraman, Daniel Wichs. "Essentially Optimal Robust Secret Sharing with Maximal Corruptions". EUROCRYPT 2016 (LNCS 9665), pp. 58-86. DOI 10.1007/978-3-662-49890-3_3. ePrint 2015/1032.
- **Level:** V2
- **Sources fetched:**
  - Crossref -> authors, title, venue, pp. 58-86, 2016
  - https://eprint.iacr.org/2015/1032 -> title, authors, abstract
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What corruption threshold and share size does it achieve? -> A: Maximal corruption setting n = 2t+1 (adaptive adversary corrupts up to t parties and modifies their shares arbitrarily). Share size m + O~(k) bits for m-bit messages and failure probability at most 2^-k; the stated lower bound is m + k bits. Earlier best (Cevallos et al.) was m + O~(k + n). The construction is efficient and uses approximation algorithms for minimum graph bisection. | read: abstract | evidence: "the maximal corruption setting, where n = 2t+1" (abstract summary) https://eprint.iacr.org/2015/1032
- **Notes:** The ePrint page text was summarised by the fetch tool, so quotes are from its restatement of the abstract. The ePrint title and the EUROCRYPT title agree; the EUROCRYPT PDF title header reads "Essentially Optimal Robust Secret Sharing" in a search listing. Theorem statement not read. Also see Cheraghchi's 2016 ISIT paper on nearly optimal robust secret sharing (separate work).

### reedsolomon1960
- **Citation (as verified):** I. S. Reed, G. Solomon. "Polynomial Codes Over Certain Finite Fields". Journal of the Society for Industrial and Applied Mathematics 8(2), pp. 300-304, June 1960. DOI 10.1137/0108018. JSTOR 2098968.
- **Level:** V2
- **Sources fetched:**
  - Crossref -> title, authors, volume 8, issue 2, pp. 300-304, June 1960
  - https://sites.math.rutgers.edu/~zeilberg/akherim/reed.pdf -> JSTOR scan of the paper, full text read
- **Hint vs found:** none.
- **Claim checks:**
  - Q: Does it construct codes by evaluating polynomials over a finite field? -> A: Yes. A message (a0..a_{m-1}) of elements of the field K (2^n elements) defines a polynomial P(x) of degree m-1, and the codeword is (P(0), P(alpha), ..., P(alpha^(2^n - 2)), P(1)). It states the code corrects (2^n - m)/2 or (2^n - m - 1)/2 symbols depending on parity of m. | read: full text (introduction) | evidence: "Code E is the mapping of the m-tuple ... into the 2^n-tuple (P(0), P(a), P(a^2), ..., P(1))" https://sites.math.rutgers.edu/~zeilberg/akherim/reed.pdf
- **Notes:** The field is of characteristic 2 (degree n over Z2) in the paper. The original decoding procedure differs from later Berlekamp-Welch / syndrome decoders.

### welchberlekamp1986
- **Citation (as verified):** Lloyd R. Welch, Elwyn R. Berlekamp. "Error correction for algebraic block codes". US Patent 4,633,470, assignee Cyclotomics, Inc.; filed 27 Sep 1983, granted 30 Dec 1986. https://patents.google.com/patent/US4633470A/en
- **Level:** MISMATCH (minor)
- **Sources fetched:**
  - https://patents.google.com/patent/US4633470A/en -> title, inventors, assignee, dates, abstract, claim 1 (first ~100,000 of 118,267 characters read; the OCR is garbled)
- **Hint vs found:** (1) The title is "Error correction for algebraic block codes", not "Error correction of algebraic block codes". (2) Author order on the patent is Welch and Berlekamp (hint had Berlekamp, Welch). (3) Year 1986 matches the grant date; the filing date is 1983.
- **Claim checks:**
  - Q: What decoding method does the patent describe for Reed-Solomon codes? -> A: It corrects errors without computing power-sum symmetric functions (syndromes in the usual sense). The received word is reduced modulo the generator polynomial G(z); the remainder is written as a rational function N(z)/W(z); roots of W give error locations and error values come from the derivative of W. A second embodiment uses a matrix transform treating selected symbols as erased checks. It corrects any error pattern of weight t with 2t < d. The patent's text speaks of "algebraic block codes" and a code of distance d with generator G(z); I did not see the words "Reed-Solomon" in the portion read, so the claim is about algebraic block codes in general. | read: abstract and claim 1 (via fetch tool summary, partial) | evidence: "correcting up to i errors ... systematic code of distance d and generator G(z), where i < d/2" (paraphrase of claim 1) https://patents.google.com/patent/US4633470A/en
- **Notes:** The text was summarised by the fetch tool, and the final 18,267 characters (probably the remaining claims) were not read. The patent is the origin of the "Welch-Berlekamp" decoder but the interpolation-form "Berlekamp-Welch" algorithm used in secret-sharing papers is a later restatement; this patent describes the remainder/rational-function (key-equation) form.

### macwilliamssloane1977
- **Citation (as verified):** F. J. MacWilliams, N. J. A. Sloane. "The Theory of Error-Correcting Codes". North-Holland Mathematical Library, vol. 16, North-Holland (Amsterdam / New York), 1977, xv + 762 pp., ISBN 0-444-85193-3 (as given by library catalogue search listings; see Notes).
- **Level:** V1
- **Sources fetched:**
  - https://shop.elsevier.com/books/the-theory-of-error-correcting-codes/macwilliams/978-0-444-85193-2 -> authors, title, "Volume 16", "1st Edition", date shown as 1 Jan 1983 (reprint listing); no publisher imprint or page count on the page
  - Crossref -> two reviews: Massey, IEEE Trans. Inf. Theory 25(4):501-502, 1979 (review title dates the book "1978"); Mattson, SIAM Review 22(4):513-519, 1980
  - Library catalogue records (TUM, Masaryk Univ.) -> only seen as search-result snippets; direct fetch blocked (Anubis wall / redirect). Not independently read.
- **Hint vs found:** The Elsevier page dates it 1983 (reprint) and one Crossref review title says 1978; 1977 comes from catalogue snippets I could not open. Treat 1977 as plausible but not confirmed from a page I read.
- **Claim checks:**
  - Q: Minimum distance of Reed-Solomon / MDS codes, and the errors-and-erasures condition 2e + s < d. -> A: not read | read: not read | evidence: none
- **Notes:** I did not obtain the book text. Do not cite page numbers for these facts from this check.

### itosaito1987
- **Citation (as verified):** Mitsuru Ito, Akira Saito, Takao Nishizeki. "Secret sharing scheme realizing general access structure". Electronics and Communications in Japan (Part III: Fundamental Electronic Science) 72(9), pp. 56-64, 1989. DOI 10.1002/ecjc.4430720906. (Conference version: IEEE GLOBECOM '87, Tokyo, 1987, per secondary listings only.)
- **Level:** V1
- **Sources fetched:**
  - Crossref (DOI 10.1002/ecjc.4430720906) -> authors, title, journal, volume 72, issue 9, pp. 56-64, Jan 1989; publisher-deposited abstract
  - Wiley page -> 403, not read
  - GLOBECOM '87 record: not found in Crossref; only secondary citations (pp. 99-102) seen in search snippets, not verified
- **Hint vs found:** Journal version matches the hint. The GLOBECOM 1987 conference record is not verified. Authors' given names (Mitsuru, Akira, Takao) are my reading of the commonly used forms; Crossref gives only family names, so treat given names as unverified.
- **Claim checks:**
  - Q: Does it realise any monotone access structure? -> A: The abstract says any access structure can be realised by giving each trustee several pieces of information from the (k,n) threshold method. It does not use the word "monotone" in the abstract; monotonicity is implied by the setting but not stated in what I read. | read: abstract | evidence: "any access structure can be realized" Crossref abstract, https://api.crossref.org/works/10.1002/ecjc.4430720906
- **Notes:** The abstract also covers updating on a change of secret trustees and a relation to threshold graphs. Full text not read.

### karchmerwigderson1993
- **Citation (as verified):** Mauricio Karchmer, Avi Wigderson. "On span programs". Proceedings of the Eighth Annual Structure in Complexity Theory Conference, 1993, pp. 102-111. DOI 10.1109/SCT.1993.336536.
- **Level:** V2
- **Sources fetched:**
  - Crossref -> title, authors (family names), "[1993] Proceedings of the Eigth Annual Structure in Complexity Theory Conference", pp. 102-111, DOI
  - https://www.math.ias.edu/~avi/PUBLICATIONS/MYPAPERS/KW93/proc.pdf (downloaded, 6 pages, full text) -> abstract, introduction, Section 8
- **Hint vs found:** none. Given name "Mauricio" is not shown in Crossref or the PDF header (it shows "M. Karchmer"); unverified.
- **Claim checks:**
  - Q: Does it define span programs? -> A: Yes. It introduces the span program as a linear algebraic model over any field K that computes a function of n variables. | read: full text (abstract, introduction) | evidence: "We introduce a linear algebraic model of computation, the Span Program" https://www.math.ias.edu/~avi/PUBLICATIONS/MYPAPERS/KW93/proc.pdf
  - Q: Is the link to linear secret sharing made there? -> A: Yes. Section 8 "Monotone Span Programs and secret sharing" shows a monotone span program yields an information-theoretic secret sharing scheme for a monotone function (Theorem 13: every monotone function has a scheme over GF(p) of size mSP_p(f)). The paper credits Rudich for first describing such a scheme and says the model captures Shamir sharing. | read: full text (Section 8, Theorem 13) | evidence: "this model captures in a natural way information theoretic secret sharing in the sense of Shamir" same URL
- **Notes:** The IAS copy is the authors' own PDF and is 6 pages, whereas the IEEE record is 10 pages (102-111); it may be a different layout or version of the conference paper. The IEEE abstract page was not accessible. The stated direction is span program to secret sharing; the converse equivalence is not claimed in the passages I read.
