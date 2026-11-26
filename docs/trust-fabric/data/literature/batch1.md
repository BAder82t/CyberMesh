# Batch 1: reference verification

Access notes: dl.acm.org, dblp.org, eprint.iacr.org and the UMD host were blocked (403, bot challenge); no workaround was attempted. Crossref (api.crossref.org) was the bibliographic authority throughout. Where a claim rests on OpenAlex's copy of the ACM abstract, that is stated and is treated as a secondary source (see rule 2), so the level is capped at V1.

### shamir1979
- **Citation (as verified):** Adi Shamir. "How to share a secret". Communications of the ACM, 22(11), pp. 612-613, November 1979. https://doi.org/10.1145/359168.359176
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works?query.bibliographic=How+to+share+a+secret+Shamir -> DOI 10.1145/359168.359176, CACM 22(11) 612-613, 1979-11, author Shamir. https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf -> scan of the paper (OCR'd locally); page header "Communications November 1979 of Volume 22 the ACM Number 11", copyright line "1979 ACM 0001-0782/79/1100-0612".
- **Hint vs found:** none
- **Claim checks:**
  - Q: Does the paper state that any k-1 of the shares give no information about the secret? -> A: Yes. Property (2) of the (k,n) threshold scheme, and the proof sketch for k-1 revealed pieces. | read: full text | evidence: "knowledge of any k-1 or fewer D_i pieces leaves D completely undetermined (in the sense that all its possible values are equally likely)" https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf
  - Q: Over which field or modulus is the scheme defined? -> A: Integers modulo a prime p, with p larger than both the secret D and n; coefficients uniform over [0,p). | read: full text | evidence: "The set of integers modulo a prime number p forms a field... we pick a prime p which is bigger than both D and n." same URL
- **Notes:** The text states the information-theoretic property in terms of "all possible values equally likely". It describes the scheme as "Knowledge of just k-1 of these values... does not suffice" first, then makes it precise with mod p arithmetic. The paper also cites Blakley [2] as "a different (and somewhat less efficient) threshold scheme". Publisher page (ACM) was not reachable; metadata comes from Crossref plus the paper's own header.

### blakley1979
- **Citation (as verified):** G. R. Blakley. "Safeguarding cryptographic keys". Proceedings of the AFIPS 1979 National Computer Conference, Vol. 48, Arlington, Va., June 1979, pp. 313-317 (as cited by Shamir). Crossref has the IEEE-hosted record at pp. 313-318: https://doi.org/10.1109/MARK.1979.8817296
- **Level:** V1
- **Sources fetched:** https://api.crossref.org/works/10.1109/MARK.1979.8817296 -> title "Safeguarding cryptographic keys", author Blakley, issued 1979-06, pp. 313-318, publisher IEEE, proceedings-article; event name given as "1979 International Workshop on Managing Requirements Knowledge", New York, 4-7 June 1979. https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf -> reference list entry 2: "Blakley, G.R. Safeguarding cryptographic keys. Proc. AFIPS 1979 NCC, Vol. 48, Arlington, Va., June 1979, pp. 313-317."
- **Hint vs found:** Venue and year match the hint (AFIPS, 1979). Differences: the Crossref/IEEE record carries a wrong-looking event label ("Managing Requirements Knowledge") and pp. 313-318 versus 313-317 in Shamir's reference. The two sources disagree on the end page.
- **Claim checks:**
  - Q: What construction does it use, and is it presented independently of Shamir's? -> A: NOT ANSWERED from Blakley's text; the paper itself could not be retrieved (IEEE Xplore returned nothing, no open copy found). What was read: Shamir's paper calls it "a different (and somewhat less efficient) threshold scheme", "recently developed". That supports "a different scheme", but it does not say independent, and it does not describe the construction. | read: not read (Blakley); Shamir reference line read in full text | evidence: "A different (and somewhat less efficient) threshold scheme was recently developed by G.R. Blakley [2]." https://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf
- **Notes:** Hyperplane construction is widely reported in secondary sources but I did not verify it at the source. Shamir's received date is April 1979 (revised September 1979); Blakley's is June 1979. Whether either saw the other's work is not stated in anything I read.

### bgw1988
- **Citation (as verified):** Michael Ben-Or, Shafi Goldwasser, Avi Wigderson. "Completeness theorems for non-cryptographic fault-tolerant distributed computation (extended abstract)". Proceedings of the 20th Annual ACM Symposium on Theory of Computing (STOC '88), pp. 1-10, 1988. https://doi.org/10.1145/62212.62213
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works/10.1145/62212.62213 -> STOC '88, pp. 1-10, 1988; author list shows ONLY Ben-Or and Wigderson. https://mit6875.github.io/PAPERS/BGW.pdf -> the proceedings paper itself (10 pp., ACM copyright 1988, ISBN 0-89791-264-0); title page lists Ben-Or, Goldwasser, Wigderson. https://api.crossref.org/works?query.bibliographic=... -> separate record 10.1145/3335741.3335756 (2019 reprint, "Providing Sound Foundations for Cryptography") lists Ben-Or, Goldwasser, Wigderson.
- **Hint vs found:** none for the hint (three authors, STOC 1988). Discrepancy found: the Crossref/ACM-DOI record for the 1988 paper omits Goldwasser; the paper's own title page and the 2019 reprint record include her.
- **Claim checks:**
  - Q: What bounds on corrupted parties does the abstract state, for (a) passive and (b) active? -> A: (a) no faults: no set of size t < n/2 learns anything beyond the function value; (b) Byzantine: no set of size t < n/3 can disrupt or learn more; bounds stated to be tight. | read: abstract (title-page text of the proceedings paper) | evidence: "no set of size t < n/2 of players gets any additional information"; "no set of size t < n/3 can either disrupt the computation" https://mit6875.github.io/PAPERS/BGW.pdf
  - Q: Does it compute products of shared values by reducing the degree of the product polynomial? -> A: Yes. Product h(x)=f(x)g(x) has degree 2t, requires n >= 2t+1, and is reduced back to degree t with a "degree reduction step" combined with a "randomization step". | read: full text | evidence: "the degree of h(z) is 2t instead of t"; "randomize the coefficients of h(z), and reduce its degree while keeping the free coefficient unchanged" https://mit6875.github.io/PAPERS/BGW.pdf
- **Notes:** The abstract says "no faults" and "Byzantine faults"; it does not use the words "passive"/"active". The paper's introduction calls the setting "non-cryptographic (or information-theoretic)". The text read is the STOC extended abstract (my OCR/text layer has errors, e.g. "z" for "x"). It assumes secure channels; for the active case it uses broadcast-style verification in the text.

### ccd1988
- **Citation (as verified):** David Chaum, Claude Crepeau, Ivan Damgard. "Multiparty unconditionally secure protocols (extended abstract)". Proceedings of the 20th Annual ACM Symposium on Theory of Computing (STOC '88), pp. 11-19, 1988. https://doi.org/10.1145/62212.62214
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works/10.1145/62212.62214 -> Chaum, Crepeau, Damgard, STOC '88, pp. 11-19. https://crypto.cs.mcgill.ca/~crepeau/PDFx/ASPUBLISHED/CCD88A.pdf -> scan of the STOC paper (9 pp.), abstract read from page image. Crossref also shows a distinct 1-page "Multiparty Unconditionally Secure Protocols (Abstract)", CRYPTO '87, LNCS 293, p. 462, doi 10.1007/3-540-48184-2_43.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What bound on corrupted parties does it state, and with what kind of security? -> A: Fewer than a third may cheat (at least 2n/3 honest). Security is unconditional (no computational assumption). Assumes secret (authenticated secrecy) channels between each pair. | read: abstract and introduction (page image checked) | evidence: "any reasonable multiparty protocol can be achieved if at least 2n/3 of the participants are honest. The secrecy achieved is unconditional." https://crypto.cs.mcgill.ca/~crepeau/PDFx/ASPUBLISHED/CCD88A.pdf
- **Notes:** The paper says the one-third assumption is needed so that Byzantine agreement is possible, and poses as an open problem tolerating more cheaters (n/3 < U < n/2) by resorting to a cryptographic assumption. Its constructions use "blobs" and polynomial sharing with degree reduction.

### rabinbenor1989
- **Citation (as verified):** Tal Rabin, Michael Ben-Or. "Verifiable secret sharing and multiparty protocols with honest majority". Proceedings of the 21st Annual ACM Symposium on Theory of Computing (STOC '89), pp. 73-85, 1989. https://doi.org/10.1145/73007.73014
- **Level:** V1
- **Sources fetched:** https://api.crossref.org/works/10.1145/73007.73014 -> STOC '89, pp. 73-85, authors Rabin, T. and Ben-Or, M. https://api.openalex.org/works/doi:10.1145/73007.73014 -> index copy of the ACM abstract (secondary). Full paper not retrieved: dl.acm.org returned 403, UMD copy returned an interstitial page.
- **Hint vs found:** none (author order is Rabin, Ben-Or as in the hint).
- **Claim checks:**
  - Q: What threshold and what channel assumptions does it state? -> A: A majority of players honest; each participant can broadcast to all, and each pair can communicate secretly. | read: abstract via OpenAlex mirror only (secondary) | evidence: "each participant can broadcast a message to all other participants and that each pair of participants can communicate secretly" https://api.openalex.org/works/doi:10.1145/73007.73014
  - Q: Does it describe "information checking" or an equivalent authentication of shares? -> A: Yes, by name, in the abstract. | read: abstract via OpenAlex mirror only | evidence: "a new tool of Information Checking which provides authentication without cryptographic assumptions" same URL
- **Notes:** The abstract says "if a majority of the players are honest" and "secrecy achieved is unconditional"; the exact inequality t < n/2 was not read from the paper. Because the abstract was not read at a primary source and the full text not read, claims are V1. Later literature reports that its weak-secret-sharing component is not secure against adaptive adversaries (seen in a search snippet only; not verified).

### grr1998
- **Citation (as verified):** Rosario Gennaro, Michael O. Rabin, Tal Rabin. "Simplified VSS and fast-track multiparty computations with applications to threshold cryptography". Proceedings of the 17th Annual ACM Symposium on Principles of Distributed Computing (PODC '98), pp. 101-111, 1998. https://doi.org/10.1145/277697.277716
- **Level:** V1
- **Sources fetched:** https://api.crossref.org/works?query.bibliographic=Simplified+VSS... -> PODC '98, pp. 101-111, Gennaro, Rabin, Rabin. https://mit6875.github.io/PAPERS/GennaroRabinRabin.pdf -> 23-page "Regular presentation submission" version (not the proceedings text), read in full.
- **Hint vs found:** none for the record.
- **Claim checks:**
  - Q: What simplification of the multiplication step does it describe, and under what condition on n and t? -> A: Degree reduction and randomization of the BGW multiplication in one step. Each player P_i for i=1..2t+1 shares the product of its two shares with a fresh random degree-t polynomial h_i; each player computes H(j)=sum lambda_i h_i(j), where lambda are fixed constants from the first row of the inverse of the (2t+1)x(2t+1) Vandermonde matrix. Result is a random degree-t sharing of ab. Secure against a computationally unbounded passive adversary (Theorem 2). Condition on n and t: not stated in a sentence I could find; the protocol uses the shares of 2t+1 players, which implies n >= 2t+1. The robust (discrete-log) version is said to raise fault tolerance "from n/4 to n/2". | read: full text of the submission version | evidence: "We will show how to achieve both the degree reduction and the randomization in a single step." https://mit6875.github.io/PAPERS/GennaroRabinRabin.pdf
- **Notes:** The explicit condition on n, t is the open item, hence V1. The text read is the submission version; the proceedings version may differ.

### cdm2000
- **Citation (as verified):** Ronald Cramer, Ivan Damgard, Ueli Maurer. "General secure multi-party computation from any linear secret-sharing scheme". Advances in Cryptology - EUROCRYPT 2000, LNCS (vol. 1807), pp. 316-334, 2000. https://doi.org/10.1007/3-540-45539-6_22 ; full version IACR ePrint 2000/037.
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works/10.1007/3-540-45539-6_22 -> authors, title, EUROCRYPT 2000, pp. 316-334, 2000 (Crossref returned no volume; vol. 1807 comes from search-result snippets of the Springer and DBLP pages, not fetched). https://rd.springer.com/content/pdf/10.1007/3-540-45539-6_22.pdf -> 7 pages of the paper, read. eprint.iacr.org/2000/037 blocked by bot check.
- **Hint vs found:** none
- **Claim checks:**
  - Q: What condition on the access/adversary structure does it require for passive security? -> A: Q2: the adversary structure must be Q2, together with an LSSS that is multiplicative; no two sets of the adversary structure cover the player set. | read: abstract, introduction, Theorem 2 statement | evidence: "any LSSS M with Q2 adversary structure A, there is an error-free MPC protocol... secure against any adaptive and passive A-adversary" https://rd.springer.com/content/pdf/10.1007/3-540-45539-6_22.pdf
- **Notes:** Q2 is defined in the paper as "no two... of the sets in the structure cover the full player set P" and attributed to Hirt-Maurer. Their Theorem 1 (VSS) and strongly multiplicative case need Q3 for active security. The abstract also says the field size is not restricted. The Springer PDF I read is a 7-page excerpt (introduction and results); the full proofs are in the ePrint full version, which I could not fetch.

### hirtmaurer1997
- **Citation (as verified):** Martin Hirt, Ueli Maurer. "Complete characterization of adversaries tolerable in secure multi-party computation (extended abstract)". Proceedings of the 16th Annual ACM Symposium on Principles of Distributed Computing (PODC '97), pp. 25-34, 1997. https://doi.org/10.1145/259380.259412
- **Level:** V1
- **Sources fetched:** https://api.crossref.org/works/10.1145/259380.259412 -> PODC '97, pp. 25-34, Hirt, Maurer. https://api.openalex.org/works/doi:10.1145/259380.259412 -> index copy of the ACM abstract (secondary). https://rd.springer.com/content/pdf/10.1007/3-540-45539-6_22.pdf -> CDM2000 restating the Hirt-Maurer result and Q2/Q3. https://api.semanticscholar.org/graph/v1/paper/DOI:10.1145/259380.259412 -> metadata only; abstract elided by publisher. Full PODC text not retrieved (ACM 403; ETH host gave 404).
- **Hint vs found:** none for the record. The hint's terms Q2/Q3 are NOT used in the abstract text I read; they come from CDM2000's restatement.
- **Claim checks:**
  - Q: What are Q2 and Q3 exactly as defined there? -> A: The names Q2/Q3 were not found in HM97 text I could read. The abstract states the conditions in words: Q2-type = "no two of these collusions add up to the full player set"; Q3-type = "no three of these sets add up to the full player set". CDM2000 defines Q2/Q3 the same way: "no two, resp. no three of the sets in the structure cover the full player set P". | read: abstract (via OpenAlex mirror, secondary); CDM2000 introduction read at source | evidence: "no two of these collusions add up to the full player set" https://api.openalex.org/works/doi:10.1145/259380.259412
  - Q: Which security settings (passive / active, perfect / unconditional) do they characterise? -> A: Abstract: passive adversaries: no-two-cover condition. Active adversaries WITH a broadcast channel: same no-two condition. Active adversaries WITHOUT broadcast: no-three condition. The abstract frames it as "unconditional multi-party computation" and never says "perfect". | read: abstract via OpenAlex mirror (secondary) | evidence: "Without broadcast channels... if and only if no three of these sets add up to the full player set." same URL
- **Notes:** CDM2000's one-line summary ("passive iff Q2, active iff Q3") leaves out the broadcast variant in the HM97 abstract (active with broadcast needs only Q2). Any perfect-vs-unconditional split is NOT in this abstract; I did not check where it comes from. The extended abstract is not open; claims need the PODC text for V2.

### beaver1991
- **Citation (as verified):** Donald Beaver. "Efficient multiparty protocols using circuit randomization". Advances in Cryptology - CRYPTO '91, LNCS 576, pp. 420-432. https://doi.org/10.1007/3-540-46766-1_34
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works/10.1007/3-540-46766-1_34 -> author Beaver, CRYPTO '91 proceedings, pp. 420-432; Crossref gives no issued year. https://rd.springer.com/content/pdf/10.1007/3-540-46766-1_34.pdf -> full paper (5 pages), read.
- **Hint vs found:** The hint says 1991. Crossref has no year; "1991" is the conference year (CRYPTO '91). Search snippets (not fetched pages) say Springer's online record is dated 1992, i.e. the volume's publication year; I did not verify that.
- **Claim checks:**
  - Q: Does it introduce preprocessed random multiplication triples? -> A: Yes in substance, not in name. It precomputes random products ("independent, secret products of independent, secret random numbers") and replaces each secret multiplication by a reconstruction of publicly revealed corrections. The word "triple" is not used; the author calls it a "one-time table". | read: full text | evidence: "We coin the term 'one-time table' to describe a set of precomputed values that support direct secure computation without broadcast or private channels." https://rd.springer.com/content/pdf/10.1007/3-540-46766-1_34.pdf
- **Notes:** Abstract: "set every input to every gate in the circuit completely at random, and then make corrections", replacing secret multiplication with "a simple reconstruction of secretly shared values". The check "c = ab with random corrections" builds on a technique the paper cites as [2]. Page text has OCR-like errors in my extraction.

### franklinyung1992
- **Citation (as verified):** Matthew K. Franklin, Moti Yung. "Communication complexity of secure computation (extended abstract)". Proceedings of the 24th Annual ACM Symposium on Theory of Computing (STOC '92), pp. 699-710, 1992. https://doi.org/10.1145/129712.129780
- **Level:** V1
- **Sources fetched:** https://api.crossref.org/works/10.1145/129712.129780 -> STOC '92, pp. 699-710, Franklin and Yung. https://api.openalex.org/works/doi:10.1145/129712.129780 -> index copy of the ACM abstract (secondary). Full paper not retrieved (ACM 403; Springer link was an interstitial).
- **Hint vs found:** none
- **Claim checks:**
  - Q: Does it introduce sharing several secrets in one polynomial (packed / multi-secret sharing)? -> A: The abstract says its compilation technique "is based on a new compression idea of polynomial-based multi-secret sharing". That is consistent with the question; the abstract does not use the word "packed" and I did not read the construction. | read: abstract via OpenAlex mirror only (secondary) | evidence: "Our compilation technique is based on a new compression idea of polynomial-based multi-secret sharing." https://api.openalex.org/works/doi:10.1145/129712.129780
- **Notes:** In the abstract the technique costs fault tolerance (from t to t-k+1) to compute one function at k input sets with no extra communication. "Introduces" is the authors' own claim of newness ("a new compression idea"). Crossref also lists a related chapter "The Varieties of Secure Distributed Computation" (Sequences II, 1993; 10.1007/978-1-4613-9323-8_30) by the same authors.

### cdn2015
- **Citation (as verified):** Ronald Cramer, Ivan Bjerre Damgard, Jesper Buus Nielsen. "Secure Multiparty Computation and Secret Sharing". Cambridge University Press, 2015. DOI 10.1017/CBO9781107337756. ISBN 9781107043053 (hardback, as listed on the Cambridge page; assignment of format inferred by the fetch tool) and 9781107337756 (online).
- **Level:** V2
- **Sources fetched:** https://www.cambridge.org/core/product/identifier/9781107337756/type/book (via doi.org redirect) -> title, three authors, publisher CUP, ISBNs 9781107043053 and 9781107337756, dates 05 Aug 2015 and 15 Jul 2015. https://api.crossref.org/works/10.1017/cbo9781107337756 -> monograph, publisher CUP, published online 2015-06-30, print 2015-08-05, both ISBNs.
- **Hint vs found:** none (title, authors, year match).
- **Claim checks:** not required.
- **Notes:** Crossref and the Cambridge page give slightly different dates (online 2015-06-30 vs 15 Jul 2015); the year is 2015 in both. Crossref lists the individual chapters, including "MPC from General Linear Secret-Sharing Schemes" (pp. 139-158).
