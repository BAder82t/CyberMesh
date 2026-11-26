# Batch 4 verification

General note on routes. Crossref (api.crossref.org) was the authoritative bibliographic source for every record below (DOIs given). Publisher pages (ACM DL, IEEE Xplore, Wiley, Springer) were blocked (403 / empty / cookie redirect), and DBLP was blocked by bot protection. Several PDFs downloaded from author or publisher hosts had font encodings that pdftotext could not decode, so no full text was read except where stated. Where an abstract is quoted and the source is "OpenAlex mirror", it is the OpenAlex copy (api.openalex.org/works/doi:<DOI>) of the publisher abstract. OpenAlex is not on the protocol's authoritative list, so those claim answers are capped at V1 even though the metadata matched. Abstract text for DDWY (JACM) and Ford-Fulkerson also came straight from Crossref.

### ddwy1993
- **Citation (as verified):** Dolev, D.; Dwork, C.; Waarts, O.; Yung, M. "Perfectly secure message transmission". Journal of the ACM 40(1), 17-47, January 1993. DOI 10.1145/138027.138036. FOCS version: Proc. 31st Annual Symposium on Foundations of Computer Science (1990), pp. 36-45, DOI 10.1109/fscs.1990.89522.
- **Level:** V1
- **Sources fetched:**
  - https://api.crossref.org/works?query.bibliographic=Perfectly+secure+message+transmission+Dolev+Dwork+Waarts+Yung -> JACM record (vol 40, issue 1, pp 17-47, 1993) and FOCS 1990 record (pp 36-45)
  - https://api.crossref.org/works/10.1145/138027.138036 -> JACM abstract text
  - https://projects.csail.mit.edu/jacm/References/dolevdwy1993:17.html -> JACM bibliography page confirming "Journal of the ACM, 40(1):17-47, January 1993"; no abstract
  - https://api.openalex.org/works/doi:10.1109/fscs.1990.89522 -> FOCS abstract (mirror)
  - https://dl.acm.org/doi/10.1145/138027.138036 and /doi/pdf/... -> HTTP 403, full text not obtained
  - https://eprint.iacr.org/2002/128 (Desmedt-Wang, secondary) -> says DDWY "studied secure message transmission in one-way or two-way channels" and "only consider the case when all channels are two-way or all channels are one-way". Not used as evidence for the claims below.
  - https://cris.huji.ac.il/en/publications/perfectly-secure-message-transmission-2/ -> a Hebrew University record that carries the same abstract but wrongly lists the venue as IEEE Transactions on Industry Applications 27(1), 1991. Treat that record as faulty.
- **Hint vs found:** Record matches the hint (JACM 40(1), 1993; FOCS 1990). Pages 17-47 are new information.
- **Claim checks:**
  - Q: What connectivity (number of vertex-disjoint paths) is necessary and sufficient against t Byzantine faulty nodes? -> A: NOT ANSWERED FROM SOURCE TEXT. The abstract says only that "Lower bounds are obtained on the connectivity required" and that algorithms "operate with this connectivity". It gives no number. | read: abstract | evidence: "Lower bounds are obtained on the connectivity required for successful secure communication." https://api.crossref.org/works/10.1145/138027.138036
  - Q: What does it state for one-round / one-way protocols versus more rounds? -> A: NOT ANSWERED. The abstract does not mention rounds or one-way communication. Full text not read. | read: abstract (does not address) | evidence: none
  - Q: Adversary assumptions (active? computationally unbounded? static?) -> A: Partly. The abstract says processors and communication lines "may be faulty" and that the algorithms "rely on no complexity-theoretic assumptions", which indicates an information-theoretic setting. Active versus passive, and static versus adaptive, are NOT stated in the abstract. | read: abstract | evidence: "rely on no complexity-theoretic assumptions" https://api.crossref.org/works/10.1145/138027.138036
- **Notes:** The "2t+1 paths" threshold and the one-way versus two-way contrast are NOT verified. I did not fill them from memory, as the protocol requires. The caller must read the JACM full text (ACM DL, paywalled) before relying on the condition. The abstract also says the algorithms achieve "perfect secrecy, perfect resiliency, and worst-case time linear in the diameter". The Desmedt-Wang ePrint says DDWY treated networks where all channels are one-way or all are two-way, which suggests the one-way versus two-way point needs checking against the paper itself.

### franklinwright2000
- **Citation (as verified):** Franklin, M.; Wright, R. "Secure Communication in Minimal Connectivity Models". Journal of Cryptology 13(1), 9-30, January 2000. DOI 10.1007/s001459910002. Preliminary version: EUROCRYPT 1998, LNCS, pp. 346-360, DOI 10.1007/bfb0054138.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> journal record (vol 13, issue 1, pp 9-30, 2000-01) and EUROCRYPT'98 record
  - https://link.springer.com/article/10.1007/s001459910002 -> publisher page (reached via cookie redirect), abstract summary
  - https://link.springer.com/content/pdf/10.1007/s001459910002.pdf and scispace copy -> not retrievable (cookie redirect, empty)
- **Hint vs found:** none. The Springer page lists the year as 2000 (published 01 April 2000), and Crossref gives issue date January 2000.
- **Claim checks:**
  - Q: What does it say about secure communication with fewer than the connectivity needed for perfect security (probabilistic or reliability-with-error results)? -> A: The publisher abstract states there is "a sizable gap between the connectivity required for perfect security and for almost perfect security". The abstract is about minimal-connectivity settings with a strong Byzantine adversary and a new "multicast lines" model. The exact connectivity figures for each case are NOT read. | read: abstract (publisher page; the fetch tool returned a partial paraphrase plus one quoted phrase) | evidence: "a sizable gap between the connectivity required for perfect security and for almost perfect security" https://link.springer.com/article/10.1007/s001459910002
- **Notes:** The theorem statements were not read. A follow-up by Wang and Desmedt (J. Cryptology 14, 2001) answers one of the paper's open questions (seen in a search result; not verified here).

### menger1927
- **Citation (as verified):** Menger, K. "Zur allgemeinen Kurventheorie". Fundamenta Mathematicae 10, 96-115, 1927. DOI 10.4064/fm-10-1-96-115. EuDML: http://eudml.org/doc/211191.
- **Level:** V1
- **Sources fetched:**
  - https://api.crossref.org/works/10.4064/fm-10-1-96-115 -> Menger, Fund. Math. 10, pp 96-115, publisher Institute of Mathematics, Polish Academy of Sciences
  - EuDML record, reached only through a search result (the page itself failed with an expired TLS certificate) -> volume 10, issue 1, pp 96-115
  - matwbn.icm.edu.pl full-text PDF -> HTTP 403, not read
- **Hint vs found:** none.
- **Claim checks:**
  - Q: Does it contain the theorem relating the minimum vertex cut between two points to the maximum number of disjoint paths? What is the statement? -> A: NOT READ. I could not retrieve the German text. The record confirms only the title and location. | read: not read | evidence: none
- **Notes:** The paper is on curve theory (continua). Whether its statement is the graph-theoretic form must be checked in the text. No author-supplied statement was read.

### fordfulkerson1956
- **Citation (as verified):** Ford, L. R., Jr.; Fulkerson, D. R. "Maximal Flow Through a Network". Canadian Journal of Mathematics 8, 399-404, 1956. DOI 10.4153/cjm-1956-045-5. Reprinted in Classic Papers in Combinatorics (Birkhauser, 2009), pp 243-248.
- **Level:** V2
- **Sources fetched:**
  - Crossref query -> CJM record (vol 8, pp 399-404, 1956) and the 2009 reprint
  - Cambridge University Press PDF (open access, found via OpenAlex): https://www.cambridge.org/core/services/aop-cambridge-core/content/view/5D6E55D3B06C4F7B1043BC1D82D40764/S0008414X00036890a.pdf/div-class-title-maximal-flow-through-a-network-div.pdf -> text layer read with pdftotext
- **Hint vs found:** none.
- **Claim checks:**
  - Q: Does it state the max-flow min-cut theorem? -> A: Yes. Theorem 1, titled "Minimal cut theorem", says the maximal flow value in a network N equals the minimum of v(D) over all disconnecting sets D. A corollary follows. The proof is non-constructive. | read: full text, theorem statement | evidence: "The maximal flow value obtainable in a network N is the minimum of v(D) taken over all disconnecting sets D." https://doi.org/10.4153/CJM-1956-045-5
- **Notes:** The introduction notes that the minimal cut theorem fails for networks with several source-sink pairs, and that Dantzig conjectured it before a proof. The paper also gives a computational scheme for planar networks (Theorem 2). The Cambridge copy is OCR with spacing artefacts.

### eliasfeinsteinshannon1956
- **Citation (as verified):** Elias, P.; Feinstein, A.; Shannon, C. E. "A note on the maximum flow through a network". IRE Transactions on Information Theory 2(4), 117-119, December 1956. DOI 10.1109/tit.1956.1056816.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> IEEE record, vol 2, issue 4, pp 117-119, 1956-12
  - https://api.openalex.org/works/doi:10.1109/tit.1956.1056816 -> abstract (mirror)
  - IEEE Xplore -> empty page
- **Hint vs found:** none. Crossref also lists a 2009 reprint in Shannon's collected works.
- **Claim checks:**
  - Q: Does it state the same theorem independently? -> A: The abstract states the same theorem: "The maximum possible flow from left to right through a network is equal to the minimum value among all simple cut-sets." It applies it to several inputs and outputs. "Independently" cannot be established from the text read. The abstract does not discuss priority. | read: abstract (OpenAlex mirror) | evidence: "The maximum possible flow from left to right through a network is equal to the minimum value among all simple cut-sets." https://api.openalex.org/works/doi:10.1109/tit.1956.1056816
- **Notes:** The independence claim would need the paper's own wording or a priority statement. Not checked.

### edmondskarp1972
- **Citation (as verified):** Edmonds, J.; Karp, R. M. "Theoretical Improvements in Algorithmic Efficiency for Network Flow Problems". Journal of the ACM 19(2), 248-264, April 1972. DOI 10.1145/321694.321699.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> JACM record, vol 19, issue 2, pp 248-264, 1972-04
  - https://api.openalex.org/works/doi:10.1145/321694.321699 -> abstract (mirror; truncated at "In particular, this")
  - ACM DL -> 403
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What algorithmic results does it state for max flow (shortest augmenting paths) and for min-cost flow? -> A: The abstract says that if each augmentation is along an augmenting path with a minimum number of arcs, a maximum flow in an n-node network is obtained "after no more than (n^3 - n)/4 augmentations" (the extraction renders it as "~(n a- n)", so the exponent and denominator are garbled and NOT verified). A second rule (maximum-increase augmentation, integral capacities) is bounded by 1 + log_{M/(M-1)} f*(t,s) augmentations. For minimum-cost flow it gives "a new algorithm ... in which all shortest-path computations are performed on networks with all weights nonnegative". The rest of the abstract is cut off. | read: abstract (mirror, truncated) | evidence: "if each flow augmentation is made along an augmenting path having a minimum number of arcs, then a maximum flow ... will be obtained" https://api.openalex.org/works/doi:10.1145/321694.321699
  - Notes on the claim: the exact augmentation bound was NOT read cleanly. Do not cite a formula from this batch.
- **Notes:** A clean copy of the abstract or theorem is needed for the exact bound.

### ahlswede2000
- **Citation (as verified):** Ahlswede, R.; Cai, N.; Li, S.-Y. R.; Yeung, R. W. "Network information flow". IEEE Transactions on Information Theory 46(4), 1204-1216, July 2000. DOI 10.1109/18.850663. (A short ISIT 1998 abstract "Network information flow theory", p. 186, is a separate record.)
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> TIT record, vol 46, issue 4, pp 1204-1216, 2000-07
  - https://api.openalex.org/works/doi:10.1109/18.850663 -> abstract (mirror)
  - IEEE Xplore -> empty page
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What does it state about multicast capacity and coding at intermediate nodes? -> A: The abstract says that for one source it obtains a simple characterization of the admissible coding rate region, which "can be regarded as the max-flow min-cut theorem for network information flow". It also says it is in general not optimal to treat information as a fluid to be routed or replicated, and that "by employing coding at the nodes ... bandwidth can in general be saved". It does not state the formula in the abstract, and does not use the phrase "multicast capacity". | read: abstract (mirror) | evidence: "by employing coding at the nodes, which we refer to as network coding, bandwidth can in general be saved." https://api.openalex.org/works/doi:10.1109/18.850663
- **Notes:** The theorem (rate region as the minimum over sinks of the min-cut) was not read.

### caiyeung
- **Citation (as verified):** Two records exist.
  1. Cai, N.; Yeung, R. W. "Secure network coding". Proc. IEEE International Symposium on Information Theory (ISIT) 2002, p. 323. DOI 10.1109/isit.2002.1023595.
  2. Cai, N.; Yeung, R. W. "Secure Network Coding on a Wiretap Network". IEEE Transactions on Information Theory 57(1), 424-435, January 2011. DOI 10.1109/tit.2010.2090197.
- **Level:** V1
- **Sources fetched:**
  - Crossref queries -> both records as above (the ISIT record lists no year or month in the date field; the DOI prefix and ISIT 2002 title are the evidence for 2002)
  - https://api.openalex.org/works/doi:10.1109/tit.2010.2090197 and doi:10.1109/isit.2002.1023595 -> abstracts (mirror)
- **Hint vs found:** none. Both records exist. The journal version appeared in 2011 (the hint was right) though its DOI suffix (tit.2010.2090197) shows the 2010 online date.
- **Claim checks:**
  - Q: What does it state about the rate achievable securely when an adversary observes a bounded number of links? -> A: Journal abstract: the model is a "wiretap network" in which the wiretapper may access any one of a given collection of link subsets. It gives a secure linear network code construction "provided a certain graph-theoretic condition is satisfied". It proves that condition necessary "for the special case that the wiretapper may choose to access any subset of channels of a fixed size", and establishes optimality of the construction for that case. It does NOT state the rate formula in the abstract (the common summary "rate = number of links minus wiretapped links" was not read in the source). The ISIT 2002 abstract gives the construction under a "sufficient condition" and mentions secret sharing as a special case. | read: abstract (mirror), both records | evidence: "We also prove the necessity of this condition for the special case that the wiretapper may choose to access any subset of channels of a fixed size." https://api.openalex.org/works/doi:10.1109/tit.2010.2090197
- **Notes:** The journal abstract also covers the case where the wiretapper obtains a controlled amount of information. Whether source and intermediate-node randomness is allowed was not read.

### fmss2004
- **Citation (as verified):** Feldman, J.; Malkin, T.; Servedio, R.; Stein, C. "On the Capacity of Secure Network Coding". 42nd Annual Allerton Conference on Communication, Control, and Computing, 2004. Author copy: https://www.cs.columbia.edu/~rocco/papers/allerton04.html (PDF at https://www.cs.columbia.edu/~rocco/Public/sflow_allerton_final.pdf).
- **Level:** V1
- **Sources fetched:**
  - https://www.cs.columbia.edu/~rocco/papers/allerton04.html -> author page: title, four authors, venue, year, abstract summary
  - Crossref query -> no record for this paper (nearest hit was an unrelated paper by the same authors)
  - DBLP -> blocked by bot protection
  - The author PDF downloaded but its fonts did not decode, so the text was not read.
- **Hint vs found:** none. No DOI or DBLP record was retrieved, so the record rests on the author's page only.
- **Claim checks:**
  - Q: What result does it state? -> A: Per the author page: the paper studies using a multicast network code to send information securely against a wire-tap adversary who can eavesdrop on a bounded number of network edges. It shows that Cai and Yeung's method for securing a linear network code is inefficient and needs a very large field. It generalizes and simplifies that method, showing that making a code secure is equivalent to finding a linear code with generalized distance properties. Sacrificing a small amount of capacity lets a random code achieve this with a much smaller field, sometimes constant size. If no capacity is sacrificed, a large field may sometimes be necessary. | read: abstract (author page, as summarised by the fetch tool, not verbatim) | evidence: no verbatim quote above 25 words available; paraphrase only. https://www.cs.columbia.edu/~rocco/papers/allerton04.html
- **Notes:** Proceedings pages unknown. Needs a DBLP or proceedings record to reach V2.

### wyner1975
- **Citation (as verified):** Wyner, A. D. "The Wire-Tap Channel". Bell System Technical Journal 54(8), 1355-1387, October 1975. DOI 10.1002/j.1538-7305.1975.tb02040.x.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> BSTJ record, vol 54, issue 8, pp 1355-1387, 1975-10
  - https://api.openalex.org/works/doi:10.1002/j.1538-7305.1975.tb02040.x -> abstract (mirror)
- **Hint vs found:** none.
- **Claim checks:**
  - Q: Does it define a secrecy capacity for the degraded wiretap channel? -> A: Partly. The abstract treats a discrete memoryless channel with the wire-tapper viewing the output through a second DMC, finds the trade-off between rate R and equivocation d, and concludes there exists a number Cs > 0 such that reliable transmission up to rate Cs is possible in approximately perfect secrecy. The abstract does NOT use the word "degraded" and does not name Cs "secrecy capacity". Whether the full text assumes a degraded channel was not read. | read: abstract (mirror) | evidence: "there exists a Cs> 0, such that reliable transmission at rates up to Cs is possible in approximately perfect secrecy." https://api.openalex.org/works/doi:10.1002/j.1538-7305.1975.tb02040.x
- **Notes:** Full text not read.

### maurer1993
- **Citation (as verified):** Maurer, U. M. "Secret key agreement by public discussion from common information". IEEE Transactions on Information Theory 39(3), 733-742, May 1993. DOI 10.1109/18.256484.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> TIT record, vol 39, issue 3, pp 733-742, 1993-05
  - https://api.openalex.org/works/doi:10.1109/18.256484 -> abstract (mirror)
  - An ETH PDF guess returned a file whose text did not decode; not read.
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What bounds on the secret-key rate does it state? -> A: The abstract says "Upper bounds on H(S) as a function of P_XYZ are presented" and "Lower bounds on the rate H(S)/N (as N to infinity) are derived" for N independent repetitions. It adds that key agreement is possible for three parties receiving the output of a binary symmetric source over independent BSCs, even when the enemy's channel is superior. The bound expressions themselves were not read. | read: abstract (mirror) | evidence: "Upper bounds on H(S) as a function of P/sub XYZ/ are presented." https://api.openalex.org/works/doi:10.1109/18.256484
- **Notes:** The abstract says "H(S)" and "H(S)/N" and does not name the mutual-information or intrinsic-information bounds, so do not cite those from this batch.

### ahlswedecsiszar1993
- **Citation (as verified):** Ahlswede, R.; Csiszar, I. "Common randomness in information theory and cryptography. I. Secret sharing". IEEE Transactions on Information Theory 39(4), 1121-1132, July 1993. DOI 10.1109/18.243431.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> TIT record, vol 39, issue 4, pp 1121-1132, 1993-07
  - https://api.openalex.org/works/doi:10.1109/18.243431 -> abstract (mirror; OpenAlex also lists an open copy at https://pub.uni-bielefeld.de/record/1780491, not fetched)
- **Hint vs found:** none. Part II (CR capacity) is a separate paper: IEEE TIT 44(1), 225-240, 1998, DOI 10.1109/18.651026.
- **Claim checks:**
  - Q: What does it state about the secret key capacity? -> A: The abstract says it defines the concept of key-capacity, obtains "single-letter formulas of key-capacity ... for several models", and derives bounds to key-capacity for other models. It gives no formula in the abstract. | read: abstract (mirror) | evidence: "The concept of key-capacity is defined. Single-letter formulas of key-capacity are obtained for several models" https://api.openalex.org/works/doi:10.1109/18.243431
- **Notes:** The abstract says "key-capacity" and does not use the term "secret key capacity".

### csiszarnarayan2004
- **Citation (as verified):** Csiszar, I.; Narayan, P. "Secrecy Capacities for Multiple Terminals". IEEE Transactions on Information Theory 50(12), 3047-3061, December 2004. DOI 10.1109/tit.2004.838380.
- **Level:** V1
- **Sources fetched:**
  - Crossref query -> TIT record, vol 50, issue 12, pp 3047-3061, 2004-12
  - https://api.openalex.org/works/doi:10.1109/tit.2004.838380 -> abstract (mirror)
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What secret-key capacity result does it state for several terminals? -> A: The abstract states single-letter characterizations of (strong) secrecy capacities for an arbitrary number of terminals, each observing one component of a discrete memoryless multiple source, with unrestricted interactive public communication. It covers three kinds: secret key (SK), private key (PK) and wiretap secret key (WSK) capacity. The SK and PK characterizations are linked to multiterminal source coding without secrecy requirements. The capacities are achievable with non-interactive communication, and the achievability results are universal. The formula itself is not in the abstract. | read: abstract (mirror) | evidence: "We derive single-letter characterizations of (strong) secrecy capacities for models with an arbitrary number of terminals" https://api.openalex.org/works/doi:10.1109/tit.2004.838380
- **Notes:** The abstract states a general upper bound for WSK capacity, tight when the eavesdropper wiretaps noisy versions of the components (with randomization permitted). Full text not read.
