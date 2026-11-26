# Batch 3 verification

Method note: bibliographic data from Crossref API (api.crossref.org) plus Springer landing-page metadata (retrieved via web.archive.org snapshots of link.springer.com, because the live site redirects bots). Claim text read from open copies listed per entry. Several sites (eprint.iacr.org direct, cr.yp.to some paths, dblp.org, sciencedirect.com) blocked automated access; ePrint PDFs were read from web.archive.org copies of eprint.iacr.org. I did not attempt to bypass the ScienceDirect paywall for Wegman-Carter 1981 after a permission denial.

### cartermegman1979
- **Citation (as verified):** J. Lawrence Carter, Mark N. Wegman. "Universal classes of hash functions". Journal of Computer and System Sciences 18(2), 143-154, April 1979. DOI 10.1016/0022-0000(79)90044-8. Conference version: "Universal classes of hash functions (Extended Abstract)", STOC '77, pp. 106-112, DOI 10.1145/800105.803400.
- **Level:** V2
- **Sources fetched:** https://api.crossref.org/works?query.bibliographic=... -> both JCSS and STOC '77 records with the above data. https://www.cs.princeton.edu/courses/archive/fall09/cos521/Handouts/universalclasses.pdf -> full-text scan of the JCSS article (header "JOURNAL OF COMPUTER AND SYSTEM SCIENCES 18, 143-154 (1979)", received Aug 8 1977, revised Aug 10 1978).
- **Hint vs found:** none (author order Carter, Wegman as hinted).
- **Claim checks:**
  - Q: How is a universal class of hash functions defined? -> A: A class H of functions A->B is "universal_2" if for all distinct x, y in A the number of h in H with h(x)=h(y), written delta_h(x,y), is at most |H|/|B|; i.e. no pair of distinct keys collides under more than a 1/|B| fraction of the functions. | read: full text | evidence: "H is universal, if for all x, y in A, 6,(x, y) < 1H //I B I." (OCR of delta_h(x,y) <= |H|/|B|) https://www.cs.princeton.edu/courses/archive/fall09/cos521/Handouts/universalclasses.pdf
- **Notes:** The paper's stated purpose is storage/retrieval (hashing); the abstract does not mention authentication. The Princeton file is a course handout copy of the journal scan, not the publisher page.

### wegmancarter1981
- **Citation (as verified):** Mark N. Wegman, J. Lawrence Carter. "New hash functions and their use in authentication and set equality". Journal of Computer and System Sciences 22(3), 265-279, June 1981. DOI 10.1016/0022-0000(81)90033-7. (Earlier FOCS 1979 version: "New classes and applications of hash functions", pp. 175-182, DOI 10.1109/SFCS.1979.26.)
- **Level:** V1
- **Sources fetched:** Crossref query -> JCSS record with above data, and the FOCS 1979 record. https://cr.yp.to/bib/1981/wegman.bibtex -> same volume/pages/year. ScienceDirect (403), full text not obtained.
- **Hint vs found:** none for the journal record. Note the author order is Wegman, Carter (reverse of the 1979 paper).
- **Claim checks:**
  - Q: How does it build MAC from a hash family? -> A: not read.
  - Q: One-time pad on the hash value, hash reused while pad changes? -> A: not read.
  - Q: What forgery probability does it state? -> A: not read.
  - A web-search snippet (secondary, not counted) says UMAC/other papers attribute "strongly universal family + one-time pad" to this paper; I did not verify it at the source.
- **Notes:** Open full text was not found. Someone with Elsevier access should check the authentication section directly.

### gms1974
- **Citation (as verified):** E. N. Gilbert, F. J. MacWilliams, N. J. A. Sloane. "Codes which detect deception". Bell System Technical Journal 53(3), 405-424, March 1974. DOI 10.1002/j.1538-7305.1974.tb02751.x.
- **Level:** V2
- **Sources fetched:** Crossref -> record above. https://archive.org/download/bstj53-3-405/bstj53-3-405_djvu.txt -> OCR text of the BSTJ article (abstract and introduction read).
- **Hint vs found:** none (author "Mrs. F. J. MacWilliams" in the print byline).
- **Claim checks:**
  - Q: What does it define and bound? -> A: Defines the deception (substitution) problem: message x encoded with key m to y = phi(x,m); opponent B knows x, y, phi but not m and substitutes a false y. Bounds B's best probability of an undetected substitution: if the key takes K values, it is at least K^(-1/2) ("optimal strategy for B secures him a probability of an undetected substitution >= K^-1/2" - OCR renders it as "^ K~^"); several encoding functions meeting the bound are given. | read: abstract + introduction | evidence: "if the key can take K values, then an optimal strategy for B secures him a probability of an undetected substitution" https://archive.org/download/bstj53-3-405/bstj53-3-405_djvu.txt
- **Notes:** The exponent in the OCR is garbled ("^ K~^"); my reading as K^(-1/2) comes from the garbled glyphs plus the known result, so the exponent itself should be confirmed against a clean scan before it is quoted. The paper itself says the problem was posed by G. J. Simmons.

### simmons1985
- **Citation (as verified):** Gustavus J. Simmons. "Authentication Theory/Coding Theory". In Advances in Cryptology (CRYPTO '84), LNCS 196, pp. 411-431, Springer, 1985. DOI 10.1007/3-540-39568-7_32.
- **Level:** V1
- **Sources fetched:** Crossref -> title, author, pages 411-431, DOI. Springer landing page via web.archive.org -> year 1985, pages 411-431, abstract.
- **Hint vs found:** none on author/title/pages/year. The Springer page metadata labels the conference generically ("Workshop on the Theory and Application of Cryptographic Techniques"); I did not obtain a source that names CRYPTO '84 explicitly, so that detail is from the hint.
- **Claim checks:**
  - Q: Does it state lower bounds on key size for a given probability of deception? -> A: not answerable from the abstract; the abstract only describes redundancy added to messages to detect error versus deception by an active opponent. | read: abstract | evidence: "the deliberate introduction of redundant information into the transmitted message" https://link.springer.com/chapter/10.1007/3-540-39568-7_32
- **Notes:** Full text not obtained.

### stinson1994
- **Citation (as verified):** Douglas R. Stinson. "Universal hashing and authentication codes". Designs, Codes and Cryptography 4(3), 369-380, 1994 (July). DOI 10.1007/BF01388651. Conference version: CRYPTO '91, LNCS 576, pp. 74-85, DOI 10.1007/3-540-46766-1_5 (proceedings published 1992).
- **Level:** V2 (for the CRYPTO '91 text; the DCC 1994 text itself was not read)
- **Sources fetched:** Crossref -> both records. https://rd.springer.com/content/pdf/10.1007/3-540-46766-1_5.pdf -> full text of the CRYPTO '91 paper (9 pages). Springer landing page (archive) -> abstract and pages 74-85.
- **Hint vs found:** none. Crossref's DCC record is a different (journal) text from the one I read.
- **Claim checks:**
  - Q: What relation between (almost) universal hash families and authentication codes? -> A: An epsilon-almost strongly universal (epsilon-ASU_2) class of hash functions from A to B yields an authentication code (no secrecy) with |A| source states, |B| authenticators, |H| encoding rules, with P_d0 = 1/|B| and P_d1 <= epsilon. | read: full text (Theorem 3.2) | evidence: "there exists an authentication code for |A| source states, having |B| authenticators and |H| encoding rules, such that Pd0 = 1/|B| and Pd1 <= epsilon" https://rd.springer.com/content/pdf/10.1007/3-540-46766-1_5.pdf (OCR of text)
  - Q: What bounds on key length? -> A: Theorem 4.1 gives a lower bound on |H| for epsilon-AU_2 classes (|H| >= a(b-1)/(a(epsilon-1)+b^2(1-epsilon)) as OCR'd), Theorem 4.2 a lower bound for epsilon-ASU_2 classes. Theorem 6.4 gives a construction for an a'-bit source with a b'-bit authenticator, P_d0 = 2^-b', P_d1 = (log a' - log b' + 1)2^-b', and key length (log a' - log b' + 2)b'. | read: full text | evidence: "with a key of length (log a' - log b' + 2)b'" https://rd.springer.com/content/pdf/10.1007/3-540-46766-1_5.pdf
- **Notes:** The OCR of the Theorem 4.1/4.2 formulas is imperfect; confirm exact inequalities in the typeset paper before quoting. The paper reports lower key length than Wegman-Carter's [We] bound by a factor it states in section 6.

### bernstein2005poly
- **Citation (as verified):** Daniel J. Bernstein. "The Poly1305-AES Message-Authentication Code". Fast Software Encryption (FSE 2005), LNCS 3557, pp. 32-49. DOI 10.1007/11502760_3.
- **Level:** V2
- **Sources fetched:** Crossref -> record. https://cr.yp.to/mac/poly1305-20050329.pdf -> full text (18 pages, dated 2005.03.29, "final and may be freely cited").
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What forgery bound for a polynomial-evaluation MAC in terms of message length and field size? -> A: Abstract: security gap at most 14*ceil(L/16)/2^106 per forgery attempt (times D attempts: 14D*ceil(L/16)/2^106) for messages of at most L bytes, at most 2^64 authenticated messages seen. The hash is polynomial evaluation modulo the prime 2^130-5. Theorem 3.3: for distinct messages of at most L bytes and r uniform in a set of size 2^106, Pr[H_r(m)=H_r(m')+g] <= 8*ceil(L/16)/2^106. | read: abstract + Theorem 3.3 | evidence: "the security gap is at most 14DdL/16e/2^106 if messages have at most L bytes" (PDF text extraction) https://cr.yp.to/mac/poly1305-20050329.pdf
- **Notes:** The constant 14 in the abstract vs 8 in Theorem 3.3 reflects other terms in the overall proof; I did not trace the derivation. Poly1305-AES masks the hash with AES_k(n) for a nonce n, so it is computationally (AES) based, not information-theoretic.

### bernstein2005wcs
- **Citation (as verified):** Daniel J. Bernstein. "Stronger Security Bounds for Wegman-Carter-Shoup Authenticators". Advances in Cryptology - EUROCRYPT 2005, LNCS 3494, pp. 164-180. DOI 10.1007/11426639_10.
- **Level:** V1 (abstract read; the specific "attempts and message length" aspect is only partly addressed by the abstract)
- **Sources fetched:** Crossref -> record. Springer landing page via web.archive.org -> abstract, conference name, pages 164-180, year 2005.
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What does the abstract say about forgery probability as a function of attempts and message length? -> A: The abstract does not state a forgery probability formula. It says Shoup's result gives security up to sqrt(1/epsilon) authenticated messages (about 2^50 for some systems), and this paper proves the same systems stay secure up to sqrt(#G) authenticated messages (typically 2^64), via a one-sided theorem using differential probabilities of h and interpolation probabilities of f. It says nothing about attempts or message length. | read: abstract | evidence: "security of the same systems is retained up to sqrt(#G) authenticated messages. In a typical state-of-the-art system, sqrt(#G) is 2^64" https://link.springer.com/chapter/10.1007/11426639_10
- **Notes:** The question's presumption (abstract speaks of forgery probability vs attempts and message length) does not match the abstract. The abstract's bound is on the number of authenticated messages observed. Full text not obtained (cr.yp.to PDF link guessed was not found).

### mcgrewviega2004
- **Citation (as verified):** David A. McGrew, John Viega. "The Security and Performance of the Galois/Counter Mode (GCM) of Operation". Progress in Cryptology - INDOCRYPT 2004, LNCS 3348, pp. 343-355. DOI 10.1007/978-3-540-30556-9_27. ePrint 2004/193 (title there ends "(Full Version)").
- **Level:** V2
- **Sources fetched:** Crossref -> record. https://eprint.iacr.org/2004/193 -> title, authors, received 2004-08-10, revised 2004-10-07. Full text read from a web.archive.org copy of https://eprint.iacr.org/2004/193.pdf (6 pages as served by the archive; theorems and appendix present).
- **Hint vs found:** none. The ePrint title carries "(Full Version)".
- **Claim checks:**
  - Q: How is GHASH defined? -> A: GHASH(H,A,C) = X_{m+n+1}, a polynomial-evaluation chain X_i = (X_{i-1} xor block_i)*H, with multiplication in the binary field GF(2^w) (w = 128), H = E(K, 0^w), over padded A, C and a final length block. | read: full text | evidence: "It uses polynomial hashing in the finite field GF(2^w)" https://eprint.iacr.org/2004/193.pdf
  - Q: What bound is stated? -> A: Lemma 2: GHASH is ceil(l/w + 1) * 2^-t almost-XOR-universal (inputs summing to at most l bits, output truncated to t bits). Theorem 2: forgery advantage F_GCM <= A_E + (l_P/w + 2q)^2 2^(-w-1) + q((l_P/w + 2q + 1) ceil(l_IV/w + 1) 2^(1-w) + ceil(l/w + 1) 2^-t). | read: Lemma 2 and Theorem 2 | evidence: "GHASH is dl/w + 1e2^-t -almost xor universal" (PDF text extraction) https://eprint.iacr.org/2004/193.pdf
- **Notes:** Direct curl/WebFetch of eprint.iacr.org PDF was blocked by Cloudflare; the archived copy was used. Security is in the PRP model (E assumed a PRP), not information-theoretic.

### shannon1949
- **Citation (as verified):** Claude E. Shannon. "Communication Theory of Secrecy Systems". Bell System Technical Journal 28(4), 656-715, October 1949. DOI 10.1002/j.1538-7305.1949.tb00928.x.
- **Level:** V2
- **Sources fetched:** Crossref -> record. https://archive.org/download/bstj28-4-656/bstj28-4-656_djvu.txt -> OCR text of the BSTJ article.
- **Hint vs found:** none. The hint wording "key entropy" is an interpretation; see below.
- **Claim checks:**
  - Q: Does it prove perfect secrecy requires at least as many keys (key entropy) as messages? -> A: Yes for the count of keys: Section 10 shows that the number of different keys is at least the number of messages. In the infinite-message case it states perfect secrecy requires R_M L_M <= R_K L_K (key rate at least message rate). The key-entropy form H(K) >= H(M) is not stated as such in the passage I read. | read: full text of Section 10 | evidence: "the number of different keys is at least as great as the number of M's" https://archive.org/download/bstj28-4-656/bstj28-4-656_djvu.txt
- **Notes:** Theorem 6 gives the necessary and sufficient condition P_M(E) = P(E). The counting argument assumes a finite message set. The H(K) >= H(M) statement is the standard textbook form but I did not find it in Shannon's text, so cite the counting statement.

### chaumroijakkers1990
- **Citation (as verified):** David Chaum, Sandra Roijakkers. "Unconditionally-Secure Digital Signatures". Advances in Cryptology - CRYPTO '90, LNCS 537, pp. 206-214, Springer. DOI 10.1007/3-540-38424-3_15.
- **Level:** V1
- **Sources fetched:** Crossref -> title, authors, pages 206-214, DOI. Springer landing page via web.archive.org -> same title/pages; abstract truncated by Springer ("We present a polynomial time protocol in..."). Semantic Scholar -> year 1990, venue "Annual International Cryptology Conference" (abstract withheld).
- **Hint vs found:** title uses a hyphen ("Unconditionally-Secure"); hint had no hyphen. Otherwise none.
- **Claim checks:**
  - Q: What model and assumptions does it use? -> A: Only the truncated abstract was readable: "All known digital signature schemes can be forged by anyone having enough computing power. For a finite set of participants, we can overcome this weakness." The model is not stated in the readable text. | read: partial abstract | evidence: "For a finite set of participants, we can overcome this weakness." https://link.springer.com/chapter/10.1007/3-540-38424-3_15
  - Secondary (Swanson-Stinson 2011, which I read): says Chaum-Roijakkers is "an interactive scheme that does not have transferability". Not counted as a source answer.
- **Notes:** Full text not obtained.

### hanaoka2000
- **Citation (as verified):** Goichiro Hanaoka, Junji Shikata, Yuliang Zheng, Hideki Imai. "Unconditionally Secure Digital Signature Schemes Admitting Transferability". Advances in Cryptology - ASIACRYPT 2000, LNCS 1976, pp. 130-142. DOI 10.1007/3-540-44448-3_11.
- **Level:** V1
- **Sources fetched:** Crossref -> record. Springer landing page via web.archive.org -> abstract.
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What assumptions limit the scheme (number of verifiers/signatures, keys, channels)? -> A: The abstract does not state these limits. It says the authors "establish a model for unconditionally secure digital signatures in a group", with "unlimited transfer of signatures", the "first unconditionally secure signature that admits provably secure transfer". | read: abstract | evidence: "we establish a model for unconditionally secure digital signatures in a group, and demonstrate practical schemes in that model" https://link.springer.com/chapter/10.1007/3-540-44448-3_11
  - Secondary (Swanson-Stinson, read): says Hanaoka et al.'s model is MAC-based and that they "do not provide an analysis" of their construction's security. Not counted.
- **Notes:** The limits on verifiers, signatures and keys need the full text (not obtained). Note Swanson-Stinson's claim that Hanaoka et al. give no proof of security for the construction.

### swansonstinson2011
- **Citation (as verified):** Colleen M. Swanson, Douglas R. Stinson. "Unconditionally Secure Signature Schemes Revisited". Information Theoretic Security (ICITS 2011), LNCS 6673, pp. 100-116. DOI 10.1007/978-3-642-20728-0_10. ePrint 2011/104. Extended journal version: Journal of Mathematical Cryptology 10(1), 35-67, 2016, DOI 10.1515/jmc-2016-0002.
- **Level:** V2
- **Sources fetched:** Crossref -> conference and journal records. Web search result listing eprint.iacr.org/2011/104 (ePrint number). Text read from a web.archive.org copy of https://eprint.iacr.org/2011/104.pdf (6 pages served; abstract, introduction and section outline readable).
- **Hint vs found:** none; note the 2016 journal expansion.
- **Claim checks:**
  - Q: What does it say about models/assumptions needed for USS? -> A: USS schemes need different signing and verification algorithms for each user, so a security model must define what counts as a valid signature, and must handle disagreements via dispute resolution with explicit trust assumptions. It gives a new security model, formal non-repudiation and transferability definitions, and analyses the Hanaoka et al. construction. It also notes MAC-based models (A2/A3 codes) rely on trusted arbiters and broadcast settings. | read: abstract + introduction | evidence: "a USS scheme must necessarily handle the event of a disagreement" https://eprint.iacr.org/2011/104
- **Notes:** The archived PDF I read was only 6 pages, so Sections 5-8 were not read in full.

### pfitzmannwaidner
- **Citation (as verified):** Not verified as hinted. The only authoritative record found for Pfitzmann/Waidner on this topic: Birgit Pfitzmann, Michael Waidner. "Unconditional Byzantine agreement for any number of faulty processors". STACS 92, LNCS 577, pp. 337-350, 1992. DOI 10.1007/3-540-55210-3_195 (Crossref). Also: Baum-Waidner, Pfitzmann, Waidner, "Unconditional Byzantine Agreement with good majority", STACS 91, pp. 285-295, DOI 10.1007/BFb0020806.
- **Level:** V0 for the hinted IBM report (RZ 2882, 1996, "Information-theoretic pseudosignatures and Byzantine agreement for t >= n/3"). The STACS 92 paper is a different, verified record whose claims were not read.
- **Sources fetched:** Crossref (three queries) -> STACS 91 and STACS 92 records; no IBM report. dblp.org -> blocked by bot protection. Semantic Scholar -> STACS 92 record, abstract withheld. A web search found later papers citing "[PW96] ... Technical Report, IBM Research, 1996" but none confirming the report number RZ 2882 (search snippet only, not counted).
- **Hint vs found:** The report number, exact title and year could not be matched to an authoritative record. Citing papers give the title as hinted and "IBM Research, 1996".
- **Claim checks:**
  - Q: What does it state about the setting (broadcast, threshold)? -> A: not read (STACS 92 abstract and the report both inaccessible).
- **Notes:** Do not cite RZ 2882 with a report number unless the IBM report or DBLP entry is checked. If a verified citation is needed, STACS 92 (pseudosignature-based unconditional BA for any number of faulty processors) is the confirmed record, but its content was not read here.

### blom1984
- **Citation (as verified):** Rolf Blom. "An Optimal Class of Symmetric Key Generation Systems". Advances in Cryptology - EUROCRYPT '84, LNCS 209, pp. 335-338, Springer, 1985. DOI 10.1007/3-540-39757-4_22.
- **Level:** V1
- **Sources fetched:** Crossref -> title, author, pages 335-338, DOI. Springer landing page via web.archive.org -> year 1985 (proceedings), pages 335-338, abstract.
- **Hint vs found:** Hint says 1984 (the conference year); Springer's publication date is 1985 (proceedings). Not a conflict.
- **Claim checks:**
  - Q: What security property (collusion bound) and storage per party? -> A: Abstract only: the scheme gives each user "the least possible" amount of secret information while "a certain minimum number of users have to cooperate to resolve the uncertainty of unknown keys". The specific bound (coalition size) and the storage figure are not stated in the abstract. | read: abstract | evidence: "the amount of secret information needed by each user to generate his keys is the least possible" https://link.springer.com/chapter/10.1007/3-540-39757-4_22
- **Notes:** Full text not obtained. The usual statement (storage of lambda+1 field elements, security against lambda colluders) was not read at the source here.

### blundo1998
- **Citation (as verified):** Carlo Blundo, Alfredo De Santis, Amir Herzberg, Shay Kutten, Ugo Vaccaro, Moti Yung. "Perfectly Secure Key Distribution for Dynamic Conferences". Information and Computation 146(1), 1-23, October 1998. DOI 10.1006/inco.1998.2717. Conference: "Perfectly-Secure Key Distribution for Dynamic Conferences", CRYPTO '92, LNCS 740, pp. 471-486, DOI 10.1007/3-540-48071-4_33 (proceedings 1993).
- **Level:** V2 (claim read in the CRYPTO '92 abstract; the journal text was not read)
- **Sources fetched:** Crossref -> both records. Springer landing page via web.archive.org -> abstract, CRYPTO conference, pages 471-486, 1993.
- **Hint vs found:** none.
- **Claim checks:**
  - Q: What lower bound on memory per user? -> A: In the non-interactive model with coalitions of up to k users and conferences of size t, each user's piece of information must be at least C(k+t-1, t-1) times the size of the common key, and this is shown optimal by a scheme meeting it. An interactive scheme needs only k+t-1 times the key size. | read: abstract | evidence: "We prove a lower bound on the size of the user's piece of information of (k+t-1 choose t-1) times the size of the common key." https://link.springer.com/chapter/10.1007/3-540-48071-4_33
- **Notes:** Abstract wording is "k users pool together" and "t-size conference". The abstract is of the CRYPTO '92 version; the journal version may differ in detail.
