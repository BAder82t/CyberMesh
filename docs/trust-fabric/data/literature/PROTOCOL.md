# Reference verification protocol (read fully before starting)

You are verifying bibliographic references and specific claims for the literature review of an
information-theoretic security project. The reader will rely on your output as evidence, so an
honest "could not verify" is worth far more than a plausible guess.

## Rules

1. **The hints you are given are search keys only.** They were written from memory and may have the
   wrong year, venue, author spelling, title wording, or may not exist. Find the real record
   independently and report what the source says, including every discrepancy with the hint.
2. **Use authoritative sources only** to establish bibliographic facts: the publisher or DOI landing
   page, Crossref (https://api.crossref.org/works?query.bibliographic=...), DBLP (dblp.org), the
   IACR ePrint archive, arXiv, ACM Digital Library, IEEE Xplore, Springer, Elsevier/ScienceDirect, the
   IETF datatracker / rfc-editor.org, NIST CSRC, USENIX, Google Patents (for patents). A blog, a
   Wikipedia page, a citation in another paper, or a search-result snippet is NOT enough on its own.
3. **Never fill a field from memory.** If you could not retrieve a page, say so; do not "recall" it.
   If a fetch is blocked (paywall, bot protection), try another authoritative route (DBLP, Crossref,
   publisher abstract, author's own copy, ePrint). If you still cannot, mark the level accordingly.
4. **Claim checks.** For each reference you are also given neutral questions about what the source
   states. Answer them only from text you actually read at the source (abstract, introduction,
   theorem statement, full text). Quote at most 25 words as evidence and give the URL. State exactly
   what you read: `abstract`, `full text`, `theorem statement`, or `not read`. Do not answer a
   question from a secondary source or from memory. If the source says something different from
   what the question presumes, say so plainly: that is the most valuable result you can return.
5. Do not try to make the sources agree with each other or with the project. Report what each says.

## Verification levels (assign one per reference)

- **V2**: bibliographic metadata matches an authoritative record AND every claim question was
  answered from text read at the source.
- **V1**: bibliographic metadata matches an authoritative record; claim questions were answered
  only partly or not at all from the source text (say which).
- **V0**: could not match the reference to an authoritative record (say what you tried).
- **MISMATCH**: a record exists but differs materially from the hint (different authors, year,
  venue, or the claim does not hold). Describe it.

## Output

Write one Markdown file at the path given in your task (create the directory if needed), with one
section per reference exactly in this form, then reply with a short summary (under 300 words)
listing counts per level and every MISMATCH or V0 with one line each.

```
### <key>
- **Citation (as verified):** Authors. "Title". Venue, volume(issue), pages, year. DOI or URL.
- **Level:** V2 | V1 | V0 | MISMATCH
- **Sources fetched:** URL -> what it showed (one line each)
- **Hint vs found:** differences from the hint, or "none"
- **Claim checks:**
  - Q: <the question> -> A: <answer, only from source text> | read: abstract/full text/theorem/not read | evidence: "<quote <=25 words>" <URL>
- **Notes:** anything else a careful reader should know (retractions, errata, later corrections,
  journal vs conference versions, where the open text is)
```
