# Privacy

## Principles

1. **Browsing data stays in the browser.** The extension downloads the *whole* signed release and matches locally. It never sends visited URLs, hostnames, lookup queries or telemetry.
2. **Workers process public data only.** A task contains domain names and evidence pins. Results contain scores and findings about those public names. Workers never read browser histories, internal documents, credentials or security logs. The engine has no network access to analysed domains.
3. **Anchors learn nothing about content.** Only a 32-byte hash of a log checkpoint is anchored. With OpenTimestamps the hash is blinded with a random nonce before it is sent to calendars.
4. **Reporting is user-initiated.** "Report a false positive" opens a prefilled GitHub issue form, which the user reviews and submits manually. Nothing is sent automatically.

## What each party can observe

| Party | Can observe | Cannot observe |
|---|---|---|
| Release host (static HTTPS) | Client IP, fetch time, extension version (User-Agent) | Visited sites, matches, warnings shown |
| Other operators (peers) | Peer IP addresses, participation, heartbeat timing, results for assigned public domains | Anything about users; other organisations' internal data |
| Coordinator / verifier | Same as peers, plus all task results | Users' browsing |
| CT log operators (only workers with `ct_scanning = true`) | The worker's IP address, and which public tiles it downloads | Anything about users or the organisation's internal data |
| OpenTimestamps calendars | A blinded 32-byte hash and the submitter's IP | Release content, domains |
| GitHub (false-positive report) | What the user chooses to submit | Anything else |

## Data retention

- **Workers** keep a status file and, optionally, logs. They hold no user data.
- **The coordinator** keeps signed verification records and results. These are public-domain information plus pseudonymous worker keys.
- **The extension** keeps the current release, the anti-rollback state, the strict-mode setting, and the attempted URL *of a listed host only*, per tab, in memory and `chrome.storage.session` (memory-backed, cleared when the browser closes) so that "Continue anyway" works. URLs of unlisted sites leave no trace, and nothing is transmitted.

## Residual risks

- **Peer exposure.** Operators' IP addresses are visible to peers. The network is permissioned and not anonymous.
- **Fetch-time inference.** A release host could infer the approximate number and timing of consumers from fetch patterns. Mirroring releases on several hosts, or a CDN, spreads this.
- **Attacker-chosen domains.** Lexical analysis of attacker-chosen domain names reveals nothing about users.
