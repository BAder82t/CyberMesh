# CyberMesh browser extension (Chromium, Manifest V3)

The extension downloads a signed CyberMesh threat-intelligence release and verifies it
offline against a bundled trust root. It caches the release and warns you before you open
a host that the release lists. It has no runtime dependencies (vanilla ES modules) and
needs Chrome/Chromium 137 or later, for WebCrypto Ed25519.

## Build and install

```sh
cd apps/browser-extension
npm install                      # dev dependency only: playwright (for test:e2e)
npm run build -- --trust-root /path/to/trust-root.json \
                 --release-url https://releases.example.org/release.json
```

The build writes `dist/`, an unpacked extension, and `artifacts/cybermesh-extension-<version>.zip`
when the `zip` command is available. To install, open `chrome://extensions`, enable
Developer mode, choose **Load unpacked** and select `dist/`.

Build options (`node scripts/build.mjs --help`):

| option | default |
| --- | --- |
| `--trust-root <path>` | `src/trust-root.json`: the deterministic test keys from `cybermesh dev test-vectors`. They are for development only; anyone can sign for them, and the build prints a warning. |
| `--release-url <url>` | `http://127.0.0.1:8088/release.json`, which is what `cybermesh serve` serves |
| `--out <dir>` | `dist/` |
| `--zip <path>` / `--no-zip` | `artifacts/cybermesh-extension-<version>.zip` |

The build validates the trust root with the extension's own verifier. It writes
`config.json` and `trust-root.json`. It also sets `host_permissions` and the CSP
`connect-src` to the origin of the release URL, and to nothing else.

To try it locally:

```sh
cargo run -p cybermesh-cli --features dev-tools -- dev test-vectors --out /tmp/cm --now $(date +%s)
cp /tmp/cm/release-valid.json /tmp/cm/release.json
cargo run -p cybermesh-cli -- serve --dir /tmp/cm          # 127.0.0.1:8088, plus *.phish.localhost test pages
npm run build -- --trust-root /tmp/cm/trust-root.json
# then open http://examplebank-secure-login.phish.localhost:8088/
```

## How it works

1. **Update.** This runs on install, on browser start, every 30 minutes (`chrome.alarms`)
   and on **Update now**. The service worker fetches the release URL with `cache: 'no-store'`,
   no credentials, no referrer and no redirects, and caps the size at 16 MiB. The verifier,
   `src/lib/verify.js`, mirrors `verify_release` in `crates/cybermesh-intelligence`:
   - the DSSE envelope, PAE and payload type;
   - strict Ed25519 (the same rules as `verify_strict`);
   - valid signatures from at least `threshold` *distinct operators*;
   - canonical JSON;
   - the time window, entry and correction rules;
   - anti-rollback against the stored `{sequence, digest}`.

   A verified release is stored in `chrome.storage.local` with its envelope text, digest,
   sequence and timestamps, and the anti-rollback state is advanced.
2. **Offline.** If a download fails or is rejected, the cached release stays in use while
   it is valid. Each time the service worker starts, it re-verifies the cached envelope
   (signatures, expiry, anti-rollback) before using it. Once the release expires, all rules
   are removed and the badge shows `EXP`. Expired data is never enforced, and an alarm fires
   at `expires_at`.
3. **Enforcement.** The extension installs one `declarativeNetRequest` dynamic rule per entry
   (`requestDomains: [indicator]`, `main_frame` only), and replaces the rule set atomically
   in a single `updateDynamicRules` call. The rules are **`block`** rules, not `redirect`
   rules. Chromium silently ignores a redirect rule unless the extension has host permission
   for the request URL, so redirect rules would fail open (verified on Chromium 145). A block
   rule needs no host access and stops the listed site from loading at the network layer.
   The service worker then opens `warning.html?d=<indicator>` in that tab, from
   `webNavigation.onBeforeNavigate` or from `onErrorOccurred` with `ERR_BLOCKED_BY_CLIENT`.
   If a release has more entries than the dynamic-rule limit, the domains are packed into
   fewer rules.
4. **Warning page.** It shows the host, the matched indicator, **Warning** or **Blocked by
   policy**, the classification, confidence, risk score, reasons, the release sequence and the
   signing operators. Reasons are untrusted and are rendered with `textContent` only. The `d`
   parameter is used only to look up the entry in the verified release. The page is not
   web-accessible, so web pages can neither open it nor frame it.
   - **Go back.**
   - **Continue anyway**, unless strict mode applies. It adds a session-scoped `allow` rule
     with higher priority for the attempted host, then loads the URL recorded for that tab.
     A newer release that changes the listing revokes the exception.
   - **Report a false positive.** This opens
     `https://github.com/BAder82t/CyberMesh/issues/new?template=false-positive.yml&title=…`
     with the indicator and release sequence filled in. You review it and submit it yourself.
5. **Popup.** It shows the state (protected, offline (cached), cached, degraded, expired, no
   intelligence, or error), the sequence, the block and warn counts, the expiry, the signing
   operators and the last successful update. It also has the strict-mode toggle, **Report a
   false positive for this site** and **Update now**.

## Strict mode

`warn` entries always show a warning you can dismiss. `block` entries show the same page with
**Continue anyway** unless strict mode is on. In strict mode the heading reads "Blocked by
policy" and the service worker refuses to add an allow rule. Turning strict mode on also
revokes exceptions that were granted earlier for `block` hosts. Strict mode is on if either
of these is set:

- the popup toggle, stored in `chrome.storage.local`;
- the enterprise policy `strictBlocking: true`, read through `chrome.storage.managed` (schema
  in `managed_schema.json`). When the policy is set, the toggle is locked on. Example of a
  Chrome policy for Linux, in `/etc/opt/chrome/policies/managed/cybermesh.json`:
  `{"3rdparty":{"extensions":{"<extension-id>":{"strictBlocking":true}}}}`.

## Permissions

| permission | why |
| --- | --- |
| `storage` | Caches the verified release, the anti-rollback state, update status and the strict-mode setting (`local`). Holds attempted URLs of listed hosts for the current session (`session`). Reads the enterprise policy (`managed`). |
| `alarms` | Updates every 30 minutes and stops enforcing exactly when the release expires. |
| `declarativeNetRequest` | Blocks main-frame requests to listed hosts. Adds the per-session "Continue anyway" exceptions. |
| `webNavigation` | Detects top-level navigations to listed hosts so the warning page can be shown in that tab, and records the attempted URL for **Continue anyway**. Only URLs of listed hosts are kept, in memory and session storage. Other navigations leave no trace. |
| `activeTab` | Lets the popup read the current tab's URL, only when the user opens the popup, for **Report a false positive for this site**. |
| `unlimitedStorage` | Lets releases larger than the default 10 MB `storage.local` quota be cached for offline use. No install warning. |
| host permission for the release URL's origin only | Downloads the release. The CSP `connect-src` allows only `'self'` and this origin. |

The CSP for extension pages is `default-src 'self'; script-src 'self'; object-src 'none';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'; connect-src 'self' <release origin>`.
There is no inline script, no remote code and no `eval`. `npm run lint` checks this.

## Privacy

The extension never uploads your browsing history or the URLs you visit. It sends no
telemetry, has no analytics and does not look anything up online. All matching runs locally
against the verified release. The only network request it makes is a cookie-less GET of the
configured release URL. **Report a false positive** sends nothing. It opens a pre-filled
GitHub page containing only the listed indicator and the release sequence, never the URL you
visited, and you decide whether to submit it.

## Tests

```sh
npm test          # unit tests (node --test), including the Rust differential test
npm run lint      # node --check on all .js/.mjs plus policy checks
npm run test:e2e  # Chromium end-to-end (HEADED=1 to watch, KEEP_E2E=1 to keep temp files)
```

- `test/verify.test.mjs` runs the fixtures from `test/fixtures` (made with `cybermesh dev
  test-vectors`). It also runs releases re-signed with the deterministic test keys, to cover
  every rule: canonical form, lifetime, sorting, printable fields, sequence jump, previous
  link, and the 16 MiB and 16-signature limits.
- `test/malformed.test.mjs` runs garbage, wrong types, 100k-signature arrays, deep nesting,
  invalid UTF-8, random bytes and bit flips. All of them must be rejected with a
  `ReleaseError`, never an uncaught exception.
- `test/differential.test.mjs` runs about 450 cases (fixtures, crafted, fuzzed) through both
  this verifier and `cybermesh release verify`. They must agree on accept or reject and on
  the digest. The test is skipped if `target/debug/cybermesh` is not built. Set
  `CYBERMESH_BIN` to use another binary.
- `test/controller.test.mjs` tests the service-worker logic against a fake `chrome`: caching,
  offline restart, expiry, rollback, strict mode, exceptions and degraded rules.
- `test/e2e/extension.e2e.mjs` uses Playwright with its cached Chromium. It generates fresh
  vectors with cargo, starts local servers and builds the extension, then checks the
  warning, strict mode, **Continue anyway**, an unlisted host, offline operation across a
  service-worker restart, and that the extension made no network request other than the
  release URL.

## Limitations

- Only hosts listed in the current release are covered. The extension does not protect
  against every malicious or phishing site, and a host that is not listed is not a statement
  that it is safe.
- Only top-level (`main_frame`) navigations are blocked. Iframes, subresources, downloads, IP
  literals and URL paths are not covered.
- If the block rule acts before the warning page opens, Chromium briefly shows its "blocked
  by an extension" page and keeps it in the history. The warning page's **Go back** skips that
  entry. The browser's own back button goes to it, which re-opens the warning.
- **Continue anyway** exceptions cover the host and its subdomains until the browser
  restarts.
- `chrome.storage.local` holds about 10 MB. A larger release is still used from memory, with
  anti-rollback state kept, but it is not cached for offline use. Requesting
  `unlimitedStorage` would remove this limit.
- u64 values above 2^53 − 1 (sequence, timestamps) cannot be represented exactly in
  JavaScript and are rejected. The Rust verifier accepts them.
- The release URL may be plain `http`. Tampering is still detected, but an observer can see
  that the browser fetches CyberMesh releases. Use `https` in production.
