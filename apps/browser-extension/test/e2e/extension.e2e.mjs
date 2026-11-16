// Browser end-to-end test: real Chromium (Playwright's cached build), the built extension,
// fresh release vectors from the Rust CLI, and local HTTP servers.
//
//   npm run test:e2e            (HEADED=1 to watch, KEEP_E2E=1 to keep the temp directory)
//
// Steps (a)-(j) follow apps/browser-extension/README.md#end-to-end-test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(here, '../..');
const repoRoot = path.resolve(pkgRoot, '../..');

const BLOCK = 'examplebank-secure-login.phish.localhost';
const WARN = 'examplebank-account-verify.phish.localhost';
const UNLISTED = 'examplebank.test.localhost';

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Serves /release.json and a test page for any *.localhost host; logs every request. */
function startServer(releaseFile) {
  const log = [];
  const server = http.createServer((req, res) => {
    const host = String(req.headers.host ?? '').toLowerCase().replace(/:\d+$/, '');
    log.push({ host, method: req.method, url: req.url, at: Date.now() });
    if (host.endsWith('.localhost')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(`<!doctype html><title>Test page</title><h1 id="test-page">CyberMesh e2e test page: ${escapeHtml(host)}</h1>`);
      return;
    }
    if (req.method === 'GET' && req.url.split('?')[0] === '/release.json') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(readFileSync(releaseFile));
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        server,
        log,
        port: server.address().port,
        close: () =>
          new Promise((r) => {
            server.closeAllConnections();
            server.close(() => r());
          }),
      });
    });
  });
}

async function waitFor(fn, { timeout = 20_000, interval = 200, what = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  let last;
  for (;;) {
    try {
      last = await fn();
      if (last) return last;
    } catch (e) {
      last = e;
    }
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what} (last: ${last instanceof Error ? last.message : JSON.stringify(last)})`);
    await new Promise((r) => setTimeout(r, interval));
  }
}

/** Navigates to a URL that the extension is expected to intercept (the original navigation fails). */
async function gotoIntercepted(page, url) {
  await page.goto(url, { waitUntil: 'commit', timeout: 15_000 }).catch(() => {});
  await page.waitForURL(/^chrome-extension:\/\/[a-p]{32}\/warning\.html\?d=/, { timeout: 15_000 });
  await page.waitForSelector('#main[data-state="listed"]', { timeout: 15_000 });
}

test('CyberMesh extension end to end', { timeout: 600_000 }, async (t) => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'cybermesh-e2e-'));
  const vectors = path.join(tmp, 'vectors');
  const extDir = path.join(tmp, 'extension');
  const profile = path.join(tmp, 'profile');
  let releaseSrv;
  let pageSrv;
  let context;
  let sw;
  let extId;
  const extRequests = [];
  const ctx = {};

  const extensionOrigin = () => `chrome-extension://${extId}/`;
  const releaseUrl = () => `http://127.0.0.1:${releaseSrv.port}/release.json`;
  const pageUrl = (host, p = '/') => `http://${host}:${pageSrv.port}${p}`;
  const storage = (keys) => sw.evaluate((k) => chrome.storage.local.get(k), keys);
  const currentWorker = () => context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));

  try {
    await t.test('(a) generate release vectors valid now with the Rust CLI', () => {
      const now = Math.floor(Date.now() / 1000);
      const r = spawnSync(
        'cargo',
        ['run', '-q', '-p', 'cybermesh-cli', '--features', 'dev-tools', '--', 'dev', 'test-vectors', '--out', vectors, '--now', String(now)],
        { cwd: repoRoot, encoding: 'utf8', timeout: 600_000 },
      );
      assert.equal(r.status, 0, `cargo failed: ${r.stderr}`);
      const exp = JSON.parse(readFileSync(path.join(vectors, 'expected.json'), 'utf8'));
      assert.equal(exp.block, BLOCK);
      assert.equal(exp.warn, WARN);
      ctx.expected = exp;
    });

    await t.test('(b) start local release and test-page servers', async () => {
      releaseSrv = await startServer(path.join(vectors, 'release-valid.json'));
      pageSrv = await startServer(path.join(vectors, 'release-valid.json'));
      const r = await fetch(releaseUrl());
      assert.equal(r.status, 200);
      releaseSrv.log.length = 0;
    });

    await t.test('(c) build the extension with the fresh trust root and release URL', () => {
      const r = spawnSync(
        process.execPath,
        ['scripts/build.mjs', '--trust-root', path.join(vectors, 'trust-root.json'), '--release-url', releaseUrl(), '--out', extDir, '--no-zip'],
        { cwd: pkgRoot, encoding: 'utf8' },
      );
      assert.equal(r.status, 0, r.stderr);
      const manifest = JSON.parse(readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
      assert.deepEqual(manifest.host_permissions, [`http://127.0.0.1:${releaseSrv.port}/*`]);
      assert.match(manifest.content_security_policy.extension_pages, new RegExp(`connect-src 'self' http://127\\.0\\.0\\.1:${releaseSrv.port}$`));
    });

    await t.test('(d) launch Chromium with the unpacked extension', async () => {
      context = await chromium.launchPersistentContext(profile, {
        channel: 'chromium',
        headless: process.env.HEADED !== '1',
        executablePath: process.env.CHROMIUM_PATH || undefined,
        args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
      });
      context.on('request', (req) => {
        let origin = null;
        const worker = req.serviceWorker();
        if (worker) origin = worker.url();
        else if (!req.isNavigationRequest()) {
          try {
            origin = req.frame().url();
          } catch {
            origin = null;
          }
        }
        if (origin && extId && origin.startsWith(extensionOrigin())) extRequests.push({ url: req.url(), from: worker ? 'service-worker' : origin });
      });
      sw = currentWorker() ?? (await context.waitForEvent('serviceworker', { timeout: 15_000 }));
      extId = new URL(sw.url()).host;
      assert.match(extId, /^[a-p]{32}$/);
      t.diagnostic(`browser ${context.browser()?.version() ?? 'chromium (persistent context)'}, extension ${extId}`);
    });

    await t.test('(e) the release is downloaded and verified', async () => {
      const stored = await waitFor(async () => {
        const s = await storage(['release', 'updateStatus']);
        return s.release?.sequence === 7 ? s : null;
      }, { what: 'verified release in storage' });
      assert.equal(stored.release.digest, ctx.expected.valid_digest);
      assert.deepEqual(stored.release.operators, ['org-a', 'org-b']);
      assert.equal(stored.updateStatus.lastAttemptOk, true);
      const rules = await sw.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
      assert.deepEqual(rules.map((r) => r.condition.requestDomains).flat().sort(), [WARN, BLOCK].sort());

      // Defence in depth, checked here while Playwright has a live worker handle: the CSP
      // stops the service worker from contacting any origin other than the release origin.
      ctx.swCspProbe = await sw.evaluate(async (u) => {
        try {
          await fetch(u);
          return 'fetched';
        } catch (e) {
          return `blocked: ${e.message}`;
        }
      }, pageUrl('csp-probe.localhost'));

      const popup = await context.newPage();
      await popup.goto(`${extensionOrigin()}popup.html`);
      await popup.waitForSelector('#main[data-mode="active"]');
      assert.equal(await popup.textContent('#mode'), 'Protected');
      assert.equal(await popup.textContent('#sequence'), '7');
      assert.equal(await popup.textContent('#block-count'), '1');
      assert.equal(await popup.textContent('#warn-count'), '1');
      assert.equal(await popup.textContent('#operators'), 'org-a, org-b');
      await popup.close();
    });

    await t.test('(f) a "block" host shows the warning page with classification and reasons', async () => {
      const page = await context.newPage();
      const before = pageSrv.log.length;
      await gotoIntercepted(page, pageUrl(BLOCK, '/login?session=abc'));
      assert.equal(new URL(page.url()).searchParams.get('d'), BLOCK);
      assert.equal(await page.textContent('#heading'), 'Warning');
      assert.equal(await page.getAttribute('#classification', 'data-action'), 'block');
      assert.equal(await page.textContent('#host'), BLOCK);
      assert.equal(await page.textContent('#indicator'), BLOCK);
      assert.equal(await page.textContent('#confidence'), 'high');
      const reasons = await page.$$eval('#reasons li', (lis) => lis.map((li) => li.textContent));
      assert.deepEqual(reasons, [
        'feed-match listed in reference feed: reference-feed',
        'brand-impersonation brand name outside its legitimate domains: examplebank',
      ]);
      assert.match(await page.textContent('#release'), /^sequence 7, network cybermesh-test/);
      assert.equal(await page.textContent('#signers'), 'org-a, org-b');
      assert.ok(await page.isVisible('#continue'), 'continue is offered when strict mode is off');
      assert.ok(await page.isVisible('#report'));
      assert.ok(!pageSrv.log.slice(before).some((r) => r.host === BLOCK), 'the blocked host never received a request');

      // Report a false positive opens a pre-filled GitHub issue form (stubbed here so the
      // test stays offline); nothing is submitted.
      await context.route('https://github.com/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<title>stub</title>' }));
      const [issue] = await Promise.all([context.waitForEvent('page'), page.click('#report')]);
      await issue.waitForURL(/^https:\/\/github\.com\//, { timeout: 15_000 });
      const issueUrl = new URL(issue.url());
      await issue.close();
      ctx.issueUrl = issueUrl.href;
      assert.equal(issueUrl.origin + issueUrl.pathname, 'https://github.com/BAder82t/CyberMesh/issues/new');
      assert.equal(issueUrl.searchParams.get('title'), `False positive: ${BLOCK} (release 7)`);
      await page.close();
    });

    await t.test('(f1) "Go back" returns to the previous page', async () => {
      const page = await context.newPage();
      const start = pageUrl(UNLISTED, '/start');
      await page.goto(start);
      await gotoIntercepted(page, pageUrl(BLOCK, '/from-link'));
      await page.click('#back');
      await page.waitForURL(start, { timeout: 15_000 });
      assert.match(await page.textContent('#test-page'), /examplebank\.test\.localhost/);
      await page.close();
    });

    await t.test('(f2) strict mode turns the "block" warning into "Blocked by policy"', async () => {
      const popup = await context.newPage();
      await popup.goto(`${extensionOrigin()}popup.html`);
      await popup.waitForSelector('#main[data-mode="active"]');
      await popup.check('#strict');
      await waitFor(async () => (await storage('strictMode')).strictMode === true, { what: 'strict mode stored' });
      const page = await context.newPage();
      await gotoIntercepted(page, pageUrl(BLOCK));
      assert.equal(await page.textContent('#heading'), 'Blocked by policy');
      assert.ok(!(await page.isVisible('#continue')), 'no continue in strict mode');
      assert.ok(await page.isVisible('#policy-note'));
      await page.close();
      await popup.uncheck('#strict');
      await waitFor(async () => (await storage('strictMode')).strictMode === false, { what: 'strict mode off' });
      await popup.close();
    });

    await t.test('(g) a "warn" host is dismissible: Continue anyway loads the original page', async () => {
      const page = await context.newPage();
      const target = pageUrl(WARN, '/account?step=2');
      await gotoIntercepted(page, target);
      assert.equal(await page.textContent('#heading'), 'Warning');
      assert.equal(await page.getAttribute('#classification', 'data-action'), 'warn');
      assert.equal(await page.textContent('#confidence'), 'medium');
      assert.ok(await page.isVisible('#continue'));
      await page.click('#continue');
      await page.waitForURL(target, { timeout: 15_000 });
      assert.match(await page.textContent('#test-page'), new RegExp(WARN.replace(/\./g, '\\.')));
      assert.ok(pageSrv.log.some((r) => r.host === WARN && r.url === '/account?step=2'));
      const allow = await sw.evaluate(() => chrome.declarativeNetRequest.getSessionRules());
      assert.deepEqual(allow.map((r) => [r.action.type, r.condition.requestDomains[0]]), [['allow', WARN]]);
      await page.close();
    });

    await t.test('(h) an unlisted host loads without a warning', async () => {
      const page = await context.newPage();
      const target = pageUrl(UNLISTED, '/');
      await page.goto(target, { timeout: 15_000 });
      await page.waitForTimeout(1_000);
      assert.equal(page.url(), target);
      assert.match(await page.textContent('#test-page'), /examplebank\.test\.localhost/);
      await page.close();
    });

    await t.test('(i) offline: with the release server stopped, warnings still work from the cache', async () => {
      await releaseSrv.close();
      // 1. "Update now" fails to download and keeps the cached release.
      const popup = await context.newPage();
      await popup.goto(`${extensionOrigin()}popup.html`);
      await popup.click('#update-now');
      await popup.waitForSelector('#main[data-mode="offline"]', { timeout: 30_000 });
      assert.equal(await popup.textContent('#mode'), 'Offline (cached)');
      assert.equal(await popup.textContent('#sequence'), '7');
      await popup.close();

      // 2. Restart the service worker after deleting its blocking rules: the new worker
      //    must re-verify the cached release and rebuild the rules without network.
      //    (chrome.runtime.reload() disables a command-line-loaded extension in this
      //    setup, so the worker is stopped through the DevTools protocol instead.)
      await sw.evaluate(async () => {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: rules.map((r) => r.id) });
      });
      assert.equal((await sw.evaluate(() => chrome.declarativeNetRequest.getDynamicRules())).length, 0);
      const cdpPage = await context.newPage();
      const cdp = await context.newCDPSession(cdpPage);
      await cdp.send('ServiceWorker.enable');
      await cdp.send('ServiceWorker.stopAllWorkers');
      await cdp.detach();
      await cdpPage.close();
      // Playwright keeps a stale handle for a restarted worker, so the checks below run
      // the extension APIs from an extension page instead. Only a newly started worker
      // re-installs the deleted rules (from the re-verified cache).
      sw = null;
      const api = await context.newPage();
      await api.goto(`${extensionOrigin()}popup.html`);
      const stored = await waitFor(async () => {
        const rules = await api.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
        return rules.length === 2 ? api.evaluate(() => chrome.storage.local.get(['updateStatus', 'release'])) : null;
      }, { timeout: 30_000, what: 'rules rebuilt from the cache by the restarted worker' });
      assert.equal(stored.updateStatus.lastAttemptOk, false);
      assert.equal(stored.updateStatus.lastErrorKind, 'fetch');
      assert.equal(stored.release.sequence, 7);
      await api.waitForSelector('#main[data-mode="offline"]');
      await api.close();

      const page = await context.newPage();
      await gotoIntercepted(page, pageUrl(BLOCK, '/again'));
      assert.equal(await page.getAttribute('#classification', 'data-action'), 'block');
      await page.close();
      const p2 = await context.newPage();
      await p2.goto(`${extensionOrigin()}popup.html`);
      await p2.waitForSelector('#main[data-mode="offline"]');
      await p2.close();
    });

    await t.test('(j) the extension made no network request other than the release URL', async () => {
      const web = extRequests.filter((r) => /^https?:/.test(r.url));
      const releaseFetches = web.filter((r) => r.url === releaseUrl());
      const others = web.filter((r) => r.url !== releaseUrl());
      t.diagnostic(`extension http(s) requests observed: ${web.length} (release URL: ${releaseFetches.length})`);
      assert.ok(releaseFetches.length >= 2, 'request recording works (initial download and "Update now")');
      assert.deepEqual(others, []);
      assert.ok(releaseSrv.log.every((r) => r.method === 'GET' && r.url === '/release.json'), 'release server saw only GET /release.json');
      const unexpected = pageSrv.log.filter((r) => ![BLOCK, WARN, UNLISTED].includes(r.host) || r.host === BLOCK);
      assert.deepEqual(unexpected, [], 'test-page server saw only the navigations made by the test (never the blocked host)');
      // Defence in depth: the CSP stops the extension (worker and pages) from contacting
      // any other origin.
      assert.match(ctx.swCspProbe, /^blocked/);
      const api = await context.newPage();
      await api.goto(`${extensionOrigin()}popup.html`);
      const probe = await api.evaluate(async (u) => {
        try {
          await fetch(u);
          return 'fetched';
        } catch (e) {
          return `blocked: ${e.message}`;
        }
      }, pageUrl('csp-probe.localhost'));
      await api.close();
      assert.match(probe, /^blocked/);
      assert.ok(!pageSrv.log.some((r) => r.host === 'csp-probe.localhost'));
    });
  } finally {
    await context?.close().catch(() => {});
    await releaseSrv?.close().catch(() => {});
    await pageSrv?.close().catch(() => {});
    if (process.env.KEEP_E2E === '1') t.diagnostic(`kept ${tmp}`);
    else rmSync(tmp, { recursive: true, force: true });
  }
});
