// Service-worker behaviour against a fake browser: download + verify + cache, offline
// operation, expiry, anti-rollback, interception, "Continue anyway", strict mode.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ALARM_EXPIRY, KEYS, createController } from '../src/lib/controller.js';
import { createFakeChrome, fakeFetch } from './fake-chrome.mjs';
import { expected, fixtureText, signedRelease, validReleaseObject } from './helpers.mjs';

const RELEASE_URL = 'http://127.0.0.1:8088/release.json';
const quietLogger = { error() {}, warn() {} };

function setup({ fake = createFakeChrome(), serve = () => fixtureText('release-valid.json'), nowSecs = expected.now, trustRoot } = {}) {
  const clock = { now: nowSecs * 1000 };
  const fetchImpl = fakeFetch(serve);
  const controller = createController({
    chrome: fake.chrome,
    fetchImpl,
    nowMs: () => clock.now,
    loadConfig: async () => ({ release_url: RELEASE_URL }),
    loadTrustRootText: async () => trustRoot ?? fixtureText('trust-root.json'),
    logger: quietLogger,
  });
  return { fake, controller, clock, fetchImpl };
}

const nav = (url, tabId = 5) => ({ tabId, frameId: 0, url });
const warningUrl = (d) => `chrome-extension://fakeextensionid/warning.html?d=${d}`;
const sender = (tabId) => ({ tab: { id: tabId } });

test('install: downloads, verifies, caches and installs one block rule per entry', async () => {
  const { fake, controller, fetchImpl } = setup();
  const status = await controller.update();
  assert.equal(status.mode, 'active');
  assert.equal(status.release.sequence, 7);
  assert.deepEqual(status.release.counts, { block: 1, warn: 1 });
  assert.deepEqual(status.release.operators, ['org-a', 'org-b']);
  assert.equal(fetchImpl.calls.length, 1);
  assert.equal(fetchImpl.calls[0].url, RELEASE_URL);
  assert.equal(fetchImpl.calls[0].init.cache, 'no-store');
  assert.equal(fetchImpl.calls[0].init.credentials, 'omit');
  assert.deepEqual(
    fake.dynamicRules.map((r) => [r.action.type, r.condition.requestDomains, r.condition.resourceTypes]),
    [
      ['block', [expected.warn], ['main_frame']],
      ['block', [expected.block], ['main_frame']],
    ],
  );
  const local = fake.chrome.storage.local._data();
  assert.equal(local[KEYS.release].digest, expected.valid_digest);
  assert.equal(local[KEYS.release].sequence, 7);
  assert.equal(local[KEYS.release].envelope, fixtureText('release-valid.json'));
  assert.deepEqual(local[KEYS.state], { sequence: 7, digest: expected.valid_digest });
  assert.equal(fake.alarms.get(ALARM_EXPIRY).when, 1_800_086_400_000);
  assert.ok(fake.alarms.get('cybermesh-update').periodInMinutes === 30);
  assert.equal(fake.badge.text, '');
});

test('navigation to a listed host shows the warning page; unlisted hosts are untouched and not recorded', async () => {
  const { fake, controller } = setup();
  await controller.update();
  await controller.onBeforeNavigate(nav(`http://${expected.unlisted}/`));
  await controller.onBeforeNavigate(nav('https://example.org/private?token=1', 9));
  assert.equal(fake.tabUpdates.length, 0);
  assert.deepEqual(fake.chrome.storage.session._data(), {});

  await controller.onBeforeNavigate(nav(`http://${expected.subdomain_of_block}:8080/login`));
  assert.deepEqual(fake.tabUpdates, [{ tabId: 5, url: warningUrl(expected.block) }]);
  assert.equal(fake.chrome.storage.session._data()['nav:5'].url, `http://${expected.subdomain_of_block}:8080/login`);
  // The DNR block of the same navigation does not open the warning page twice.
  await controller.onNavigationError({ ...nav(`http://${expected.subdomain_of_block}:8080/login`), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  assert.equal(fake.tabUpdates.length, 1);
  // Sub-frames and other errors are ignored.
  await controller.onBeforeNavigate({ ...nav(`http://${expected.block}/`), frameId: 3 });
  await controller.onNavigationError({ ...nav(`http://${expected.warn}/`), error: 'net::ERR_NAME_NOT_RESOLVED' });
  assert.equal(fake.tabUpdates.length, 1);
  // A blocked navigation the worker missed earlier (e.g. after a redirect) is still caught.
  await controller.onNavigationError({ ...nav(`http://${expected.warn}/x`, 6), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  assert.deepEqual(fake.tabUpdates[1], { tabId: 6, url: warningUrl(expected.warn) });
});

test('warning context comes from the verified release, not from the page URL', async () => {
  const { controller } = setup();
  await controller.update();
  await controller.onBeforeNavigate(nav(`http://${expected.block}/`));
  const ctx = await controller.handleMessage({ type: 'warningContext', indicator: expected.block }, sender(5));
  assert.equal(ctx.found, true);
  assert.equal(ctx.entry.action, 'block');
  assert.equal(ctx.entry.confidence, 'high');
  assert.deepEqual(ctx.entry.reasons.map((r) => r.code), ['feed-match', 'brand-impersonation']);
  assert.equal(ctx.release.sequence, 7);
  assert.deepEqual(ctx.release.operators, ['org-a', 'org-b']);
  assert.equal(ctx.attemptedHost, expected.block);
  assert.equal(ctx.canContinue, true);
  assert.equal(ctx.blockedByPolicy, false);
  assert.equal(ctx.backSteps, 1);
  // After the block rule committed an error page, "Go back" skips that history entry.
  await controller.onNavigationError({ ...nav(`http://${expected.block}/`), error: 'net::ERR_BLOCKED_BY_CLIENT' });
  assert.equal((await controller.handleMessage({ type: 'warningContext', indicator: expected.block }, sender(5))).backSteps, 2);
  // Another tab (no recorded navigation) cannot continue; unknown indicators are not listed.
  assert.equal((await controller.handleMessage({ type: 'warningContext', indicator: expected.block }, sender(77))).canContinue, false);
  assert.equal((await controller.handleMessage({ type: 'warningContext', indicator: 'evil.example' }, sender(5))).found, false);
});

test('continue anyway adds a session allow rule and resumes the recorded URL', async () => {
  const { fake, controller } = setup();
  await controller.update();
  const url = `http://${expected.warn}:9999/account?x=1`;
  await controller.onBeforeNavigate(nav(url));
  await assert.rejects(controller.handleMessage({ type: 'continue', indicator: expected.block }, sender(5)));
  await assert.rejects(controller.handleMessage({ type: 'continue', indicator: expected.warn }, sender(8)));
  await controller.handleMessage({ type: 'continue', indicator: expected.warn }, sender(5));
  assert.equal(fake.sessionRules.length, 1);
  assert.equal(fake.sessionRules[0].action.type, 'allow');
  assert.deepEqual(fake.sessionRules[0].condition.requestDomains, [expected.warn]);
  assert.ok(fake.sessionRules[0].priority > fake.dynamicRules[0].priority);
  assert.deepEqual(fake.tabUpdates.at(-1), { tabId: 5, url });
  const before = fake.tabUpdates.length;
  await controller.onBeforeNavigate(nav(url));
  assert.equal(fake.tabUpdates.length, before, 'allowed host is not intercepted again');
});

test('strict mode: block entries cannot be bypassed, warn entries still can', async () => {
  const { fake, controller } = setup();
  await controller.update();
  // Allowed before strict mode was switched on ...
  await controller.onBeforeNavigate(nav(`http://${expected.block}/`, 1));
  await controller.handleMessage({ type: 'continue', indicator: expected.block }, sender(1));
  assert.equal(fake.sessionRules.length, 1);
  const status = await controller.handleMessage({ type: 'setStrict', value: true }, {});
  assert.equal(status.strict.effective, true);
  // ... and revoked when it is.
  assert.equal(fake.sessionRules.length, 0);

  await controller.onBeforeNavigate(nav(`http://${expected.block}/`, 2));
  const ctx = await controller.handleMessage({ type: 'warningContext', indicator: expected.block }, sender(2));
  assert.equal(ctx.blockedByPolicy, true);
  assert.equal(ctx.canContinue, false);
  await assert.rejects(controller.handleMessage({ type: 'continue', indicator: expected.block }, sender(2)), /blocked by policy/);
  assert.equal(fake.sessionRules.length, 0);

  await controller.onBeforeNavigate(nav(`http://${expected.warn}/`, 3));
  assert.equal((await controller.handleMessage({ type: 'warningContext', indicator: expected.warn }, sender(3))).canContinue, true);
  await controller.handleMessage({ type: 'continue', indicator: expected.warn }, sender(3));
  assert.equal(fake.sessionRules.length, 1);
});

test('enterprise policy strictBlocking enforces strict mode', async () => {
  const fake = createFakeChrome({ managed: { strictBlocking: true } });
  const { controller } = setup({ fake });
  const status = await controller.update();
  assert.deepEqual(status.strict, { user: false, managed: true, effective: true });
  await controller.onBeforeNavigate(nav(`http://${expected.block}/`, 2));
  await assert.rejects(controller.handleMessage({ type: 'continue', indicator: expected.block }, sender(2)));
  // Without a managed schema the API throws; strict mode then follows the user setting.
  const { controller: c2 } = setup({ fake: createFakeChrome({ noManagedSchema: true }) });
  assert.equal((await c2.update()).strict.effective, false);
});

test('offline: after a restart the cached release is re-verified and enforced', async () => {
  const first = setup();
  await first.controller.update();
  first.fake.restartBrowser();
  // New service worker instance; the release server is down.
  const second = setup({ fake: first.fake, serve: () => new TypeError('Failed to fetch') });
  const status = await second.controller.update();
  assert.equal(status.mode, 'offline');
  assert.equal(status.release.sequence, 7);
  assert.equal(status.lastErrorKind, 'fetch');
  assert.ok(status.lastSuccessAt > 0);
  assert.equal(second.fake.dynamicRules.length, 2);
  await second.controller.onBeforeNavigate(nav(`http://${expected.block}/`));
  assert.deepEqual(second.fake.tabUpdates, [{ tabId: 5, url: warningUrl(expected.block) }]);
});

test('offline: dynamic rules are rebuilt from the cache if they were lost', async () => {
  const first = setup();
  await first.controller.update();
  await first.fake.chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [1, 2] });
  await first.fake.chrome.storage.local.remove(KEYS.rules);
  const second = setup({ fake: first.fake, serve: () => ({ status: 503 }) });
  assert.equal((await second.controller.update()).mode, 'offline');
  assert.equal(second.fake.dynamicRules.length, 2);
});

test('expiry: rules are removed and the badge shows the expired state', async () => {
  const { fake, controller, clock } = setup();
  await controller.update();
  clock.now = expected.expired_now * 1000;
  await controller.onAlarm({ name: ALARM_EXPIRY });
  const status = await controller.getStatus();
  assert.equal(status.mode, 'expired');
  assert.equal(status.expired.sequence, 7);
  assert.equal(status.release, null);
  assert.equal(fake.dynamicRules.length, 0);
  assert.equal(fake.badge.text, 'EXP');
  await controller.onBeforeNavigate(nav(`http://${expected.block}/`));
  assert.equal(fake.tabUpdates.length, 0);
});

test('expiry is enforced even if the alarm never fires', async () => {
  const { fake, controller, clock } = setup();
  await controller.update();
  clock.now = expected.expired_now * 1000;
  await controller.onBeforeNavigate(nav(`http://${expected.block}/`));
  assert.equal(fake.tabUpdates.length, 0);
  assert.equal(fake.dynamicRules.length, 0);
  assert.equal((await controller.getStatus()).mode, 'expired');
});

test('expired cache is not enforced after a restart, even offline', async () => {
  const first = setup();
  await first.controller.update();
  const second = setup({ fake: first.fake, serve: () => new TypeError('offline'), nowSecs: expected.expired_now });
  const status = await second.controller.update();
  assert.equal(status.mode, 'expired');
  assert.equal(second.fake.dynamicRules.length, 0);
  assert.equal(second.fake.badge.text, 'EXP');
});

test('anti-rollback: an older release is rejected and the current one stays active', async () => {
  let body = fixtureText('release-valid.json');
  const { fake, controller } = setup({ serve: () => body });
  await controller.update();
  body = fixtureText('release-older-sequence.json');
  const status = await controller.update();
  assert.equal(status.mode, 'cached');
  assert.equal(status.lastErrorKind, 'verify');
  assert.match(status.lastError, /^rollback:/);
  assert.equal(status.release.sequence, 7);
  assert.equal(fake.dynamicRules.length, 2);
  assert.deepEqual(fake.chrome.storage.local._data()[KEYS.state], { sequence: 7, digest: expected.valid_digest });
});

test('a newer release replaces the old one atomically and advances the state', async () => {
  let body = fixtureText('release-valid.json');
  const { fake, controller } = setup({ serve: () => body });
  await controller.update();
  const next = validReleaseObject();
  next.sequence = 8;
  next.previous = { sequence: 7, digest: expected.valid_digest };
  next.entries = next.entries.slice(1); // drop the warn entry
  body = signedRelease(next);
  const status = await controller.update();
  assert.equal(status.mode, 'active');
  assert.equal(status.release.sequence, 8);
  assert.deepEqual(fake.dynamicRules.map((r) => r.condition.requestDomains[0]), [expected.block]);
  assert.equal(fake.chrome.storage.local._data()[KEYS.state].sequence, 8);
});

test('tampered or unsigned downloads are never enforced', async () => {
  const { fake, controller } = setup({ serve: () => fixtureText('release-tampered.json') });
  const status = await controller.update();
  assert.equal(status.mode, 'none');
  assert.match(status.lastError, /^threshold:/);
  assert.equal(fake.dynamicRules.length, 0);
  assert.equal(fake.badge.text, '!');
  assert.equal(fake.chrome.storage.local._data()[KEYS.release], undefined);
});

test('a corrupted cache is rejected instead of enforced', async () => {
  const first = setup();
  await first.controller.update();
  const local = first.fake.chrome.storage.local;
  const cached = (await local.get(KEYS.release))[KEYS.release];
  await local.set({ [KEYS.release]: { ...cached, envelope: fixtureText('release-tampered.json') } });
  const second = setup({ fake: first.fake, serve: () => new TypeError('offline') });
  const status = await second.controller.update();
  assert.equal(status.mode, 'none');
  assert.ok(status.problems.some((p) => p.startsWith('cached release rejected')));
  assert.equal(second.fake.dynamicRules.length, 0);
});

test('a release too large for the storage quota is used from memory and keeps anti-rollback state', async () => {
  const fake = createFakeChrome();
  fake.chrome.storage.local._failSetsContaining(KEYS.release);
  const { controller } = setup({ fake });
  const status = await controller.update();
  assert.equal(status.mode, 'active');
  assert.ok(status.problems.some((p) => p.includes('not cached')));
  assert.deepEqual(fake.chrome.storage.local._data()[KEYS.state], { sequence: 7, digest: expected.valid_digest });
});

test('oversized and non-200 downloads are rejected', async () => {
  const big = new Uint8Array(16 * 1024 * 1024 + 1);
  const { controller } = setup({ serve: () => big });
  const s1 = await controller.update();
  assert.equal(s1.mode, 'none');
  assert.match(s1.lastError, /16 MiB/);
  const { controller: c2 } = setup({ serve: () => ({ status: 404 }) });
  assert.match((await c2.update()).lastError, /HTTP 404/);
});

test('a broken trust root disables enforcement and reports a configuration error', async () => {
  const { fake, controller } = setup({ trustRoot: '{"network_id":"x"}' });
  const status = await controller.update();
  assert.equal(status.mode, 'error');
  assert.ok(status.problems[0].startsWith('configuration error'));
  assert.equal(fake.dynamicRules.length, 0);
  assert.equal(fake.badge.text, 'ERR');
});

test('siteInfo for the popup', async () => {
  const { controller } = setup();
  await controller.update();
  assert.deepEqual(await controller.handleMessage({ type: 'siteInfo', url: `https://${expected.subdomain_of_block}/` }, {}), {
    host: expected.subdomain_of_block,
    listed: true,
    indicator: expected.block,
    action: 'block',
    sequence: 7,
  });
  assert.deepEqual(await controller.handleMessage({ type: 'siteInfo', url: 'https://example.org/' }, {}), { host: 'example.org', listed: false });
  const w = await controller.handleMessage({ type: 'siteInfo', url: warningUrl(expected.warn) }, {});
  assert.equal(w.indicator, expected.warn);
  await assert.rejects(controller.handleMessage({ type: 'nope' }, {}));
  await assert.rejects(controller.handleMessage(null, {}));
});
