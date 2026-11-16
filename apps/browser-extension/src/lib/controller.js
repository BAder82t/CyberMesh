// Service-worker logic, written against an injected `chrome` object so that it can be unit
// tested with a fake browser (test/controller.test.mjs). background.js wires it to the real
// extension events.
//
// Data flow: release URL --fetch--> verifyRelease (offline, bundled trust root)
//   --> chrome.storage.local (envelope text, digest, sequence, timestamps, anti-rollback
//   state) --> declarativeNetRequest block rules + in-memory host index.
// Nothing about the user's browsing leaves the browser: the only network request this code
// makes is the GET of the configured release URL.

import { MAX_RELEASE_BYTES, ReleaseError, parseTrustRoot, verifyRelease } from './verify.js';
import { buildIndex, countActions, hostFromUrl, lookupHost } from './lookup.js';
import { ALLOW_RULE_ID_BASE, allowRule, domainMatches, planBlockRules, warningPath, moreSpecificIndicators } from './rules.js';
import { concatBytes, utf8DecodeStrict } from './encoding.js';

export const ALARM_UPDATE = 'cybermesh-update';
export const ALARM_EXPIRY = 'cybermesh-expiry';
export const UPDATE_PERIOD_MINUTES = 30;
/** chrome.storage.local keys. */
export const KEYS = Object.freeze({
  release: 'release',
  state: 'rollbackState',
  status: 'updateStatus',
  strict: 'strictMode',
  rules: 'rulesInstalledFor',
});
const NAV_PREFIX = 'nav:';
/** chrome.storage.session key: allow-rule id -> the entry the user accepted. */
const ALLOW_META = 'allowMeta';
const FETCH_TIMEOUT_MS = 30_000;
const BLOCKED_DEDUPE_MS = 3_000;
const DEFAULT_MAX_DYNAMIC_RULES = 5_000;

function message(e) {
  if (e instanceof ReleaseError) return `${e.code}: ${e.message}`;
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * @param {unknown} obj
 * @returns {{ release_url: string }}
 */
export function validateConfig(obj) {
  if (obj === null || typeof obj !== 'object' || typeof obj.release_url !== 'string') {
    throw new Error('config.json must contain release_url');
  }
  const u = new URL(obj.release_url);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('release_url must be http(s)');
  if (u.username || u.password) throw new Error('release_url must not contain credentials');
  return { release_url: u.href };
}

/**
 * @param {object} deps
 * @param {typeof chrome} deps.chrome
 * @param {typeof fetch} deps.fetchImpl
 * @param {() => Promise<unknown>} deps.loadConfig
 * @param {() => Promise<string>} deps.loadTrustRootText
 * @param {() => number} [deps.nowMs]
 * @param {{ error: Function, warn: Function }} [deps.logger]
 */
export function createController({ chrome, fetchImpl, loadConfig, loadTrustRootText, nowMs = () => Date.now(), logger = console }) {
  let readyPromise = null;
  let config = null;
  let trustRoot = null;
  let fatal = null;
  /** @type {null | { verified: import('./verify.js').VerifiedRelease, index: Map<string, object>, meta: object, counts: { block: number, warn: number } }} */
  let current = null;
  let expired = null;
  let cacheProblem = null;
  let rulesProblem = null;
  let status = { lastAttemptAt: null, lastAttemptOk: null, lastErrorKind: null, lastError: null, lastSuccessAt: null };
  const navs = new Map();
  const pendingWarnings = new Map();
  let queue = Promise.resolve();

  const nowSecs = () => Math.floor(nowMs() / 1000);
  const dnr = () => chrome.declarativeNetRequest;

  /** Runs `fn` after every previously queued task (no nesting: callers must not re-enter). */
  function exclusive(fn) {
    const run = queue.then(fn, fn);
    queue = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  function ready() {
    if (!readyPromise) readyPromise = exclusive(initialize);
    return readyPromise;
  }

  async function initialize() {
    try {
      const stored = await chrome.storage.local.get(KEYS.status);
      if (stored[KEYS.status]) status = { ...status, ...stored[KEYS.status] };
      config = validateConfig(await loadConfig());
      trustRoot = await parseTrustRoot(await loadTrustRootText());
    } catch (e) {
      fatal = `configuration error: ${message(e)}`;
      logger.error('CyberMesh:', fatal);
      current = null;
      await applyRules();
      await updateBadge();
      return;
    }
    await restoreFromCache();
    await ensureUpdateAlarm();
  }

  /** Re-verifies the cached envelope (signatures, expiry, anti-rollback) before using it. */
  async function restoreFromCache() {
    const stored = await chrome.storage.local.get([KEYS.release, KEYS.state]);
    const cached = stored[KEYS.release];
    if (!cached || typeof cached.envelope !== 'string') {
      current = null;
      await applyRules();
      await updateBadge();
      return;
    }
    try {
      const verified = await verifyRelease(cached.envelope, trustRoot, nowSecs(), stored[KEYS.state] ?? null);
      await activate(verified, cached);
    } catch (e) {
      current = null;
      if (e instanceof ReleaseError && e.code === 'expired') {
        expired = { sequence: cached.sequence ?? null, expiresAt: cached.expiresAt ?? null };
      } else {
        cacheProblem = `cached release rejected: ${message(e)}`;
        logger.warn('CyberMesh:', cacheProblem);
      }
      await applyRules();
      await reconcileAllowRules();
      await updateBadge();
    }
  }

  async function activate(verified, meta) {
    current = {
      verified,
      index: buildIndex(verified.release.entries),
      meta,
      counts: countActions(verified.release.entries),
    };
    expired = null;
    await applyRules();
    await chrome.alarms.create(ALARM_EXPIRY, { when: verified.release.expires_at * 1000 });
    await reconcileAllowRules();
    await updateBadge();
  }

  function maxDynamicRules() {
    const n = dnr().MAX_NUMBER_OF_DYNAMIC_RULES;
    return Number.isInteger(n) && n > 0 ? n : DEFAULT_MAX_DYNAMIC_RULES;
  }

  /** Atomically replaces all dynamic rules with the rules for the current release (or none). */
  async function applyRules() {
    const desired = current ? planBlockRules(current.verified.release.entries, maxDynamicRules()) : [];
    const marker = current ? current.verified.digest : null;
    try {
      const existing = await dnr().getDynamicRules();
      const installed = (await chrome.storage.local.get(KEYS.rules))[KEYS.rules] ?? null;
      if (installed === marker && existing.length === desired.length) {
        rulesProblem = null;
        return;
      }
      await dnr().updateDynamicRules({ removeRuleIds: existing.map((r) => r.id), addRules: desired });
      await chrome.storage.local.set({ [KEYS.rules]: marker });
      rulesProblem = null;
    } catch (e) {
      rulesProblem = `could not install blocking rules: ${message(e)}`;
      logger.error('CyberMesh:', rulesProblem);
    }
  }

  async function ensureUpdateAlarm() {
    const existing = await chrome.alarms.get(ALARM_UPDATE);
    if (!existing) {
      await chrome.alarms.create(ALARM_UPDATE, { periodInMinutes: UPDATE_PERIOD_MINUTES, delayInMinutes: UPDATE_PERIOD_MINUTES });
    }
  }

  /** Stops enforcing a release whose lifetime is over. Must run inside `exclusive`. */
  async function expireIfNeeded() {
    if (!current || nowSecs() < current.verified.release.expires_at) return;
    expired = { sequence: current.verified.release.sequence, expiresAt: current.verified.release.expires_at };
    current = null;
    await applyRules();
    await reconcileAllowRules();
    await updateBadge();
  }

  async function fetchRelease(url) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const resp = await fetchImpl(url, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: ctrl.signal,
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const declared = Number(resp.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > MAX_RELEASE_BYTES) throw new Error('release exceeds 16 MiB');
      if (!resp.body || typeof resp.body.getReader !== 'function') {
        const buf = new Uint8Array(await resp.arrayBuffer());
        if (buf.length > MAX_RELEASE_BYTES) throw new Error('release exceeds 16 MiB');
        return buf;
      }
      const reader = resp.body.getReader();
      const chunks = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > MAX_RELEASE_BYTES) {
          await reader.cancel().catch(() => {});
          throw new Error('release exceeds 16 MiB');
        }
        chunks.push(value);
      }
      return concatBytes(...chunks);
    } finally {
      clearTimeout(timer);
    }
  }

  async function recordAttempt(patch) {
    status = { ...status, ...patch };
    await chrome.storage.local.set({ [KEYS.status]: status });
    await updateBadge();
  }

  /** Downloads, verifies and activates the latest release; keeps the cache on failure. */
  async function update() {
    await ready();
    if (fatal) return getStatus();
    await exclusive(async () => {
      await expireIfNeeded();
      if (rulesProblem) await applyRules(); // retry a failed rule installation
      const at = nowMs();
      let bytes;
      try {
        bytes = await fetchRelease(config.release_url);
      } catch (e) {
        await recordAttempt({ lastAttemptAt: at, lastAttemptOk: false, lastErrorKind: 'fetch', lastError: message(e) });
        return;
      }
      const state = (await chrome.storage.local.get(KEYS.state))[KEYS.state] ?? null;
      let verified;
      try {
        verified = await verifyRelease(bytes, trustRoot, nowSecs(), state);
      } catch (e) {
        await recordAttempt({ lastAttemptAt: at, lastAttemptOk: false, lastErrorKind: 'verify', lastError: message(e) });
        return;
      }
      if (!current || current.verified.digest !== verified.digest) {
        const r = verified.release;
        const meta = {
          envelope: utf8DecodeStrict(bytes),
          digest: verified.digest,
          sequence: r.sequence,
          networkId: r.network_id,
          issuedAt: r.issued_at,
          expiresAt: r.expires_at,
          operators: verified.operators,
          signers: verified.signers,
          fetchedAt: at,
          verifiedAt: nowMs(),
        };
        const nextState = { sequence: r.sequence, digest: verified.digest };
        try {
          await chrome.storage.local.set({ [KEYS.release]: meta, [KEYS.state]: nextState });
          cacheProblem = null;
        } catch (e) {
          // Typically the 10 MB chrome.storage.local quota. Keep the anti-rollback state and
          // use the release from memory; it is downloaded again after a restart.
          cacheProblem = `release verified but not cached for offline use: ${message(e)}`;
          logger.warn('CyberMesh:', cacheProblem);
          await chrome.storage.local.remove(KEYS.release);
          await chrome.storage.local.set({ [KEYS.state]: nextState });
        }
        await activate(verified, meta);
      }
      await recordAttempt({ lastAttemptAt: at, lastAttemptOk: true, lastErrorKind: null, lastError: null, lastSuccessAt: at });
    });
    return getStatus();
  }

  // ------------------------------------------------------------------------------------
  // Strict mode and allow rules

  async function strictSettings() {
    let managed = false;
    try {
      const m = await chrome.storage.managed.get('strictBlocking');
      managed = m?.strictBlocking === true;
    } catch {
      managed = false;
    }
    const user = (await chrome.storage.local.get(KEYS.strict))[KEYS.strict] === true;
    return { user, managed, effective: user || managed };
  }

  async function allowRules() {
    const rules = await dnr().getSessionRules();
    return rules.filter((r) => r.action?.type === 'allow');
  }

  /**
   * An exception applies only if it was granted for the very entry that matches `host`
   * (same indicator and listing), never for a different, more specific entry.
   */
  async function isAllowed(host, entry) {
    if (entry.action === 'block' && (await strictSettings()).effective) return false;
    const rules = await allowRules();
    const meta = await allowMeta();
    return rules.some((r) => {
      const granted = meta[r.id];
      return (
        (r.condition?.requestDomains ?? []).some((d) => domainMatches(host, d)) &&
        !(r.condition?.excludedRequestDomains ?? []).some((d) => domainMatches(host, d)) &&
        granted?.indicator === entry.indicator &&
        granted?.action === entry.action
      );
    });
  }

  async function allowMeta() {
    try {
      return (await chrome.storage.session.get(ALLOW_META))[ALLOW_META] ?? {};
    } catch {
      return {};
    }
  }

  /**
   * Drops "Continue anyway" allow rules that are no longer justified: no current release,
   * host no longer listed, strict mode now covers it, or the listing changed (e.g. a newer
   * release upgraded the entry from warn to block) since the user accepted the warning.
   */
  async function reconcileAllowRules() {
    const rules = await allowRules();
    if (rules.length === 0) return;
    const strict = (await strictSettings()).effective;
    const meta = await allowMeta();
    const remove = rules
      .filter((r) => {
        const host = r.condition?.requestDomains?.[0];
        if (!host || !current) return true;
        const e = lookupHost(current.index, host);
        const accepted = meta[r.id];
        // A newer release that lists a more specific host below this one invalidates the
        // exception (its exclusions would be out of date).
        const excluded = [...(r.condition?.excludedRequestDomains ?? [])].sort();
        const needed = moreSpecificIndicators(current.index, host);
        return (
          excluded.join(',') !== needed.join(',') ||
          !e ||
          (strict && e.action === 'block') ||
          !accepted ||
          accepted.indicator !== e.indicator ||
          accepted.action !== e.action ||
          accepted.confidence !== e.confidence
        );
      })
      .map((r) => r.id);
    if (remove.length === 0) return;
    await dnr().updateSessionRules({ removeRuleIds: remove });
    const kept = Object.fromEntries(Object.entries(meta).filter(([id]) => !remove.includes(Number(id))));
    await chrome.storage.session.set({ [ALLOW_META]: kept }).catch(() => {});
  }

  async function setStrict(value) {
    await chrome.storage.local.set({ [KEYS.strict]: value === true });
    await reconcileAllowRules();
  }

  // ------------------------------------------------------------------------------------
  // Navigation handling

  async function rememberNavigation(tabId, rec) {
    navs.set(tabId, rec);
    try {
      await chrome.storage.session.set({ [`${NAV_PREFIX}${tabId}`]: rec });
    } catch (e) {
      logger.warn('CyberMesh: session storage unavailable', message(e));
    }
  }

  async function getNavigation(tabId) {
    if (!Number.isInteger(tabId)) return null;
    if (navs.has(tabId)) return navs.get(tabId);
    try {
      const key = `${NAV_PREFIX}${tabId}`;
      const rec = (await chrome.storage.session.get(key))[key] ?? null;
      if (rec) navs.set(tabId, rec);
      return rec;
    } catch {
      return null;
    }
  }

  async function onTabRemoved(tabId) {
    navs.delete(tabId);
    pendingWarnings.delete(tabId);
    try {
      await chrome.storage.session.remove(`${NAV_PREFIX}${tabId}`);
    } catch {
      // Session storage is best effort.
    }
  }

  /**
   * Shows the warning page when a top-level navigation targets a listed host. Only URLs of
   * listed hosts are remembered (per tab, in memory and session storage) so that
   * "Continue anyway" can resume them; other navigations leave no trace.
   *
   * @param {number} tabId
   * @param {string} url
   * @param {'before' | 'blocked'} phase
   */
  async function interceptNavigation(tabId, url, phase) {
    await ready();
    if (!current) return;
    if (nowSecs() >= current.verified.release.expires_at) {
      await exclusive(expireIfNeeded);
      return;
    }
    const host = hostFromUrl(url);
    if (!host) return;
    const entry = lookupHost(current.index, host);
    if (!entry) return;
    if (await isAllowed(host, entry)) return;
    // When the block rule wins the race against the warning navigation, Chromium commits an
    // error page for the blocked URL first; "Go back" on the warning page must skip it.
    await rememberNavigation(tabId, { url, host, indicator: entry.indicator, at: nowMs(), errorEntry: phase === 'blocked' });
    const pending = pendingWarnings.get(tabId);
    if (phase === 'blocked' && pending && pending.url === url && nowMs() - pending.at < BLOCKED_DEDUPE_MS) return;
    pendingWarnings.set(tabId, { url, at: nowMs() });
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(warningPath(entry.indicator)) });
  }

  async function onBeforeNavigate(details) {
    if (details.frameId !== 0 || details.tabId < 0) return;
    await interceptNavigation(details.tabId, details.url, 'before');
  }

  async function onNavigationError(details) {
    if (details.frameId !== 0 || details.tabId < 0) return;
    if (!String(details.error ?? '').includes('ERR_BLOCKED_BY_CLIENT')) return;
    await interceptNavigation(details.tabId, details.url, 'blocked');
  }

  async function continueToSite(tabId, indicator) {
    await ready();
    if (!current) throw new Error('no verified release is active');
    const nav = await getNavigation(tabId);
    if (!nav || nav.indicator !== indicator) throw new Error('no blocked navigation is recorded for this tab');
    const entry = lookupHost(current.index, nav.host);
    if (entry) {
      if (entry.action === 'block' && (await strictSettings()).effective) {
        throw new Error('blocked by policy: strict mode does not allow continuing to this site');
      }
      const rules = await dnr().getSessionRules();
      const exists = rules.some((r) => r.action?.type === 'allow' && r.condition?.requestDomains?.includes(nav.host));
      if (!exists) {
        const id = Math.max(ALLOW_RULE_ID_BASE, ...rules.map((r) => r.id)) + 1;
        const meta = await allowMeta();
        meta[id] = { host: nav.host, indicator: entry.indicator, action: entry.action, confidence: entry.confidence };
        await chrome.storage.session.set({ [ALLOW_META]: meta });
        await dnr().updateSessionRules({
          addRules: [allowRule(id, nav.host, moreSpecificIndicators(current.index, nav.host))],
        });
      }
    }
    pendingWarnings.delete(tabId);
    await chrome.tabs.update(tabId, { url: nav.url });
  }

  // ------------------------------------------------------------------------------------
  // Status for the popup and warning page

  function mode() {
    if (fatal) return 'error';
    if (current) {
      // Verified data whose block rules could not be installed: only the (racy) navigation
      // listener protects, so say so instead of claiming full protection.
      if (rulesProblem) return 'degraded';
      if (status.lastAttemptOk === false) return status.lastErrorKind === 'fetch' ? 'offline' : 'cached';
      return 'active';
    }
    if (expired) return 'expired';
    return 'none';
  }

  function releaseSummary() {
    if (!current) return null;
    const r = current.verified.release;
    return {
      sequence: r.sequence,
      digest: current.verified.digest,
      networkId: r.network_id,
      issuedAt: r.issued_at,
      expiresAt: r.expires_at,
      counts: current.counts,
      operators: current.verified.operators,
      signerCount: current.verified.signers.length,
      fetchedAt: current.meta?.fetchedAt ?? null,
    };
  }

  async function getStatus() {
    await ready();
    return {
      mode: mode(),
      networkId: trustRoot?.networkId ?? null,
      threshold: trustRoot?.threshold ?? null,
      releaseUrl: config?.release_url ?? null,
      release: releaseSummary(),
      expired,
      ...status,
      problems: [fatal, cacheProblem, rulesProblem].filter(Boolean),
      strict: await strictSettings(),
    };
  }

  async function updateBadge() {
    const m = mode();
    const seq = current?.verified.release.sequence;
    const badge = {
      active: ['', null, `protection active (release ${seq})`],
      offline: ['', null, `offline: using cached release ${seq}`],
      cached: ['', null, `using cached release ${seq}; the latest download was rejected`],
      degraded: ['!', '#b3261e', `release ${seq} verified, but its blocking rules could not be installed`],
      expired: ['EXP', '#b3261e', 'intelligence expired: no sites are being blocked'],
      none: ['!', '#9a5b00', 'no verified intelligence yet'],
      error: ['ERR', '#b3261e', fatal ?? 'configuration error'],
    }[m];
    try {
      await chrome.action.setBadgeText({ text: badge[0] });
      if (badge[1]) await chrome.action.setBadgeBackgroundColor({ color: badge[1] });
      await chrome.action.setTitle({ title: `CyberMesh: ${badge[2]}` });
    } catch {
      // The badge is cosmetic.
    }
  }

  /**
   * Lookup for the popup's "this site" section.
   * @param {string} url
   */
  async function siteInfo(url) {
    await ready();
    let host = hostFromUrl(url);
    let indicator = null;
    const warningBase = chrome.runtime.getURL('warning.html');
    if (!host && url.startsWith(warningBase)) {
      indicator = new URL(url).searchParams.get('d');
      host = indicator;
    }
    if (!host || !current) return { host, listed: false };
    const entry = indicator ? current.index.get(indicator) : lookupHost(current.index, host);
    if (!entry) return { host, listed: false };
    return { host, listed: true, indicator: entry.indicator, action: entry.action, sequence: current.verified.release.sequence };
  }

  /**
   * Everything the warning page shows. The indicator comes from the page URL, which
   * anyone can construct, so the data shown is looked up in the verified release.
   * @param {number | undefined} tabId
   * @param {string} indicator
   */
  async function warningContext(tabId, indicator) {
    await ready();
    const strict = await strictSettings();
    const base = { indicator, strict, release: releaseSummary() };
    if (!current) return { ...base, found: false, reason: expired ? 'expired' : 'no-release' };
    const entry = current.index.get(indicator);
    if (!entry) return { ...base, found: false, reason: 'not-listed' };
    const nav = await getNavigation(tabId);
    const navMatches = Boolean(nav && nav.indicator === indicator);
    const blockedByPolicy = entry.action === 'block' && strict.effective;
    return {
      ...base,
      found: true,
      entry: {
        indicator: entry.indicator,
        action: entry.action,
        confidence: entry.confidence,
        risk_score_bp: entry.risk_score_bp,
        operators: entry.operators,
        reasons: entry.reasons.map((r) => ({ code: r.code, detail: r.detail })),
      },
      attemptedHost: navMatches ? nav.host : null,
      backSteps: navMatches && nav.errorEntry ? 2 : 1,
      blockedByPolicy,
      canContinue: navMatches && !blockedByPolicy,
    };
  }

  /**
   * @param {unknown} msg
   * @param {{ tab?: { id?: number } }} sender
   */
  async function handleMessage(msg, sender) {
    if (!msg || typeof msg !== 'object') throw new Error('malformed message');
    const tabId = sender?.tab?.id;
    switch (msg.type) {
      case 'status':
        return getStatus();
      case 'updateNow':
        return update();
      case 'setStrict':
        await ready();
        await setStrict(msg.value === true);
        return getStatus();
      case 'siteInfo':
        return siteInfo(String(msg.url ?? ''));
      case 'warningContext':
        return warningContext(tabId, String(msg.indicator ?? ''));
      case 'continue':
        await continueToSite(tabId, String(msg.indicator ?? ''));
        return { continued: true };
      default:
        throw new Error('unknown message type');
    }
  }

  async function onAlarm(alarm) {
    if (alarm?.name === ALARM_UPDATE) return update();
    if (alarm?.name === ALARM_EXPIRY) {
      await ready();
      return exclusive(expireIfNeeded);
    }
    return undefined;
  }

  async function onStorageChanged(changes, area) {
    if ((area === 'managed' && 'strictBlocking' in changes) || (area === 'local' && KEYS.strict in changes)) {
      await ready();
      await reconcileAllowRules();
    }
  }

  return {
    ready,
    update,
    getStatus,
    handleMessage,
    onAlarm,
    onBeforeNavigate,
    onNavigationError,
    onTabRemoved,
    onStorageChanged,
  };
}
