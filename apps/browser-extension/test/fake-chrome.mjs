// Minimal in-memory stand-in for the chrome.* APIs used by the controller.

function storageArea(initial = {}) {
  let data = structuredClone(initial);
  let failSetFor = null;
  return {
    _data: () => data,
    _failSetsContaining(key) {
      failSetFor = key;
    },
    async get(keys) {
      if (keys === null || keys === undefined) return structuredClone(data);
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const k of list) if (k in data) out[k] = structuredClone(data[k]);
      return out;
    },
    async set(items) {
      if (failSetFor && failSetFor in items) throw new Error('QUOTA_BYTES quota exceeded');
      data = { ...data, ...structuredClone(items) };
    },
    async remove(keys) {
      const list = Array.isArray(keys) ? keys : [keys];
      data = Object.fromEntries(Object.entries(data).filter(([k]) => !list.includes(k)));
    },
    _reset(next = {}) {
      data = structuredClone(next);
    },
  };
}

function applyUpdate(rules, { removeRuleIds = [], addRules = [] }) {
  const kept = rules.filter((r) => !removeRuleIds.includes(r.id));
  const ids = new Set(kept.map((r) => r.id));
  for (const r of addRules) {
    if (ids.has(r.id)) throw new Error(`Rule with id ${r.id} already exists`);
    ids.add(r.id);
  }
  return [...kept, ...structuredClone(addRules)];
}

/**
 * @param {{ managed?: object, local?: object }} [opts]
 */
export function createFakeChrome(opts = {}) {
  let dynamicRules = [];
  let sessionRules = [];
  const alarms = new Map();
  const tabUpdates = [];
  const badge = { text: '', color: null, title: '' };
  const managed = storageArea(opts.managed ?? {});
  const chrome = {
    runtime: {
      id: 'fakeextensionid',
      getURL: (p) => `chrome-extension://fakeextensionid/${p.replace(/^\//, '')}`,
    },
    storage: {
      local: storageArea(opts.local ?? {}),
      session: storageArea(),
      managed: {
        get: (k) => (opts.noManagedSchema ? Promise.reject(new Error('Managed storage manifest not found')) : managed.get(k)),
        _area: managed,
      },
    },
    declarativeNetRequest: {
      MAX_NUMBER_OF_DYNAMIC_RULES: opts.maxDynamicRules ?? 30_000,
      async getDynamicRules() {
        return structuredClone(dynamicRules);
      },
      failUpdates: false,
      async updateDynamicRules(u) {
        if (this.failUpdates) throw new Error('internal error');
        if ((u.addRules ?? []).length + dynamicRules.length - (u.removeRuleIds ?? []).length > this.MAX_NUMBER_OF_DYNAMIC_RULES) {
          throw new Error('too many rules');
        }
        dynamicRules = applyUpdate(dynamicRules, u);
      },
      async getSessionRules() {
        return structuredClone(sessionRules);
      },
      async updateSessionRules(u) {
        sessionRules = applyUpdate(sessionRules, u);
      },
    },
    alarms: {
      async create(name, info) {
        alarms.set(name, { name, ...info });
      },
      async get(name) {
        return alarms.get(name);
      },
    },
    tabs: {
      async update(tabId, props) {
        tabUpdates.push({ tabId, ...props });
        return { id: tabId, ...props };
      },
    },
    action: {
      async setBadgeText({ text }) {
        badge.text = text;
      },
      async setBadgeBackgroundColor({ color }) {
        badge.color = color;
      },
      async setTitle({ title }) {
        badge.title = title;
      },
    },
  };
  return {
    chrome,
    get dynamicRules() {
      return dynamicRules;
    },
    get sessionRules() {
      return sessionRules;
    },
    alarms,
    tabUpdates,
    badge,
    /** Simulates a browser restart: session state is lost, local storage and dynamic rules persist. */
    restartBrowser() {
      sessionRules = [];
      chrome.storage.session._reset();
      tabUpdates.length = 0;
    },
  };
}

/** A fetch stand-in serving `body` (string | Uint8Array | Error | {status}) for any URL. */
export function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    const r = await handler(url, init);
    if (r instanceof Error) throw r;
    if (r && typeof r === 'object' && 'status' in r && !(r instanceof Uint8Array)) {
      return new Response(r.body ?? '', { status: r.status });
    }
    return new Response(r, { status: 200 });
  };
  fn.calls = calls;
  return fn;
}
