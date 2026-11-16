// Host lookup against a verified release (mirrors `ThreatRelease::lookup` in model.rs):
// exact host first, then each parent domain obtained by removing the leftmost label; the
// most specific listed indicator wins.

/**
 * @typedef {object} ThreatEntry
 * @property {string} indicator
 * @property {'host-and-subdomains'} scope
 * @property {'block' | 'warn'} action
 * @property {'high' | 'medium'} confidence
 * @property {number} risk_score_bp
 * @property {number} operators
 * @property {{ code: string, detail: string }[]} reasons
 * @property {{ kind: string, id: string, digest: string }[]} evidence
 */

/**
 * @param {ThreatEntry[]} entries   sorted, unique entries of a verified release
 * @returns {Map<string, ThreatEntry>}
 */
export function buildIndex(entries) {
  const index = new Map();
  for (const e of entries) index.set(e.indicator, e);
  return index;
}

/**
 * @param {Map<string, ThreatEntry>} index
 * @param {string} host   normalised host name (see `hostFromUrl`)
 * @returns {ThreatEntry | null}
 */
export function lookupHost(index, host) {
  if (typeof host !== 'string' || host.length === 0) return null;
  let candidate = host;
  for (;;) {
    const hit = index.get(candidate);
    if (hit) return hit;
    const dot = candidate.indexOf('.');
    if (dot < 0) return null;
    candidate = candidate.slice(dot + 1);
  }
}

/**
 * Extracts the normalised host of an http(s) URL: lowercase, IDNA (punycode) as produced
 * by the URL parser, one trailing dot removed. Returns null for other schemes, IP literals
 * and unparsable input.
 *
 * @param {string} url
 * @returns {string | null}
 */
export function hostFromUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  let host = u.hostname.toLowerCase();
  if (host.endsWith('.')) host = host.slice(0, -1);
  if (host.length === 0 || host.startsWith('[')) return null;
  return host;
}

/**
 * Counts entries by action.
 * @param {ThreatEntry[]} entries
 * @returns {{ block: number, warn: number }}
 */
export function countActions(entries) {
  let block = 0;
  let warn = 0;
  for (const e of entries) {
    if (e.action === 'block') block++;
    else warn++;
  }
  return { block, warn };
}
