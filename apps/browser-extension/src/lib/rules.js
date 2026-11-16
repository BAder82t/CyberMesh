// declarativeNetRequest rule construction and other pure helpers shared by the service
// worker and the extension pages.
//
// Enforcement uses `block` rules, not `redirect` rules: Chromium silently ignores a
// `redirect` rule unless the extension holds host permissions for the request URL, and
// this extension deliberately has host access only to the release origin. A blocked
// main-frame navigation can never load the listed site; the service worker then shows the
// warning page in that tab (see controller.js).

export const BLOCK_RULE_PRIORITY = 1;
export const ALLOW_RULE_PRIORITY = 2;
/** Session (allow) rule ids start here so they never collide with dynamic rule ids. */
export const ALLOW_RULE_ID_BASE = 1_000_000;
export const ISSUE_URL = 'https://github.com/BAder82t/CyberMesh/issues/new';

/**
 * One `block` rule per entry (`requestDomains: [indicator]`, main frame only). When a
 * release has more entries than the browser's dynamic-rule limit, indicators are packed
 * evenly into `maxRules` rules so that every entry is still enforced.
 *
 * @param {{ indicator: string }[]} entries
 * @param {number} maxRules
 * @returns {chrome.declarativeNetRequest.Rule[]}
 */
export function planBlockRules(entries, maxRules) {
  if (entries.length === 0) return [];
  const limit = Math.max(1, Math.floor(maxRules));
  const perRule = Math.max(1, Math.ceil(entries.length / limit));
  const rules = [];
  for (let i = 0; i < entries.length; i += perRule) {
    rules.push({
      id: rules.length + 1,
      priority: BLOCK_RULE_PRIORITY,
      action: { type: 'block' },
      condition: {
        requestDomains: entries.slice(i, i + perRule).map((e) => e.indicator),
        resourceTypes: ['main_frame'],
      },
    });
  }
  return rules;
}

/**
 * Session-scoped allow rule for one host (and, as with every `requestDomains` condition,
 * its subdomains). Higher priority than the block rules.
 *
 * @param {number} id
 * @param {string} host
 * @returns {chrome.declarativeNetRequest.Rule}
 */
export function allowRule(id, host) {
  return {
    id,
    priority: ALLOW_RULE_PRIORITY,
    action: { type: 'allow' },
    condition: { requestDomains: [host], resourceTypes: ['main_frame'] },
  };
}

/**
 * `requestDomains` matching: the host itself or any subdomain of it.
 * @param {string} host
 * @param {string} domain
 * @returns {boolean}
 */
export function domainMatches(host, domain) {
  return host === domain || host.endsWith(`.${domain}`);
}

/**
 * Extension-relative path of the warning page for a matched indicator.
 * @param {string} indicator
 * @returns {string}
 */
export function warningPath(indicator) {
  return `/warning.html?d=${encodeURIComponent(indicator)}`;
}

/**
 * GitHub "new issue" URL for a false-positive report. Only the listed indicator and the
 * release sequence are included (never the visited URL); the user reviews and submits.
 *
 * @param {string} indicator
 * @param {number | null} sequence
 * @returns {string}
 */
export function falsePositiveUrl(indicator, sequence) {
  const release = sequence === null || sequence === undefined ? 'unknown release' : `release ${sequence}`;
  const title = `False positive: ${indicator} (${release})`;
  return `${ISSUE_URL}?template=false-positive.yml&title=${encodeURIComponent(title)}`;
}
