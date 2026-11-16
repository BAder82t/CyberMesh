import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildIndex, countActions, hostFromUrl, lookupHost } from '../src/lib/lookup.js';
import { allowRule, domainMatches, falsePositiveUrl, planBlockRules, warningPath } from '../src/lib/rules.js';
import { isNormalizedDomain } from '../src/lib/verify.js';

const entries = [
  { indicator: 'evil.example', action: 'block' },
  { indicator: 'login.evil.example', action: 'warn' },
  { indicator: 'sus.test', action: 'warn' },
];
const index = buildIndex(entries);

test('most specific listed indicator wins', () => {
  assert.equal(lookupHost(index, 'evil.example').indicator, 'evil.example');
  assert.equal(lookupHost(index, 'a.b.evil.example').indicator, 'evil.example');
  assert.equal(lookupHost(index, 'login.evil.example').indicator, 'login.evil.example');
  assert.equal(lookupHost(index, 'x.login.evil.example').indicator, 'login.evil.example');
  assert.equal(lookupHost(index, 'notevil.example'), null);
  assert.equal(lookupHost(index, 'example'), null);
  assert.equal(lookupHost(index, ''), null);
  assert.equal(lookupHost(index, null), null);
});

test('hostFromUrl normalises http(s) hosts only', () => {
  assert.equal(hostFromUrl('https://Login.EVIL.example./path?q'), 'login.evil.example');
  assert.equal(hostFromUrl('http://xn--pypal-4ve.com:8080/'), 'xn--pypal-4ve.com');
  assert.equal(hostFromUrl('https://pаypal.com/'), 'xn--pypal-4ve.com');
  assert.equal(hostFromUrl('ftp://evil.example/'), null);
  assert.equal(hostFromUrl('chrome://settings'), null);
  assert.equal(hostFromUrl('http://[::1]/'), null);
  assert.equal(hostFromUrl('not a url'), null);
});

test('countActions', () => {
  assert.deepEqual(countActions(entries), { block: 1, warn: 2 });
});

test('isNormalizedDomain mirrors the Rust rules', () => {
  for (const ok of ['example.com', 'a.b.c.example.co.uk', 'xn--pypal-4ve.com', 'login-secure.example.test', 'examplebank-secure-login.phish.localhost']) {
    assert.ok(isNormalizedDomain(ok), ok);
  }
  for (const bad of ['', 'com', 'Example.com', 'example.com.', '-a.com', 'a-.com', 'a..com', '192.168.1.1', 'exa mple.com', 'ex_ample.com', 'пример.рф', `${'a'.repeat(64)}.com`, `${'a.'.repeat(130)}com`]) {
    assert.ok(!isNormalizedDomain(bad), bad);
  }
});

test('one block rule per entry, main frame only', () => {
  const rules = planBlockRules(entries, 30_000);
  assert.equal(rules.length, 3);
  assert.deepEqual(rules[0], {
    id: 1,
    priority: 1,
    action: { type: 'block' },
    condition: { requestDomains: ['evil.example'], resourceTypes: ['main_frame'] },
  });
  assert.deepEqual(rules.map((r) => r.id), [1, 2, 3]);
  assert.deepEqual(planBlockRules([], 10), []);
});

test('entries beyond the rule limit are packed so that all are enforced', () => {
  const many = Array.from({ length: 100_001 }, (_, i) => ({ indicator: `h${i}.example` }));
  const rules = planBlockRules(many, 30_000);
  assert.ok(rules.length <= 30_000);
  const covered = rules.flatMap((r) => r.condition.requestDomains);
  assert.equal(covered.length, many.length);
  assert.equal(new Set(rules.map((r) => r.id)).size, rules.length);
});

test('allow rules outrank block rules', () => {
  const a = allowRule(1_000_001, 'login.evil.example');
  assert.equal(a.action.type, 'allow');
  assert.ok(a.priority > planBlockRules(entries, 10)[0].priority);
  assert.deepEqual(a.condition, { requestDomains: ['login.evil.example'], resourceTypes: ['main_frame'] });
});

test('domainMatches follows requestDomains semantics', () => {
  assert.ok(domainMatches('evil.example', 'evil.example'));
  assert.ok(domainMatches('a.evil.example', 'evil.example'));
  assert.ok(!domainMatches('notevil.example', 'evil.example'));
});

test('warning path and false-positive URL', () => {
  assert.equal(warningPath('evil.example'), '/warning.html?d=evil.example');
  const url = new URL(falsePositiveUrl('evil.example', 7));
  assert.equal(url.origin + url.pathname, 'https://github.com/BAder82t/CyberMesh/issues/new');
  assert.equal(url.searchParams.get('template'), 'false-positive.yml');
  assert.equal(url.searchParams.get('title'), 'False positive: evil.example (release 7)');
  assert.equal([...url.searchParams.keys()].length, 2);
});
