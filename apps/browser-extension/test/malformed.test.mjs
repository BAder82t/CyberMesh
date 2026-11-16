// Malformed and hostile inputs must be rejected with a ReleaseError (never a TypeError,
// RangeError or other uncaught exception), and must never produce a different verified
// release.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseTrustRoot, ReleaseError, verifyRelease } from '../src/lib/verify.js';
import { expected, fixtureBytes, fixtureText } from './helpers.mjs';

const NOW = expected.now;
const root = await parseTrustRoot(fixtureText('trust-root.json'));
const validText = fixtureText('release-valid.json');
const validEnv = JSON.parse(validText);

async function mustReject(input, label) {
  let result;
  try {
    result = await verifyRelease(input, root, NOW);
  } catch (e) {
    assert.ok(e instanceof ReleaseError, `${label}: threw ${e?.name}: ${e?.message}`);
    assert.notEqual(e.code, undefined, label);
    return e;
  }
  assert.fail(`${label}: accepted (digest ${result.digest})`);
}

/** Deterministic PRNG (mulberry32). */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test('garbage strings are rejected', async () => {
  const inputs = [
    '',
    ' ',
    'null',
    'true',
    '0',
    '-0',
    '1e309',
    '"string"',
    '[]',
    '{}',
    '{',
    '}',
    '[[[[',
    'not json at all',
    '{"payloadType":1,"payload":2,"signatures":3}',
    '{"payloadType":null,"payload":null,"signatures":null}',
    '{"payloadType":"x","payload":"","signatures":[]}',
    '{"payloadType":"application/vnd.cybermesh.release+json;v=1","payload":"","signatures":[{"keyid":"","sig":""}]}',
    '{"payloadType":"application/vnd.cybermesh.release+json;v=1","payload":"e30=","signatures":[{"keyid":"00","sig":"AA=="}]}',
    '{"__proto__":{"polluted":true},"payloadType":"a","payload":"b","signatures":[]}',
    '{"constructor":1,"payloadType":"a","payload":"b","signatures":[]}',
    '\u0000',
    '\ud800',
    validText.slice(0, validText.length / 2),
    validText.replace(/"/g, "'"),
    validText.replace('"signatures":[', '"signatures":[null,'),
    validText.replace('"signatures":[', '"signatures":[1,'),
    validText.replace('"signatures":[', '"signatures":["x",'),
    validText.replace('"signatures":[', '"signatures":[[],'),
    validText.replace(/"payload":"[^"]*"/, '"payload":{"a":1}'),
    validText.replace(/"payload":"[^"]*"/, '"payload":"AAAA"'),
    validText.replace(/"payload":"[^"]*"/, '"payload":"////"'),
  ];
  for (const s of inputs) await mustReject(s, JSON.stringify(s.slice(0, 60)));
  assert.equal(Object.prototype.polluted, undefined);
});

test('wrong input types are rejected', async () => {
  for (const v of [undefined, null, 0, 1, true, {}, [], () => {}, Symbol('x'), 10n, new Date(), validEnv]) {
    await mustReject(v, `type ${typeof v}`);
  }
});

test('hostile structure: huge signature arrays, deep nesting, long strings', async () => {
  const sig = validEnv.signatures[0];
  await mustReject(JSON.stringify({ ...validEnv, signatures: Array.from({ length: 100_000 }, () => sig) }), '100k signatures');
  await mustReject(JSON.stringify({ ...validEnv, signatures: Array.from({ length: 17 }, () => sig) }), '17 signatures');
  await mustReject(`${'['.repeat(200_000)}${']'.repeat(200_000)}`, 'deep arrays');
  await mustReject(`${'{"a":'.repeat(50_000)}1${'}'.repeat(50_000)}`, 'deep objects');
  await mustReject(JSON.stringify({ ...validEnv, signatures: [{ keyid: 'a'.repeat(1_000_000), sig: 'b'.repeat(1_000_000) }] }), 'long fields');
  await mustReject(JSON.stringify({ ...validEnv, payloadType: 'x'.repeat(5_000_000) }), 'long payload type');
  await mustReject('"' + 'a'.repeat(17 * 1024 * 1024) + '"', 'oversized string');
});

test('invalid UTF-8 and byte-order marks are rejected', async () => {
  const bytes = fixtureBytes('release-valid.json');
  const withBom = new Uint8Array(bytes.length + 3);
  withBom.set([0xef, 0xbb, 0xbf]);
  withBom.set(bytes, 3);
  await mustReject(withBom, 'BOM');
  const broken = Uint8Array.from(bytes);
  broken[20] = 0xff;
  await mustReject(broken, 'invalid UTF-8');
  await mustReject(new Uint8Array([0xc3]), 'truncated UTF-8');
});

test('random bytes are rejected', async () => {
  const next = rng(1);
  for (let i = 0; i < 300; i++) {
    const len = Math.floor(next() * 512);
    const b = new Uint8Array(len);
    for (let j = 0; j < len; j++) b[j] = Math.floor(next() * 256);
    await mustReject(b, `random #${i}`);
  }
});

test('mutations of the valid envelope never yield a different verified release', async () => {
  const bytes = fixtureBytes('release-valid.json');
  const next = rng(42);
  let rejected = 0;
  for (let i = 0; i < 400; i++) {
    const m = Uint8Array.from(bytes);
    const flips = 1 + Math.floor(next() * 3);
    for (let k = 0; k < flips; k++) {
      const pos = Math.floor(next() * m.length);
      m[pos] ^= 1 << Math.floor(next() * 8);
    }
    try {
      const v = await verifyRelease(m, root, NOW);
      // Only harmless changes (none exist in a compact envelope) may still verify.
      assert.equal(v.digest, expected.valid_digest, `mutation #${i} changed the release`);
    } catch (e) {
      assert.ok(e instanceof ReleaseError, `mutation #${i}: threw ${e?.name}: ${e?.message}`);
      rejected++;
    }
  }
  assert.ok(rejected > 350, `only ${rejected} mutations rejected`);
});

test('malformed trust roots are rejected with ReleaseError', async () => {
  for (const v of [undefined, null, 1, 'x', '[]', '{}', '{"network_id":1,"threshold":1,"signers":[]}', new Uint8Array([0xff]), { signers: 'x' }]) {
    await assert.rejects(parseTrustRoot(v), (e) => e instanceof ReleaseError && e.code === 'trust-root');
  }
});

test('malformed anti-rollback state and clock are rejected with ReleaseError', async () => {
  for (const state of [{}, { sequence: 7 }, { sequence: '7', digest: expected.valid_digest }, { sequence: 7, digest: 'abc' }, 'x', 5]) {
    await assert.rejects(verifyRelease(validText, root, NOW, state), (e) => e instanceof ReleaseError && e.code === 'state');
  }
  for (const now of [-1, 1.5, '1800000000', NaN, Infinity, null]) {
    await assert.rejects(verifyRelease(validText, root, now), (e) => e instanceof ReleaseError);
  }
});
