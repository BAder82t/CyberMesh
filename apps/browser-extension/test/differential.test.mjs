// Differential test: the JavaScript verifier and the Rust verifier
// (`cybermesh release verify`) must accept and reject exactly the same inputs and report
// the same digest. Skipped when the CLI binary is not built; set CYBERMESH_BIN or build it
// with `cargo build -p cybermesh-cli` (binary: target/debug/cybermesh).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseTrustRoot, verifyRelease } from '../src/lib/verify.js';
import { ORG_A, ORG_B, ORG_C, expected, fixtureText, makeEnvelope, signedRelease, validReleaseObject } from './helpers.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = process.env.CYBERMESH_BIN ?? path.resolve(here, '../../../target/debug/cybermesh');
const NOW = expected.now;

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

function buildCorpus() {
  const tr = JSON.parse(fixtureText('trust-root.json'));
  const roots = {
    main: fixtureText('trust-root.json'),
    sameOp: fixtureText('trust-root-same-operator.json'),
    t3: JSON.stringify({ ...tr, threshold: 3 }),
    t0: JSON.stringify({ ...tr, threshold: 0 }),
    t1: JSON.stringify({ ...tr, threshold: 1 }),
  };
  const cases = [];
  const add = (name, envelope, opts = {}) =>
    cases.push({ name, envelope, root: opts.root ?? 'main', now: opts.now ?? NOW, state: opts.state ?? null });
  const valid = fixtureText('release-valid.json');
  const validState = { sequence: 7, digest: expected.valid_digest };

  for (const f of ['valid', 'one-signature', 'unknown-signers', 'tampered', 'duplicate-signature', 'older-sequence']) {
    const env = fixtureText(`release-${f}.json`);
    for (const root of Object.keys(roots)) add(`${f}/${root}`, env, { root });
    add(`${f}/expired`, env, { now: expected.expired_now });
    add(`${f}/future`, env, { now: expected.future_now });
    add(`${f}/state7`, env, { state: validState });
    add(`${f}/state7-other`, env, { state: { sequence: 7, digest: `sha256:${'0'.repeat(64)}` } });
    add(`${f}/state6`, env, { state: { sequence: 6, digest: `sha256:${'0'.repeat(64)}` } });
  }
  for (const now of [1_800_000_000 - 301, 1_800_000_000 - 300, 1_800_086_399, 1_800_086_400]) add(`valid/now${now}`, valid, { now });

  const mut = (name, fn, opts) => {
    const r = validReleaseObject();
    fn(r);
    add(`payload/${name}`, signedRelease(r), opts);
  };
  mut('v2', (r) => (r.v = 2));
  mut('network', (r) => (r.network_id = 'other'));
  mut('ttl-max', (r) => (r.expires_at = r.issued_at + 30 * 86_400));
  mut('ttl-over', (r) => (r.expires_at = r.issued_at + 30 * 86_400 + 1));
  mut('unsorted', (r) => r.entries.reverse());
  mut('dup-entry', (r) => r.entries.push({ ...r.entries[1] }));
  mut('upper', (r) => (r.entries[0].indicator = 'Ex.phish.localhost'));
  mut('numeric-tld', (r) => (r.entries[0].indicator = 'a.123'));
  mut('score', (r) => (r.entries[0].risk_score_bp = 10_001));
  mut('score-u16', (r) => (r.entries[0].risk_score_bp = 65_536));
  mut('operators-u8', (r) => (r.entries[0].operators = 256));
  mut('detail-200', (r) => (r.entries[0].reasons[0].detail = '~'.repeat(200)));
  mut('detail-201', (r) => (r.entries[0].reasons[0].detail = '~'.repeat(201)));
  mut('detail-nonascii', (r) => (r.entries[0].reasons[0].detail = 'café'));
  mut('detail-ctrl', (r) => (r.entries[0].reasons[0].detail = 'a\u007fb'));
  mut('reasons-17', (r) => (r.entries[0].reasons = Array.from({ length: 17 }, () => ({ code: 'feed-match', detail: 'x' }))));
  mut('evidence-id-129', (r) => (r.entries[0].evidence[0].id = 'x'.repeat(129)));
  mut('generator-unicode', (r) => (r.generator = 'gené 😀'));
  mut('generator-ctrl', (r) => (r.generator = 'a\u0001\n"\\b'));
  mut('corrections-ok', (r) => (r.corrections = [{ indicator: 'a.b', kind: 'appeal-upheld', reference: 'r', note: 'n' }, { indicator: 'a.b', kind: 'rollback', reference: 'r', note: 'n' }]));
  mut('corrections-order', (r) => (r.corrections = [{ indicator: 'a.b', kind: 'rollback', reference: 'r', note: 'n' }, { indicator: 'a.b', kind: 'appeal-upheld', reference: 'r', note: 'n' }]));
  mut('previous-link', (r) => Object.assign(r, { sequence: 8, previous: { sequence: 7, digest: expected.valid_digest } }), { state: validState });
  mut('previous-fork', (r) => Object.assign(r, { sequence: 8, previous: { sequence: 7, digest: `sha256:${'1'.repeat(64)}` } }), { state: validState });
  mut('jump-max', (r) => (r.sequence = 7 + 1_000_000), { state: validState });
  mut('jump-over', (r) => (r.sequence = 7 + 1_000_001), { state: validState });
  mut('big-seq', (r) => (r.sequence = 2 ** 52));

  const canonical = JSON.stringify(validReleaseObject());
  const text = (name, payload) => add(`text/${name}`, makeEnvelope(payload, [ORG_A, ORG_B]));
  text('pretty', JSON.stringify(validReleaseObject(), null, 1));
  text('reordered', canonical.replace('{"v":1,"network_id":"cybermesh-test",', '{"network_id":"cybermesh-test","v":1,'));
  text('float', canonical.replace('"sequence":7', '"sequence":7.0'));
  text('escape', canonical.replace('"generator":"cybermesh', '"generator":"\\u0063ybermesh'));
  text('dup-key', canonical.replace('{"v":1,', '{"v":1,"v":1,'));
  text('unknown', canonical.replace('{"v":1,', '{"v":1,"x":1,'));
  text('missing-previous', canonical.replace('"previous":null,', ''));
  text('lone-surrogate', canonical.replace('"generator":"cybermesh-intelligence/0.1.0"', '"generator":"\\ud800"'));
  text('bom', `﻿${canonical}`);
  text('enum-object', canonical.replace('"action":"warn"', '"action":{"warn":null}'));

  const env = JSON.parse(valid);
  add('env/reordered-pretty', JSON.stringify({ signatures: env.signatures, payload: env.payload, payloadType: env.payloadType }, null, 2));
  add('env/dup-key', valid.replace('{"payloadType"', '{"payload":"AAAA","payloadType"'));
  add('env/unknown', JSON.stringify({ ...env, x: 1 }));
  add('env/16-sigs', JSON.stringify({ ...env, signatures: [...env.signatures, ...Array.from({ length: 14 }, () => env.signatures[0])] }));
  add('env/17-sigs', JSON.stringify({ ...env, signatures: Array.from({ length: 17 }, () => env.signatures[0]) }));
  add('env/unpadded', JSON.stringify({ ...env, payload: env.payload.replace(/=+$/, '') }));
  add('env/bad-keyids', JSON.stringify({ ...env, signatures: [{ keyid: 'zz', sig: '!' }, { keyid: ORG_C.keyId.toUpperCase(), sig: env.signatures[0].sig }, ...env.signatures] }));
  add('env/three-ops-t3', signedRelease(validReleaseObject(), [ORG_A, ORG_B, ORG_C]), { root: 't3' });
  add('env/bom', `﻿${valid}`);
  add('env/trailing', `${valid}\n`);

  // Random edits of the canonical payload, re-signed so that only parsing/validation decides.
  const next = rng(7);
  const alphabet = '{}[]",:0123456789-.eE+u\\ abzAZ~é/';
  for (let i = 0; i < 250; i++) {
    let p = canonical;
    const edits = 1 + Math.floor(next() * 2);
    for (let k = 0; k < edits; k++) {
      const pos = Math.floor(next() * p.length);
      const op = next();
      const ch = alphabet[Math.floor(next() * alphabet.length)];
      if (op < 0.4) p = p.slice(0, pos) + ch + p.slice(pos + 1);
      else if (op < 0.7) p = p.slice(0, pos) + ch + p.slice(pos);
      else p = p.slice(0, pos) + p.slice(pos + 1);
    }
    text(`fuzz-${i}`, p);
  }
  // Random bit flips in the envelope bytes.
  const raw = Buffer.from(valid);
  for (let i = 0; i < 80; i++) {
    const m = Buffer.from(raw);
    m[Math.floor(next() * m.length)] ^= 1 << Math.floor(next() * 8);
    add(`flip-${i}`, m.toString('latin1'));
    cases[cases.length - 1].bytes = m;
  }
  return { roots, cases };
}

test('JS verifier agrees with the Rust verifier', { skip: !existsSync(BIN) && `CLI not built at ${BIN}` }, async (t) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'cybermesh-diff-'));
  try {
    const { roots, cases } = buildCorpus();
    const parsedRoots = {};
    for (const [k, v] of Object.entries(roots)) {
      writeFileSync(path.join(dir, `root-${k}.json`), v);
      parsedRoots[k] = await parseTrustRoot(v);
    }
    let accepted = 0;
    const mismatches = [];
    for (const [i, c] of cases.entries()) {
      const bytes = c.bytes ?? Buffer.from(c.envelope, 'utf8');
      const file = path.join(dir, `case-${i}.json`);
      writeFileSync(file, bytes);
      const args = ['release', 'verify', '--release', file, '--trust-root', path.join(dir, `root-${c.root}.json`), '--now', String(c.now)];
      if (c.state) {
        const stateFile = path.join(dir, `state-${i}.json`);
        writeFileSync(stateFile, JSON.stringify(c.state));
        args.push('--state', stateFile);
      }
      const rust = spawnSync(BIN, args, { encoding: 'utf8' });
      const rustOk = rust.status === 0;
      const rustDigest = rustOk ? /digest=(\S+)/.exec(rust.stdout)?.[1] : null;
      let jsOk = false;
      let jsDigest = null;
      let jsErr = null;
      try {
        jsDigest = (await verifyRelease(new Uint8Array(bytes), parsedRoots[c.root], c.now, c.state)).digest;
        jsOk = true;
      } catch (e) {
        jsErr = `${e.code}: ${e.message}`;
      }
      if (jsOk) accepted++;
      if (rustOk !== jsOk || rustDigest !== jsDigest) {
        mismatches.push({ name: c.name, rust: rustOk ? rustDigest : (rust.stderr || rust.stdout).trim().split('\n').pop(), js: jsOk ? jsDigest : jsErr });
      }
    }
    assert.deepEqual(mismatches, [], `${mismatches.length} of ${cases.length} cases disagree`);
    assert.ok(accepted > 10, 'corpus should contain accepted releases');
    t.diagnostic(`compared ${cases.length} cases with ${BIN}: ${accepted} accepted by both, ${cases.length - accepted} rejected by both`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
