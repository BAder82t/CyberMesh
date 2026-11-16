import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decodeBase64Strict, encodeBase64, hexToBytes } from '../src/lib/encoding.js';
import { JsonError, JsonFloat, parseStrictJson } from '../src/lib/json.js';
import { isCanonicalScalar, isSmallOrderEncoding, isValidPointEncoding } from '../src/lib/ed25519.js';
import { pae } from '../src/lib/verify.js';
import { ORG_A } from './helpers.mjs';

test('PAE matches the DSSE specification example', () => {
  const out = pae('http://example.com/HelloWorld', new TextEncoder().encode('hello world'));
  assert.equal(new TextDecoder().decode(out), 'DSSEv1 29 http://example.com/HelloWorld 11 hello world');
});

test('PAE lengths are byte lengths', () => {
  const out = pae('té', new TextEncoder().encode('é'));
  assert.equal(new TextDecoder().decode(out), 'DSSEv1 3 té 2 é');
});

test('strict base64 accepts canonical padded input only', () => {
  for (const [s, hex] of [['', ''], ['AA==', '00'], ['AAA=', '0000'], ['AAAA', '000000'], ['/+8=', 'ffef']]) {
    assert.deepEqual(decodeBase64Strict(s), hexToBytes(hex), s);
  }
  for (const s of ['A', 'AA', 'AAA', 'AB==', 'AAB=', 'A===', '====', 'AA=A', 'AA==AAAA', ' AAAA', 'AAAA\n', '-_-_', 'AAé=', null, 5]) {
    assert.equal(decodeBase64Strict(s), null, JSON.stringify(s));
  }
  for (let n = 0; n < 40; n++) {
    const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
    const enc = encodeBase64(b);
    assert.equal(enc, Buffer.from(b).toString('base64'));
    assert.deepEqual(decodeBase64Strict(enc), b);
  }
});

test('hexToBytes requires even-length lowercase hex', () => {
  assert.deepEqual(hexToBytes('00ff'), Uint8Array.from([0, 255]));
  for (const s of ['0', '0F', 'zz', ' 00', null]) assert.equal(hexToBytes(s), null);
});

test('strict JSON parser follows serde_json rules', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(parseStrictJson('{"a":[1,"x",null,true,false,{}]}'))), { a: [1, 'x', null, true, false, {}] });
  assert.equal(parseStrictJson(' \t\r\n"\\u00e9\\ud83d\\ude00\\/" '), 'é😀/');
  assert.ok(parseStrictJson('1.5') instanceof JsonFloat);
  assert.ok(parseStrictJson('1e2') instanceof JsonFloat);
  assert.ok(parseStrictJson('-0') instanceof JsonFloat);
  assert.equal(parseStrictJson('-12'), -12);
  const proto = parseStrictJson('{"__proto__":{"x":1}}');
  assert.equal(Object.getPrototypeOf(proto), null);
  assert.deepEqual(Object.keys(proto), ['__proto__']);
  for (const bad of [
    '',
    '{"a":1,"a":2}',
    '"\\ud800"',
    '"\\ud800\\u0041"',
    '"\\udc00"',
    '"\u0001"',
    '[1,]',
    '{"a":1,}',
    '01',
    '1.',
    '.5',
    '+1',
    'NaN',
    'Infinity',
    "'a'",
    '[1] x',
    '\ufeff{}',
    '"\\x41"',
    '{"a" 1}',
    '[' .repeat(129) + ']'.repeat(129),
  ]) {
    assert.throws(() => parseStrictJson(bad), JsonError, JSON.stringify(bad));
  }
  assert.doesNotThrow(() => parseStrictJson('['.repeat(128) + ']'.repeat(128)));
});

test('Ed25519 point checks: valid key, small-order points, scalar range', () => {
  assert.ok(isValidPointEncoding(new Uint8Array(ORG_A.publicKey)));
  assert.ok(!isSmallOrderEncoding(new Uint8Array(ORG_A.publicKey)));
  const smallOrder = [
    '0100000000000000000000000000000000000000000000000000000000000000',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0000000000000000000000000000000000000000000000000000000000000080',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    // Non-canonical encodings (y >= p) of small-order points.
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ];
  for (const h of smallOrder) {
    assert.ok(isSmallOrderEncoding(hexToBytes(h)), h);
    assert.ok(isValidPointEncoding(hexToBytes(h)), h);
  }
  // y = 2 is not on the curve.
  assert.ok(!isValidPointEncoding(hexToBytes('02'.padEnd(64, '0'))));
  const L = hexToBytes('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
  assert.ok(!isCanonicalScalar(L));
  const lMinus1 = Uint8Array.from(L);
  lMinus1[0] -= 1;
  assert.ok(isCanonicalScalar(lMinus1));
});
