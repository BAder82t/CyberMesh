// Shared test helpers: fixtures and re-signing with the deterministic CyberMesh test keys.
//
// The fixtures are produced by `cybermesh dev test-vectors`, whose release signers are
// `cybermesh_protocol::testkit::test_key("org-{a,b,c}-release")`, i.e. Ed25519 seeds
// SHA-256("cybermesh/testkit/key" || 0x00 || u64be(len(label)) || label). Deriving the same
// keys here lets tests sign arbitrary payloads that the bundled trust root accepts.

import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { encodeBase64 } from '../src/lib/encoding.js';
import { pae, RELEASE_PAYLOAD_TYPE } from '../src/lib/verify.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.join(here, 'fixtures');

export function fixtureText(name) {
  return readFileSync(path.join(FIXTURES, name), 'utf8');
}

export function fixtureBytes(name) {
  return new Uint8Array(readFileSync(path.join(FIXTURES, name)));
}

export const expected = JSON.parse(fixtureText('expected.json'));

function taggedDigest(tag, parts) {
  const h = createHash('sha256');
  h.update(Buffer.from(tag, 'utf8'));
  h.update(Buffer.from([0]));
  for (const p of parts) {
    const len = Buffer.alloc(8);
    len.writeBigUInt64BE(BigInt(p.length));
    h.update(len);
    h.update(p);
  }
  return h.digest();
}

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function testKey(label) {
  const seed = taggedDigest('cybermesh/testkit/key', [Buffer.from(label, 'utf8')]);
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  const publicKey = Buffer.from(jwk.x, 'base64url');
  const keyId = createHash('sha256').update(publicKey).digest('hex');
  return { label, privateKey, publicKey, publicKeyHex: publicKey.toString('hex'), keyId };
}

export const ORG_A = testKey('org-a-release');
export const ORG_B = testKey('org-b-release');
export const ORG_C = testKey('org-c-release');

export function signBytes(key, message) {
  return new Uint8Array(sign(null, Buffer.from(message), key.privateKey));
}

/**
 * Builds a DSSE envelope (as a JSON string) over `payload` signed by `keys`.
 * @param {string | Uint8Array} payload   payload bytes (strings are UTF-8 encoded)
 * @param {ReturnType<typeof testKey>[]} keys
 * @param {{ payloadType?: string }} [opts]
 */
export function makeEnvelope(payload, keys, opts = {}) {
  const payloadType = opts.payloadType ?? RELEASE_PAYLOAD_TYPE;
  const bytes = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
  const message = pae(payloadType, bytes);
  return JSON.stringify({
    payloadType,
    payload: encodeBase64(bytes),
    signatures: keys.map((k) => ({ keyid: k.keyId, sig: encodeBase64(signBytes(k, message)) })),
  });
}

/** The decoded payload of release-valid.json, as a fresh mutable object. */
export function validReleaseObject() {
  const env = JSON.parse(fixtureText('release-valid.json'));
  return JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
}

/** Signs a release object (canonical JSON via JSON.stringify) with org-a and org-b. */
export function signedRelease(release, keys = [ORG_A, ORG_B]) {
  return makeEnvelope(JSON.stringify(release), keys);
}

export function sha256Digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
