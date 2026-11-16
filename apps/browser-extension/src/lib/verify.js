// Offline verification of CyberMesh threat-intelligence releases.
//
// Mirrors `cybermesh_intelligence::verify_release` (crates/cybermesh-intelligence/src/verify.rs)
// and the DSSE envelope rules of `cybermesh_crypto::Envelope`
// (crates/cybermesh-crypto/src/envelope.rs). Every rule is applied in the same order as the
// Rust implementation so that both accept exactly the same releases. Error codes name the
// Rust `ReleaseError` variants.

import {
  bytesToHex,
  concatBytes,
  decodeBase64Strict,
  hexToBytes,
  sha256,
  toBytes,
  utf8DecodeStrict,
  utf8Encode,
} from './encoding.js';
import { JsonError, isJsonObject, parseStrictJson } from './json.js';
import {
  importEd25519PublicKey,
  isSmallOrderEncoding,
  isValidPointEncoding,
  verifyEd25519Strict,
} from './ed25519.js';

export const RELEASE_PAYLOAD_TYPE = 'application/vnd.cybermesh.release+json;v=1';
export const PROTOCOL_VERSION = 1;
export const MAX_RELEASE_BYTES = 16 * 1024 * 1024;
export const MAX_SIGNATURES = 16;
export const MAX_ENTRIES = 200_000;
export const MAX_RELEASE_TTL_SECS = 30 * 86_400;
export const MAX_SEQUENCE_JUMP = 1_000_000;
export const MAX_RELEASE_SKEW_SECS = 300;
const MAX_REASONS = 16;
const MAX_EVIDENCE = 16;
const MAX_DETAIL = 200;
const MAX_NOTE = 500;
const MAX_REFERENCE = 128;
const MAX_CORRECTION_INDICATOR = 253;

/** `cybermesh_protocol::FindingCode`, kebab-case. */
export const FINDING_CODES = Object.freeze([
  'feed-match',
  'popular-domain',
  'brand-impersonation',
  'brand-lookalike',
  'idn-homograph',
  'mixed-script',
  'suspicious-keywords',
  'many-hyphens',
  'deep-subdomain',
  'long-hostname',
  'high-entropy',
  'digit-heavy',
  'suspicious-tld',
]);
const ACTIONS = ['block', 'warn'];
const CONFIDENCES = ['high', 'medium'];
const SCOPES = ['host-and-subdomains'];
const EVIDENCE_KINDS = ['verification', 'snapshot'];
/** Declaration order of `CorrectionKind` (used by its derived `Ord`). */
const CORRECTION_KINDS = ['appeal-upheld', 'rollback'];

/**
 * Error codes: `envelope`, `threshold`, `wrong-network`, `version`, `expired`,
 * `not-yet-valid`, `rollback`, `equivocation`, `invalid` (all mirror `ReleaseError`), plus
 * `trust-root` and `state` for malformed local inputs.
 */
export class ReleaseError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message);
    this.name = 'ReleaseError';
    this.code = code;
  }
}

const err = (code, message) => new ReleaseError(code, message);

// ---------------------------------------------------------------------------------------
// Field validators (serde semantics)

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const KEY_ID_RE = /^[0-9a-f]{64}$/;
const OPERATOR_RE = /^[a-z0-9-]{2,32}$/;
const PRINTABLE_RE = /^[\x20-\x7e]*$/;
const LABEL_RE = /^[a-z0-9-]+$/;
const ALL_DIGITS_RE = /^[0-9]+$/;

function isWellFormedString(v) {
  if (typeof v !== 'string') return false;
  if (typeof v.isWellFormed === 'function') return v.isWellFormed();
  return !/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(v);
}

function isUint(v, max) {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
}

const U8 = 0xff;
const U16 = 0xffff;
// u64 values above 2^53 - 1 cannot be represented exactly in JavaScript and are rejected.
const U64 = Number.MAX_SAFE_INTEGER;

/** `printable` from verify.rs: byte length <= max, all bytes in 0x20..=0x7e. */
export function isPrintable(s, max) {
  return typeof s === 'string' && s.length <= max && PRINTABLE_RE.test(s);
}

/** `cybermesh_protocol::domain::is_normalized_domain`. */
export function isNormalizedDomain(s) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 253 || s.endsWith('.')) return false;
  const labels = s.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    if (!LABEL_RE.test(label)) return false;
  }
  return labels.length >= 2 && !ALL_DIGITS_RE.test(labels[labels.length - 1]);
}

/**
 * Checks that `obj` is a JSON object with exactly `keys`. With `ordered`, the keys must
 * also appear in that order (needed for canonical payloads, whose re-encoding uses the
 * struct field order).
 */
function exactKeys(obj, keys, ordered) {
  if (!isJsonObject(obj)) return false;
  const actual = Object.keys(obj);
  if (actual.length !== keys.length) return false;
  if (ordered) return actual.every((k, i) => k === keys[i]);
  return keys.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

function parseJsonText(text, what) {
  try {
    return parseStrictJson(text);
  } catch (e) {
    if (e instanceof JsonError || e instanceof RangeError) throw err('envelope', `${what}: ${e.message}`);
    throw e;
  }
}

// ---------------------------------------------------------------------------------------
// Trust root

/**
 * @typedef {object} TrustSigner
 * @property {string} label
 * @property {string} operator
 * @property {string} publicKeyHex
 * @property {string} keyId    lowercase hex SHA-256 of the raw public key
 */

/**
 * @typedef {object} TrustRoot
 * @property {string} networkId
 * @property {number} threshold
 * @property {ReadonlyArray<TrustSigner>} signers
 * @property {(keyId: string) => Promise<{ signer: TrustSigner, key: CryptoKey } | null>} lookup
 */

const TRUST_ROOT_BRAND = Symbol('cybermesh.trustRoot');

/**
 * Parses and validates a trust root (`cybermesh_intelligence::TrustRoot` JSON). Throws
 * `ReleaseError('trust-root')` when it would not deserialize in Rust. A threshold of 0
 * parses (as in Rust) but every verification against it fails.
 *
 * @param {string | Uint8Array | ArrayBuffer | object} input
 * @returns {Promise<TrustRoot>}
 */
export async function parseTrustRoot(input) {
  let obj = input;
  if (typeof input === 'string' || input instanceof Uint8Array || input instanceof ArrayBuffer) {
    let text;
    try {
      text = typeof input === 'string' ? input : utf8DecodeStrict(toBytes(input));
      obj = parseStrictJson(text);
    } catch (e) {
      throw err('trust-root', `trust root is not valid JSON: ${e.message}`);
    }
  }
  if (!exactKeys(obj, ['network_id', 'threshold', 'signers'], false)) {
    throw err('trust-root', 'trust root must have exactly network_id, threshold, signers');
  }
  if (!isWellFormedString(obj.network_id)) throw err('trust-root', 'network_id must be a string');
  if (!isUint(obj.threshold, U8)) throw err('trust-root', 'threshold must be an integer 0..=255');
  if (!Array.isArray(obj.signers)) throw err('trust-root', 'signers must be an array');
  const signers = [];
  for (const s of obj.signers) {
    if (!exactKeys(s, ['label', 'operator', 'public_key'], false)) {
      throw err('trust-root', 'signer must have exactly label, operator, public_key');
    }
    if (!isWellFormedString(s.label)) throw err('trust-root', 'signer label must be a string');
    if (typeof s.operator !== 'string' || !OPERATOR_RE.test(s.operator)) {
      throw err('trust-root', 'operator id must be 2-32 chars of [a-z0-9-]');
    }
    const raw = typeof s.public_key === 'string' && s.public_key.length === 64 ? hexToBytes(s.public_key) : null;
    if (!raw || !isValidPointEncoding(raw) || isSmallOrderEncoding(raw)) {
      throw err('trust-root', 'public key must be 64 lowercase hex characters of a valid, non-weak Ed25519 key');
    }
    signers.push(
      Object.freeze({
        label: s.label,
        operator: s.operator,
        publicKeyHex: s.public_key,
        keyId: bytesToHex(await sha256(raw)),
        raw,
      }),
    );
  }
  const keyCache = new Map();
  const lookup = async (keyId) => {
    // First signer with this key id wins, like `Iterator::find` in Rust.
    const signer = signers.find((x) => x.keyId === keyId);
    if (!signer) return null;
    if (!keyCache.has(keyId)) keyCache.set(keyId, importEd25519PublicKey(signer.raw));
    let key;
    try {
      key = await keyCache.get(keyId);
    } catch (e) {
      keyCache.delete(keyId);
      throw err('trust-root', `cannot import Ed25519 key (WebCrypto Ed25519 unsupported?): ${e.message}`);
    }
    return { signer, key };
  };
  return Object.freeze({
    [TRUST_ROOT_BRAND]: true,
    networkId: obj.network_id,
    threshold: obj.threshold,
    signers: Object.freeze(signers.map(({ label, operator, publicKeyHex, keyId }) => Object.freeze({ label, operator, publicKeyHex, keyId }))),
    lookup,
  });
}

// ---------------------------------------------------------------------------------------
// DSSE envelope

/** DSSE pre-authentication encoding. */
export function pae(payloadType, payload) {
  const typeBytes = utf8Encode(payloadType);
  const header = utf8Encode(`DSSEv1 ${typeBytes.length} ${payloadType} ${payload.length} `);
  return concatBytes(header, payload);
}

/** `Envelope::parse`: size limit, strict JSON, exact fields, 1..=16 signatures. */
function parseEnvelope(bytes) {
  if (bytes.length > MAX_RELEASE_BYTES) {
    throw err('envelope', `envelope is ${bytes.length} bytes, limit ${MAX_RELEASE_BYTES}`);
  }
  let text;
  try {
    text = utf8DecodeStrict(bytes);
  } catch {
    throw err('envelope', 'envelope is not valid UTF-8');
  }
  const env = parseJsonText(text, 'malformed envelope');
  if (!exactKeys(env, ['payloadType', 'payload', 'signatures'], false)) {
    throw err('envelope', 'envelope must have exactly payloadType, payload, signatures');
  }
  if (!isWellFormedString(env.payloadType) || !isWellFormedString(env.payload) || !Array.isArray(env.signatures)) {
    throw err('envelope', 'envelope field has the wrong type');
  }
  for (const s of env.signatures) {
    if (!exactKeys(s, ['keyid', 'sig'], false) || !isWellFormedString(s.keyid) || !isWellFormedString(s.sig)) {
      throw err('envelope', 'signature must be {keyid, sig} strings');
    }
  }
  if (env.signatures.length === 0 || env.signatures.length > MAX_SIGNATURES) {
    throw err('envelope', `signature count must be 1..=${MAX_SIGNATURES}`);
  }
  return env;
}

/**
 * `Envelope::verify` with threshold 1: returns the payload bytes and the distinct trusted
 * key ids with valid signatures, in envelope order.
 */
async function verifyEnvelope(env, root) {
  if (env.payloadType !== RELEASE_PAYLOAD_TYPE) {
    throw err('envelope', `wrong payload type ${JSON.stringify(env.payloadType)}`);
  }
  const payload = decodeBase64Strict(env.payload);
  if (!payload) throw err('envelope', 'payload is not canonical padded base64');
  const message = pae(env.payloadType, payload);
  const seen = new Set();
  const signers = [];
  for (const s of env.signatures) {
    if (!KEY_ID_RE.test(s.keyid)) continue;
    if (seen.has(s.keyid)) continue;
    const found = await root.lookup(s.keyid);
    if (!found) continue;
    const sig = decodeBase64Strict(s.sig);
    if (!sig) continue;
    if (await verifyEd25519Strict(found.key, sig, message)) {
      seen.add(s.keyid);
      signers.push(s.keyid);
    }
  }
  return { payload, signers };
}

// ---------------------------------------------------------------------------------------
// Release payload schema (serde derive + canonical re-encoding)

const RELEASE_KEYS = ['v', 'network_id', 'sequence', 'previous', 'issued_at', 'expires_at', 'generator', 'inputs', 'entries', 'corrections'];
const REF_KEYS = ['sequence', 'digest'];
const ENTRY_KEYS = ['indicator', 'scope', 'action', 'confidence', 'risk_score_bp', 'operators', 'reasons', 'evidence'];
const REASON_KEYS = ['code', 'detail'];
const EVIDENCE_KEYS = ['kind', 'id', 'digest'];
const CORRECTION_KEYS = ['indicator', 'kind', 'reference', 'note'];

const isDigest = (v) => typeof v === 'string' && DIGEST_RE.test(v);
const oneOf = (v, options) => typeof v === 'string' && options.includes(v);

function schemaError(what) {
  return err('envelope', `release payload does not match the schema: ${what}`);
}

function checkReleaseSchema(r) {
  if (!exactKeys(r, RELEASE_KEYS, true)) throw schemaError('release fields');
  if (!isUint(r.v, U16)) throw schemaError('v');
  if (!isWellFormedString(r.network_id)) throw schemaError('network_id');
  if (!isUint(r.sequence, U64)) throw schemaError('sequence');
  if (r.previous !== null) {
    if (!exactKeys(r.previous, REF_KEYS, true) || !isUint(r.previous.sequence, U64) || !isDigest(r.previous.digest)) {
      throw schemaError('previous');
    }
  }
  if (!isUint(r.issued_at, U64) || !isUint(r.expires_at, U64)) throw schemaError('timestamps');
  if (!isWellFormedString(r.generator)) throw schemaError('generator');
  if (!Array.isArray(r.inputs) || !r.inputs.every(isDigest)) throw schemaError('inputs');
  if (!Array.isArray(r.entries)) throw schemaError('entries');
  for (const e of r.entries) {
    if (!exactKeys(e, ENTRY_KEYS, true)) throw schemaError('entry fields');
    if (!isWellFormedString(e.indicator)) throw schemaError('indicator');
    if (!oneOf(e.scope, SCOPES)) throw schemaError('scope');
    if (!oneOf(e.action, ACTIONS)) throw schemaError('action');
    if (!oneOf(e.confidence, CONFIDENCES)) throw schemaError('confidence');
    if (!isUint(e.risk_score_bp, U16)) throw schemaError('risk_score_bp');
    if (!isUint(e.operators, U8)) throw schemaError('operators');
    if (!Array.isArray(e.reasons) || !Array.isArray(e.evidence)) throw schemaError('reasons/evidence');
    for (const x of e.reasons) {
      if (!exactKeys(x, REASON_KEYS, true) || !oneOf(x.code, FINDING_CODES) || !isWellFormedString(x.detail)) {
        throw schemaError('reason');
      }
    }
    for (const x of e.evidence) {
      if (!exactKeys(x, EVIDENCE_KEYS, true) || !oneOf(x.kind, EVIDENCE_KINDS) || !isWellFormedString(x.id) || !isDigest(x.digest)) {
        throw schemaError('evidence');
      }
    }
  }
  if (!Array.isArray(r.corrections)) throw schemaError('corrections');
  for (const c of r.corrections) {
    if (
      !exactKeys(c, CORRECTION_KEYS, true) ||
      !isWellFormedString(c.indicator) ||
      !oneOf(c.kind, CORRECTION_KINDS) ||
      !isWellFormedString(c.reference) ||
      !isWellFormedString(c.note)
    ) {
      throw schemaError('correction');
    }
  }
}

/** `canonical::from_slice`: strict parse, schema, and byte-identical re-encoding. */
function decodeCanonicalRelease(payload) {
  let text;
  try {
    text = utf8DecodeStrict(payload);
  } catch {
    throw err('envelope', 'release payload is not valid UTF-8');
  }
  const release = parseJsonText(text, 'release payload');
  checkReleaseSchema(release);
  if (JSON.stringify(release) !== text) throw err('envelope', 'release payload is not canonical JSON');
  return release;
}

function compareStrings(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Derived `Ord` for `Correction`: indicator, kind (declaration order), reference, note. */
function compareCorrections(a, b) {
  return (
    compareStrings(a.indicator, b.indicator) ||
    CORRECTION_KINDS.indexOf(a.kind) - CORRECTION_KINDS.indexOf(b.kind) ||
    compareStrings(a.reference, b.reference) ||
    compareStrings(a.note, b.note)
  );
}

function checkState(state) {
  if (state === null || state === undefined) return null;
  if (!exactKeys(state, ['sequence', 'digest'], false) || !isUint(state.sequence, U64) || !isDigest(state.digest)) {
    throw err('state', 'anti-rollback state must be {sequence, digest}');
  }
  return state;
}

// ---------------------------------------------------------------------------------------
// verify_release

/**
 * @typedef {object} VerifiedRelease
 * @property {object} release        the decoded release payload
 * @property {string} digest         `sha256:<hex>` of the exact payload bytes
 * @property {string[]} signers      distinct trusted key ids with valid signatures
 * @property {string[]} operators    distinct signing operators, sorted
 */

/**
 * Verifies a release envelope offline. Throws `ReleaseError` on rejection.
 *
 * @param {string | Uint8Array | ArrayBuffer} input   raw envelope bytes (strings are UTF-8 encoded)
 * @param {TrustRoot} root                            from `parseTrustRoot`
 * @param {number} now                                Unix seconds
 * @param {{ sequence: number, digest: string } | null} [state]  last accepted release
 * @returns {Promise<VerifiedRelease>}
 */
export async function verifyRelease(input, root, now, state = null) {
  if (!root || root[TRUST_ROOT_BRAND] !== true) throw err('trust-root', 'trust root must come from parseTrustRoot');
  if (!isUint(now, U64)) throw err('invalid', 'now must be a non-negative integer number of seconds');
  const prior = checkState(state);
  const required = root.threshold;
  if (required === 0) throw err('invalid', 'trust root threshold must be >= 1');

  if (typeof input === 'string' && input.length > MAX_RELEASE_BYTES) {
    throw err('envelope', `envelope exceeds ${MAX_RELEASE_BYTES} bytes`);
  }
  const bytes = toBytes(input);
  if (!bytes) throw err('envelope', 'envelope must be bytes or a string');
  const env = parseEnvelope(bytes);
  const v = await verifyEnvelope(env, root);
  if (v.signers.length < 1) {
    throw err('threshold', `signatures from 0 distinct operators, ${required} required`);
  }
  const operatorSet = new Set();
  for (const id of v.signers) {
    const found = await root.lookup(id);
    if (found) operatorSet.add(found.signer.operator);
  }
  const operators = [...operatorSet].sort(compareStrings);
  if (operators.length < required) {
    throw err('threshold', `signatures from ${operators.length} distinct operators, ${required} required`);
  }

  const release = decodeCanonicalRelease(v.payload);
  if (release.v !== PROTOCOL_VERSION) throw err('version', `unsupported release version ${release.v}`);
  if (release.network_id !== root.networkId) {
    throw err('wrong-network', `release is for network ${release.network_id}`);
  }
  if (release.issued_at > now + MAX_RELEASE_SKEW_SECS) throw err('not-yet-valid', 'release issued in the future');
  if (now >= release.expires_at) throw err('expired', 'release expired');
  if (release.expires_at <= release.issued_at || release.expires_at - release.issued_at > MAX_RELEASE_TTL_SECS) {
    throw err('invalid', 'release lifetime out of range');
  }
  if (release.entries.length > MAX_ENTRIES) throw err('invalid', 'too many entries');
  let prev = null;
  for (const e of release.entries) {
    if (!isNormalizedDomain(e.indicator)) throw err('invalid', `bad indicator ${e.indicator}`);
    if (prev !== null && prev >= e.indicator) throw err('invalid', 'entries not sorted/unique');
    if (e.risk_score_bp > 10_000) throw err('invalid', 'score out of range');
    if (
      e.reasons.length > MAX_REASONS ||
      e.evidence.length > MAX_EVIDENCE ||
      e.reasons.some((r) => !isPrintable(r.detail, MAX_DETAIL)) ||
      e.evidence.some((r) => !isPrintable(r.id, MAX_REFERENCE))
    ) {
      throw err('invalid', `entry ${e.indicator} has oversized or non-printable fields`);
    }
    prev = e.indicator;
  }
  for (let i = 1; i < release.corrections.length; i++) {
    if (compareCorrections(release.corrections[i - 1], release.corrections[i]) >= 0) {
      throw err('invalid', 'corrections not sorted/unique');
    }
  }
  if (
    release.corrections.some(
      (c) =>
        !isPrintable(c.indicator, MAX_CORRECTION_INDICATOR) ||
        !isPrintable(c.reference, MAX_REFERENCE) ||
        !isPrintable(c.note, MAX_NOTE),
    )
  ) {
    throw err('invalid', 'correction has oversized or non-printable fields');
  }

  const digest = `sha256:${bytesToHex(await sha256(v.payload))}`;
  if (prior) {
    if (release.sequence < prior.sequence) {
      throw err('rollback', `rollback: release sequence ${release.sequence} is older than accepted sequence ${prior.sequence}`);
    }
    if (release.sequence === prior.sequence && digest !== prior.digest) {
      throw err('equivocation', `two different releases claim sequence ${release.sequence}`);
    }
    if (release.sequence - prior.sequence > MAX_SEQUENCE_JUMP) throw err('invalid', 'sequence jump too large');
    if (
      release.sequence === prior.sequence + 1 &&
      release.previous !== null &&
      (release.previous.sequence !== prior.sequence || release.previous.digest !== prior.digest)
    ) {
      throw err('invalid', 'previous-release link does not match the accepted release (fork)');
    }
  }
  return { release, digest, signers: v.signers, operators };
}
