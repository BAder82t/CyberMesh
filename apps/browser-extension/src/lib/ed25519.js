// Ed25519 verification with the same acceptance rules as ed25519-dalek's `verify_strict`,
// which the Rust verifier uses. WebCrypto performs the curve arithmetic; the extra checks
// that differ between implementations are done here explicitly:
//   * public keys must decode to a curve point and must not have small order (weak keys);
//   * the signature's R must not have small order;
//   * the signature's S must be a canonical scalar (S < L).
// The checks only reject; they never make a signature valid that WebCrypto rejects.

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function mod(a) {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function powMod(base, exp) {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

const D = mod(-121665n * powMod(121666n, P - 2n));

function leToBigInt(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/** The y coordinate of a compressed Edwards point, reduced mod p (sign bit cleared). */
function decodeY(bytes32) {
  const b = Uint8Array.from(bytes32);
  b[31] &= 0x7f;
  return mod(leToBigInt(b));
}

function hexLe(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// y coordinates of the eight small-order points (orders 1, 2, 4 and 8).
const Y_ORDER_8 = decodeY(hexLe('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'));
const SMALL_ORDER_Y = new Set([0n, 1n, P - 1n, Y_ORDER_8, P - Y_ORDER_8]);

/**
 * True when 32 bytes decode to a point on edwards25519 (curve25519-dalek `decompress`
 * semantics: the y coordinate is reduced mod p, x = 0 with the sign bit set is accepted).
 * @param {Uint8Array} bytes32
 * @returns {boolean}
 */
export function isValidPointEncoding(bytes32) {
  if (!(bytes32 instanceof Uint8Array) || bytes32.length !== 32) return false;
  const y = decodeY(bytes32);
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const x2 = (u * powMod(v, P - 2n)) % P;
  if (x2 === 0n) return true;
  return powMod(x2, (P - 1n) / 2n) === 1n;
}

/**
 * True when 32 bytes encode a small-order point (one of the eight torsion points, in any
 * encoding).
 * @param {Uint8Array} bytes32
 * @returns {boolean}
 */
export function isSmallOrderEncoding(bytes32) {
  return SMALL_ORDER_Y.has(decodeY(bytes32));
}

/**
 * True when a 32-byte little-endian scalar is reduced (S < L).
 * @param {Uint8Array} bytes32
 * @returns {boolean}
 */
export function isCanonicalScalar(bytes32) {
  return leToBigInt(bytes32) < L;
}

/**
 * Imports a raw Ed25519 public key for verification. Throws when WebCrypto lacks Ed25519.
 * @param {Uint8Array} raw32
 * @returns {Promise<CryptoKey>}
 */
export function importEd25519PublicKey(raw32) {
  return crypto.subtle.importKey('raw', raw32, { name: 'Ed25519' }, false, ['verify']);
}

/**
 * Strict Ed25519 verification. Never throws for malformed signatures; returns false.
 * @param {CryptoKey} key
 * @param {Uint8Array} signature
 * @param {Uint8Array} message
 * @returns {Promise<boolean>}
 */
export async function verifyEd25519Strict(key, signature, message) {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  const r = signature.subarray(0, 32);
  const s = signature.subarray(32, 64);
  if (!isCanonicalScalar(s)) return false;
  if (isSmallOrderEncoding(r)) return false;
  try {
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
  } catch {
    return false;
  }
}
