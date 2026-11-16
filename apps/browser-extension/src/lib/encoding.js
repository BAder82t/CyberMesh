// Byte encodings used by the release verifier. No dependencies; runs in the extension
// service worker, extension pages and Node (unit tests).

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < B64_ALPHABET.length; i++) B64_LOOKUP[B64_ALPHABET.charCodeAt(i)] = i;

function b64Value(s, i) {
  const c = s.charCodeAt(i);
  return c < 128 ? B64_LOOKUP[c] : -1;
}

/**
 * Strict standard base64 decoding, equivalent to the Rust `base64` crate's `STANDARD`
 * engine: alphabet `A-Z a-z 0-9 + /`, canonical `=` padding required, no whitespace, and
 * the unused trailing bits of the last symbol must be zero.
 *
 * @param {unknown} s
 * @returns {Uint8Array | null} decoded bytes, or null when the input is not canonical base64
 */
export function decodeBase64Strict(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0) return null;
  const n = s.length;
  let pad = 0;
  if (n > 0 && s.charCodeAt(n - 1) === 0x3d) pad = s.charCodeAt(n - 2) === 0x3d ? 2 : 1;
  const out = new Uint8Array((n / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < n; i += 4) {
    const last = i + 4 === n;
    const c0 = b64Value(s, i);
    const c1 = b64Value(s, i + 1);
    if (c0 < 0 || c1 < 0) return null;
    if (last && pad === 2) {
      if ((c1 & 0x0f) !== 0) return null;
      out[o++] = (c0 << 2) | (c1 >> 4);
      break;
    }
    const c2 = b64Value(s, i + 2);
    if (c2 < 0) return null;
    if (last && pad === 1) {
      if ((c2 & 0x03) !== 0) return null;
      out[o++] = (c0 << 2) | (c1 >> 4);
      out[o++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
      break;
    }
    const c3 = b64Value(s, i + 3);
    if (c3 < 0) return null;
    out[o++] = (c0 << 2) | (c1 >> 4);
    out[o++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
    out[o++] = ((c2 & 0x03) << 6) | c3;
  }
  return out;
}

/** Standard padded base64 encoding (used by tests and tooling). */
export function encodeBase64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64_ALPHABET[v >> 18] + B64_ALPHABET[(v >> 12) & 63] + B64_ALPHABET[(v >> 6) & 63] + B64_ALPHABET[v & 63];
  }
  if (i < bytes.length) {
    const rest = bytes.length - i;
    const v = (bytes[i] << 16) | (rest === 2 ? bytes[i + 1] << 8 : 0);
    out += B64_ALPHABET[v >> 18] + B64_ALPHABET[(v >> 12) & 63];
    out += rest === 2 ? B64_ALPHABET[(v >> 6) & 63] + '=' : '==';
  }
  return out;
}

const HEX_RE = /^(?:[0-9a-f]{2})*$/;

/** Lowercase hex to bytes; null unless the input is even-length lowercase hex. */
export function hexToBytes(s) {
  if (typeof s !== 'string' || !HEX_RE.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

const encoder = new TextEncoder();

export function utf8Encode(s) {
  return encoder.encode(s);
}

/**
 * Strict UTF-8 decoding: invalid sequences throw, and a leading byte-order mark is kept
 * (so that a JSON parser rejects it, as serde_json does).
 *
 * @returns {string}
 */
export function utf8DecodeStrict(bytes) {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}

/** Normalises Uint8Array | ArrayBuffer | ArrayBufferView | string to a Uint8Array. */
export function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof input === 'string') return utf8Encode(input);
  return null;
}

export function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function sha256Hex(bytes) {
  return bytesToHex(await sha256(bytes));
}
