// Strict JSON parser with serde_json's acceptance rules.
//
// `JSON.parse` silently keeps the last of duplicate object keys and accepts lone UTF-16
// surrogate escapes; the Rust verifier (serde_json + `deny_unknown_fields`) rejects both.
// This parser follows RFC 8259 exactly and additionally:
//   * rejects duplicate keys within one object;
//   * rejects `\uD800`-style escapes that do not form a valid surrogate pair;
//   * bounds nesting depth (serde_json's default recursion limit is 128);
//   * returns numbers with a fraction, an exponent, or `-0` as `JsonFloat` instances, so
//     that integer-typed fields reject them the way serde rejects floats for integers.
// Objects are created with a null prototype (keys such as `__proto__` are plain data).

export class JsonError extends Error {
  constructor(message) {
    super(message);
    this.name = 'JsonError';
  }
}

/** A JSON number that serde would treat as a float. */
export class JsonFloat {
  /** @param {number} value */
  constructor(value) {
    this.value = value;
  }

  toJSON() {
    return this.value;
  }
}

export const MAX_JSON_DEPTH = 128;

/**
 * @param {string} text
 * @param {{ maxDepth?: number }} [options]
 * @returns {unknown}
 */
export function parseStrictJson(text, options = {}) {
  if (typeof text !== 'string') throw new JsonError('input is not a string');
  const maxDepth = options.maxDepth ?? MAX_JSON_DEPTH;
  const n = text.length;
  let i = 0;

  const fail = (msg) => {
    throw new JsonError(`${msg} at offset ${i}`);
  };

  const skipWs = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const hex4 = () => {
    if (i + 4 > n) fail('truncated unicode escape');
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = text.charCodeAt(i++);
      let d;
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x57;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x37;
      else fail('invalid unicode escape');
      v = (v << 4) | d;
    }
    return v;
  };

  const parseString = () => {
    i++; // opening quote
    let out = '';
    let start = i;
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c === 0x5c) {
        out += text.slice(start, i);
        i++;
        if (i >= n) fail('unterminated escape');
        const e = text.charCodeAt(i++);
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += '\\'; break;
          case 0x2f: out += '/'; break;
          case 0x62: out += '\b'; break;
          case 0x66: out += '\f'; break;
          case 0x6e: out += '\n'; break;
          case 0x72: out += '\r'; break;
          case 0x74: out += '\t'; break;
          case 0x75: {
            const u = hex4();
            if (u >= 0xd800 && u <= 0xdbff) {
              if (text.charCodeAt(i) !== 0x5c || text.charCodeAt(i + 1) !== 0x75) {
                fail('lone leading surrogate in escape');
              }
              i += 2;
              const lo = hex4();
              if (lo < 0xdc00 || lo > 0xdfff) fail('lone leading surrogate in escape');
              out += String.fromCharCode(u, lo);
            } else if (u >= 0xdc00 && u <= 0xdfff) {
              fail('lone trailing surrogate in escape');
            } else {
              out += String.fromCharCode(u);
            }
            break;
          }
          default:
            fail('invalid escape');
        }
        start = i;
      } else if (c < 0x20) {
        fail('control character in string');
      } else {
        i++;
      }
    }
  };

  const isDigit = (c) => c >= 0x30 && c <= 0x39;

  const parseNumber = () => {
    const start = i;
    let isFloat = false;
    if (text.charCodeAt(i) === 0x2d) i++;
    const first = text.charCodeAt(i);
    if (first === 0x30) {
      i++;
    } else if (isDigit(first) && first !== 0x30) {
      while (i < n && isDigit(text.charCodeAt(i))) i++;
    } else {
      fail('invalid number');
    }
    if (text.charCodeAt(i) === 0x2e) {
      isFloat = true;
      i++;
      if (!isDigit(text.charCodeAt(i))) fail('invalid number');
      while (i < n && isDigit(text.charCodeAt(i))) i++;
    }
    const e = text.charCodeAt(i);
    if (e === 0x65 || e === 0x45) {
      isFloat = true;
      i++;
      const s = text.charCodeAt(i);
      if (s === 0x2b || s === 0x2d) i++;
      if (!isDigit(text.charCodeAt(i))) fail('invalid number');
      while (i < n && isDigit(text.charCodeAt(i))) i++;
    }
    const literal = text.slice(start, i);
    const value = Number(literal);
    if (isFloat || Object.is(value, -0)) return new JsonFloat(value);
    return value;
  };

  const literal = (word, value) => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail('invalid literal');
  };

  const parseValue = (depth) => {
    skipWs();
    if (i >= n) fail('unexpected end of input');
    const c = text.charCodeAt(i);
    switch (c) {
      case 0x7b: return parseObject(depth + 1);
      case 0x5b: return parseArray(depth + 1);
      case 0x22: return parseString();
      case 0x74: return literal('true', true);
      case 0x66: return literal('false', false);
      case 0x6e: return literal('null', null);
      default:
        if (c === 0x2d || isDigit(c)) return parseNumber();
        return fail('unexpected character');
    }
  };

  const parseArray = (depth) => {
    if (depth > maxDepth) fail('recursion limit exceeded');
    i++;
    const out = [];
    skipWs();
    if (text.charCodeAt(i) === 0x5d) {
      i++;
      return out;
    }
    for (;;) {
      out.push(parseValue(depth));
      skipWs();
      const c = text.charCodeAt(i);
      if (c === 0x2c) {
        i++;
        continue;
      }
      if (c === 0x5d) {
        i++;
        return out;
      }
      fail('expected , or ]');
    }
  };

  const parseObject = (depth) => {
    if (depth > maxDepth) fail('recursion limit exceeded');
    i++;
    const out = Object.create(null);
    skipWs();
    if (text.charCodeAt(i) === 0x7d) {
      i++;
      return out;
    }
    for (;;) {
      skipWs();
      if (text.charCodeAt(i) !== 0x22) fail('expected object key');
      const key = parseString();
      if (Object.prototype.hasOwnProperty.call(out, key)) fail(`duplicate key ${JSON.stringify(key)}`);
      skipWs();
      if (text.charCodeAt(i) !== 0x3a) fail('expected :');
      i++;
      out[key] = parseValue(depth);
      skipWs();
      const c = text.charCodeAt(i);
      if (c === 0x2c) {
        i++;
        continue;
      }
      if (c === 0x7d) {
        i++;
        return out;
      }
      fail('expected , or }');
    }
  };

  const value = parseValue(0);
  skipWs();
  if (i !== n) fail('trailing characters');
  return value;
}

/** True for a plain JSON object produced by `parseStrictJson` or `JSON.parse`. */
export function isJsonObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v) || v instanceof JsonFloat) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === null || proto === Object.prototype;
}
