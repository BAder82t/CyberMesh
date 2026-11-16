#!/usr/bin/env node
// Lint: `node --check` on every .js/.mjs file, JSON validity, and a few policy checks for
// the extension sources (no inline scripts, no eval/Function, no innerHTML-style sinks).

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP = new Set(['node_modules', 'dist', 'artifacts', 'fixtures']);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name) || name.startsWith('.')) continue;
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const files = ['src', 'scripts', 'test'].flatMap((d) => walk(path.join(root, d)));
const problems = [];
let checked = 0;

for (const f of files) {
  const rel = path.relative(root, f);
  if (f.endsWith('.js') || f.endsWith('.mjs')) {
    const r = spawnSync(process.execPath, ['--check', f], { encoding: 'utf8' });
    if (r.status !== 0) problems.push(`${rel}: ${r.stderr.trim()}`);
    checked++;
  } else if (f.endsWith('.json')) {
    try {
      JSON.parse(readFileSync(f, 'utf8'));
    } catch (e) {
      problems.push(`${rel}: invalid JSON: ${e.message}`);
    }
    checked++;
  }
  if (!rel.startsWith(`src${path.sep}`)) continue;
  const text = readFileSync(f, 'utf8');
  if (f.endsWith('.html')) {
    if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(text)) problems.push(`${rel}: inline <script>`);
    if (/\son[a-z]+\s*=/i.test(text)) problems.push(`${rel}: inline event handler`);
    if (/<(script|link|img)[^>]+(src|href)=["']https?:/i.test(text)) problems.push(`${rel}: remote resource`);
  }
  if (f.endsWith('.js')) {
    for (const [re, what] of [
      [/\beval\s*\(/, 'eval'],
      [/\bnew\s+Function\s*\(/, 'new Function'],
      [/\.(innerHTML|outerHTML)\s*=/, 'innerHTML/outerHTML assignment'],
      [/insertAdjacentHTML|document\.write/, 'HTML string sink'],
      [/console\.log\(/, 'console.log'],
    ]) {
      if (re.test(text)) problems.push(`${rel}: ${what}`);
    }
  }
}

if (problems.length > 0) {
  process.stderr.write(`${problems.join('\n')}\n`);
  process.exit(1);
}
process.stdout.write(`lint: ${checked} files OK\n`);
