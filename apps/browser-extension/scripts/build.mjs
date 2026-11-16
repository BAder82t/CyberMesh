#!/usr/bin/env node
// Builds the unpacked extension into dist/ (or --out) and, when the `zip` CLI exists, a zip.
//
//   node scripts/build.mjs [--trust-root <path>] [--release-url <url>] [--out <dir>]
//                          [--zip <path> | --no-zip]
//
// The trust root is validated with the same code the extension uses; the release URL's
// origin becomes the only host permission and the only non-extension connect-src.

import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { parseTrustRoot } from '../src/lib/verify.js';
import { validateConfig } from '../src/lib/controller.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(here, '..');
const srcDir = path.join(pkgRoot, 'src');
const defaultOut = path.join(pkgRoot, 'dist');
const EXTENSION_NAME = 'CyberMesh Phishing Shield';

const usage = `usage: node scripts/build.mjs (--trust-root <path> | --dev-trust-root) [--release-url <url>] [--out <dir>] [--zip <path> | --no-zip]`;

function fail(msg) {
  process.stderr.write(`build: ${msg}\n`);
  process.exit(1);
}

const { values } = parseArgs({
  options: {
    'trust-root': { type: 'string' },
    'dev-trust-root': { type: 'boolean' },
    'release-url': { type: 'string' },
    out: { type: 'string' },
    zip: { type: 'string' },
    'no-zip': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
  strict: true,
});
if (values.help) {
  process.stdout.write(`${usage}\n`);
  process.exit(0);
}

const defaults = JSON.parse(readFileSync(path.join(srcDir, 'config.json'), 'utf8'));
let config;
try {
  config = validateConfig({ release_url: values['release-url'] ?? defaults.release_url });
} catch (e) {
  fail(`invalid --release-url: ${e.message}`);
}
const releaseUrl = new URL(config.release_url);
const origin = releaseUrl.origin;
const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(releaseUrl.hostname);
if (releaseUrl.protocol === 'http:' && !loopback) {
  process.stderr.write(
    'build: warning: the release URL uses plain http. Releases are signed, so tampering is detected, ' +
      'but an observer can see that this browser downloads CyberMesh releases. Prefer https.\n',
  );
}

if (!values['trust-root'] && !values['dev-trust-root']) {
  fail('pass --trust-root <path> (or --dev-trust-root for the public test keys used in development)');
}
if (values['trust-root'] && values['dev-trust-root']) fail('use either --trust-root or --dev-trust-root');
const trustRootPath = path.resolve(values['trust-root'] ?? path.join(srcDir, 'trust-root.json'));
if (!existsSync(trustRootPath)) fail(`trust root not found: ${trustRootPath}`);
const trustRootText = readFileSync(trustRootPath, 'utf8');
let trustRoot;
try {
  trustRoot = await parseTrustRoot(trustRootText);
} catch (e) {
  fail(`invalid trust root ${trustRootPath}: ${e.message}`);
}
const operators = new Set(trustRoot.signers.map((s) => s.operator));
if (trustRoot.threshold < 1) fail('trust root threshold must be >= 1');
if (operators.size < trustRoot.threshold) {
  fail(`trust root needs ${trustRoot.threshold} distinct operators but lists only ${operators.size}`);
}
if (trustRoot.threshold < 2 || operators.size < 2) {
  process.stderr.write(
    `build: warning: trust root accepts releases signed by ${trustRoot.threshold} of ${operators.size} operator(s); ` +
      'a single compromised key could then publish releases. Use a threshold of at least 2.\n',
  );
}
if (values['dev-trust-root']) {
  process.stderr.write(
    'build: warning: using the bundled development trust root (deterministic test keys from ' +
      '`cybermesh dev test-vectors`). Anyone can sign releases for it; pass --trust-root for real use.\n',
  );
}

// Refuse to delete a directory that does not look like a previous build of this extension.
const out = path.resolve(values.out ?? defaultOut);
if (out === path.parse(out).root || out === pkgRoot || out === srcDir || pkgRoot.startsWith(`${out}${path.sep}`)) {
  fail(`refusing to use ${out} as the output directory`);
}
if (existsSync(out) && readdirSync(out).length > 0 && out !== defaultOut) {
  let previous = null;
  try {
    previous = JSON.parse(readFileSync(path.join(out, 'manifest.json'), 'utf8'));
  } catch {
    previous = null;
  }
  if (previous?.name !== EXTENSION_NAME) fail(`${out} is not empty and is not a previous build; refusing to overwrite`);
}
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(srcDir, out, { recursive: true });

writeFileSync(path.join(out, 'config.json'), `${JSON.stringify({ release_url: config.release_url }, null, 2)}\n`);
writeFileSync(path.join(out, 'trust-root.json'), trustRootText);

const manifestPath = path.join(out, 'manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.host_permissions = [`${origin}/*`];
manifest.content_security_policy = {
  extension_pages: [
    "default-src 'self'",
    "script-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    `connect-src 'self' ${origin}`,
  ].join('; '),
};
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

process.stdout.write(
  [
    `built ${manifest.name} ${manifest.version} -> ${out}`,
    `  release URL:     ${config.release_url}`,
    `  host permission: ${manifest.host_permissions[0]}`,
    `  trust root:      ${trustRootPath} (network ${trustRoot.networkId}, ${trustRoot.threshold} of ${operators.size} operators, ${trustRoot.signers.length} keys)`,
    '',
  ].join('\n'),
);

if (!values['no-zip']) {
  const zipPath = path.resolve(values.zip ?? path.join(pkgRoot, 'artifacts', `cybermesh-extension-${manifest.version}.zip`));
  const probe = spawnSync('zip', ['-v'], { stdio: 'ignore' });
  if (probe.error || probe.status !== 0) {
    process.stdout.write('  zip: skipped (the `zip` command is not available)\n');
  } else {
    mkdirSync(path.dirname(zipPath), { recursive: true });
    rmSync(zipPath, { force: true });
    const z = spawnSync('zip', ['-q', '-r', '-X', zipPath, '.'], { cwd: out, stdio: 'inherit' });
    if (z.status !== 0) fail('zip failed');
    process.stdout.write(`  zip:             ${zipPath}\n`);
  }
}
