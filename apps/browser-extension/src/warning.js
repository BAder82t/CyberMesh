// Warning interstitial. Everything shown here is looked up in the verified release by the
// service worker; the `d` URL parameter is only a lookup key. Release text (reasons) is
// untrusted and is rendered with textContent only.

import { falsePositiveUrl } from './lib/rules.js';

const $ = (id) => document.getElementById(id);
const indicator = new URLSearchParams(location.search).get('d') ?? '';
let releaseSequence = null;
let backSteps = 1;

async function send(msg) {
  const r = await chrome.runtime.sendMessage(msg);
  if (!r || !r.ok) throw new Error(r?.error ?? 'the extension did not answer');
  return r.result;
}

function setText(id, value) {
  $(id).textContent = value;
}

function showError(message) {
  const el = $('error');
  el.textContent = message;
  el.hidden = false;
}

function formatTime(secs) {
  return new Date(secs * 1000).toLocaleString();
}

function formatRisk(bp) {
  return `${(bp / 100).toFixed(bp % 100 === 0 ? 0 : 2)} / 100`;
}

async function goBack() {
  // Skip the browser's error page for the blocked URL when it is in the history (see
  // `backSteps` in controller.js); going back to it would only re-open this warning.
  try {
    const ctx = await send({ type: 'warningContext', indicator });
    backSteps = ctx.backSteps ?? backSteps;
  } catch {
    // Keep the value from the initial render.
  }
  if (history.length > backSteps) {
    history.go(-backSteps);
    return;
  }
  try {
    const tab = await chrome.tabs.getCurrent();
    await chrome.tabs.update(tab.id, { url: 'chrome://newtab/' });
  } catch {
    location.replace('about:blank');
  }
}

async function continueAnyway() {
  $('continue').disabled = true;
  try {
    await send({ type: 'continue', indicator });
  } catch (e) {
    $('continue').disabled = false;
    showError(`Could not continue: ${e.message}`);
  }
}

function report() {
  chrome.tabs.create({ url: falsePositiveUrl(indicator, releaseSequence) });
}

function renderNotFound(ctx) {
  const main = $('main');
  main.dataset.state = 'not-found';
  setText('heading', 'No current listing');
  const reasons = {
    expired: 'The CyberMesh intelligence has expired, so no sites are being blocked until a new release is verified.',
    'no-release': 'No verified CyberMesh release is loaded.',
    'not-listed': 'This host is not listed in the current verified release.',
  };
  setText('summary', reasons[ctx.reason] ?? reasons['not-listed']);
}

function render(ctx) {
  if (!ctx.found) {
    renderNotFound(ctx);
    return;
  }
  const { entry, release } = ctx;
  releaseSequence = release?.sequence ?? null;
  backSteps = ctx.backSteps ?? 1;
  const main = $('main');
  main.dataset.state = 'listed';
  main.dataset.action = entry.action;
  document.title = ctx.blockedByPolicy ? 'Blocked by policy - CyberMesh' : 'Warning - CyberMesh';
  setText('heading', ctx.blockedByPolicy ? 'Blocked by policy' : 'Warning');
  const host = ctx.attemptedHost ?? entry.indicator;
  setText(
    'summary',
    entry.action === 'block'
      ? `${host} is listed as a high-risk phishing or malicious site.`
      : `${host} is listed as suspicious. Continue only if you are sure it is legitimate.`,
  );
  setText('host', host);
  setText('indicator', entry.indicator);
  const cls = $('classification');
  cls.dataset.action = entry.action;
  cls.textContent =
    entry.action === 'block'
      ? 'block (high risk, independently corroborated)'
      : 'warn (advisory)';
  setText('confidence', entry.confidence);
  setText('risk', formatRisk(entry.risk_score_bp));
  setText('entry-operators', String(entry.operators));
  if (release) {
    setText('release', `sequence ${release.sequence}, network ${release.networkId}, valid until ${formatTime(release.expiresAt)}`);
    setText('signers', release.operators.join(', '));
  }
  $('details').hidden = false;

  const list = $('reasons');
  list.replaceChildren();
  for (const r of entry.reasons) {
    const li = document.createElement('li');
    const code = document.createElement('code');
    code.textContent = r.code;
    const detail = document.createElement('span');
    detail.textContent = r.detail;
    li.append(code, ' ', detail);
    list.append(li);
  }
  $('reasons-section').hidden = entry.reasons.length === 0;

  if (ctx.blockedByPolicy) {
    const note = $('policy-note');
    note.textContent = ctx.strict.managed
      ? 'Your administrator has enabled strict blocking: sites classified as "block" cannot be opened.'
      : 'Strict mode is on: sites classified as "block" cannot be opened. You can change this in the CyberMesh popup.';
    note.hidden = false;
  }
  $('continue').hidden = !ctx.canContinue;
  $('report').hidden = false;
}

$('back').addEventListener('click', () => {
  goBack();
});
$('continue').addEventListener('click', () => {
  continueAnyway();
});
$('report').addEventListener('click', report);

send({ type: 'warningContext', indicator }).then(render, (e) => {
  $('main').dataset.state = 'error';
  setText('heading', 'Warning');
  setText('summary', 'This site may be dangerous, but the details could not be loaded.');
  showError(e.message);
});
