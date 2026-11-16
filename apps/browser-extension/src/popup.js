// Popup: status of the verified release, strict mode, false-positive report, manual update.

import { falsePositiveUrl } from './lib/rules.js';

const $ = (id) => document.getElementById(id);

const MODES = {
  active: ['Protected', 'A verified release is in use.'],
  offline: ['Offline (cached)', 'The release server could not be reached; the cached release is still valid and in use.'],
  cached: ['Cached', 'The latest download was rejected; the previous verified release is still in use.'],
  degraded: ['Degraded', 'The release is verified, but its blocking rules could not be installed. Listed sites are only caught by the navigation check. Retrying on the next update.'],
  expired: ['Intelligence expired', 'The last verified release has expired. No sites are blocked until a new release is verified.'],
  none: ['No intelligence', 'No verified release has been downloaded yet.'],
  error: ['Error', 'The extension is misconfigured.'],
};

async function send(msg) {
  const r = await chrome.runtime.sendMessage(msg);
  if (!r || !r.ok) throw new Error(r?.error ?? 'the extension did not answer');
  return r.result;
}

function setText(id, value) {
  $(id).textContent = value;
}

function formatTime(ms) {
  return ms ? new Date(ms).toLocaleString() : 'never';
}

function renderStatus(s) {
  const [label, detail] = MODES[s.mode] ?? MODES.error;
  $('main').dataset.mode = s.mode;
  setText('mode', label);
  let modeDetail = detail;
  if (s.mode === 'expired' && s.expired?.expiresAt) {
    modeDetail += ` Release ${s.expired.sequence} expired at ${formatTime(s.expired.expiresAt * 1000)}.`;
  }
  if ((s.mode === 'offline' || s.mode === 'cached') && s.lastError) modeDetail += ` (${s.lastError})`;
  setText('mode-detail', modeDetail);

  const r = s.release;
  setText('sequence', r ? String(r.sequence) : '-');
  setText('block-count', r ? String(r.counts.block) : '0');
  setText('warn-count', r ? String(r.counts.warn) : '0');
  setText('expires', r ? formatTime(r.expiresAt * 1000) : '-');
  setText('operators', r ? r.operators.join(', ') : '-');
  setText('last-success', formatTime(s.lastSuccessAt));
  setText('last-attempt', s.lastAttemptAt ? `${formatTime(s.lastAttemptAt)}${s.lastAttemptOk ? '' : ' (failed)'}` : 'never');
  setText('network', s.networkId ? `${s.networkId} (requires signatures from ${s.threshold} distinct operators)` : '-');

  const problems = [...s.problems];
  if (s.mode === 'none' && s.lastError) problems.push(s.lastError);
  $('problems').hidden = problems.length === 0;
  setText('problems', problems.join(' '));

  const strict = $('strict');
  strict.checked = s.strict.effective;
  strict.disabled = s.strict.managed;
  const note = $('strict-note');
  note.hidden = !s.strict.managed;
  note.textContent = s.strict.managed ? 'Strict blocking is enforced by your administrator.' : '';
}

async function renderSite() {
  const button = $('report-site');
  let tab;
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch {
    tab = null;
  }
  if (!tab?.url) {
    setText('site-status', 'unavailable');
    return;
  }
  const info = await send({ type: 'siteInfo', url: tab.url });
  if (!info.host) {
    setText('site-status', 'not a web page');
    return;
  }
  if (!info.listed) {
    setText('site-status', `${info.host} is not listed`);
    button.disabled = true;
    button.title = 'Only listed sites can be reported as false positives.';
    return;
  }
  setText('site-status', `${info.host} is listed (${info.action}, indicator ${info.indicator})`);
  button.disabled = false;
  button.onclick = () => {
    chrome.tabs.create({ url: falsePositiveUrl(info.indicator, info.sequence) });
    window.close();
  };
}

async function refresh() {
  renderStatus(await send({ type: 'status' }));
}

$('strict').addEventListener('change', async (ev) => {
  try {
    renderStatus(await send({ type: 'setStrict', value: ev.target.checked }));
  } catch (e) {
    setText('problems', e.message);
    $('problems').hidden = false;
  }
});

$('update-now').addEventListener('click', async () => {
  const b = $('update-now');
  b.disabled = true;
  setText('update-now', 'Updating...');
  try {
    renderStatus(await send({ type: 'updateNow' }));
    await renderSite();
  } catch (e) {
    setText('problems', e.message);
    $('problems').hidden = false;
  } finally {
    b.disabled = false;
    setText('update-now', 'Update now');
  }
});

refresh()
  .then(renderSite)
  .catch((e) => {
    setText('problems', e.message);
    $('problems').hidden = false;
  });
