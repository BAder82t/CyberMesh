// CyberMesh service worker: wires extension events to the controller. All listeners are
// registered synchronously at the top level, as Manifest V3 requires.

import { createController } from './lib/controller.js';

async function loadPackaged(path) {
  const resp = await fetch(chrome.runtime.getURL(path), { cache: 'no-store' });
  if (!resp.ok) throw new Error(`cannot read packaged ${path}`);
  return resp.text();
}

const controller = createController({
  chrome,
  fetchImpl: (url, init) => fetch(url, init),
  loadConfig: async () => JSON.parse(await loadPackaged('config.json')),
  loadTrustRootText: () => loadPackaged('trust-root.json'),
});

const report = (e) => console.error('CyberMesh:', e);
const HTTP_ONLY = { url: [{ schemes: ['http', 'https'] }] };
const EXTENSION_ORIGIN = chrome.runtime.getURL('');

chrome.runtime.onInstalled.addListener(() => {
  controller.update().catch(report);
});
chrome.runtime.onStartup.addListener(() => {
  controller.update().catch(report);
});
chrome.alarms.onAlarm.addListener((alarm) => {
  controller.onAlarm(alarm).catch(report);
});
chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  controller.onBeforeNavigate(d).catch(report);
}, HTTP_ONLY);
chrome.webNavigation.onErrorOccurred.addListener((d) => {
  controller.onNavigationError(d).catch(report);
}, HTTP_ONLY);
chrome.tabs.onRemoved.addListener((tabId) => {
  controller.onTabRemoved(tabId).catch(report);
});
chrome.storage.onChanged.addListener((changes, area) => {
  controller.onStorageChanged(changes, area).catch(report);
});
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only this extension's own pages (popup, warning page) may talk to the worker.
  if (sender.id !== chrome.runtime.id || typeof sender.url !== 'string' || !sender.url.startsWith(EXTENSION_ORIGIN)) {
    return false;
  }
  controller.handleMessage(msg, sender).then(
    (result) => sendResponse({ ok: true, result }),
    (e) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }),
  );
  return true;
});

// Restore protection from the cached release (re-verified) whenever the worker starts.
controller.ready().catch(report);
