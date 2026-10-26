/**
 * Popup UI for BB-Extension Module1.
 *
 * Talks to the background service worker via runtime.sendMessage:
 * - GET_STATUS: model readiness
 * - SCAN_URL: scan the active tab's URL on demand
 * - TOGGLE_BLOCKING: enable/disable blocking
 * - GET_RECENT: list recent scans
 */

const statusEl = document.getElementById('status');
const scanBtn = document.getElementById('scanBtn');
const blockToggle = document.getElementById('blockToggle');
const blockLabel = document.getElementById('blockLabel');
const recentList = document.getElementById('recentList');

let blockingEnabled = true;

/** Send a message to the background worker and await its response. */
function send(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (res) => {
      // chrome.runtime.lastError may be set if the worker isn't ready yet.
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message });
      } else {
        resolve(res || {});
      }
    });
  });
}

function setStatus(text, kind) {
  statusEl.textContent = text;
  statusEl.className = 'status ' + (kind || '');
}

function renderRecent(recent) {
  recentList.innerHTML = '';
  if (!recent || recent.length === 0) {
    recentList.innerHTML = '<div class="empty">No scans yet.</div>';
    return;
  }
  for (const item of recent) {
    const el = document.createElement('div');
    el.className = 'item';
    const isThreat = item.category === 'High Threat';
    el.innerHTML = `
      <div class="item-info">
        <div class="item-url">${escapeHtml(item.url)}</div>
        <div class="item-meta">
          ${item.category} &#8226; ${(item.confidence * 100).toFixed(1)}% confidence
          &#8226; ${new Date(item.timestamp).toLocaleTimeString()}
        </div>
      </div>
      <div class="item-badge ${isThreat ? '' : 'legit'}">
        ${isThreat ? 'BLOCKED' : 'OK'}
      </div>
    `;
    recentList.appendChild(el);
  }
}

function escapeHtml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function loadStatus() {
  const res = await send({ type: 'GET_STATUS' });
  if (res.error) {
    setStatus('Extension starting…', '');
    return;
  }
  if (!res.modelReady) {
    setStatus('Model not loaded: ' + (res.modelError || 'unknown'), 'err');
    scanBtn.disabled = true;
    return;
  }
  setStatus('Model ready &#8226; local XGBoost', 'ok');
}

async function loadRecent() {
  const res = await send({ type: 'GET_RECENT' });
  renderRecent(res.recent);
}

async function loadSettings() {
  const res = await send({ type: 'GET_SETTINGS' });
  blockingEnabled = res.blockingEnabled !== false;
  blockToggle.checked = blockingEnabled;
  blockLabel.textContent = blockingEnabled
    ? 'Block high-threat sites'
    : 'Blocking disabled';
}

async function scanActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    setStatus('No scannable tab.', '');
    return;
  }
  // Don't scan extension/interstitial pages.
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
    setStatus('Cannot scan this page.', '');
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning…';
  setStatus('Scanning ' + new URL(tab.url).hostname + '…', '');

  try {
    const res = await send({ type: 'SCAN_URL', url: tab.url });
    if (!res.ok) {
      setStatus('Scan failed: ' + res.error, 'err');
      return;
    }
    const r = res.result;
    const isThreat = r.category === 'High Threat';
    setStatus(
      isThreat
        ? `High threat: ${(r.confidence * 100).toFixed(1)}%`
        : `Legitimate: ${(r.confidence * 100).toFixed(1)}%`,
      isThreat ? 'err' : 'ok'
    );
    await loadRecent();
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan current tab';
  }
}

scanBtn.addEventListener('click', scanActiveTab);

blockToggle.addEventListener('change', async () => {
  blockingEnabled = blockToggle.checked;
  blockLabel.textContent = blockingEnabled
    ? 'Block high-threat sites'
    : 'Blocking disabled';
  await send({ type: 'TOGGLE_BLOCKING', enabled: blockingEnabled });
  setStatus(
    blockingEnabled ? 'Blocking enabled' : 'Blocking disabled',
    ''
  );
});

// Init.
loadStatus();
loadSettings();
loadRecent();
