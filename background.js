/**
 * BB-Extension Module1 background service worker.
 *
 * Captures every URL the browser loads via the webNavigation API, runs the
 * local XGBoost phishing model, and blocks high-threat pages with a warning
 * interstitial using the declarativeNetRequest API.
 */

import { loadModel, predict, classify } from './inference.js';
import { extractFeatures } from './features.js';

const MODEL_URL = chrome.runtime.getURL('model.json');

let modelReady = false;
let modelError = null;
const cache = new Map();
const recent = [];
const MAX_RECENT = 50;

// Scan threshold (>= 0.5 phishing probability => High Threat => block).
const THREAT_THRESHOLD = 0.73;

// One-time allow list: when the user chooses "Visit anyway" on the warning
// interstitial, the target URL is permitted once before the re-scan fires.
const allowOnce = new Map();
const ALLOW_ONCE_TTL_MS = 10000;


// Storage keys.
const STORAGE_KEYS = {
  enabled: 'bbExtensionModule1_blocking_enabled',
};

/** Default settings. */
let settings = {
  blockingEnabled: true,
};

async function init() {
  try {
    await loadModel(MODEL_URL);
    modelReady = true;
    console.log('[BB-Extension Module1] Model loaded.');
  } catch (err) {
    modelError = err;
    console.error('[BB-Extension Module1] Failed to load model:', err);
  }

  // Restore settings.
  const stored = await chrome.storage.sync.get(STORAGE_KEYS.enabled);
  settings.blockingEnabled =
    stored[STORAGE_KEYS.enabled] !== undefined
      ? stored[STORAGE_KEYS.enabled]
      : true;

  // Listen for setting changes from options/popup.
  chrome.storage.onChanged.addListener((changes) => {
    if (changes[STORAGE_KEYS.enabled]) {
      settings.blockingEnabled = changes[STORAGE_KEYS.enabled].newValue === true;
      console.log('[BB-Extension Module1] blockingEnabled =', settings.blockingEnabled);
    }
  });

  // Capture every navigation (main frame + subframes).
  chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate, {
    url: [{ urlPrefix: 'http' }],
  });

  console.log('[BB-Extension Module1] Service worker ready.');
}

/**
 * Called before each navigation. Scan the target URL. If high threat and
 * blocking is enabled, cancel this navigation and redirect to the warning
 * interstitial (carrying the scan result as query state).
 */
async function onBeforeNavigate(details) {
  if (!modelReady) {
    return; // model failed; fail open (don't block).
  }

  const { url, tabId, frameId } = details;

  // Skip extension pages (e.g. the warning interstitial itself) and
  // non-http(s) schemes; scan only main-frame navigations.
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;
  if (frameId !== 0) return;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return;
  } catch {
    return;
  }

  // One-time allow: user chose "Visit anyway" on the interstitial.
  const now = Date.now();
  const token = allowOnce.get(url);
  const allowedOnce = token && now - token < ALLOW_ONCE_TTL_MS;
  if (allowedOnce) allowOnce.delete(url);

  let result = cache.get(url);
  if (!result) {
    try {
      result = await scanUrl(url);
    } catch (err) {
      console.error('[BB-Extension Module1] scan failed for', url, err);
      return; // fail open.
    }
    cache.set(url, result);
  }
  recordRecent(url, result);

  // Skip SRP (search results page) - never block.
  const isSRP = /\/search\?|\/search\/|q=|search_query=|query=/i.test(url);

  if (result.block && settings.blockingEnabled && !allowedOnce && !isSRP && result.confidence > 0.9) {
    await blockNavigation(tabId, url, result);
  }
}

/** Run feature extraction + model inference for a URL. */
async function scanUrl(url) {
  const { feature_vector } = extractFeatures(url);
  const { probability, margin } = predict(feature_vector);
  const classification = classify(probability);

  // Block only when confidence > 90%.
  const block = classification.category === 'High Threat' && classification.confidence > 0.9;

  return {
    url,
    category: classification.category,
    confidence: classification.confidence,
    probability,
    margin,
    block,
    timestamp: Date.now(),
    features: null, // kept null in bg to save memory; popup can re-scan.
  };
}

/**
 * Cancel the in-flight navigation and open the warning interstitial.
 * We navigate the current tab to warning.html carrying scan state.
 */
async function blockNavigation(tabId, url, result) {
  try {
    await chrome.tabs.update(tabId, {
      url: `${chrome.runtime.getURL('warning.html')}?` +
        new URLSearchParams({
          url,
          category: result.category,
          confidence: String(result.confidence),
          probability: String(result.probability),
          timestamp: String(result.timestamp),
        }),
    });
  } catch (err) {
    // Tab may not be updatable (e.g. about:blank, extension pages).
    console.warn('[BB-Extension Module1] could not navigate tab', tabId, err);
  }
}

function recordRecent(url, result) {
  // Remove existing entry for this url so it moves to front.
  const idx = recent.findIndex((r) => r.url === url);
  if (idx !== -1) recent.splice(idx, 1);
  recent.unshift({ url, ...result });
  if (recent.length > MAX_RECENT) recent.pop();
}

/** Expose recent scans to popup via messaging. */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_RECENT') {
    sendResponse({ recent });
    return true;
  }
  if (message.type === 'GET_SETTINGS') {
    sendResponse(settings);
    return true;
  }
  if (message.type === 'GET_STATUS') {
    sendResponse({ modelReady, modelError: modelError ? modelError.message : null });
    return true;
  }
  if (message.type === 'SCAN_URL') {
    (async () => {
      try {
        const result = await scanUrl(message.url);
        cache.set(message.url, result);
        recordRecent(message.url, result);
        sendResponse({ ok: true, result });
      } catch (err) {
        sendResponse({ ok: false, error: err.message });
      }
    })();
    return true;
  }
  if (message.type === 'ALLOW_URL') {
    allowOnce.set(message.url, Date.now());
    sendResponse({ ok: true });
    return true;
  }
  if (message.type === 'TOGGLE_BLOCKING') {
    settings.blockingEnabled = !!message.enabled;
    chrome.storage.sync.set({ [STORAGE_KEYS.enabled]: settings.blockingEnabled });
    sendResponse({ ok: true, blockingEnabled: settings.blockingEnabled });
    return true;
  }
  return false;
});

init();
