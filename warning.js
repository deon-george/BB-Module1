/**
 * Warning interstitial: render scan state carried in the query string and
 * handle "Visit anyway" (re-open the original URL) / "Go back".
 */

(function () {
  const params = new URLSearchParams(location.search.slice(1));

  const url = params.get('url') || '—';
  const category = params.get('category') || 'High Threat';
  const confidence = parseFloat(params.get('confidence') || '0');
  const timestamp = parseInt(params.get('timestamp') || '0', 10);

  document.getElementById('displayUrl').textContent = url;
  document.getElementById('displayCategory').textContent = category;
  document.getElementById('displayConfidence').textContent =
    (confidence * 100).toFixed(1) + '%';
  document.getElementById('confBar').style.setProperty(
    '--conf-w',
    (confidence * 100).toFixed(1) + '%'
  );

  if (timestamp) {
    const when = new Date(timestamp).toLocaleTimeString();
    const fine = document.querySelector('.fine');
    if (fine) {
      fine.textContent += ` Blocked at ${when}.`;
    }
  }

  document.getElementById('goBack').addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      const tab = await chrome.tabs.getCurrent();
      if (tab && tab.id) {
        await chrome.tabs.update(tab.id, { url: 'chrome://newtab/' });
        return;
      }
    } catch (err) {
      console.warn('[BB-Extension Module1] goBack failed:', err);
    }
    location.href = 'chrome://newtab/';
  });

  document.getElementById('visitAnyway').addEventListener('click', async (e) => {
    e.preventDefault();
    // Allow this URL through once, then navigate to it.
    try {
      await chrome.runtime.sendMessage({ type: 'ALLOW_URL', url });
    } catch (err) {
      console.warn('[BB-Extension Module1] allow-list message failed:', err);
    }
    location.href = url;
  });
})();
