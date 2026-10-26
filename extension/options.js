/**
 * Options page: persists blockingEnabled to chrome.storage.sync.
 */

const toggle = document.getElementById('blockToggle');

function send(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (res) => {
      resolve(res || {});
    });
  });
}

async function load() {
  const res = await send({ type: 'GET_SETTINGS' });
  toggle.checked = res.blockingEnabled !== false;
}

toggle.addEventListener('change', async () => {
  await send({ type: 'TOGGLE_BLOCKING', enabled: toggle.checked });
});

load();
