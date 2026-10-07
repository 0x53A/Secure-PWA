import init, { render_status } from './pkg/secure_pwa.js';
const root = new URL(document.querySelector('meta[name="app-base"]').content, location.origin);
const message = document.querySelector('#message');
const app = document.querySelector('#app');
let busy = false;
let registration;
function notice(text, error = false) { message.textContent = text; message.classList.toggle('error', error); }
async function rpc(type, digest) {
  const worker = navigator.serviceWorker.controller ?? registration?.active;
  if (!worker) throw Error('Updater is not ready');
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timeout = setTimeout(() => { channel.port1.close(); reject(Error('Updater timed out; check its status before retrying')); }, 180000);
    channel.port1.onmessage = ({ data }) => {
      clearTimeout(timeout); channel.port1.close();
      if (data.ok) resolve(data.result); else reject(Error(data.error));
    };
    worker.postMessage({ type, digest }, [channel.port2]);
  });
}
function render(state) { app.innerHTML = render_status(JSON.stringify(state)); }
function download(name, bytes, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
app.addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button || busy) return;
  const { action, digest } = button.dataset;
  busy = true;
  app.querySelectorAll('button').forEach(b => b.disabled = true);
  notice({ STAGE: 'Downloading and verifying…', INSTALL: 'Verifying staged files…', DISCARD: 'Discarding…', EXPORT: 'Preparing files…' }[action]);
  try {
    const result = await rpc(action, digest);
    if (action === 'INSTALL') { location.replace(root); return; }
    if (action === 'EXPORT') {
      // One download avoids browser restrictions on multiple automatic downloads.
      download(`secure-pwa-${digest}.json`, JSON.stringify({ release_base64: bytesBase64(result.bytes), attestation: JSON.parse(result.attestation) }), 'application/json');
      notice('Verification files downloaded.');
    } else {
      render(result);
      notice(action === 'STAGE' ? 'Update verified and staged.' : 'Staged update discarded.');
    }
  } catch (e) { notice(e.message ?? String(e), true); }
  finally { busy = false; app.querySelectorAll('button').forEach(b => b.disabled = false); }
});
function bytesBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary);
}
navigator.serviceWorker?.addEventListener('message', async ({ data }) => {
  if (data?.type === 'STATE_CHANGED' && !busy) {
    try { render(await rpc('STATUS')); } catch (e) { notice(e.message, true); }
  }
});
try {
  if (!isSecureContext || !('serviceWorker' in navigator)) throw Error('Use HTTPS or localhost in a browser with service workers.');
  await init();
  registration = await navigator.serviceWorker.register(new URL('sw.js', root), { scope: root.pathname, updateViaCache: 'none' });
  await navigator.serviceWorker.ready;
  render(await rpc('STATUS'));
  notice('');
} catch (e) { notice(e.message ?? String(e), true); }
