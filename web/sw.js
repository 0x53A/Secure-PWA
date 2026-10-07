import { openStore } from './storage.js';
import { Updater } from './updater.js';
import { verifyRelease } from './verify.js';

const scope = self.registration.scope;
const root = new URL(scope);
const store = openStore(`secure-pwa:${root.pathname}`);
const updater = store.then(db => new Updater(db, verifyRelease, scope));
// No skipWaiting: replacing this browser-managed loader is separate from the
// application update protocol. The platform does not let us enforce pinning.
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
self.addEventListener('message', event => {
  const port = event.ports[0];
  if (!port || !event.source?.id) return;
  event.waitUntil((async () => {
    try {
      const client = await self.clients.get(event.source.id);
      if (!client || new URL(client.url).origin !== root.origin || !new URL(client.url).pathname.startsWith(root.pathname)) throw Error('Client outside app scope');
      const result = await (await updater).command(event.data?.type, event.data?.digest);
      port.postMessage({ ok: true, result });
      if (['STAGE', 'INSTALL', 'DISCARD'].includes(event.data?.type)) {
        for (const page of await self.clients.matchAll()) page.postMessage({ type: 'STATE_CHANGED' });
      }
    } catch (error) { port.postMessage({ ok: false, error: error?.message ?? String(error) }); }
  })());
});
const CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
function errorResponse(message, status = 503) {
  return new Response(message, { status, headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
}
self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== root.origin || !url.pathname.startsWith(root.pathname)) return;
  event.respondWith((async () => {
    const db = await store;
    const s = await db.state();
    const path = url.pathname.slice(root.pathname.length);
    // Downloads made by this worker go directly to fetch, without this handler.
    // Pages cannot accidentally execute bytes from release download endpoints.
    if (path.startsWith('releases/') || path === 'latest.json') return errorResponse('Use the update page', 403);
    if (request.method !== 'GET') return errorResponse('Method not allowed', 405);
    if (path === '' || path === 'index.html') {
      if (s.active) return Response.redirect(new URL(`_app/${s.active}/index.html`, root), 302);
      return fetch(request); // Initial bootstrap: explicitly outside attested app state.
    }
    const match = /^_app\/([a-f0-9]{64})\/(.+)$/.exec(path);
    if (match) {
      // Staged code cannot execute. Only previously activated versions are served.
      const release = await db.release(match[1]);
      if (!release?.installed && s.active !== match[1]) return errorResponse('Release is not installed', 404);
      const asset = release?.assets.find(a => a.path === match[2]);
      if (!asset) return errorResponse('Verified asset is missing', 404);
      const metadata = release.report.files.find(a => a.path === asset.path);
      const bytes = Uint8Array.from(atob(asset.content), c => c.charCodeAt(0));
      const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
      if (hash !== metadata?.sha256) return errorResponse('Stored asset failed integrity check');
      return new Response(bytes, { headers: {
        'Content-Type': metadata.media_type, 'Content-Security-Policy': CSP,
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
      } });
    }
    if (!s.active) return fetch(request);
    return errorResponse('Asset is outside the installed release', 404);
  })().catch(error => errorResponse(error.message)));
});
