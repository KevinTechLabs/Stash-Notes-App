// Stash v2 offline support: keeps the app files on the phone so it opens without internet.
const CACHE = 'stash-v2-8';
const FILES = ['./', './index.html', './app.js', './vendor/argon2.js', './vendor/argon2-glue.js', './vendor/argon2.wasm', './manifest.json', './icon-192.png', './icon-512.png', './icon-maskable-512.png', './apple-touch-icon.png'];
// Always fetch fresh copies (bypassing the browser's own cache) so an update never mixes old and new files.
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES.map(f => new Request(f, {cache: 'no-store'})))).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;   // Stash never loads anything from other sites
  if (req.mode === 'navigate'){
    // Fresh copy when online, saved copy when offline
    e.respondWith(fetch(req, {cache: 'no-store'}).then(r => { const c = r.clone(); caches.open(CACHE).then(x => x.put('./index.html', c)); return r; }).catch(() => caches.match('./index.html')));
    return;
  }
  e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(r => {
    if (r.ok){ const c = r.clone(); caches.open(CACHE).then(x => x.put(req, c)); }
    return r;
  })));
});
