const CACHE = 'patrol-cache-v1';
const ASSETS = [
    '/static/styles.css',
    '/static/app.js',
    '/static/favicon.svg',
    '/manifest.webmanifest'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.origin !== location.origin) return;

    // Страницы: сеть → кэш (чтобы открывались офлайн)
    if (req.mode === 'navigate') {
        event.respondWith(
            fetch(req)
                .then((resp) => {
                    const copy = resp.clone();
                    caches.open(CACHE).then((cache) => cache.put(req, copy));
                    return resp;
                })
                .catch(() => caches.match(req).then((hit) => hit || caches.match('/')))
        );
        return;
    }

    // Статика: кэш → сеть
    if (url.pathname.startsWith('/static/')) {
        event.respondWith(
            caches.match(req).then((hit) => hit || fetch(req).then((resp) => {
                const copy = resp.clone();
                caches.open(CACHE).then((cache) => cache.put(req, copy));
                return resp;
            }))
        );
    }
});
