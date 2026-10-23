// Service worker портала NoNetPass: оболочка портала открывается и без связи
// с сервером (видно, что сеть пропала), а живое состояние идёт по WebSocket.
// API и WebSocket не кешируются никогда.
const CACHE = "nonetpass-v3";
const SHELL = ["/", "/manifest.webmanifest", "/static/icon.svg", "/static/icon-192.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin) return;
  if (!SHELL.includes(url.pathname)) return;
  // Сначала сеть: портал всегда свежий, кеш только на случай обрыва.
  event.respondWith(
    fetch(event.request)
      .then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        return resp;
      })
      .catch(() => caches.match(event.request))
  );
});
