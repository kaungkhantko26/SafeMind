const CACHE_NAME = "safemind-v7";
const APP_SHELL = [
  "/welcome",
  "/",
  "/assets/green-wordmark.png",
  "/assets/green-logo.png"
];
self.addEventListener("install", (event) => event.waitUntil(
  caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
));
self.addEventListener("activate", (event) => event.waitUntil(
  caches.keys()
    .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))))
    .then(() => self.clients.claim())
));
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;
  // Browsers request media in byte ranges. Cache Storage cannot store the
  // resulting 206 Partial Content response, so always send range/media
  // requests directly to the network.
  if (event.request.headers.has("range") || url.pathname === "/assets/video.mp4") {
    event.respondWith(fetch(event.request));
    return;
  }
  if (url.pathname === "/simple" || url.pathname.startsWith("/assets/simple-")) {
    event.respondWith(fetch(event.request, { cache: "no-store" }));
    return;
  }
  event.respondWith(fetch(event.request).then((response) => {
    if (response.status === 200 && response.type === "basic" && !response.headers.get("Cache-Control")?.includes("no-store")) {
      const cacheWrite = caches.open(CACHE_NAME)
        .then((cache) => cache.put(event.request, response.clone()))
        .catch(() => undefined);
      void cacheWrite;
    }
    return response;
  }).catch(() => caches.match(event.request).then((cached) => cached || (event.request.mode === "navigate" ? caches.match("/") : Response.error()))));
});
