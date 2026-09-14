'use strict';

// Root-scope service worker for Web Push (docs/worker-slim.md §5.6). No fetch
// handler and no caching: the Worker renders every page per request.
self.addEventListener('push', function (e) {
  var d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { /* opaque payload → generic notice */ }
  e.waitUntil(self.registration.showNotification(d.title || 'VT', {
    body: d.body || '', tag: d.tag, data: { url: d.url },
  }));
});

self.addEventListener('notificationclick', function (e) {
  e.notification.close();
  var url = e.notification.data && e.notification.data.url;
  if (url) e.waitUntil(self.clients.openWindow(url));
});
