'use strict';

// Root-scope service worker for Web Push (docs/worker-slim.md#installed-app). No fetch
// handler and no caching: the Worker renders every page per request.

// Take over the installed app on the next launch instead of waiting for every
// window to close: a fixed worker that only applies days later is not a fix.
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

// The approval a tap (or a live app) should land on, handed to the page rather
// than navigated from here: an iOS home-screen app answers a notification tap
// by showing its start page, overriding whatever the worker navigates. A page
// asks for it on load and navigates itself, so a cold launch lands there too.
// Approval tokens expire in minutes; an older one is not worth a jump.
var PENDING_MAX_MS = 3 * 60 * 1000;
var pending = null;

function setPending(url) { pending = { url: url, at: Date.now() }; }

function sendPending(target) {
  if (!pending || Date.now() - pending.at > PENDING_MAX_MS) { pending = null; return; }
  target.postMessage({ type: 'vt-navigate', url: pending.url });
  pending = null;   // one jump per notification; a spent token only renders 410
}

self.addEventListener('message', function (e) {
  if (e.data && e.data.type === 'vt-pending' && e.source) sendPending(e.source);
});

// The app's own window, preferring the one the operator is looking at. Focusing
// it beats openWindow(), which creates an auxiliary context that iOS home-screen
// apps present as an in-app browser — its own domain bar and back/reload/share
// toolbar, a page that cannot close itself.
function appWindow() {
  return self.clients.matchAll({ type: 'window' }).then(function (list) {
    var best = null;
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (c.url.lastIndexOf(self.registration.scope, 0) !== 0) continue;
      if (c.focused) return c;
      if (!best || c.visibilityState === 'visible') best = c;
    }
    return best;
  });
}

self.addEventListener('push', function (e) {
  var d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { /* opaque payload → generic notice */ }
  e.waitUntil(self.registration.showNotification(d.title || 'vt', {
    body: d.body || '', tag: d.tag, data: { url: d.url },
  }).then(function () {
    // An approval is time-boxed, so an app that is already open shows the
    // request itself rather than waiting for the tap. Cache-hit notices are
    // read-only news and never take the screen. No focus() here: without a
    // user gesture it is not permitted.
    if (!d.url || (d.kind !== 'approval' && d.kind !== 'enroll')) return;
    setPending(d.url);
    return appWindow().then(function (c) { if (c) sendPending(c); });
  }).catch(function () { /* the notification is shown; navigation is a bonus */ }));
});

self.addEventListener('notificationclick', function (e) {
  e.notification.close();
  var url = e.notification.data && e.notification.data.url;
  if (!url) return;
  setPending(url);
  e.waitUntil(appWindow().then(function (c) {
    if (!c) return self.clients.openWindow(url);
    sendPending(c);
    return c.focus();
  }));
});
