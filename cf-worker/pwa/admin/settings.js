'use strict';

// Settings tab: the Passkeys block (setup.js, mounted on its #tab-setup
// sub-panel), the session (logout / log out everywhere), the config knobs (hit
// notify, UV policy — GET/PUT /api/admin/config), SECRET rotation, and push
// subscriptions — this device subscribes with the Worker's VAPID key and posts
// the result; every row can be tested or removed. Rendering is textContent
// only; the endpoint's keys never come back from the server.

vt.tabs.settings = function (panel, data) {
  var $ = function (sel) { return panel.querySelector(sel); };
  var setStatus = vt.statusLine($('#subs').parentNode.parentNode.querySelector('.status'));
  var sessionStatus = vt.statusLine($('#session-status'));
  var el = vt.el, fmtTime = vt.fmtTime;
  var subs = [];
  var mine = null;

  async function post(op, body) {
    var resp = await vt.postJson('push/' + op, body);
    if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + (await resp.text()));
    return resp.json();
  }

  // ── Config ────────────────────────────────────────────────────────────────
  var cfgStatus = vt.statusLine($('#cfg-status'));

  async function loadConfig() {
    var resp = await vt.apiFetch(vt.api('config'), { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) { cfgStatus('Config load failed: HTTP ' + resp.status, 'error'); return; }
    var c = await resp.json();
    $('#cfg-hit-notify').checked = !!c.cache_hit_notify;
    $('#cfg-uv').value = c.uv_policy == null ? '' : JSON.stringify(c.uv_policy);
  }

  $('#cfg-save').addEventListener('click', async function () {
    var btn = this; btn.disabled = true;
    try {
      var raw = $('#cfg-uv').value.trim();
      var uv = null;
      if (raw) {
        try { uv = JSON.parse(raw); } catch (e) { cfgStatus('UV policy is not valid JSON', 'error'); return; }
      }
      var resp = await vt.apiFetch(vt.api('config'), {
        method: 'PUT', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ cache_hit_notify: $('#cfg-hit-notify').checked, uv_policy: uv }),
      });
      if (!resp.ok) { cfgStatus('Save failed: ' + (await resp.text()), 'error'); return; }
      cfgStatus('Saved', 'ok');
      await loadConfig();
    } finally { btn.disabled = false; }
  });

  // ── SECRET rotation ───────────────────────────────────────────────────────
  var rotateStatus = vt.statusLine($('#rotate-status'));
  $('#rotate-secret').addEventListener('click', async function () {
    if (!confirm('Generate a new SECRET? You must then run wrangler secret put SECRET.')) return;
    var btn = this; btn.disabled = true;
    try {
      var resp = await vt.postJson('rotate-secret');
      if (!resp.ok) { rotateStatus('Rotation failed: HTTP ' + resp.status, 'error'); return; }
      $('#rotate-value').value = (await resp.json()).secret;
      $('#rotate-output').hidden = false;
      rotateStatus('Generated; deploy it now', 'ok');
    } finally { btn.disabled = false; }
  });
  $('#rotate-copy').addEventListener('click', function () {
    var ta = $('#rotate-value');
    ta.select();
    navigator.clipboard.writeText(ta.value).then(
      function () { rotateStatus('Copied to clipboard', 'ok'); },
      function () { rotateStatus('Copy failed; select the text manually', 'error'); }
    );
  });

  // ── Session ───────────────────────────────────────────────────────────────
  $('#logout').addEventListener('click', async function () {
    await vt.postJson('logout');
    vt.showLogin('Logged out');
  });
  $('#sessions-revoke').addEventListener('click', async function () {
    if (!confirm('End the login sessions on every device?')) return;
    var resp = await vt.postJson('sessions-revoke');
    if (resp.status !== 204 && resp.status !== 401) { sessionStatus('Failed: HTTP ' + resp.status, 'error'); return; }
    vt.showLogin('All sessions ended, please log in again');
  });

  var list = vt.list($('#subs').parentNode);   // rows on a phone, the table on desktop

  function renderRow(s) {
    var isMine = mine && mine.endpoint === s.endpoint;
    var label = (s.label || 'unnamed') + (isMine ? ' (this device)' : '');
    var host = '';
    try { host = new URL(s.endpoint).host; } catch (_) { host = '?'; }
    var test = el('button', 'ghost small', 'Test');
    test.type = 'button';
    test.addEventListener('click', async function () {
      test.disabled = true;
      try {
        var r = await post('test', { endpoint: s.endpoint });
        setStatus(r.status >= 200 && r.status < 300 ? 'Sent (HTTP ' + r.status + ')'
          : 'Push service returned ' + r.status + (r.error ? ': ' + r.error : ''), r.status >= 200 && r.status < 300 ? 'ok' : 'error');
      } catch (e) { setStatus('Test failed: ' + (e.message || e), 'error'); }
      test.disabled = false;
    });
    var del = el('button', 'danger small', 'Delete');
    del.type = 'button';
    del.addEventListener('click', async function () {
      if (!confirm('Delete the subscription of ' + (s.label || host) + '?')) return;
      try {
        await post('unsubscribe', { endpoint: s.endpoint });
        if (isMine) await mine.unsubscribe().catch(function () {});
        await load();
      } catch (e) { setStatus('Delete failed: ' + (e.message || e), 'error'); }
    });
    return list.item({
      cells: function () {
        var td = document.createElement('td');
        td.appendChild(test);
        td.appendChild(document.createTextNode(' '));
        td.appendChild(del);
        return [el('td', null, label), el('td', null, host), el('td', null, fmtTime(s.created_ms)), td];
      },
      row: function () {
        return { main: label, sub: host + ' · ' + fmtTime(s.created_ms), actions: [test, del] };
      },
    });
  }

  function render() {
    list.clear();
    subs.forEach(function (s) { list.body().appendChild(renderRow(s)); });
    if (!subs.length) list.empty('No subscriptions');
  }

  async function load() {
    var resp = await vt.apiFetch(vt.api('push/vapid'), { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) { setStatus('Load failed: HTTP ' + resp.status, 'error'); return null; }
    var json = await resp.json();
    subs = json.subscriptions || [];
    render();
    return json.pub_b64u;
  }

  async function subscribe() {
    var btn = $('#subscribe');
    btn.disabled = true;
    try {
      var pub = await load();
      if (!pub) return;
      if ((await Notification.requestPermission()) !== 'granted') { setStatus('Notification permission not granted', 'error'); return; }
      var reg = await navigator.serviceWorker.ready;
      var sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: vt.b64uDec(pub) });
      await post('subscribe', {
        endpoint: sub.endpoint,
        p256dh: vt.b64uEnc(new Uint8Array(sub.getKey('p256dh'))),
        auth: vt.b64uEnc(new Uint8Array(sub.getKey('auth'))),
        label: $('#push-label').value.trim(),
      });
      mine = sub;
      setStatus('Subscribed', 'ok');
      await load();
    } catch (e) {
      setStatus('Subscribe failed: ' + (e.message || e), 'error');
    } finally {
      btn.disabled = false;
    }
  }

  async function init() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      setStatus('This browser lacks Web Push (on iOS open from the Home Screen icon)', 'error');
      await load();
      return;
    }
    try {
      var reg = await navigator.serviceWorker.register('/sw.js');
      mine = await reg.pushManager.getSubscription();
    } catch (e) {
      setStatus('Service worker registration failed: ' + (e.message || e), 'error');
    }
    await load();
    $('#subscribe').disabled = false;
  }

  $('#subscribe').addEventListener('click', subscribe);
  vt.onLayout(render);
  loadConfig();
  init();
  vt.tabs.setup($('#tab-setup'), data);
};
