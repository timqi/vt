'use strict';

// Push subscriptions: this device subscribes with the Worker's VAPID key and
// posts the result; every row can be tested or removed. Rendering is
// textContent only; the endpoint's keys never come back from the server.

(function () {
  var seg = location.pathname.split('/')[1] || '';
  var API = '/' + seg + '/api/push/';
  var setStatus = window.vt.setStatus;
  var subs = [];
  var mine = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function fmtTime(ms) {
    var d = new Date(ms);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  async function post(op, body) {
    var resp = await fetch(API + op, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status + ' ' + (await resp.text()));
    return resp.json();
  }

  function render() {
    var tbody = document.getElementById('rows');
    tbody.innerHTML = '';
    subs.forEach(function (s) {
      var tr = document.createElement('tr');
      var isMine = mine && mine.endpoint === s.endpoint;
      tr.appendChild(el('td', null, (s.label || '未命名') + (isMine ? '（本设备）' : '')));
      var host = '';
      try { host = new URL(s.endpoint).host; } catch (_) { host = '?'; }
      tr.appendChild(el('td', null, host));
      tr.appendChild(el('td', null, fmtTime(s.created_ms)));
      var td = document.createElement('td');
      var test = el('button', 'ghost small', '测试');
      test.addEventListener('click', async function () {
        test.disabled = true;
        try {
          var r = await post('test', { endpoint: s.endpoint });
          setStatus(r.status >= 200 && r.status < 300 ? '已发送（HTTP ' + r.status + '）'
            : '推送服务返回 ' + r.status + (r.error ? '：' + r.error : ''), r.status >= 200 && r.status < 300 ? 'ok' : 'error');
        } catch (e) { setStatus('测试失败: ' + (e.message || e), 'error'); }
        test.disabled = false;
      });
      var del = el('button', 'danger small', '删除');
      del.addEventListener('click', async function () {
        if (!confirm('删除 ' + (s.label || host) + ' 的订阅？')) return;
        try {
          await post('unsubscribe', { endpoint: s.endpoint });
          if (isMine) await mine.unsubscribe().catch(function () {});
          await load();
        } catch (e) { setStatus('删除失败: ' + (e.message || e), 'error'); }
      });
      td.appendChild(test);
      td.appendChild(document.createTextNode(' '));
      td.appendChild(del);
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
    if (!subs.length) {
      var tr0 = document.createElement('tr');
      var td0 = el('td', null, '没有订阅');
      td0.colSpan = 4;
      tr0.appendChild(td0);
      tbody.appendChild(tr0);
    }
  }

  async function load() {
    var resp = await fetch(API + 'vapid', { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return null; }
    var json = await resp.json();
    subs = json.subscriptions || [];
    render();
    return json.pub_b64u;
  }

  async function subscribe() {
    var btn = document.getElementById('subscribe');
    btn.disabled = true;
    try {
      var pub = await load();
      if (!pub) return;
      if ((await Notification.requestPermission()) !== 'granted') { setStatus('未授予通知权限', 'error'); return; }
      var reg = await navigator.serviceWorker.ready;
      var sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: window.vt.b64uDec(pub) });
      await post('subscribe', {
        endpoint: sub.endpoint,
        p256dh: window.vt.b64uEnc(new Uint8Array(sub.getKey('p256dh'))),
        auth: window.vt.b64uEnc(new Uint8Array(sub.getKey('auth'))),
        label: document.getElementById('label').value.trim(),
      });
      mine = sub;
      setStatus('已订阅', 'ok');
      await load();
    } catch (e) {
      setStatus('订阅失败: ' + (e.message || e), 'error');
    } finally {
      btn.disabled = false;
    }
  }

  async function init() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      setStatus('此浏览器不支持 Web Push（iOS 需从主屏幕图标打开）', 'error');
      await load();
      return;
    }
    try {
      var reg = await navigator.serviceWorker.register('/sw.js');
      mine = await reg.pushManager.getSubscription();
    } catch (e) {
      setStatus('Service worker 注册失败: ' + (e.message || e), 'error');
    }
    await load();
    document.getElementById('subscribe').disabled = false;
  }

  document.getElementById('subscribe').addEventListener('click', subscribe);
  init();
})();
