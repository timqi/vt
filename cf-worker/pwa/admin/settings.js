'use strict';

// 设置 tab: the session (logout / 退出所有会话), the config knobs (hit
// notify, UV policy — GET/PUT /api/admin/config), SECRET rotation, and push
// subscriptions — this device subscribes with the Worker's VAPID key and posts
// the result; every row can be tested or removed. Rendering is textContent
// only; the endpoint's keys never come back from the server.

vt.tabs.settings = function (panel) {
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
    if (!resp.ok) { cfgStatus('读取配置失败 HTTP ' + resp.status, 'error'); return; }
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
        try { uv = JSON.parse(raw); } catch (e) { cfgStatus('UV 策略不是合法 JSON', 'error'); return; }
      }
      var resp = await vt.apiFetch(vt.api('config'), {
        method: 'PUT', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ cache_hit_notify: $('#cfg-hit-notify').checked, uv_policy: uv }),
      });
      if (!resp.ok) { cfgStatus('保存失败：' + (await resp.text()), 'error'); return; }
      cfgStatus('已保存', 'ok');
      await loadConfig();
    } finally { btn.disabled = false; }
  });

  // ── SECRET rotation ───────────────────────────────────────────────────────
  var rotateStatus = vt.statusLine($('#rotate-status'));
  $('#rotate-secret').addEventListener('click', async function () {
    if (!confirm('生成新的 SECRET？需要随后执行 wrangler secret put SECRET。')) return;
    var btn = this; btn.disabled = true;
    try {
      var resp = await vt.postJson('rotate-secret');
      if (!resp.ok) { rotateStatus('轮换失败 HTTP ' + resp.status, 'error'); return; }
      $('#rotate-value').value = (await resp.json()).secret;
      $('#rotate-output').hidden = false;
      rotateStatus('已生成，请立即部署', 'ok');
    } finally { btn.disabled = false; }
  });
  $('#rotate-copy').addEventListener('click', function () {
    var ta = $('#rotate-value');
    ta.select();
    navigator.clipboard.writeText(ta.value).then(
      function () { rotateStatus('已复制到剪贴板', 'ok'); },
      function () { rotateStatus('复制失败，请手动选择文本', 'error'); }
    );
  });

  // ── Session ───────────────────────────────────────────────────────────────
  $('#logout').addEventListener('click', async function () {
    await vt.postJson('logout');
    vt.showLogin('已退出登录');
  });
  $('#sessions-revoke').addEventListener('click', async function () {
    if (!confirm('结束所有设备上的登录会话？')) return;
    var resp = await vt.postJson('sessions-revoke');
    if (resp.status !== 204 && resp.status !== 401) { sessionStatus('失败 HTTP ' + resp.status, 'error'); return; }
    vt.showLogin('所有会话已结束，请重新登录');
  });

  var list = vt.list($('#subs').parentNode);   // rows on a phone, the table on desktop

  function renderRow(s) {
    var isMine = mine && mine.endpoint === s.endpoint;
    var label = (s.label || '未命名') + (isMine ? '（本设备）' : '');
    var host = '';
    try { host = new URL(s.endpoint).host; } catch (_) { host = '?'; }
    var test = el('button', 'ghost small', '测试');
    test.type = 'button';
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
    del.type = 'button';
    del.addEventListener('click', async function () {
      if (!confirm('删除 ' + (s.label || host) + ' 的订阅？')) return;
      try {
        await post('unsubscribe', { endpoint: s.endpoint });
        if (isMine) await mine.unsubscribe().catch(function () {});
        await load();
      } catch (e) { setStatus('删除失败: ' + (e.message || e), 'error'); }
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
    if (!subs.length) list.empty('没有订阅');
  }

  async function load() {
    var resp = await vt.apiFetch(vt.api('push/vapid'), { headers: { 'Accept': 'application/json' } });
    if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return null; }
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
      if ((await Notification.requestPermission()) !== 'granted') { setStatus('未授予通知权限', 'error'); return; }
      var reg = await navigator.serviceWorker.ready;
      var sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: vt.b64uDec(pub) });
      await post('subscribe', {
        endpoint: sub.endpoint,
        p256dh: vt.b64uEnc(new Uint8Array(sub.getKey('p256dh'))),
        auth: vt.b64uEnc(new Uint8Array(sub.getKey('auth'))),
        label: $('#push-label').value.trim(),
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
    $('#subscribe').disabled = false;
  }

  $('#subscribe').addEventListener('click', subscribe);
  vt.onLayout(render);
  loadConfig();
  init();
};
