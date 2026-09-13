'use strict';

// Host-token inventory. One row per enrolled host credential, from
// /{seg}/api/tokens. Read-only rendering via textContent; the only mutation is
// revoke — authority-REDUCING, one POST, immediate (same rule as cache clears).
// Countdowns run against the SERVER clock (now_ms from the listing).

(function () {
  var seg = location.pathname.split('/')[1] || '';
  var API = '/' + seg + '/api/tokens';

  var statusEl = document.getElementById('status');
  function setStatus(t, kind) { statusEl.textContent = t || ''; statusEl.className = kind || ''; }

  var tokens = [];
  var serverNowMs = 0;
  var localRefMs = 0;
  function now() { return serverNowMs + (Date.now() - localRefMs); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function fmtTime(ms) {
    if (typeof ms !== 'number' || ms <= 0) return '';
    var d = new Date(ms);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function fmtRemaining(ms) {
    if (ms <= 0) return '已过期';
    var mins = Math.floor(ms / 60000);
    if (mins < 60) return mins + ' 分钟';
    if (mins >= 1440) {
      var d = Math.floor(mins / 1440), dh = Math.floor((mins % 1440) / 60);
      return d + ' 天' + (dh ? ' ' + dh + ' 小时' : '');
    }
    return Math.floor(mins / 60) + ' 小时';
  }

  function isLive(t) { return t.revoked_ms == null && t.expires_ms > now(); }

  function cell(main, sub) {
    var td = document.createElement('td');
    td.appendChild(el('div', 'cell-main', main));
    if (sub) td.appendChild(el('div', 'cell-sub', sub));
    return td;
  }

  function render() {
    var tbody = document.getElementById('rows');
    tbody.innerHTML = '';
    var onlyLive = document.getElementById('f-live').value === 'live';
    var hostQ = (document.getElementById('f-host').value || '').trim().toLowerCase();
    var shown = 0;
    tokens.forEach(function (t) {
      if (onlyLive && !isLive(t)) return;
      if (hostQ && String(t.host || '').toLowerCase().indexOf(hostQ) < 0) return;
      shown++;
      var tr = document.createElement('tr');
      if (!isLive(t)) tr.className = 'expired';
      tr.appendChild(cell(t.host || '?', (t.user ? t.user + ' · ' : '') + t.token_id));
      tr.appendChild(cell(t.enroll_ip || '', (t.origin || '') + (t.origin ? ' · ' : '') + '签发 ' + fmtTime(t.created_ms)));
      tr.appendChild(cell(fmtTime(t.last_used_ms), t.last_ip && t.last_ip !== t.enroll_ip ? 'IP ' + t.last_ip : ''));
      var state = t.revoked_ms != null ? '已吊销 ' + fmtTime(t.revoked_ms) : fmtRemaining(t.expires_ms - now());
      tr.appendChild(cell(state, t.revoked_ms == null ? fmtTime(t.expires_ms) : ''));
      var td = document.createElement('td');
      if (isLive(t)) {
        var btn = el('button', 'danger small', '吊销');
        btn.addEventListener('click', function () { revoke(t, btn); });
        td.appendChild(btn);
      }
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
    if (shown === 0) {
      var tr0 = document.createElement('tr');
      var td0 = document.createElement('td');
      td0.colSpan = 5;
      td0.textContent = onlyLive ? '没有有效令牌（切换到「全部」查看历史）' : '没有令牌';
      tr0.appendChild(td0);
      tbody.appendChild(tr0);
    }
  }

  async function revoke(t, btn) {
    if (!confirm('吊销 ' + (t.host || t.token_id) + ' 的令牌？该主机随后需要重新 vt enroll。')) return;
    btn.disabled = true;
    try {
      var resp = await fetch('/' + seg + '/api/tokens-revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token_id: t.token_id }),
      });
      if (!resp.ok) { setStatus('吊销失败 HTTP ' + resp.status, 'error'); btn.disabled = false; return; }
      var json = await resp.json();
      setStatus(json.revoked ? '已吊销 ' + (t.host || t.token_id) : '令牌已不再有效', json.revoked ? 'ok' : '');
      await load();
    } catch (e) {
      setStatus('吊销失败: ' + (e.message || e), 'error');
      btn.disabled = false;
    }
  }

  async function load() {
    setStatus('查询中…');
    try {
      var resp = await fetch(API, { headers: { 'Accept': 'application/json' } });
      if (resp.status === 403) {
        setStatus('未授权（Cloudflare Access 会话可能已过期，请刷新登录）', 'error');
        return;
      }
      if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      tokens = (json && json.tokens) || [];
      serverNowMs = typeof json.now_ms === 'number' ? json.now_ms : Date.now();
      localRefMs = Date.now();
      render();
      var live = tokens.filter(isLive).length;
      setStatus(live + ' 个有效 / 共 ' + tokens.length + (json.truncated ? '（列表已截断）' : ''), json.truncated ? 'error' : '');
    } catch (e) {
      setStatus('查询失败: ' + (e.message || e), 'error');
    }
  }

  document.getElementById('refresh').addEventListener('click', function () { load(); });
  document.getElementById('f-live').addEventListener('change', render);
  document.getElementById('f-host').addEventListener('input', render);
  setInterval(render, 60000);
  load();
})();
