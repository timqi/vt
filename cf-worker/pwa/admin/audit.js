'use strict';

// Audit viewer. One row per challenge from /{seg}/api/audit (id-cursor
// pagination). Read-only; all rendering via textContent (no HTML injection).
// Click a row to open a detail card with the full stored params.

(function () {
  // Derive the admin segment from the current path (page is /{seg}/audit), so
  // this works regardless of the configured ADMIN_SEG.
  var seg = location.pathname.split('/')[1] || '';
  var API = '/' + seg + '/api/audit';

  var statusEl = document.getElementById('status');
  function setStatus(t, kind) { statusEl.textContent = t || ''; statusEl.className = kind || ''; }

  var oldestId = null;   // cursor: smallest id seen so far
  var exhausted = false;
  var byId = {};         // id -> full row, for the detail card

  function fmtTime(ms) {
    if (typeof ms !== 'number') return '';
    var d = new Date(ms);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function clip(s, max) {
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  // Column summary for the multi-line command body
  // (`op: …\nfile: …\ncmd: …\nreason: …`). Prefer the `cmd:` line (the actual
  // shell command, e.g. for `inject`); otherwise fall back to the first line.
  function commandSummary(cmd, max) {
    if (!cmd) return '';
    var lines = String(cmd).split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf('cmd:') === 0) return clip(lines[i].slice(4).trim(), max);
    }
    return clip(lines[0], max);
  }

  function cell(tr, text) {
    var td = document.createElement('td');
    td.textContent = (text === null || text === undefined) ? '' : String(text);
    tr.appendChild(td);
  }

  function statusBadge(row) {
    var span = document.createElement('span');
    var s = row.status || '—';
    span.className = 'badge badge-' + s;
    span.textContent = s + (row.verify_failures ? ' ⚠' + row.verify_failures : '');
    return span;
  }

  function render(rows, append) {
    var tbody = document.getElementById('rows');
    if (!append) { tbody.innerHTML = ''; byId = {}; }
    rows.forEach(function (r) {
      if (typeof r.id === 'number') {
        byId[r.id] = r;
        oldestId = (oldestId === null) ? r.id : Math.min(oldestId, r.id);
      }
      var tr = document.createElement('tr');
      tr.className = 'clickable';
      tr.setAttribute('data-id', r.id);
      cell(tr, fmtTime(r.created_ms));
      var st = document.createElement('td'); st.appendChild(statusBadge(r)); tr.appendChild(st);
      cell(tr, r.host);
      cell(tr, commandSummary(r.command, 48));
      cell(tr, r.ip);
      cell(tr, r.salts);
      cell(tr, r.latency_ms);
      tr.addEventListener('click', function () { openDetail(r.id); });
      tbody.appendChild(tr);
    });
  }

  // ── Detail card ─────────────────────────────────────────────────────────

  var backdrop = document.getElementById('detail-backdrop');

  function addRow(dl, label, value, mono) {
    if (value === null || value === undefined || value === '') return;
    var dt = document.createElement('dt'); dt.textContent = label;
    var dd = document.createElement('dd'); dd.textContent = String(value);
    if (mono) dd.className = 'mono';
    dl.appendChild(dt); dl.appendChild(dd);
  }

  function openDetail(id) {
    var r = byId[id];
    if (!r) return;
    var dl = document.getElementById('detail-dl');
    dl.innerHTML = '';
    addRow(dl, '状态', r.status + (r.verify_failures ? '（验证失败 ' + r.verify_failures + ' 次）' : ''));
    addRow(dl, '类型', r.op_kind);
    addRow(dl, '主机', r.host);
    addRow(dl, '用户', r.user);
    addRow(dl, '目录', r.pwd);
    addRow(dl, '终端', r.tty);
    addRow(dl, '父进程', r.ppid_cmd);
    addRow(dl, 'SSH 来源', r.ssh_client);
    addRow(dl, 'IP', r.ip);
    addRow(dl, 'DEK 数', r.salts);
    addRow(dl, '命令', r.command, true);
    addRow(dl, '原因', r.reason);
    addRow(dl, '创建时间', fmtTime(r.created_ms));
    addRow(dl, '终态时间', fmtTime(r.finalized_ms));
    addRow(dl, '延迟(ms)', r.latency_ms);
    addRow(dl, 'token', r.token_id);
    backdrop.hidden = false;
  }

  function closeDetail() { backdrop.hidden = true; }
  document.getElementById('detail-close').addEventListener('click', closeDetail);
  backdrop.addEventListener('click', function (e) { if (e.target === backdrop) closeDetail(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeDetail(); });

  // ── Fetch ───────────────────────────────────────────────────────────────

  function buildUrl(more) {
    var u = new URL(API, location.origin);
    u.searchParams.set('limit', '100');
    var st = document.getElementById('f-status').value;
    var host = document.getElementById('f-host').value.trim();
    if (st) u.searchParams.set('status', st);
    if (host) u.searchParams.set('host', host);
    if (more && oldestId !== null) u.searchParams.set('before_id', String(oldestId));
    return u.toString();
  }

  async function load(more) {
    setStatus(more ? '加载更多…' : '查询中…');
    try {
      var resp = await fetch(buildUrl(more), { headers: { 'Accept': 'application/json' } });
      if (resp.status === 403) { setStatus('未授权（Cloudflare Access 会话可能已过期，请刷新登录）', 'error'); return; }
      if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      var rows = (json && json.rows) || [];
      render(rows, more);
      exhausted = rows.length < 100;
      document.getElementById('more').disabled = exhausted;
      setStatus(exhausted ? '已全部加载' : '已加载，可继续加载更多', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  }

  document.getElementById('apply').addEventListener('click', function () {
    oldestId = null; exhausted = false; load(false);
  });
  document.getElementById('more').addEventListener('click', function () { if (!exhausted) load(true); });

  load(false);
})();
