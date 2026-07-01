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

  function cacheTtlLabel(s) {
    if (typeof s !== 'number' || s <= 0) return '—';
    if (s % 3600 === 0) return (s / 3600) + 'h';
    if (s % 60 === 0) return (s / 60) + 'm';
    return s + 's';
  }

  // Cosmetic, FRONTEND-ONLY: if the command's leading program is an absolute
  // path (`/usr/bin/foo …`), show just its basename (`foo …`) in the list
  // column. The stored command keeps the full path — the detail dialog still
  // renders it verbatim. Only argv[0] is trimmed; path-valued args are left
  // intact so the command stays unambiguous.
  function basenameLeadingProgram(s) {
    var m = /^(\s*)(\/\S*)(.*)$/.exec(s);
    if (!m) return s;
    var prog = m[2];
    var base = prog.slice(prog.lastIndexOf('/') + 1);
    if (base === '') return s;           // "/" or trailing-slash — leave untouched
    return m[1] + base + m[3];
  }

  // Column summary for the multi-line command body
  // (`op: …\nfile: …\ncmd: …\nreason: …`). Prefer the `cmd:` line (the actual
  // shell command, e.g. for `inject`); otherwise fall back to the first line.
  function commandSummary(cmd, max) {
    if (!cmd) return '';
    var lines = String(cmd).split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf('cmd:') === 0) return clip(basenameLeadingProgram(lines[i].slice(4).trim()), max);
    }
    return clip(basenameLeadingProgram(lines[0]), max);
  }

  function cell(tr, text) {
    var td = document.createElement('td');
    td.textContent = (text === null || text === undefined) ? '' : String(text);
    tr.appendChild(td);
  }

  // Width-capped cell: wraps the text in an inline-block span with a fixed
  // max-width (see .trunc.* in admin.css) so a long host / command truncates
  // with an ellipsis instead of widening the table into a horizontal scroll.
  // The full value stays available in the row's detail dialog. `title` gives a
  // native hover tooltip with the full text.
  function cellClipped(tr, text, cls) {
    var td = document.createElement('td');
    var span = document.createElement('span');
    span.className = 'trunc ' + cls;
    var s = (text === null || text === undefined) ? '' : String(text);
    span.textContent = s;
    if (s) span.title = s;
    td.appendChild(span);
    tr.appendChild(td);
  }

  // Friendly type label. DEK-cache events share op_kind='cache'; the status
  // distinguishes them (approved=hit, miss, cleared).
  function opKindLabel(row) {
    if (row.op_kind === 'cache') {
      if (row.status === 'approved') return 'DEK缓存自动审批';
      if (row.status === 'write_failed') return 'DEK缓存写入失败';
      return 'DEK缓存';
    }
    return row.op_kind || '';
  }

  function statusBadge(row) {
    var span = document.createElement('span');
    var s = row.status || '—';
    // Cache rows render a distinct, self-explaining badge instead of a bare
    // "approved" (which would look like a normal phone approval).
    if (row.op_kind === 'cache') {
      span.className = 'badge badge-' + (s === 'write_failed' ? 'rejected' : 'approved');
      span.textContent = (s === 'write_failed') ? '缓存写入失败' : '缓存命中';
      return span;
    }
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
      cell(tr, r.source || 'ceremony');
      cellClipped(tr, r.host, 'col-host');
      cellClipped(tr, commandSummary(r.command, 200), 'col-cmd');
      cell(tr, r.ip);
      cell(tr, r.salts);
      // 缓存列: live → TTL label; armed-but-elapsed → grey 过期; never armed → —.
      var cc = document.createElement('td');
      if (typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0) {
        if (hasLiveCache(r)) {
          cc.textContent = cacheTtlLabel(r.cache_ttl_s);
        } else {
          cc.textContent = '过期';
          cc.className = 'cache-expired';
        }
      } else {
        cc.textContent = '—';
      }
      tr.appendChild(cc);
      cell(tr, r.latency_ms);
      // 操作: a "清除缓存" button on approvals that armed a still-live cache.
      var act = document.createElement('td');
      if (hasLiveCache(r)) {
        var btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'danger small'; btn.textContent = '清除缓存';
        btn.addEventListener('click', function (e) { e.stopPropagation(); clearOrigin(r.token_id, btn); });
        act.appendChild(btn);
      }
      tr.appendChild(act);
      tr.addEventListener('click', function () { openDetail(r.id); });
      tbody.appendChild(tr);
    });
  }

  // A row "has a live cache" when it armed one (cache_ttl_s>0) and that window
  // hasn't elapsed. Cache-event rows (op_kind='cache') themselves are excluded.
  function hasLiveCache(r) {
    return r.op_kind !== 'cache'
      && typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0
      && typeof r.finalized_ms === 'number'
      && (r.finalized_ms + r.cache_ttl_s * 1000 > Date.now());
  }

  async function clearOrigin(tokenId, btn) {
    if (btn) btn.disabled = true;
    try {
      var resp = await fetch('/' + seg + '/api/cache-clear-origin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ token_id: tokenId }),
      });
      if (!resp.ok) { setStatus('清除缓存失败 HTTP ' + resp.status, 'error'); if (btn) btn.disabled = false; return; }
      var json = await resp.json();
      setStatus('✓ 已清除该请求的 ' + (json && json.cleared != null ? json.cleared : '?') + ' 条缓存', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
      if (btn) btn.disabled = false;
    }
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

  // Row with a clickable link (opens a new tab). href set via property (no
  // inline handler), so it's CSP-safe and same-origin.
  function addLinkRow(dl, label, url, text) {
    var dt = document.createElement('dt'); dt.textContent = label;
    var dd = document.createElement('dd');
    var a = document.createElement('a');
    a.href = url; a.target = '_blank'; a.rel = 'noopener';
    a.textContent = text || url;
    dd.appendChild(a);
    dl.appendChild(dt); dl.appendChild(dd);
  }

  function openDetail(id) {
    var r = byId[id];
    if (!r) return;
    var dl = document.getElementById('detail-dl');
    dl.innerHTML = '';
    addRow(dl, '状态', r.status + (r.verify_failures ? '（验证失败 ' + r.verify_failures + ' 次）' : ''));
    addRow(dl, '来源', r.source || 'ceremony');
    addRow(dl, '类型', opKindLabel(r));
    addRow(dl, '主机', r.host);
    addRow(dl, '用户', r.user);
    addRow(dl, '目录', r.pwd);
    addRow(dl, '终端', r.tty);
    addRow(dl, '父进程', r.ppid_cmd);
    if (r.ppid != null) addRow(dl, '父进程PID', r.ppid);
    addRow(dl, 'SSH 来源', r.ssh_client);
    addRow(dl, 'IP', r.ip);
    addRow(dl, 'DEK 数', r.salts);
    if (typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0) addRow(dl, '缓存 TTL', cacheTtlLabel(r.cache_ttl_s));
    addRow(dl, '命令', r.command, true);
    addRow(dl, '原因', r.reason);
    addRow(dl, '创建时间', fmtTime(r.created_ms));
    addRow(dl, '终态时间', fmtTime(r.finalized_ms));
    addRow(dl, '延迟(ms)', r.latency_ms);
    addRow(dl, 'token', r.token_id);
    // Approve URL: token_id IS the full approve_token (12-byte / 16-char) for
    // ceremony rows, so /a/{token_id} is the approval page. Only actionable while
    // pending; shown for non-cache rows. Cache events have a synthetic token_id.
    if (r.op_kind !== 'cache' && r.token_id) {
      var approveUrl = location.origin + '/a/' + r.token_id;
      addLinkRow(dl, '审批链接', approveUrl, approveUrl);
    }
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
    var src = document.getElementById('f-source').value;
    if (st) u.searchParams.set('status', st);
    if (host) u.searchParams.set('host', host);
    if (src) u.searchParams.set('source', src);
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
  // Quick filter: show only cache-related records (hits + armed approvals).
  document.getElementById('filter-cache').addEventListener('click', function () {
    document.getElementById('f-status').value = 'cache';
    oldestId = null; exhausted = false; load(false);
  });
  document.getElementById('more').addEventListener('click', function () { if (!exhausted) load(true); });

  document.getElementById('clear-all-cache').addEventListener('click', async function () {
    if (!confirm('删除全部已缓存 DEK？此后解密将重新需要手机审批。')) return;
    setStatus('清空缓存中…');
    try {
      var resp = await fetch('/' + seg + '/api/clear-cache', { method: 'POST', headers: { 'Accept': 'application/json' } });
      if (!resp.ok) { setStatus('清空缓存失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      setStatus('✓ 已清空 ' + (json && json.cleared != null ? json.cleared : '?') + ' 条 DEK 缓存', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  });

  document.getElementById('clear-audit').addEventListener('click', async function () {
    if (!confirm('清空全部审计日志？此操作不可恢复。')) return;
    setStatus('清空审计中…');
    try {
      var resp = await fetch('/' + seg + '/api/clear-audit', { method: 'POST', headers: { 'Accept': 'application/json' } });
      if (!resp.ok) { setStatus('清空审计失败 HTTP ' + resp.status, 'error'); return; }
      oldestId = null; exhausted = false;
      load(false);
      setStatus('✓ 已清空全部审计日志', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  });

  load(false);
})();
