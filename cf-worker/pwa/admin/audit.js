'use strict';

// Audit viewer. One row per challenge from /{seg}/api/audit (id-cursor
// pagination). Read-only; all rendering via textContent (no HTML injection).
// Click a row to open a detail card with the full stored params.
//
// Real-time: a WebSocket (/{seg}/api/audit-stream, Access-gated) pushes each
// audit change (new pending / approved / rejected / expired / verify-fail /
// cache event / agent decision) as a full row, applied in place — no re-fetch.
// On (re)connect the client replays anything missed via after_seq catch-up
// (see the monotonic `seq` the server bumps on every write).

(function () {
  // Derive the admin segment from the current path (page is /{seg}/audit), so
  // this works regardless of the configured ADMIN_SEG.
  var seg = location.pathname.split('/')[1] || '';
  var API = '/' + seg + '/api/audit';

  var statusEl = document.getElementById('status');
  function setStatus(t, kind) { statusEl.textContent = t || ''; statusEl.className = kind || ''; }

  var oldestId = null;   // cursor: smallest id seen so far (before_id pagination)
  var exhausted = false;
  var byId = {};         // id -> full row, for the detail card + in-place updates
  var trById = {};       // id -> <tr> element, for in-place update/remove

  // ── Real-time stream state ────────────────────────────────────────────────
  // newestSeq: high-water mark over the monotonic `seq` the server bumps on every
  // audit write. Doubles as the reconnect cursor — fetch after_seq=newestSeq to
  // replay what was missed while the socket was down (an id cursor can't: a
  // lifecycle UPDATE bumps seq but not id).
  var newestSeq = 0;
  var ws = null;
  var wsBackoff = 1000;        // reconnect backoff, ms (capped)
  var reconnectTimer = null;
  var catchingUp = false;
  var pendingLoad = false;     // a fresh (non-append) REST snapshot is in flight
  var evtBuffer = [];          // live events buffered during catch-up / a fresh load, drained after
  // The filter ACTUALLY applied to the rendered list (not the live input values).
  // Incoming rows are matched against these so a pushed row respects the filter.
  var activeStatus = '';
  var activeHost = '';

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

  // Build the <tr> for one row. Pure of list state, so it is reused for the
  // initial render, in-place updates, and the cache-expiry refresh.
  function renderRow(r) {
    var tr = document.createElement('tr');
    tr.className = 'clickable';
    tr.setAttribute('data-id', r.id);
    // data-cache-live drives the cache-expiry timer: it only re-renders a row
    // when this flag flips from live→elapsed, avoiding needless DOM churn.
    var live = hasLiveCache(r);
    tr.setAttribute('data-cache-live', live ? '1' : '0');
    cell(tr, fmtTime(r.created_ms));
    var st = document.createElement('td'); st.appendChild(statusBadge(r)); tr.appendChild(st);
    cellClipped(tr, r.host, 'col-host');
    cellClipped(tr, commandSummary(r.command, 200), 'col-cmd');
    cell(tr, r.ip);
    cell(tr, r.salts);
    // 缓存列: live → TTL label; armed-but-elapsed → grey 过期; never armed → —.
    var cc = document.createElement('td');
    if (typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0) {
      if (live) {
        cc.textContent = cacheTtlLabel(r.cache_ttl_s);
      } else {
        cc.textContent = '过期';
        cc.className = 'cache-expired';
      }
    } else {
      cc.textContent = '—';
    }
    tr.appendChild(cc);
    // 操作: a "清除缓存" button on approvals that armed a still-live cache.
    var act = document.createElement('td');
    if (live) {
      var btn = document.createElement('button');
      btn.type = 'button'; btn.className = 'danger small'; btn.textContent = '清除缓存';
      btn.addEventListener('click', function (e) { e.stopPropagation(); clearOrigin(r.token_id, btn); });
      act.appendChild(btn);
    }
    tr.appendChild(act);
    tr.addEventListener('click', function () { openDetail(r.id); });
    return tr;
  }

  // Track the highest seq seen from ANY source (initial load, catch-up, live) —
  // the reconnect cursor and the live-event dedup high-water mark.
  function trackNewest(r) {
    if (typeof r.seq === 'number' && r.seq > newestSeq) newestSeq = r.seq;
  }

  function render(rows, append) {
    var tbody = document.getElementById('rows');
    if (!append) { tbody.innerHTML = ''; byId = {}; trById = {}; }
    rows.forEach(function (r) {
      if (typeof r.id !== 'number') return;
      trackNewest(r);
      // Dedup: a row may already be shown (pushed live, or an overlapping page).
      if (byId[r.id]) return;
      byId[r.id] = r;
      oldestId = (oldestId === null) ? r.id : Math.min(oldestId, r.id);
      var tr = renderRow(r);
      trById[r.id] = tr;
      tbody.appendChild(tr);
    });
  }

  // ── Real-time apply ───────────────────────────────────────────────────────

  // Does a row match the CURRENTLY-applied filter? Mirrors the server's
  // opAuditQuery predicates (status incl. the 'cache' pseudo-filter; host exact).
  function matchesFilter(r) {
    if (activeHost && r.host !== activeHost) return false;
    if (activeStatus === 'cache') return r.cache_ttl_s != null;
    if (activeStatus && r.status !== activeStatus) return false;
    return true;
  }

  // Insert a not-yet-shown row into the tbody at its id-DESC position.
  function insertRowSorted(r) {
    var tbody = document.getElementById('rows');
    byId[r.id] = r;
    oldestId = (oldestId === null) ? r.id : Math.min(oldestId, r.id);
    var tr = renderRow(r);
    trById[r.id] = tr;
    var ref = null, kids = tbody.children;
    for (var i = 0; i < kids.length; i++) {
      var idAttr = parseInt(kids[i].getAttribute('data-id'), 10);
      if (idAttr < r.id) { ref = kids[i]; break; }
    }
    tbody.insertBefore(tr, ref); // ref null → append at end
  }

  // Apply one row (from a live event or catch-up). Identifies the row by `id`
  // (NOT token_id — cache-event rows carry synthetic token_ids). Insert vs update
  // is decided by whether the row is currently shown.
  function applyRow(r) {
    if (typeof r.id !== 'number') return;
    trackNewest(r);
    if (byId[r.id]) {
      // In-place update. If it no longer matches the active filter (e.g. a
      // pending row approved while filtering pending), remove it from the view.
      byId[r.id] = r;
      var oldTr = trById[r.id];
      if (!matchesFilter(r)) {
        if (oldTr && oldTr.parentNode) oldTr.parentNode.removeChild(oldTr);
        delete byId[r.id]; delete trById[r.id];
        return;
      }
      var newTr = renderRow(r);
      if (oldTr && oldTr.parentNode) oldTr.parentNode.replaceChild(newTr, oldTr);
      else document.getElementById('rows').appendChild(newTr);
      trById[r.id] = newTr;
      // Keep an open detail card for this row in sync (isRefresh=true so a
      // mounted, in-flight ceremony below isn't torn down mid-approval).
      if (!backdrop.hidden && openDetailId === r.id) openDetail(r.id, true);
    } else {
      // Not currently shown. Only surface it if it matches the filter; the
      // cursor still advanced via trackNewest so it won't be re-fetched.
      if (matchesFilter(r)) insertRowSorted(r);
    }
  }

  // A live event: skip anything at or below the high-water mark (already applied
  // via an earlier event or catch-up), otherwise apply.
  function applyEvent(msg) {
    var r = msg && msg.row;
    if (!r) return;
    if (typeof r.seq === 'number' && r.seq <= newestSeq) return;
    applyRow(r);
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
  var openDetailId = null;   // id of the row shown in the detail card, or null

  function addRow(dl, label, value, mono) {
    if (value === null || value === undefined || value === '') return;
    var dt = document.createElement('dt'); dt.textContent = label;
    var dd = document.createElement('dd'); dd.textContent = String(value);
    if (mono) dd.className = 'mono';
    dl.appendChild(dt); dl.appendChild(dd);
  }

  // Monotonic guard so a slow /api/page fetch from a stale openDetail() (row
  // re-opened, or live-refreshed to a new status) can't mount into the card
  // after a newer call already re-rendered it.
  var detailApproveSeq = 0;

  // isRefresh: true when re-rendering the already-open row from a live WS update
  // (vs. a fresh click). On a refresh we leave any mounted ceremony untouched.
  function openDetail(id, isRefresh) {
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
    openDetailId = id;
    backdrop.hidden = false;
    // Pending ceremony rows (token_id IS the approve_token) get the approval
    // ceremony mounted inline — approve/reject happen right here, no new tab.
    // Everything else just shows details.
    mountApproval(r, isRefresh);
  }

  // Fetch this row's ApprovePageData and mount the shared ceremony into
  // #detail-approve. Only for pending non-cache rows; a no-op (cleared box)
  // otherwise. Guarded against races via detailApproveSeq.
  function mountApproval(r, isRefresh) {
    var box = document.getElementById('detail-approve');
    // Live re-render of the already-open row: never disturb a mounted ceremony.
    // The running ceremony owns the modal until it settles (success → close) or
    // the admin closes it; a settle-elsewhere just surfaces as a 410 on submit.
    if (isRefresh && box.firstChild) return;
    box.innerHTML = '';
    var seq = ++detailApproveSeq;
    if (r.op_kind === 'cache' || r.status !== 'pending' || !r.token_id) return;
    if (!window.vt || !vt.mountApprove) return;
    fetch('/api/page/' + encodeURIComponent(r.token_id), { headers: { 'Accept': 'application/json' } })
      .then(function (resp) { return resp.ok ? resp.json() : null; })
      .then(function (data) {
        // Bail if a newer openDetail()/close happened, or the row is no longer
        // the pending one on screen (data null → already handled/expired).
        if (!data || seq !== detailApproveSeq || openDetailId !== r.id) return;
        vt.mountApprove({
          data: data,
          root: box,
          showMeta: false,   // the detail dl above already shows request info
          onSettled: function () { setTimeout(closeDetail, 800); },
        });
      })
      .catch(function () { /* leave details-only on any error */ });
  }

  function closeDetail() {
    backdrop.hidden = true; openDetailId = null;
    detailApproveSeq++;    // invalidate any in-flight mount
    var box = document.getElementById('detail-approve');
    if (box) box.innerHTML = '';
  }
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
    // Freeze the filter that this (fresh) load applies, so live events + catch-up
    // are matched against what is actually on screen, not later input edits.
    // pendingLoad makes concurrent live events buffer until the snapshot renders,
    // so render()'s byId wipe can't drop a just-pushed row while newestSeq has
    // already advanced past it (which would hide it until a manual reload).
    if (!more) {
      activeStatus = document.getElementById('f-status').value;
      activeHost = document.getElementById('f-host').value.trim();
      pendingLoad = true;
    }
    setStatus(more ? '加载更多…' : '查询中…');
    try {
      var resp = await fetch(buildUrl(more), { headers: { 'Accept': 'application/json' } });
      if (resp.status === 403) { setStatus('未授权（Cloudflare Access 会话可能已过期，请刷新登录）', 'error'); return; }
      if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      var rows = (json && json.rows) || [];
      render(rows, more);
      if (typeof json.snapshot_seq === 'number' && json.snapshot_seq > newestSeq) {
        newestSeq = json.snapshot_seq;
      }
      exhausted = rows.length < 100;
      document.getElementById('more').disabled = exhausted;
      setStatus(exhausted ? '已全部加载' : '已加载，可继续加载更多', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    } finally {
      // Drain events buffered during this fresh snapshot (applyEvent re-checks seq
      // so anything already covered by the snapshot is dropped).
      if (!more) {
        pendingLoad = false;
        var buf = evtBuffer; evtBuffer = [];
        buf.forEach(applyEvent);
      }
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

  // ── Real-time WebSocket ───────────────────────────────────────────────────

  // Connection indicator, appended to the actions bar (CSP-safe: class only, no
  // inline style). States: live (green) / sync (amber) / down (grey).
  var wsDot = document.createElement('span');
  wsDot.id = 'ws-status';
  (function () {
    var actions = document.getElementById('actions');
    if (actions) actions.appendChild(wsDot);
  })();
  function setWsStatus(state) {
    wsDot.className = 'ws-' + state;
    wsDot.textContent = state === 'live' ? '● 实时'
      : state === 'sync' ? '● 同步中'
        : '● 已断开';
  }
  setWsStatus('down');

  function scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(function () { reconnectTimer = null; connectWs(); }, wsBackoff);
    wsBackoff = Math.min(wsBackoff * 2, 30000);   // exponential backoff, capped 30s
  }

  function connectWs() {
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var url = proto + '//' + location.host + '/' + seg + '/api/audit-stream';
    try { ws = new WebSocket(url); }
    catch (e) { scheduleReconnect(); return; }
    ws.onopen = function () { wsBackoff = 1000; setWsStatus('live'); };
    ws.onmessage = function (ev) {
      var msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.kind === 'hello') { startCatchup(); return; }
      if (msg.kind === 'clear') {
        // Another tab wiped the audit log — reset and reload so we don't keep
        // showing deleted rows. newestSeq is left intact (server seq stays
        // monotonic across a clear), so live events still apply correctly.
        oldestId = null; exhausted = false; load(false);
        return;
      }
      if (msg.kind === 'audit') {
        // Buffer live events during catch-up OR a fresh snapshot load so they
        // aren't lost or applied against a to-be-wiped list; drained (in arrival
        // order) once that finishes.
        if (catchingUp || pendingLoad) evtBuffer.push(msg); else applyEvent(msg);
      }
    };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    ws.onclose = function () { ws = null; setWsStatus('down'); scheduleReconnect(); };
  }

  // Reconcile everything that changed since our high-water mark (missed while the
  // socket was down, or between the initial snapshot and the socket opening).
  function startCatchup() {
    if (catchingUp) return;
    catchingUp = true;
    setWsStatus('sync');
    catchupLoop().then(function (truncated) {
      // Too many changes to replay incrementally — fall back to a full reload so
      // the view can't be left silently partial.
      if (truncated) { oldestId = null; exhausted = false; load(false); }
    }).catch(function () {}).then(function () {
      catchingUp = false;
      var buf = evtBuffer; evtBuffer = [];
      buf.forEach(applyEvent);   // applyEvent re-checks seq, so post-catchup dups are dropped
      // Only claim "live" if the socket is still actually open — it may have
      // closed mid-catch-up, in which case a reconnect is already pending.
      if (ws && ws.readyState === WebSocket.OPEN) setWsStatus('live');
    });
  }

  // Returns true if catch-up was truncated by the hard guard (caller does a full
  // reload). Deliberately filter-BLIND: like the live broadcast, it fetches every
  // changed row and lets applyRow()/matchesFilter() include-or-remove it. Sending
  // the active status filter here would hide status-EXIT transitions (e.g. a
  // pending row approved while disconnected would never arrive, staying stale).
  async function catchupLoop() {
    var guard = 0;
    while (guard++ < 200) {      // hard stop so a bug can't spin forever
      var u = new URL(API, location.origin);
      u.searchParams.set('after_seq', String(newestSeq));
      u.searchParams.set('limit', '500');
      var resp = await fetch(u.toString(), { headers: { 'Accept': 'application/json' } });
      if (!resp.ok) return false; // 403 etc. — leave it to the next reconnect
      var json = await resp.json();
      var rows = (json && json.rows) || [];   // ascending seq
      // applyRow advances newestSeq per row, driving the next page's after_seq
      // cursor forward (no infinite loop).
      rows.forEach(function (r) { applyRow(r); });
      if (rows.length < 500) return false;    // fully caught up
    }
    return true;                 // guard hit with full pages still coming → truncated
  }

  // ── Cache-expiry ticker (client-side) ─────────────────────────────────────
  // The 缓存 column is a pure time calc, so nothing pushes a "cache expired"
  // event. Periodically re-render only rows whose live cache has just elapsed
  // (data-cache-live flips 1→0), turning the column grey 过期 and dropping the
  // 清除缓存 button without a round-trip.
  setInterval(function () {
    Object.keys(trById).forEach(function (id) {
      var tr = trById[id];
      if (!tr || tr.getAttribute('data-cache-live') !== '1') return;
      var r = byId[id];
      if (r && !hasLiveCache(r)) {
        var fresh = renderRow(r);
        if (tr.parentNode) tr.parentNode.replaceChild(fresh, tr);
        trById[id] = fresh;
      }
    });
  }, 15000);

  // Sequence: finish the initial REST snapshot BEFORE opening the socket, so the
  // socket's 'hello' catch-up can never race ahead of (and be wiped by) the
  // initial render. connectWs runs whether the load succeeded or failed.
  load(false).finally(function () { connectWs(); });
})();
