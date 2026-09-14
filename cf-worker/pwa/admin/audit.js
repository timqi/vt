'use strict';

// Audit tab. One row per challenge from /{seg}/api/audit (id-cursor
// pagination). Read-only; all rendering via textContent (no HTML injection).
// Click a row to open the shared detail sheet with the full stored params.
//
// Real-time: a WebSocket (/api/admin/audit-stream, session-gated) pushes each
// audit change (new pending / approved / rejected / expired / verify-fail /
// cache event / agent decision) as a full row, applied in place — no re-fetch.
// On (re)connect the client replays anything missed via after_seq catch-up
// (see the monotonic `seq` the server bumps on every write).

vt.tabs.audit = function (panel) {
  var $ = function (sel) { return panel.querySelector(sel); };
  var API = vt.api('audit');
  var setStatus = vt.statusLine($('.status'));
  var fmtTime = vt.fmtTime, ttlLabel = vt.ttlLabel;

  var list = vt.list($('.table-wrap'));   // rows on a phone, the table on desktop
  var oldestId = null;   // cursor: smallest id seen so far (before_id pagination)
  var exhausted = false;
  var byId = {};         // id -> full row, for the detail card + in-place updates
  var trById = {};       // id -> list element (tr / li), for in-place update/remove

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

  function cell(content, cls) {
    var td = document.createElement('td');
    if (cls) td.className = cls;
    if (content && content.nodeType) td.appendChild(content);
    else td.textContent = (content === null || content === undefined) ? '' : String(content);
    return td;
  }

  // Width-capped cell: wraps the text in an inline-block span with a fixed
  // max-width (see .trunc.* in admin.css) so a long host / command truncates
  // with an ellipsis instead of widening the table into a horizontal scroll.
  // The full value lives whole in the row's detail sheet.
  function cellClipped(content, cls) {
    var span = vt.el('span', 'trunc ' + cls);
    if (content && content.nodeType) span.appendChild(content);
    else span.textContent = (content === null || content === undefined) ? '' : String(content);
    return cell(span);
  }

  // Friendly type label. DEK-cache events share op_kind='cache'; the status
  // distinguishes them (approved=hit, miss, cleared).
  function opKindLabel(row) {
    if (row.op_kind === 'cache') {
      if (row.status === 'approved') return 'DEK缓存自动审批';
      if (row.status === 'write_failed') return 'DEK缓存写入失败';
      if (row.status === 'extended') return 'DEK缓存已延长';
      return 'DEK缓存';
    }
    // The admin-requested, Passkey-approved cache extension ceremony.
    if (row.op_kind === 'cache-extend') return '延长DEK缓存(审批)';
    return row.op_kind || '';
  }

  function statusBadge(row) {
    var span = document.createElement('span');
    var s = row.status || '—';
    // Cache rows render a distinct, self-explaining badge instead of a bare
    // "approved" (which would look like a normal phone approval).
    if (row.op_kind === 'cache') {
      span.className = 'badge badge-' + (s === 'write_failed' ? 'rejected'
        : s === 'extended' ? 'expired' : 'approved');
      span.textContent = (s === 'write_failed') ? '缓存写入失败'
        : (s === 'extended') ? '缓存已延长' : '缓存命中';
      return span;
    }
    span.className = 'badge badge-' + s;
    span.textContent = s + (row.verify_failures ? ' ⚠' + row.verify_failures : '');
    return span;
  }

  // Build the list element for one row (table cells or a phone .row from the
  // same nodes). Pure of list state, so it is reused for the initial render,
  // in-place updates, and the cache-expiry refresh.
  function renderRow(r) {
    // data-cache-live drives the cache-expiry timer: it only re-renders a row
    // when this flag flips from live→elapsed, avoiding needless DOM churn.
    var live = hasLiveCache(r);
    var badge = statusBadge(r);
    var recs = vt.recordsSummary(r.records, r.salts);
    var proj = vt.projectName(r.project);
    // 缓存: live → TTL label; armed-but-elapsed → grey 过期; never armed → —.
    var cache = (typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0) ? (live ? ttlLabel(r.cache_ttl_s) : '过期') : '—';
    return list.item({
      cls: 'clickable',
      attrs: { id: r.id, 'cache-live': live ? '1' : '0' },
      click: function () { openDetail(r.id); },
      cells: function () {
        // 记录: the row's records by name (server-owned, else the 自报 claim),
        // or the bare count for rows written before names were stored.
        // Command and IP live in the detail sheet.
        return [cell(fmtTime(r.created_ms)), cell(badge), cellClipped(r.host, 'col-host'),
          cellClipped(proj, 'col-proj'), cellClipped(recs, 'col-rec'),
          cell(cache, cache === '过期' ? 'cache-expired' : null)];
      },
      row: function () {
        // Sub line: the project, then the records; the full path is in the sheet.
        var line = (proj || recs) ? vt.el('div', null, proj) : null;
        if (line && recs) { if (proj) line.appendChild(document.createTextNode(' · ')); line.appendChild(recs); }
        return {
          main: r.host || '—',
          sub: [line,
            vt.el('div', null, fmtTime(r.created_ms) + (cache !== '—' ? ' · 缓存 ' + cache : ''))],
          trail: badge,
        };
      },
    });
  }

  // Track the highest seq seen from ANY source (initial load, catch-up, live) —
  // the reconnect cursor and the live-event dedup high-water mark.
  function trackNewest(r) {
    if (typeof r.seq === 'number' && r.seq > newestSeq) newestSeq = r.seq;
  }

  function render(rows, append) {
    var tbody = list.body();
    if (!append) { list.clear(); byId = {}; trById = {}; }
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
  // opAuditQuery predicates (status and host exact).
  function matchesFilter(r) {
    if (activeHost && r.host !== activeHost) return false;
    if (activeStatus && r.status !== activeStatus) return false;
    return true;
  }

  // Re-render every shown row in place (the phone/desktop layout switched).
  function renderAll() {
    list.clear();
    trById = {};
    Object.keys(byId).map(Number).sort(function (a, b) { return b - a; }).forEach(function (id) {
      trById[id] = renderRow(byId[id]);
      list.body().appendChild(trById[id]);
    });
  }
  vt.onLayout(renderAll);

  // Insert a not-yet-shown row into the list at its id-DESC position.
  function insertRowSorted(r) {
    var tbody = list.body();
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
      else list.body().appendChild(newTr);
      trById[r.id] = newTr;
      // Keep an open detail card for this row in sync (isRefresh=true so a
      // mounted, in-flight ceremony below isn't torn down mid-approval); an
      // in-progress rename in the card is left alone too.
      if (vt.dialog.isOpen() && openDetailId === r.id && !document.querySelector('#detail-dl .rec-edit')) openDetail(r.id, true);
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

  // Did this row ever arm a DEK cache? Cache-event rows (op_kind='cache') are
  // themselves excluded — they are consumption logs, not grants.
  function armedCache(r) {
    return r.op_kind !== 'cache'
      && typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0;
  }

  // A row "has a live cache" when it armed one and cache_expires_ms — the
  // server's record of the ACTUAL expiry, which an approved extension moves —
  // is still ahead. cache_ttl_s keeps its original meaning (the TTL the
  // approver chose) and is never rewritten by an extension, so it is never
  // used to infer liveness.
  function hasLiveCache(r) {
    return armedCache(r)
      && typeof r.cache_expires_ms === 'number' && r.cache_expires_ms > Date.now();
  }

  // ── Detail dialog (shared, admin.js) ────────────────────────────────────

  var openDetailId = null;   // id of the row shown in the detail dialog, or null
  var addRow = vt.dialog.addRow;

  // Monotonic guard so a slow /api/page fetch from a stale openDetail() (row
  // re-opened, or live-refreshed to a new status) can't mount into the card
  // after a newer call already re-rendered it.
  var detailApproveSeq = 0;

  // isRefresh: true when re-rendering the already-open row from a live WS update
  // (vs. a fresh click). On a refresh we leave any mounted ceremony untouched.
  function openDetail(id, isRefresh) {
    var r = byId[id];
    if (!r) return;
    var d = vt.dialog.open({ onClose: onDialogClosed });
    var dl = d.dl;
    openDetailId = id;
    addRow(dl, '状态', r.status + (r.verify_failures ? '（验证失败 ' + r.verify_failures + ' 次）' : ''));
    addRow(dl, '来源', r.source || 'ceremony');
    addRow(dl, '类型', opKindLabel(r));
    addRow(dl, '主机', r.host);
    addRow(dl, '用户', r.user);
    addRow(dl, '目录', r.pwd);
    addRow(dl, '项目', r.project);
    addRow(dl, '终端', r.tty);
    addRow(dl, '父进程', r.ppid_cmd);
    if (r.ppid != null) addRow(dl, '父进程PID', r.ppid);
    // Agent-authoritative fields (source='agent' rows; addRow skips ''/null,
    // so pre-migration and non-agent rows render unchanged).
    addRow(dl, '调用进程', r.peer_exe);
    addRow(dl, '密钥', r.key_fp);
    addRow(dl, '目的主机', r.dest);
    addRow(dl, '复用范围', r.scope_label);
    addRow(dl, '范围类型', r.scope_family);
    if (typeof r.grant_ttl_s === 'number' && r.grant_ttl_s > 0) addRow(dl, '授权时长', ttlLabel(r.grant_ttl_s));
    if (r.relayed === 1) addRow(dl, '经中继', '是');
    addRow(dl, 'SSH 来源', r.ssh_client);
    addRow(dl, 'IP', r.ip);
    addRow(dl, 'DEK 数', r.salts);
    // Records with inline rename; a saved name updates this row's cached copy so
    // the table cell and a later re-open agree without a refetch.
    if (r.records && r.records.length) {
      dl.appendChild(vt.el('dt', null, '记录'));
      var dd = vt.el('dd', null);
      dd.appendChild(vt.recordList(r.records, function () {
        var fresh = renderRow(r);
        var old = trById[r.id];
        if (old && old.parentNode) old.parentNode.replaceChild(fresh, old);
        trById[r.id] = fresh;
      }));
      dl.appendChild(dd);
    }
    if (typeof r.cache_ttl_s === 'number' && r.cache_ttl_s > 0) addRow(dl, '缓存 TTL', ttlLabel(r.cache_ttl_s));
    // Actual expiry (updated by an approved extension); shown alongside the
    // originally-approved TTL so an extended row is self-explaining.
    if (typeof r.cache_expires_ms === 'number') addRow(dl, '缓存到期', fmtTime(r.cache_expires_ms));
    addRow(dl, '命令', r.command, true);
    addRow(dl, '原因', r.reason);
    addRow(dl, '创建时间', fmtTime(r.created_ms));
    addRow(dl, '终态时间', fmtTime(r.finalized_ms));
    addRow(dl, '延迟(ms)', r.latency_ms);
    addRow(dl, 'token', r.token_id);
    // Pending ceremony rows (token_id IS the approve_token) get the approval
    // ceremony mounted inline — approve/reject happen right here, no new tab.
    // Everything else just shows details.
    mountApproval(r, isRefresh, d.approve);
  }

  // Fetch this row's ApprovePageData and mount the shared ceremony into the
  // dialog's ceremony box. Only for pending non-cache rows; a no-op (cleared
  // box) otherwise. Guarded against races via detailApproveSeq.
  function mountApproval(r, isRefresh, box) {
    // Live re-render of the already-open row: never disturb a mounted ceremony.
    // The running ceremony owns the modal until it settles (success → close) or
    // the admin closes it; a settle-elsewhere just surfaces as a 410 on submit.
    if (isRefresh && box.firstChild) return;
    box.innerHTML = '';
    var seq = ++detailApproveSeq;
    if (r.op_kind === 'cache' || r.status !== 'pending' || !r.token_id) return;
    if (!vt.mountApprove) return;
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
          onSettled: function () { setTimeout(vt.dialog.close, 800); },
        });
      })
      .catch(function () { /* leave details-only on any error */ });
  }

  // vt.dialog.close() has already hidden the dialog and emptied the ceremony box.
  function onDialogClosed() {
    openDetailId = null;
    detailApproveSeq++;    // invalidate any in-flight mount
  }

  // ── Fetch ───────────────────────────────────────────────────────────────

  function buildUrl(more) {
    var u = new URL(API, location.origin);
    u.searchParams.set('limit', '100');
    var st = $('#f-status').value;
    var host = $('.f-host').value.trim();
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
      activeStatus = $('#f-status').value;
      activeHost = $('.f-host').value.trim();
      pendingLoad = true;
    }
    setStatus(more ? '加载更多…' : '查询中…');
    try {
      var resp = await vt.apiFetch(buildUrl(more), { headers: { 'Accept': 'application/json' } });
      if (resp.status === 401) return; // the shell shows the login view
      if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      var rows = (json && json.rows) || [];
      render(rows, more);
      if (typeof json.snapshot_seq === 'number' && json.snapshot_seq > newestSeq) {
        newestSeq = json.snapshot_seq;
      }
      exhausted = rows.length < 100;
      $('#more').disabled = exhausted;
      setStatus('已加载 ' + Object.keys(byId).length + ' 条' + (exhausted ? ' · 已全部加载' : ' · 加载更多'), 'ok');
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

  $('#apply').addEventListener('click', function () {
    oldestId = null; exhausted = false; load(false);
  });
  $('#more').addEventListener('click', function () { if (!exhausted) load(true); });

  // ── Real-time WebSocket ───────────────────────────────────────────────────

  // Connection indicator, appended to the actions bar (CSP-safe: class only, no
  // inline style). States: live (green) / sync (amber) / down (grey).
  var wsDot = vt.el('span');
  wsDot.id = 'ws-status';
  $('.actions').appendChild(wsDot);
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
    var url = proto + '//' + location.host + vt.api('audit-stream');
    try { ws = new WebSocket(url); }
    catch (e) { scheduleReconnect(); return; }
    ws.onopen = function () { wsBackoff = 1000; setWsStatus('live'); };
    ws.onmessage = function (ev) {
      var msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.kind === 'hello') { startCatchup(); return; }
      if (msg.kind === 'audit') {
        // Buffer live events during catch-up OR a fresh snapshot load so they
        // aren't lost or applied against a to-be-wiped list; drained (in arrival
        // order) once that finishes.
        if (catchingUp || pendingLoad) evtBuffer.push(msg); else applyEvent(msg);
      }
    };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    ws.onclose = function (e) {
      ws = null; setWsStatus('down');
      // 4001: the DO closed it because the session's exp_s passed.
      if (e && e.code === 4001) { vt.showLogin('会话已过期，请重新登录'); return; }
      scheduleReconnect();
    };
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
      var resp = await vt.apiFetch(u.toString(), { headers: { 'Accept': 'application/json' } });
      if (!resp.ok) return false; // 401 etc. — the shell handles the session
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
  // (data-cache-live flips 1→0), turning the column grey 过期 without a round-trip.
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
};
