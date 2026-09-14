'use strict';

// DEK 缓存 tab. One row per live cache ENTRY from /{seg}/api/cache-list, grouped
// client-side under collapsible 主机 · 项目 headers (the two halves of the key:
// verified token, advisory project). Read-only rendering via textContent;
// every mutation is an explicit POST on the selected entries.
//
// Two classes of action, deliberately asymmetric:
//   • 撤销 (selected) / 清除全部 — authority-REDUCING, one POST, immediate.
//   • 延长 — authority-GRANTING, so the admin session alone cannot do it: the
//     POST only opens a pending Passkey ceremony, which is then mounted inline via
//     the SAME vt.mountApprove() the approval page uses. Nothing expires later
//     until that ceremony is approved on a Passkey. One 主机 · 项目 per ceremony.
//
// Countdowns run against the SERVER clock (now_ms from the listing, advanced
// locally), so a skewed browser clock cannot invent remaining time.
//
// `#cache?host=…&project=…` (the audit tab's 查看缓存 link) fills the filter bar.

vt.tabs.cache = function (panel) {
  var $ = function (sel) { return panel.querySelector(sel); };
  var API = vt.api('cache-list');
  var setStatus = vt.statusLine($('.status'));
  var el = vt.el, fmtTime = vt.fmtTime, fmtRemaining = vt.fmtRemaining, ttlLabel = vt.ttlLabel;

  var list = vt.list($('.table-wrap'));   // rows on a phone, the table on desktop
  var entries = [];           // last listing, latest expiry first
  var byId = {};              // id -> entry
  var selected = {};          // id -> true
  var collapsed = {};         // scope -> true
  var meta = { ttl_options_s: [], truncated: false, scanned: 0 };
  // Server clock at listing time + the local monotonic reference we advance it
  // from, so remaining-time math never depends on the browser's wall clock.
  var serverNowMs = 0;
  var localRefMs = 0;
  function now() { return serverNowMs + (Date.now() - localRefMs); }

  // The scope is the key's two halves; the id adds the salt.
  function scopeOf(e) { return e.token_id + '\u0000' + e.project; }
  function idOf(e) { return scopeOf(e) + '\u0000' + e.salt_b64u; }
  function refOf(e) { return { token_id: e.token_id, project: e.project, salt_b64u: e.salt_b64u }; }
  function scopeLabel(e) { return (e.host || '—') + ' · ' + (e.project ? vt.projectName(e.project) : '项目未知'); }

  // A multi-day window is a materially different exposure from a workday one, so
  // the picker says so instead of letting "1 周" read like just another option.
  function ttlIsLong(s) { return s >= 86400; }

  // Would extending with `ttl` actually move this entry's expiry? Extension is
  // absolute (now + ttl), never additive, so a TTL shorter than the time already
  // on the clock is a no-op — the server refuses it as `no_gain`. Deciding this
  // client-side is what lets the UI say so BEFORE the click.
  function wouldGain(e, ttl) { return now() + ttl * 1000 > e.expires_ms; }

  // Smallest rung that would move every entry in `es` forward, so the UI can
  // name the fix ("请选择 ≥ 2 天") rather than just refusing.
  function smallestUsefulTtl(es) {
    var opts = meta.ttl_options_s || [];
    for (var i = 0; i < opts.length; i++) {
      if (es.length && es.every(function (e) { return wouldGain(e, opts[i]); })) return opts[i];
    }
    return 0;
  }

  // Server reason codes (do_account.opCacheExtendCreate) in the operator's language.
  var REASON_TEXT = {
    expired: '已过期，需重新手机审批（延长只能续期仍然有效的缓存）',
    no_gain: '现有剩余时间已长于所选时长',
    gone: '已被清除',
  };

  // ── Filtering (client-side; the listing is one bounded snapshot) ───────────

  function visibleEntries() {
    var host = $('.f-host').value.trim();
    var project = $('.f-project').value.trim();
    var t = now();
    return entries.filter(function (e) {
      if (!(e.expires_ms > t)) return false;
      if (host && e.host !== host) return false;
      if (project && (e.project || '').indexOf(project) === -1) return false;
      return true;
    });
  }

  // `#cache?host=…&project=…` fills the filter bar; a bare `#cache` leaves it.
  function applyHash() {
    var h = location.hash.slice(1).split('?');
    if (h[0] !== 'cache' || h.length < 2) return;
    var q = new URLSearchParams(h[1]);
    $('.f-host').value = q.get('host') || '';
    $('.f-project').value = q.get('project') || '';
    render();
  }

  // ── Render ────────────────────────────────────────────────────────────────

  function pickBox(on, label, onChange) {
    var pick = document.createElement('input');
    pick.type = 'checkbox';
    pick.checked = on;
    pick.setAttribute('aria-label', label);
    pick.addEventListener('click', function (ev) { ev.stopPropagation(); });
    pick.addEventListener('change', onChange);
    return pick;
  }

  // Two-line cell: a primary value plus a muted secondary line.
  function cell2(main, subs) {
    var td = document.createElement('td');
    td.appendChild(el('div', 'cell-main', main || '—'));
    (subs || []).forEach(function (s) { if (s) td.appendChild(el('div', 'cell-sub', s)); });
    return td;
  }

  // One 主机 · 项目 header: its checkbox selects every listed entry of the
  // scope; the label toggles the scope's rows. Full path, user and token in the
  // hovercard (the same sheet-or-hover rule as every long value).
  function renderHeader(scope, es) {
    var e = es[0];
    var allOn = es.every(function (x) { return selected[idOf(x)]; });
    var pick = pickBox(allOn, '选择 ' + scopeLabel(e), function () {
      es.forEach(function (x) { if (pick.checked) selected[idOf(x)] = true; else delete selected[idOf(x)]; });
      render();
    });
    var hover = '主机: ' + (e.host || '—') + '\n用户: ' + (e.user || '—') + '\n项目: ' + (e.project || '未知（早期条目）')
      + '\n令牌: ' + e.token_id + '\n\n（缓存绑定该主机的令牌与客户端自报的项目，两者一致才会命中）';
    var mark = (collapsed[scope] ? '▸ ' : '▾ ');
    var label = el('span', 'group-label has-hover', mark + scopeLabel(e));
    label.setAttribute('data-hover', hover);
    var count = el('span', 'cell-sub', es.length + ' 条');
    function toggle() { if (collapsed[scope]) delete collapsed[scope]; else collapsed[scope] = true; render(); }
    return list.item({
      cls: 'group-head',
      click: toggle,
      cells: function () {
        var pickTd = document.createElement('td');
        pickTd.className = 'col-pick';
        pickTd.appendChild(pick);
        var td = document.createElement('td');
        td.colSpan = 2;
        td.appendChild(label);
        td.appendChild(count);
        return [pickTd, td];
      },
      row: function () { return { lead: pick, main: label, trail: count }; },
    });
  }

  function renderRow(e) {
    var t = now();
    var id = idOf(e);
    var pick = pickBox(!!selected[id], '选择 ' + vt.recordLabel(e.record), function () {
      if (pick.checked) selected[id] = true; else delete selected[id];
      syncBulkBar();
    });
    // 记录: the entry's record by name, renameable in place (the salt is the key).
    var record = vt.recordList([e.record], null);
    var remaining = fmtRemaining(e.expires_ms - t);
    var until = '至 ' + fmtTime(e.expires_ms);
    var created = '创建于 ' + (fmtTime(e.created_ms) || '未知');
    return list.item({
      cls: 'clickable',
      attrs: { id: id },
      click: function () { openDetail(e); },
      cells: function () {
        var pickTd = document.createElement('td');
        pickTd.className = 'col-pick';
        pickTd.appendChild(pick);
        var recTd = document.createElement('td');
        recTd.className = 'col-rec';
        recTd.appendChild(record);
        return [pickTd, recTd, cell2(remaining, [until, created])];
      },
      row: function () {
        return { lead: pick, main: record, sub: [el('div', null, until + ' · ' + created)], trail: remaining };
      },
    });
  }

  function render() {
    list.clear();
    var rows = visibleEntries();
    var scopes = {};
    var order = [];
    rows.forEach(function (e) {
      var s = scopeOf(e);
      if (!scopes[s]) { scopes[s] = []; order.push(s); }
      scopes[s].push(e);
    });
    order.forEach(function (s) {
      list.body().appendChild(renderHeader(s, scopes[s]));
      if (!collapsed[s]) scopes[s].forEach(function (e) { list.body().appendChild(renderRow(e)); });
    });
    if (!rows.length) list.empty('没有有效的 DEK 缓存');
    var pickAll = $('#pick-all');
    pickAll.checked = rows.length > 0 && rows.every(function (e) { return selected[idOf(e)]; });
    syncBulkBar();
    var msg = rows.length + ' 条有效缓存 · ' + order.length + ' 个项目';
    if (meta.truncated) {
      msg += ' ⚠ 已扫描 ' + meta.scanned + ' 条并截断，列表不完整（「清除全部」仍覆盖所有条目）';
    }
    setStatus(msg, meta.truncated ? 'error' : 'ok');
  }

  // Selected entries that still exist in the current listing (a stale selection
  // must never be POSTed as a target).
  function selectedEntries() {
    return Object.keys(selected).filter(function (id) { return !!byId[id]; }).map(function (id) { return byId[id]; });
  }

  function syncBulkBar() {
    var ttl = selectedTtl();
    var es = selectedEntries();
    var bar = $('#bulkbar');
    bar.hidden = es.length === 0;
    if (es.length === 0) return;
    var scopes = {};
    es.forEach(function (e) { scopes[scopeOf(e)] = true; });
    var nScopes = Object.keys(scopes).length;
    $('#bulk-count').textContent = '已选 ' + es.length + ' 条 / ' + nScopes + ' 个项目';
    var gainers = es.filter(function (e) { return wouldGain(e, ttl); });
    var extendBtn = $('#extend-selected');
    var note = $('#extend-note');
    var parts = [];
    var warn = false;
    // Disabled when the request would provably fail — the server would refuse
    // it anyway, and a button that 400s is worse than one that explains itself.
    extendBtn.disabled = nScopes !== 1 || gainers.length === 0;
    if (nScopes !== 1) {
      parts.push('延长一次只能针对一个「主机 · 项目」，请缩小选择（撤销不受此限）');
      warn = true;
    } else if (gainers.length === 0) {
      // The common trap: extension is absolute, so a rung shorter than the time
      // already on the clock does nothing. Name the smallest rung that would work.
      var longest = 0;
      es.forEach(function (e) { var left = e.expires_ms - now(); if (left > longest) longest = left; });
      var need = smallestUsefulTtl(es);
      parts.push('所选时长 ' + ttlLabel(ttl) + ' 不会生效：现有剩余最长 '
        + fmtRemaining(longest) + '（延长是重设为「批准时刻 + 时长」，不是叠加）'
        + (need ? '，请选择 ' + ttlLabel(need) + ' 或更长' : ''));
      warn = true;
    } else {
      if (gainers.length < es.length) {
        parts.push('仅 ' + gainers.length + ' / ' + es.length + ' 条会因此延长（其余现有剩余已更长）');
        warn = true;
      }
      // A multi-day pick is a materially larger exposure than a workday one. The
      // approval page states it too, but say it before the request is even made.
      if (ttlIsLong(ttl)) {
        parts.push('⚠ ' + ttlLabel(ttl) + '内这 ' + gainers.length + ' 条记录的解密将持续免手机审批（同一主机令牌 + 项目）');
        warn = true;
      }
      parts.push('批准后有效期重设为「批准时刻 + ' + ttlLabel(ttl) + '」，可再次延长');
    }
    note.textContent = parts.join('；');
    note.className = warn ? 'hint warn' : 'hint';
  }

  // ── Detail sheet ─────────────────────────────────────────────────────────

  var addDetail = vt.dialog.addRow;

  function openDetail(e) {
    var d = vt.dialog.open({ title: '缓存条目' });
    var dl = d.dl;
    addDetail(dl, '主机', e.host);
    addDetail(dl, '用户', e.user);
    addDetail(dl, '项目', e.project, true);
    dl.appendChild(el('dt', null, '记录'));
    dl.appendChild(el('dd', null)).appendChild(vt.recordList([e.record], render));
    addDetail(dl, '批准时来源 IP', e.ip ? e.ip + '（仅作审计，不参与绑定）' : '');
    addDetail(dl, '缓存 TTL', typeof e.ttl_s === 'number' ? ttlLabel(e.ttl_s) : '');
    addDetail(dl, '创建于', fmtTime(e.created_ms) || '未知');
    addDetail(dl, '到期', fmtTime(e.expires_ms) + '（剩余 ' + fmtRemaining(e.expires_ms - now()) + '）');
    addDetail(dl, '主机令牌', e.token_id, true);
    addDetail(dl, '来源审批', e.origin_token_id, true);
  }

  // ── Load ──────────────────────────────────────────────────────────────────

  async function load() {
    setStatus('查询中…');
    try {
      var resp = await vt.apiFetch(API, { headers: { 'Accept': 'application/json' } });
      if (resp.status === 401) return; // the shell shows the login view
      if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      entries = (json && json.entries) || [];
      byId = {};
      entries.forEach(function (e) { byId[idOf(e)] = e; });
      // Drop selections whose entry is gone (cleared elsewhere, or expired).
      Object.keys(selected).forEach(function (id) { if (!byId[id]) delete selected[id]; });
      serverNowMs = typeof json.now_ms === 'number' ? json.now_ms : Date.now();
      localRefMs = Date.now();
      meta.ttl_options_s = json.ttl_options_s || [];
      meta.truncated = !!json.truncated;
      meta.scanned = json.scanned || 0;
      renderTtlOptions();
      render();
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  }

  function renderTtlOptions() {
    var sel = $('#extend-ttl');
    if (sel.options.length === meta.ttl_options_s.length && sel.options.length > 0) return;
    sel.innerHTML = '';
    meta.ttl_options_s.forEach(function (s) {
      var o = document.createElement('option');
      o.value = String(s);
      o.textContent = ttlLabel(s);
      sel.appendChild(o);
    });
  }

  function selectedTtl() {
    var v = parseInt($('#extend-ttl').value, 10);
    return Number.isFinite(v) && v > 0 ? v : 0;
  }

  // ── Revoke ────────────────────────────────────────────────────────────────

  async function revoke(es, btn) {
    if (!es.length) { setStatus('未选择任何条目', 'error'); return; }
    if (!confirm('撤销 ' + es.length + ' 条缓存？此后这些记录的解密将重新需要手机审批。')) return;
    btn.disabled = true;
    setStatus('撤销中…');
    try {
      var resp = await vt.postJson('cache-clear-entries', { entries: es.map(refOf) });
      if (!resp.ok) { setStatus('撤销失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      selected = {};
      // Refresh FIRST, then report — load() renders its own status line.
      await load();
      setStatus('✓ 已撤销 ' + (json && json.cleared != null ? json.cleared : '?') + ' 条缓存', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    } finally {
      btn.disabled = false;
    }
  }

  // ── Extend (Passkey-gated) ────────────────────────────────────────────────

  // Step 1: ask the Worker to mint a ceremony. This grants nothing on its own —
  // the response is a pending challenge that expires in ~5 minutes if untouched.
  async function requestExtend(es, btn) {
    var ttl = selectedTtl();
    if (!ttl) { setStatus('请选择延长时长', 'error'); return; }
    var targets = es.filter(function (e) { return wouldGain(e, ttl); });
    if (!targets.length) {
      var need = smallestUsefulTtl(es);
      setStatus('所选时长 ' + ttlLabel(ttl) + ' 短于现有剩余，不会生效'
        + (need ? '；请选择 ' + ttlLabel(need) + ' 或更长' : ''), 'error');
      return;
    }
    btn.disabled = true;
    setStatus('正在创建审批请求…');
    try {
      var resp = await vt.postJson('cache-extend-request', { entries: targets.map(refOf), ttl_s: ttl });
      if (resp.status === 401) return; // the shell shows the login view
      if (resp.status === 409) {
        // Refresh FIRST, then report — load() re-renders and would otherwise
        // overwrite the message.
        var why = null;
        try { why = (await resp.json()).rejected; } catch (e) { /* keep generic */ }
        await load();
        setStatus('没有可延长的目标' + reasonSummary(why), 'error');
        return;
      }
      if (!resp.ok) { setStatus('创建失败 HTTP ' + resp.status, 'error'); return; }
      openCeremony(await resp.json(), targets[0], ttl);
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    } finally {
      btn.disabled = false;
    }
  }

  function reasonSummary(rejected) {
    if (!rejected || !rejected.length) return '';
    var counts = {};
    rejected.forEach(function (r) { counts[r.reason] = (counts[r.reason] || 0) + 1; });
    return '：' + Object.keys(counts).map(function (k) { return (REASON_TEXT[k] || k) + ' ×' + counts[k]; }).join('；');
  }

  // Step 2: mount the standard approval ceremony for that challenge in the shared
  // dialog. The data comes from the public capability endpoint /api/page/:token —
  // exactly what the audit tab does for a pending row — so there is one ceremony
  // implementation, not two.
  function openCeremony(req, scope, ttl) {
    var d = vt.dialog.open({
      title: '延长 DEK 缓存',
      warn: '⚠️ 批准即延长这些缓存的免审批解密窗口。请确认主机、项目与记录符合预期。',
    });
    var dl = d.dl;
    var targets = req.targets || [];
    addDetail(dl, '范围', scopeLabel(scope) + ' · ' + targets.length + ' 条');
    addDetail(dl, '项目', scope.project, true);
    addDetail(dl, '记录', targets.map(function (salt) {
      var e = byId[scopeOf(scope) + '\u0000' + salt];
      return e ? vt.recordLabel(e.record) : salt.slice(0, 8) + '…';
    }).join(', '));
    addDetail(dl, '延长', ttlLabel(ttl) + '（自批准时刻起算）');
    addDetail(dl, '生效方式', '批准后有效期重设为「批准时刻 + ' + ttlLabel(ttl) + '」，覆盖原有效期');
    if (req.rejected && req.rejected.length) addDetail(dl, '已忽略', reasonSummary(req.rejected).slice(1));
    var box = d.approve;
    box.innerHTML = '';
    if (!vt.mountApprove) {
      setStatus('Passkey 组件未加载，无法完成延长', 'error');
      return;
    }
    setStatus('等待 Passkey 批准…');
    fetch('/api/page/' + encodeURIComponent(req.approve_token), { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) { setStatus('审批请求已失效，请重试', 'error'); return; }
        vt.mountApprove({
          data: data,
          root: box,
          showMeta: false,   // the dl above already states the intent
          onSettled: function (outcome) {
            setTimeout(function () {
              vt.dialog.close();
              if (outcome === 'approved') {
                selected = {};
                setStatus('✓ 已批准延长，正在刷新…', 'ok');
              } else {
                setStatus('已拒绝，缓存有效期未改变');
              }
              load();
            }, 800);
          },
        });
      })
      .catch(function (e) { setStatus('网络错误：' + (e.message || e), 'error'); });
  }

  // ── Wiring ────────────────────────────────────────────────────────────────

  $('.refresh').addEventListener('click', function () { load(); });
  $('.f-host').addEventListener('input', render);
  $('.f-project').addEventListener('input', render);
  // Re-run the note so the multi-day warning appears the moment 1d/2d/1w is picked.
  $('#extend-ttl').addEventListener('change', syncBulkBar);
  window.addEventListener('hashchange', applyHash);
  applyHash();

  $('#pick-all').addEventListener('change', function () {
    var on = this.checked;
    visibleEntries().forEach(function (e) { if (on) selected[idOf(e)] = true; else delete selected[idOf(e)]; });
    render();
  });

  $('#revoke-selected').addEventListener('click', function () { revoke(selectedEntries(), this); });
  $('#extend-selected').addEventListener('click', function () { requestExtend(selectedEntries(), this); });

  $('.clear-all-cache').addEventListener('click', async function () {
    if (!confirm('删除全部已缓存 DEK？此后解密将重新需要手机审批。')) return;
    setStatus('清空缓存中…');
    try {
      var resp = await vt.postJson('clear-cache');
      if (!resp.ok) { setStatus('清空缓存失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      selected = {};
      await load();
      setStatus('✓ 已清空 ' + (json && json.cleared != null ? json.cleared : '?') + ' 条 DEK 缓存', 'ok');
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  });

  // Expiry is pure time arithmetic, so nothing pushes a "cache expired" event.
  // Re-render every 15s: countdowns tick down and an entry that just lapsed
  // leaves the list without a round trip. Skipped while the ceremony modal is
  // open so a re-render cannot tear down a live WebAuthn prompt, and while a
  // record name is being edited in place.
  setInterval(function () { if (!vt.dialog.isOpen() && !panel.querySelector('.rec-edit')) render(); }, 15000);

  vt.hovercard.attach($('.table-wrap'));
  vt.onLayout(render);
  load();
};
