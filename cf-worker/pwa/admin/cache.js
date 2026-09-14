'use strict';

// DEK 缓存 tab. One row per cache GROUP (all entries one approval wrote
// under one binding ctx), from /{seg}/api/cache-list. Read-only rendering via
// textContent; every mutation is an explicit POST.
//
// Two classes of action, deliberately asymmetric:
//   • clear (per row / selected / all) — authority-REDUCING, one POST, immediate.
//   • extend — authority-GRANTING, so the admin session alone cannot do it: the
//     POST only opens a pending Passkey ceremony, which is then mounted inline via
//     the SAME vt.mountApprove() the approval page uses. Nothing expires later
//     until that ceremony is approved on a Passkey.
//
// Countdowns run against the SERVER clock (now_ms from the listing, advanced
// locally), so a skewed browser clock cannot invent remaining time.

vt.tabs.cache = function (panel) {
  var $ = function (sel) { return panel.querySelector(sel); };
  var API = vt.api('cache-list');
  var setStatus = vt.statusLine($('.status'));
  var el = vt.el, fmtTime = vt.fmtTime, fmtRemaining = vt.fmtRemaining, ttlLabel = vt.ttlLabel;

  var groups = [];            // last listing, newest expiry first
  var byGroup = {};           // group_id -> summary
  var selected = {};          // group_id -> true
  var meta = {                // listing-level fields
    extend_enabled: false, ttl_options_s: [],
    truncated: false, scanned: 0,
  };
  // Server clock at listing time + the local monotonic reference we advance it
  // from, so remaining-time math never depends on the browser's wall clock.
  var serverNowMs = 0;
  var localRefMs = 0;
  function now() { return serverNowMs + (Date.now() - localRefMs); }

  // A multi-day window is a materially different exposure from a workday one, so
  // the picker says so instead of letting "1 周" read like just another option.
  function ttlIsLong(s) { return s >= 86400; }

  // Would extending with `ttl` actually move this group's expiry? Extension is
  // absolute (now + ttl), never additive, so a TTL shorter than the time already
  // on the clock is a no-op — the server refuses it as `no_gain`. Deciding this
  // client-side is what lets the UI say so BEFORE the click instead of firing a
  // request that comes back 409 with nothing to show for it.
  function wouldGain(g, ttl) { return now() + ttl * 1000 > g.max_expires_ms; }

  // Smallest rung that would move every extendable group in `gs` forward, so the
  // UI can name the fix ("请选择 ≥ 2 天") rather than just refusing.
  function smallestUsefulTtl(gs) {
    var opts = meta.ttl_options_s || [];
    for (var i = 0; i < opts.length; i++) {
      var ok = gs.length > 0;
      for (var j = 0; j < gs.length; j++) {
        if (!wouldGain(gs[j], opts[i])) { ok = false; break; }
      }
      if (ok) return opts[i];
    }
    return 0;
  }

  // Why a group cannot be extended, in the operator's language. These mirror the
  // server's reason codes 1:1 (do_account.opCacheList) — the server decides, the
  // UI only translates, so the button state can never disagree with the policy.
  var REASON_TEXT = {
    expired: '已过期，需重新手机审批（延长只能续期仍然有效的缓存）',
    inconsistent: '组内条目不一致，仅允许清除',
    no_gain: '现有剩余时间已长于所选时长',
    not_extendable: '分组标识异常，仅允许清除',
    gone: '已被清除',
  };

  // Shorten a long path for the sub-line: keep the last two segments, which is
  // what identifies the working tree (…/code/dev/avibe), not the mount prefix.
  function shortPath(p) {
    if (!p) return '';
    var parts = String(p).split('/').filter(Boolean);
    if (parts.length <= 2) return p;
    return '…/' + parts.slice(-2).join('/');
  }

  // ── Filtering (client-side; the listing is one bounded snapshot) ───────────

  function visibleGroups() {
    var liveOnly = $('.f-live').value === 'live';
    var host = $('.f-host').value.trim();
    var t = now();
    return groups.filter(function (g) {
      if (liveOnly && !(g.max_expires_ms > t)) return false;
      if (host && g.host !== host) return false;
      return true;
    });
  }

  // ── Render ────────────────────────────────────────────────────────────────

  // Two-line cell: a primary value plus a muted secondary line. Halves the column
  // count so the action buttons and the extendability reason stay on screen at
  // laptop width instead of hiding behind a horizontal scroll.
  function cell2(tr, main, sub, opts) {
    opts = opts || {};
    var td = document.createElement('td');
    var m = el('div', 'cell-main' + (opts.mainCls ? ' ' + opts.mainCls : ''), main || '—');
    if (opts.mainHover) { m.setAttribute('data-hover', opts.mainHover); m.classList.add('has-hover'); }
    td.appendChild(m);
    if (sub != null && sub !== '') {
      var s = el('div', 'cell-sub' + (opts.subCls ? ' ' + opts.subCls : ''), sub);
      if (opts.subHover) { s.setAttribute('data-hover', opts.subHover); s.classList.add('has-hover'); }
      td.appendChild(s);
    } else if (opts.subNode) {
      td.appendChild(opts.subNode);
    }
    tr.appendChild(td);
    return td;
  }

  function renderRow(g) {
    var t = now();
    var live = g.max_expires_ms > t;
    var tr = document.createElement('tr');
    tr.setAttribute('data-group', g.group_id);
    tr.setAttribute('data-live', live ? '1' : '0');

    var pickTd = document.createElement('td');
    pickTd.className = 'col-pick';
    var pick = document.createElement('input');
    pick.type = 'checkbox';
    pick.checked = !!selected[g.group_id];
    pick.setAttribute('aria-label', '选择 ' + (g.host || g.group_id));
    pick.addEventListener('change', function () {
      if (pick.checked) selected[g.group_id] = true; else delete selected[g.group_id];
      syncBulkBar();
    });
    pickTd.appendChild(pick);
    tr.appendChild(pickTd);

    // 目标: host over user · directory. The full directory is the hover title;
    // the key binds the host token plus the project the approval reported.
    cell2(tr, g.host || '—',
      (g.user || '?') + (g.pwd ? ' · ' + shortPath(g.pwd) : ''),
      { mainCls: 'trunc-host',
        mainHover: '主机: ' + (g.host || '—') + '\n分组: ' + g.group_id
          + '\n来源审批: ' + g.origin_token_id,
        subCls: 'trunc-sub',
        subHover: '用户: ' + (g.user || '—') + '\n工作目录: ' + (g.pwd || '—')
          + '\n\n（缓存绑定该主机的令牌与客户端自报的项目，两者一致才会命中）' });

    // 命令: the command over the source IP at approval (audit metadata).
    cell2(tr, vt.commandSummary(g.command, 120), g.ip,
      { mainCls: 'trunc-cmd',
        mainHover: (g.command || '—') + (g.ppid_cmd ? '\n\n父进程: ' + g.ppid_cmd : ''),
        subCls: 'mono',
        subHover: '批准时来源 IP: ' + (g.ip || '—')
          + '\n（Worker 侧取自 CF-Connecting-IP，仅作审计，不参与绑定）' });

    // 条目: live count, with the swept-but-present total only when they differ.
    cell2(tr, String(g.live), g.entries !== g.live ? '共 ' + g.entries : '',
      { mainCls: 'col-num' }).className = 'col-num';

    // 剩余 / 余量: remaining window on top; below it either the extendable
    // headroom or — critically — WHY this group cannot be extended. The reason
    // used to live only in the far-right action cell, which scrolled off screen,
    // so the page never explained itself.
    var remTd = cell2(tr, live ? fmtRemaining(g.max_expires_ms - t) : '已过期', '',
      { mainCls: live ? '' : 'cache-expired' });
    // Sub-line: the exact expiry while live, or WHY the row cannot be extended.
    var sub = null;
    if (meta.extend_enabled && !g.extendable && g.reason) {
      sub = el('div', 'cell-sub reason-badge', REASON_TEXT[g.reason] || g.reason);
    } else if (live) {
      sub = el('div', 'cell-sub', '至 ' + fmtTime(g.max_expires_ms));
    }
    if (sub) remTd.appendChild(sub);
    remTd.appendChild(el('div', 'cell-sub', '创建于 ' + (fmtTime(g.created_ms) || '未知')));

    var act = document.createElement('td');
    act.className = 'col-act';
    var clr = el('button', 'danger small', '清除');
    clr.type = 'button';
    clr.title = '立即失效这 ' + g.live + ' 条缓存，之后解密需重新手机审批';
    clr.addEventListener('click', function () { clearGroups([g.group_id], clr); });
    act.appendChild(clr);
    if (meta.extend_enabled && g.extendable) {
      var ttlNow = selectedTtl();
      var gains = wouldGain(g, ttlNow);
      var ext = el('button', 'small ghost', '延长');
      ext.type = 'button';
      ext.disabled = !gains;
      ext.title = gains
        ? '发起延长审批（需 Passkey 批准）：有效期将重设为「批准时刻 + ' + ttlLabel(ttlNow) + '」'
        : '所选时长 ' + ttlLabel(ttlNow) + ' 短于现有剩余 '
          + fmtRemaining(g.max_expires_ms - t) + '，不会生效；请在上方选更长的时长';
      ext.addEventListener('click', function () { requestExtend([g.group_id], ext); });
      act.appendChild(ext);
    }
    tr.appendChild(act);
    return tr;
  }

  function render() {
    var tbody = $('.rows');
    tbody.innerHTML = '';
    var rows = visibleGroups();
    rows.forEach(function (g) { tbody.appendChild(renderRow(g)); });
    var pickAll = $('#pick-all');
    pickAll.checked = rows.length > 0 && rows.every(function (g) { return selected[g.group_id]; });
    syncBulkBar();
    var liveTotal = groups.reduce(function (n, g) { return n + g.live; }, 0);
    var msg = rows.length + ' 组 / 共 ' + liveTotal + ' 条有效缓存';
    // When extension is on but NOTHING is extendable, say why up front. Without
    // this the page looks broken: buttons absent, no explanation in view.
    if (meta.extend_enabled && rows.length > 0) {
      var extendable = rows.filter(function (g) { return g.extendable; }).length;
      if (extendable === 0) {
        var why = {};
        rows.forEach(function (g) { if (g.reason) why[g.reason] = (why[g.reason] || 0) + 1; });
        msg += ' · 均不可延长（' + Object.keys(why).map(function (k) {
          return (REASON_TEXT[k] || k) + ' ×' + why[k];
        }).join('；') + '）';
      }
    }
    if (meta.truncated) {
      msg += ' ⚠ 已扫描 ' + meta.scanned + ' 条并截断，列表不完整（「清除全部」仍覆盖所有条目）';
    }
    setStatus(msg, meta.truncated ? 'error' : 'ok');
  }

  // Selected groups that still exist in the current listing (a stale selection
  // must never be POSTed as an extend target).
  function selectedIds() {
    return Object.keys(selected).filter(function (id) { return !!byGroup[id]; });
  }

  function syncBulkBar() {
    // Read the chosen duration FIRST: everything below (button state, per-row
    // eligibility, the note) is a function of it. It used to be declared further
    // down, so the `gainers` filter saw a hoisted `undefined` and disabled the
    // button unconditionally.
    var ttl = selectedTtl();
    var ids = selectedIds();
    var bar = $('#bulkbar');
    var countEl = $('#bulk-count');
    var extendBtn = $('#extend-selected');
    var note = $('#extend-note');
    bar.hidden = ids.length === 0;
    if (ids.length === 0) return;
    var entries = 0, extendable = 0;
    var extGroups = [];
    ids.forEach(function (id) {
      var g = byGroup[id];
      entries += g.live;
      if (g.extendable) { extendable++; extGroups.push(g); }
    });
    countEl.textContent = '已选 ' + ids.length + ' 组 / ' + entries + ' 条';
    var ttlLabelEl = $('#extend-ttl-label');
    if (!meta.extend_enabled) {
      // Caching off ⇒ extension is not offered. Hide the controls
      // entirely rather than offer a button that can only 404.
      extendBtn.hidden = true;
      ttlLabelEl.hidden = true;
      note.textContent = '延长不可用：请先在「设置」启用 DEK 缓存';
      return;
    }
    ttlLabelEl.hidden = false;
    extendBtn.hidden = false;
    var gainers = extGroups.filter(function (g) { return wouldGain(g, ttl); });
    // Disabled when the request would provably change nothing — the server would
    // refuse it as no_gain anyway, and a button that 409s is worse than one that
    // explains itself.
    extendBtn.disabled = gainers.length === 0;
    // Build the note additively: a partial selection and a long-window warning are
    // independent facts, and the earlier version let the former hide the latter —
    // so picking 1 周 on a mixed selection showed no exposure warning at all.
    var parts = [];
    var warn = false;
    if (extendable === 0) {
      // Explain the disabled button instead of leaving a dead control on screen.
      var reasons = {};
      ids.forEach(function (id) {
        var r = byGroup[id].reason;
        if (r) reasons[r] = (reasons[r] || 0) + 1;
      });
      parts.push('所选分组均不可延长：' + Object.keys(reasons).map(function (k) {
        return (REASON_TEXT[k] || k) + ' ×' + reasons[k];
      }).join('；'));
      warn = true;
    } else if (gainers.length === 0) {
      // The common trap: extension is absolute, so a rung shorter than the time
      // already on the clock does nothing. Name the smallest rung that would work.
      var longest = 0;
      extGroups.forEach(function (g) {
        var left = g.max_expires_ms - now();
        if (left > longest) longest = left;
      });
      var need = smallestUsefulTtl(extGroups);
      parts.push('所选时长 ' + ttlLabel(ttl) + ' 不会生效：现有剩余最长 '
        + fmtRemaining(longest) + '（延长是重设为「批准时刻 + 时长」，不是叠加）'
        + (need ? '，请选择 ' + ttlLabel(need) + ' 或更长' : ''));
      warn = true;
    } else {
      if (gainers.length < extendable) {
        parts.push('仅 ' + gainers.length + ' / ' + extendable
          + ' 组会因此延长（其余现有剩余已更长）');
        warn = true;
      } else if (extendable < ids.length) {
        parts.push('仅 ' + extendable + ' / ' + ids.length + ' 组可延长，其余将被忽略');
        warn = true;
      }
      // A multi-day pick is a materially larger exposure than a workday one. The
      // approval page states it too, but say it before the request is even made.
      if (ttlIsLong(ttl)) {
        parts.push('⚠ ' + ttlLabel(ttl) + '内这 ' + gainers.length
          + ' 组记录的解密将持续免手机审批（同一主机令牌 + 项目）');
        warn = true;
      }
      parts.push('批准后有效期重设为「批准时刻 + ' + ttlLabel(ttl) + '」，可再次延长');
    }
    note.textContent = parts.join('；');
    note.className = warn ? 'hint warn' : 'hint';
  }

  // ── Load ──────────────────────────────────────────────────────────────────

  async function load() {
    setStatus('查询中…');
    try {
      var resp = await vt.apiFetch(API, { headers: { 'Accept': 'application/json' } });
      if (resp.status === 401) return; // the shell shows the login view
      if (!resp.ok) { setStatus('查询失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      groups = (json && json.groups) || [];
      byGroup = {};
      groups.forEach(function (g) { byGroup[g.group_id] = g; });
      // Drop selections whose group is gone (cleared elsewhere, or expired+swept).
      Object.keys(selected).forEach(function (id) { if (!byGroup[id]) delete selected[id]; });
      serverNowMs = typeof json.now_ms === 'number' ? json.now_ms : Date.now();
      localRefMs = Date.now();
      meta.extend_enabled = !!json.extend_enabled;
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

  // ── Clear ─────────────────────────────────────────────────────────────────

  async function clearGroups(ids, btn) {
    if (!ids.length) return;
    if (!confirm('清除 ' + ids.length + ' 组缓存？此后这些记录的解密将重新需要手机审批。')) return;
    if (btn) btn.disabled = true;
    setStatus('清除中…');
    try {
      var resp = await vt.apiFetch(vt.api('cache-clear-groups'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ group_ids: ids }),
      });
      if (!resp.ok) { setStatus('清除失败 HTTP ' + resp.status, 'error'); if (btn) btn.disabled = false; return; }
      var json = await resp.json();
      ids.forEach(function (id) { delete selected[id]; });
      setStatus('✓ 已清除 ' + (json && json.cleared != null ? json.cleared : '?') + ' 条缓存', 'ok');
      await load();
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
      if (btn) btn.disabled = false;
    }
  }

  // ── Extend (Passkey-gated) ────────────────────────────────────────────────

  var addDetail = vt.dialog.addRow;

  // Step 1: ask the Worker to mint a ceremony. This grants nothing on its own —
  // the response is a pending challenge that expires in ~5 minutes if untouched.
  async function requestExtend(ids, btn) {
    var ttl = selectedTtl();
    if (!ttl) { setStatus('请选择延长时长', 'error'); return; }
    // Filter on the SAME predicate the server enforces, so the client never fires a
    // request it can already tell will be refused — and when it can't proceed, it
    // names the fix instead of reporting a bare failure.
    var eligible = ids.filter(function (id) { return byGroup[id] && byGroup[id].extendable; });
    var targets = eligible.filter(function (id) { return wouldGain(byGroup[id], ttl); });
    if (!targets.length) {
      if (eligible.length) {
        var need = smallestUsefulTtl(eligible.map(function (id) { return byGroup[id]; }));
        setStatus('所选时长 ' + ttlLabel(ttl) + ' 短于现有剩余，不会生效'
          + (need ? '；请选择 ' + ttlLabel(need) + ' 或更长' : ''), 'error');
      } else {
        setStatus('所选分组均不可延长', 'error');
      }
      return;
    }
    if (btn) btn.disabled = true;
    setStatus('正在创建审批请求…');
    try {
      var resp = await vt.apiFetch(vt.api('cache-extend-request'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ group_ids: targets, ttl_s: ttl }),
      });
      if (resp.status === 404) {
        setStatus('延长不可用：DEK 缓存未启用', 'error');
        return;
      }
      if (resp.status === 401) return; // the shell shows the login view
      if (resp.status === 409) {
        // Refresh FIRST, then report — load() re-renders and would otherwise
        // overwrite the message, which is exactly how this failure managed to look
        // like "the button does nothing".
        var why = null;
        try { why = (await resp.json()).rejected; } catch (e) { /* keep generic */ }
        await load();
        var detail = '';
        if (why && why.length) {
          var counts = {};
          why.forEach(function (r) { counts[r.reason] = (counts[r.reason] || 0) + 1; });
          detail = '：' + Object.keys(counts).map(function (k) {
            return (REASON_TEXT[k] || k) + ' ×' + counts[k];
          }).join('；');
        }
        setStatus('没有可延长的目标' + detail, 'error');
        return;
      }
      if (!resp.ok) { setStatus('创建失败 HTTP ' + resp.status, 'error'); return; }
      var req = await resp.json();
      openCeremony(req, targets, ttl);
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // Step 2: mount the standard approval ceremony for that challenge in the shared
  // dialog. The data comes from the public capability endpoint /api/page/:token —
  // exactly what the audit tab does for a pending row — so there is one ceremony
  // implementation, not two.
  function openCeremony(req, targets, ttl) {
    var d = vt.dialog.open({
      title: '延长 DEK 缓存',
      warn: '⚠️ 批准即延长这些缓存的免审批解密窗口。请确认上面的主机、IP 与条目数符合预期。',
    });
    var dl = d.dl;
    var entries = (req.targets || []).reduce(function (n, t) { return n + t.live; }, 0);
    addDetail(dl, '范围', (req.targets || []).length + ' 组 / ' + entries + ' 条');
    addDetail(dl, '延长', ttlLabel(ttl) + '（自批准时刻起算）');
    addDetail(dl, '生效方式', '批准后有效期重设为「批准时刻 + ' + ttlLabel(ttl) + '」，覆盖原有效期');
    (req.targets || []).forEach(function (t) {
      addDetail(dl, t.host || '?', t.ip + ' · ' + t.live + ' 条 · 现有效期至 ' + fmtTime(t.expires_ms));
    });
    if (req.rejected && req.rejected.length) {
      addDetail(dl, '已忽略', req.rejected.map(function (r) {
        return (byGroup[r.group_id] && byGroup[r.group_id].host ? byGroup[r.group_id].host : r.group_id)
          + '（' + (REASON_TEXT[r.reason] || r.reason) + '）';
      }).join('；'));
    }
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
  $('.f-live').addEventListener('change', render);
  $('.f-host').addEventListener('input', render);
  // Re-run the note so the multi-day warning appears the moment 1d/2d/1w is picked.
  $('#extend-ttl').addEventListener('change', render);

  $('#pick-all').addEventListener('change', function () {
    var on = this.checked;
    visibleGroups().forEach(function (g) {
      if (on) selected[g.group_id] = true; else delete selected[g.group_id];
    });
    render();
  });

  $('#clear-selected').addEventListener('click', function () {
    var ids = selectedIds();
    if (!ids.length) { setStatus('未选择任何分组', 'error'); return; }
    clearGroups(ids, this);
  });

  $('#extend-selected').addEventListener('click', function () {
    requestExtend(selectedIds(), this);
  });

  $('.clear-all-cache').addEventListener('click', async function () {
    if (!confirm('删除全部已缓存 DEK？此后解密将重新需要手机审批。')) return;
    setStatus('清空缓存中…');
    try {
      var resp = await vt.apiFetch(vt.api('clear-cache'), { method: 'POST', headers: { 'Accept': 'application/json' } });
      if (!resp.ok) { setStatus('清空缓存失败 HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      selected = {};
      setStatus('✓ 已清空 ' + (json && json.cleared != null ? json.cleared : '?') + ' 条 DEK 缓存', 'ok');
      await load();
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  });

  // Expiry is pure time arithmetic, so nothing pushes a "cache expired" event.
  // Re-render every 15s: countdowns tick down and a group that just lapsed turns
  // grey (and drops its 延长 button) without a round trip. Skipped while the
  // ceremony modal is open so a re-render cannot tear down a live WebAuthn prompt.
  setInterval(function () { if (!vt.dialog.isOpen()) render(); }, 15000);

  vt.hovercard.attach($('.table-wrap'));
  load();
};
