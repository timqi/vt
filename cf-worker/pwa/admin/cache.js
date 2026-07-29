'use strict';

// DEK-cache inventory. One row per cache GROUP (all entries one approval wrote
// under one binding ctx), from /{seg}/api/cache-list. Read-only rendering via
// textContent; every mutation is an explicit POST.
//
// Two classes of action, deliberately asymmetric:
//   • clear (per row / selected / all) — authority-REDUCING, one POST, immediate.
//   • extend — authority-GRANTING, so the Access session alone cannot do it: the
//     POST only opens a pending Passkey ceremony, which is then mounted inline via
//     the SAME vt.mountApprove() the approval page uses. Nothing expires later
//     until that ceremony is approved on a Passkey.
//
// Countdowns run against the SERVER clock (now_ms from the listing, advanced
// locally), so a skewed browser clock cannot invent remaining time.

(function () {
  var seg = location.pathname.split('/')[1] || '';
  var API = '/' + seg + '/api/cache-list';

  var statusEl = document.getElementById('status');
  function setStatus(t, kind) { statusEl.textContent = t || ''; statusEl.className = kind || ''; }

  var groups = [];            // last listing, newest expiry first
  var byGroup = {};           // group_id -> summary
  var selected = {};          // group_id -> true
  var meta = {                // listing-level fields
    extend_enabled: false, ttl_options_s: [], max_extend_ttl_ms: 0,
    truncated: false, scanned: 0,
  };
  // Server clock at listing time + the local monotonic reference we advance it
  // from, so remaining-time math never depends on the browser's wall clock.
  var serverNowMs = 0;
  var localRefMs = 0;
  function now() { return serverNowMs + (Date.now() - localRefMs); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function cell(tr, text, cls) {
    var td = document.createElement('td');
    if (cls) td.className = cls;
    td.textContent = (text === null || text === undefined) ? '' : String(text);
    tr.appendChild(td);
    return td;
  }

  function cellClipped(tr, text, cls) {
    var td = document.createElement('td');
    var span = el('span', 'trunc ' + cls);
    var s = (text === null || text === undefined) ? '' : String(text);
    span.textContent = s;
    if (s) span.title = s;
    td.appendChild(span);
    tr.appendChild(td);
    return td;
  }

  function fmtTime(ms) {
    if (typeof ms !== 'number' || ms <= 0) return '';
    var d = new Date(ms);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
      ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  // Coarse remaining-time label; the ticker re-renders every 15s so minute
  // granularity is honest (we never show a second-precision value that is stale).
  function fmtRemaining(ms) {
    if (ms <= 0) return '已过期';
    var mins = Math.floor(ms / 60000);
    if (mins < 1) return '< 1 分钟';
    if (mins < 60) return mins + ' 分钟';
    // Roll over to days past 24h: with a one-week ceiling, "167 小时 47 分" is a
    // number an operator has to do arithmetic on before they can judge the risk.
    if (mins >= 1440) {
      var d = Math.floor(mins / 1440), dh = Math.floor((mins % 1440) / 60);
      return d + ' 天' + (dh ? ' ' + dh + ' 小时' : '');
    }
    var h = Math.floor(mins / 60), m = mins % 60;
    return h + ' 小时' + (m ? ' ' + m + ' 分' : '');
  }

  function ttlLabel(s) {
    if (s % 604800 === 0) return (s / 604800) + ' 周';
    if (s % 86400 === 0) return (s / 86400) + ' 天';
    if (s % 3600 === 0) return (s / 3600) + ' 小时';
    if (s % 60 === 0) return (s / 60) + ' 分钟';
    return s + ' 秒';
  }

  // A multi-day window is a materially different exposure from a workday one, so
  // the picker says so instead of letting "1 周" read like just another option.
  function ttlIsLong(s) { return s >= 86400; }

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

  // Cosmetic, FRONTEND-ONLY (same rule as the audit tab): if the command's leading
  // program is an absolute path, show just its basename, so a row reads
  // `gh pr view 1064 …` instead of `/home/qiqi/.local/bin/gh pr view …` — which
  // ate the whole column. Only argv[0] is trimmed; path-valued arguments stay
  // intact so the command remains unambiguous.
  function basenameLeadingProgram(s) {
    var m = /^(\s*)(\/\S*)(.*)$/.exec(s);
    if (!m) return s;
    var prog = m[2];
    var base = prog.slice(prog.lastIndexOf('/') + 1);
    if (base === '') return s;
    return m[1] + base + m[3];
  }

  function commandSummary(cmd, max) {
    if (!cmd) return '';
    var lines = String(cmd).split('\n');
    var pick = lines[0];
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf('cmd:') === 0) { pick = lines[i].slice(4).trim(); break; }
    }
    var v = basenameLeadingProgram(pick);
    return v.length > max ? v.slice(0, max) + '…' : v;
  }

  // Shorten a long path for the sub-line: keep the last two segments, which is
  // what identifies the working tree (…/code/dev/avibe), not the mount prefix.
  function shortPath(p) {
    if (!p) return '';
    var parts = String(p).split('/').filter(Boolean);
    if (parts.length <= 2) return p;
    return '…/' + parts.slice(-2).join('/');
  }

  // ── Hover card ────────────────────────────────────────────────────────────
  // The native `title` tooltip is the wrong tool here: ~1s browser delay, tiny
  // system font, no wrapping, and it collapses a multi-line command onto one line.
  // These cells hold the two values an operator most needs to read in full — the
  // bound working directory and the exact command — so they get a real popup:
  // ~90ms, wrapping, monospace, and multi-line preserved.
  //
  // Positioned by assigning to element.style.* (CSSOM), which is NOT an inline
  // style attribute and so is allowed under `style-src 'self'` — do not switch this
  // to setAttribute('style', …), which the CSP would block.
  var hoverCard = null;
  var hoverTimer = null;

  function ensureHoverCard() {
    if (!hoverCard) {
      hoverCard = el('div', 'hovercard');
      hoverCard.hidden = true;
      document.body.appendChild(hoverCard);
    }
    return hoverCard;
  }

  function showHover(target, text) {
    var card = ensureHoverCard();
    card.textContent = text;
    card.hidden = false;
    // Measure after the text is in, then place: below the cell by default, flipped
    // above when it would overflow the viewport, and clamped horizontally.
    var r = target.getBoundingClientRect();
    var cw = card.offsetWidth, ch = card.offsetHeight;
    var pad = 8;
    var left = Math.min(Math.max(pad, r.left), window.innerWidth - cw - pad);
    var top = r.bottom + 6;
    if (top + ch > window.innerHeight - pad) top = Math.max(pad, r.top - ch - 6);
    card.style.left = left + 'px';
    card.style.top = top + 'px';
  }

  function hideHover() {
    if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
    if (hoverCard) { hoverCard.hidden = true; hoverCard.textContent = ''; }
  }

  // Delegated, so re-rendering rows every 15s never leaves stale listeners behind.
  function initHover(scopeId) {
    var scope = document.getElementById(scopeId);
    if (!scope) return;
    scope.addEventListener('mouseover', function (e) {
      var t = e.target.closest ? e.target.closest('[data-hover]') : null;
      if (!t) return;
      var text = t.getAttribute('data-hover');
      if (!text) return;
      if (hoverTimer) clearTimeout(hoverTimer);
      hoverTimer = setTimeout(function () { showHover(t, text); }, 90);
    });
    scope.addEventListener('mouseout', function (e) {
      var t = e.target.closest ? e.target.closest('[data-hover]') : null;
      if (t) hideHover();
    });
    // Tap-to-inspect on touch devices, where there is no hover at all.
    scope.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target.closest('[data-hover]') : null;
      if (!t) { hideHover(); return; }
      if (hoverCard && !hoverCard.hidden) { hideHover(); return; }
      showHover(t, t.getAttribute('data-hover') || '');
    });
    window.addEventListener('scroll', hideHover, true);
    window.addEventListener('resize', hideHover);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') hideHover(); });
  }

  // ── Filtering (client-side; the listing is one bounded snapshot) ───────────

  function visibleGroups() {
    var liveOnly = document.getElementById('f-live').value === 'live';
    var host = document.getElementById('f-host').value.trim();
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

    // 目标: host over user · directory. The full directory is the hover title —
    // it is half the cache binding, so it must stay inspectable.
    cell2(tr, g.host || '—',
      (g.user || '?') + (g.pwd ? ' · ' + shortPath(g.pwd) : ''),
      { mainCls: 'trunc-host',
        mainHover: '主机: ' + (g.host || '—') + '\n分组: ' + g.group_id
          + '\n来源审批: ' + g.origin_token_id,
        subCls: 'trunc-sub',
        subHover: '用户: ' + (g.user || '—') + '\n工作目录: ' + (g.pwd || '—')
          + '\n\n（目录与来源 IP 共同构成缓存绑定，两者一致才会命中）' });

    // 命令: the command over the bound source IP (the hard half of the binding).
    cell2(tr, commandSummary(g.command, 120), g.ip,
      { mainCls: 'trunc-cmd',
        mainHover: (g.command || '—') + (g.ppid_cmd ? '\n\n父进程: ' + g.ppid_cmd : ''),
        subCls: 'mono',
        subHover: '来源 IP: ' + (g.ip || '—')
          + '\n（Worker 侧取自 CF-Connecting-IP，客户端无法伪造）' });

    // 条目: live count, with the swept-but-present total only when they differ.
    cell2(tr, String(g.live), g.entries !== g.live ? '共 ' + g.entries : '',
      { mainCls: 'col-num' }).className = 'col-num';

    // 剩余 / 余量: remaining window on top; below it either the extendable
    // headroom or — critically — WHY this group cannot be extended. The reason
    // used to live only in the far-right action cell, which scrolled off screen,
    // so the page never explained itself.
    var remTd = cell2(tr, live ? fmtRemaining(g.max_expires_ms - t) : '已过期', '',
      { mainCls: live ? '' : 'cache-expired',
        mainTitle: live ? '有效期至 ' + fmtTime(g.max_expires_ms) : '' });
    // Sub-line: the exact expiry while live, or WHY the row cannot be extended.
    var sub = null;
    if (meta.extend_enabled && !g.extendable && g.reason) {
      sub = el('div', 'cell-sub reason-badge', REASON_TEXT[g.reason] || g.reason);
    } else if (live) {
      sub = el('div', 'cell-sub', '至 ' + fmtTime(g.max_expires_ms));
    }
    if (sub) remTd.appendChild(sub);

    var act = document.createElement('td');
    act.className = 'col-act';
    var clr = el('button', 'danger small', '清除');
    clr.type = 'button';
    clr.title = '立即失效这 ' + g.live + ' 条缓存，之后解密需重新手机审批';
    clr.addEventListener('click', function () { clearGroups([g.group_id], clr); });
    act.appendChild(clr);
    if (meta.extend_enabled && g.extendable) {
      var ext = el('button', 'small ghost', '延长');
      ext.type = 'button';
      ext.title = '发起延长审批（需 Passkey 批准）';
      ext.addEventListener('click', function () { requestExtend([g.group_id], ext); });
      act.appendChild(ext);
    }
    tr.appendChild(act);
    return tr;
  }

  function render() {
    var tbody = document.getElementById('rows');
    tbody.innerHTML = '';
    var rows = visibleGroups();
    rows.forEach(function (g) { tbody.appendChild(renderRow(g)); });
    var pickAll = document.getElementById('pick-all');
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
    var ids = selectedIds();
    var bar = document.getElementById('bulkbar');
    var countEl = document.getElementById('bulk-count');
    var extendBtn = document.getElementById('extend-selected');
    var note = document.getElementById('extend-note');
    bar.hidden = ids.length === 0;
    if (ids.length === 0) return;
    var entries = 0, extendable = 0;
    ids.forEach(function (id) {
      var g = byGroup[id];
      entries += g.live;
      if (g.extendable) extendable++;
    });
    countEl.textContent = '已选 ' + ids.length + ' 组 / ' + entries + ' 条';
    var ttlLabelEl = document.getElementById('extend-ttl-label');
    if (!meta.extend_enabled) {
      // Kill switch off ⇒ the capability does not exist. Hide the controls
      // entirely rather than offer a button that can only 404.
      extendBtn.hidden = true;
      ttlLabelEl.hidden = true;
      note.textContent = '延长功能未启用（设置 CACHE_ADMIN_EXTEND=1 后可用）';
      return;
    }
    ttlLabelEl.hidden = false;
    extendBtn.hidden = false;
    extendBtn.disabled = extendable === 0;
    // Build the note additively: a partial selection and a long-window warning are
    // independent facts, and the earlier version let the former hide the latter —
    // so picking 1 週 on a mixed selection showed no exposure warning at all.
    var ttl = selectedTtl();
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
    } else {
      if (extendable < ids.length) {
        parts.push('仅 ' + extendable + ' / ' + ids.length + ' 组可延长，其余将被忽略');
        warn = true;
      }
      // A multi-day pick is a materially larger exposure than a workday one. The
      // approval page states it too, but say it before the request is even made.
      if (ttlIsLong(ttl)) {
        parts.push('⚠ ' + ttlLabel(ttl) + '内这 ' + extendable
          + ' 组记录的解密将持续免手机审批（同一来源 IP + 工作目录）');
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
      var resp = await fetch(API, { headers: { 'Accept': 'application/json' } });
      if (resp.status === 403) {
        setStatus('未授权（Cloudflare Access 会话可能已过期，请刷新登录）', 'error');
        return;
      }
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
      meta.max_extend_ttl_ms = json.max_extend_ttl_ms || 0;
      meta.truncated = !!json.truncated;
      meta.scanned = json.scanned || 0;
      renderTtlOptions();
      render();
    } catch (e) {
      setStatus('网络错误：' + (e.message || e), 'error');
    }
  }

  function renderTtlOptions() {
    var sel = document.getElementById('extend-ttl');
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
    var v = parseInt(document.getElementById('extend-ttl').value, 10);
    return Number.isFinite(v) && v > 0 ? v : 0;
  }

  // ── Clear ─────────────────────────────────────────────────────────────────

  async function clearGroups(ids, btn) {
    if (!ids.length) return;
    if (!confirm('清除 ' + ids.length + ' 组缓存？此后这些记录的解密将重新需要手机审批。')) return;
    if (btn) btn.disabled = true;
    setStatus('清除中…');
    try {
      var resp = await fetch('/' + seg + '/api/cache-clear-groups', {
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

  var backdrop = document.getElementById('detail-backdrop');

  function closeDetail() {
    backdrop.hidden = true;
    var box = document.getElementById('detail-approve');
    if (box) box.innerHTML = '';
  }
  document.getElementById('detail-close').addEventListener('click', closeDetail);
  backdrop.addEventListener('click', function (e) { if (e.target === backdrop) closeDetail(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeDetail(); });

  function addDetail(dl, label, value) {
    if (value === null || value === undefined || value === '') return;
    var dt = el('dt', null, label);
    var dd = el('dd', null, String(value));
    dl.appendChild(dt); dl.appendChild(dd);
  }

  // Step 1: ask the Worker to mint a ceremony. This grants nothing on its own —
  // the response is a pending challenge that expires in ~5 minutes if untouched.
  async function requestExtend(ids, btn) {
    var ttl = selectedTtl();
    if (!ttl) { setStatus('请选择延长时长', 'error'); return; }
    var targets = ids.filter(function (id) { return byGroup[id] && byGroup[id].extendable; });
    if (!targets.length) { setStatus('所选分组均不可延长', 'error'); return; }
    if (btn) btn.disabled = true;
    setStatus('正在创建审批请求…');
    try {
      var resp = await fetch('/' + seg + '/api/cache-extend-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ group_ids: targets, ttl_s: ttl }),
      });
      if (resp.status === 404) {
        setStatus('延长功能未启用（CACHE_ADMIN_EXTEND）', 'error');
        return;
      }
      if (resp.status === 409) {
        setStatus('没有可延长的目标（可能刚刚过期或已被清除）', 'error');
        await load();
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

  // Step 2: mount the standard approval ceremony for that challenge. The data comes
  // from the public capability endpoint /api/page/:token — exactly what the audit
  // tab does for a pending row — so there is one ceremony implementation, not two.
  function openCeremony(req, targets, ttl) {
    var dl = document.getElementById('detail-dl');
    dl.innerHTML = '';
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
    backdrop.hidden = false;
    var box = document.getElementById('detail-approve');
    box.innerHTML = '';
    if (!window.vt || !vt.mountApprove) {
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
              closeDetail();
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

  document.getElementById('refresh').addEventListener('click', function () { load(); });
  document.getElementById('f-live').addEventListener('change', render);
  document.getElementById('f-host').addEventListener('input', render);
  // Re-run the note so the multi-day warning appears the moment 1d/2d/1w is picked.
  document.getElementById('extend-ttl').addEventListener('change', syncBulkBar);

  document.getElementById('pick-all').addEventListener('change', function () {
    var on = this.checked;
    visibleGroups().forEach(function (g) {
      if (on) selected[g.group_id] = true; else delete selected[g.group_id];
    });
    render();
  });

  document.getElementById('clear-selected').addEventListener('click', function () {
    var ids = selectedIds();
    if (!ids.length) { setStatus('未选择任何分组', 'error'); return; }
    clearGroups(ids, this);
  });

  document.getElementById('extend-selected').addEventListener('click', function () {
    requestExtend(selectedIds(), this);
  });

  document.getElementById('clear-all-cache').addEventListener('click', async function () {
    if (!confirm('删除全部已缓存 DEK？此后解密将重新需要手机审批。')) return;
    setStatus('清空缓存中…');
    try {
      var resp = await fetch('/' + seg + '/api/clear-cache', {
        method: 'POST', headers: { 'Accept': 'application/json' },
      });
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
  setInterval(function () { if (backdrop.hidden) render(); }, 15000);

  initHover('table-wrap');
  load();
})();
