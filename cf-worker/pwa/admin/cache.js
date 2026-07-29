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
    extend_enabled: false, ttl_options_s: [], max_lifetime_ms: 0,
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
    var h = Math.floor(mins / 60), m = mins % 60;
    return h + ' 小时' + (m ? ' ' + m + ' 分' : '');
  }

  function ttlLabel(s) {
    if (s % 3600 === 0) return (s / 3600) + ' 小时';
    if (s % 60 === 0) return (s / 60) + ' 分钟';
    return s + ' 秒';
  }

  // Why a group cannot be extended, in the operator's language. These mirror the
  // server's reason codes 1:1 (do_account.opCacheList) — the server decides, the
  // UI only translates, so the button state can never disagree with the policy.
  var REASON_TEXT = {
    legacy: '旧版条目（无创建时间，无法限定总时长）',
    inconsistent: '组内条目不一致，仅允许清除',
    expired: '已全部过期',
    capped: '已达创建后总时长上限',
    no_gain: '已用满总时长，延长不会生效',
    not_extendable: '不可延长',
    gone: '已被清除',
  };

  function commandSummary(cmd, max) {
    if (!cmd) return '';
    var lines = String(cmd).split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf('cmd:') === 0) {
        var v = lines[i].slice(4).trim();
        return v.length > max ? v.slice(0, max) + '…' : v;
      }
    }
    var first = lines[0];
    return first.length > max ? first.slice(0, max) + '…' : first;
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

    cellClipped(tr, g.host || '—', 'col-host');
    cellClipped(tr, (g.user || '?') + (g.pwd ? ' · ' + g.pwd : ''), 'col-cmd');
    cellClipped(tr, commandSummary(g.command, 200), 'col-cmd');
    cell(tr, g.ip);
    // 条目: live / total, so a partially-swept group is visible as such.
    cell(tr, g.live + (g.entries !== g.live ? ' / ' + g.entries : ''));

    var rem = cell(tr, fmtRemaining(g.max_expires_ms - t));
    if (!live) rem.className = 'cache-expired';
    else rem.title = '有效期至 ' + fmtTime(g.max_expires_ms);

    // 可延长至: the absolute ceiling, i.e. how much headroom an extension has.
    // Showing the cap next to the remaining time is the whole point — it makes
    // "extend" visibly bounded rather than open-ended.
    var capTd = document.createElement('td');
    if (g.lifetime_ceiling_ms) {
      var headroom = g.lifetime_ceiling_ms - t;
      capTd.textContent = headroom > 0 ? fmtRemaining(headroom) : '已达上限';
      capTd.title = '上限 ' + fmtTime(g.lifetime_ceiling_ms);
      if (headroom <= 0) capTd.className = 'cache-expired';
    } else {
      capTd.textContent = '—';
      capTd.className = 'cache-expired';
    }
    tr.appendChild(capTd);

    var act = document.createElement('td');
    var clr = el('button', 'danger small', '清除');
    clr.type = 'button';
    clr.addEventListener('click', function () { clearGroups([g.group_id], clr); });
    act.appendChild(clr);
    if (meta.extend_enabled) {
      if (g.extendable) {
        var ext = el('button', 'small', '延长');
        ext.type = 'button';
        ext.addEventListener('click', function () { requestExtend([g.group_id], ext); });
        act.appendChild(ext);
      } else if (g.reason && live) {
        var why = el('span', 'hint reason', REASON_TEXT[g.reason] || g.reason);
        act.appendChild(why);
      }
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
    note.textContent = extendable === ids.length
      ? '批准后自当前时刻起算，且不超过创建后 ' + ttlLabel(Math.floor(meta.max_lifetime_ms / 1000))
      : extendable + ' / ' + ids.length + ' 组可延长，其余将被忽略';
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
      meta.max_lifetime_ms = json.max_lifetime_ms || 0;
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
    addDetail(dl, '上限', '缓存创建后 ' + ttlLabel(Math.floor(meta.max_lifetime_ms / 1000)));
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

  load();
})();
