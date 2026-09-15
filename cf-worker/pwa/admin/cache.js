'use strict';

// DEK Cache tab. One row per live cache ENTRY from /{seg}/api/cache-list, grouped
// client-side under collapsible host · project headers (the two halves of the key:
// verified token, advisory project). Read-only rendering via textContent;
// every mutation is an explicit POST on the selected entries.
//
// Two classes of action, deliberately asymmetric:
//   • Revoke (selected) / Clear all — authority-REDUCING, one POST, immediate.
//   • Extend — authority-GRANTING, so the admin session alone cannot do it: the
//     POST only opens a pending Passkey ceremony, which is then mounted inline via
//     the SAME vt.mountApprove() the approval page uses. Nothing expires later
//     until that ceremony is approved on a Passkey. One host · project per ceremony.
//
// Countdowns run against the SERVER clock (now_ms from the listing, advanced
// locally), so a skewed browser clock cannot invent remaining time.

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
  function scopeLabel(e) { return (e.host || '—') + ' · ' + (e.project ? vt.projectName(e.project) : 'unknown project'); }

  // A multi-day window is a materially different exposure from a workday one, so
  // the picker says so instead of letting "1 w" read like just another option.
  function ttlIsLong(s) { return s >= 86400; }

  // Would extending with `ttl` actually move this entry's expiry? Extension is
  // absolute (now + ttl), never additive, so a TTL shorter than the time already
  // on the clock is a no-op — the server refuses it as `no_gain`. Deciding this
  // client-side is what lets the UI say so BEFORE the click.
  function wouldGain(e, ttl) { return now() + ttl * 1000 > e.expires_ms; }

  // Smallest rung that would move every entry in `es` forward, so the UI can
  // name the fix ("pick ≥ 2 d") rather than just refusing.
  function smallestUsefulTtl(es) {
    var opts = meta.ttl_options_s || [];
    for (var i = 0; i < opts.length; i++) {
      if (es.length && es.every(function (e) { return wouldGain(e, opts[i]); })) return opts[i];
    }
    return 0;
  }

  // Server reason codes (do_account.opCacheExtendCreate) in the operator's language.
  var REASON_TEXT = {
    expired: 'expired; needs a new phone approval (only live caches can be extended)',
    no_gain: 'remaining time already exceeds the chosen duration',
    gone: 'already cleared',
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

  // One host · project header: its checkbox selects every listed entry of the
  // scope; the label toggles the scope's rows. Full path, user and token in the
  // hovercard (the same sheet-or-hover rule as every long value).
  function renderHeader(scope, es) {
    var e = es[0];
    var allOn = es.every(function (x) { return selected[idOf(x)]; });
    var pick = pickBox(allOn, 'Select ' + scopeLabel(e), function () {
      es.forEach(function (x) { if (pick.checked) selected[idOf(x)] = true; else delete selected[idOf(x)]; });
      render();
    });
    var hover = 'Host: ' + (e.host || '—') + '\nUser: ' + (e.user || '—') + '\nProject: ' + (e.project || 'unknown (early entry)')
      + '\nToken: ' + e.token_id + '\n\n(A cache is bound to this host token and the client-claimed project; both must match to hit.)';
    var mark = (collapsed[scope] ? '▸ ' : '▾ ');
    var label = el('span', 'group-label has-hover', mark + scopeLabel(e));
    label.setAttribute('data-hover', hover);
    var count = el('span', 'cell-sub', es.length + ' entries');
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
    var pick = pickBox(!!selected[id], 'Select ' + vt.recordLabel(e.record), function () {
      if (pick.checked) selected[id] = true; else delete selected[id];
      syncBulkBar();
    });
    // Record: the entry's record by name, renameable in place (the salt is the key).
    var record = vt.recordList([e.record], null);
    var remaining = fmtRemaining(e.expires_ms - t);
    var until = 'until ' + fmtTime(e.expires_ms);
    var created = 'created ' + (fmtTime(e.created_ms) || 'unknown');
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
    if (!rows.length) list.empty('No live DEK caches');
    var pickAll = $('#pick-all');
    pickAll.checked = rows.length > 0 && rows.every(function (e) { return selected[idOf(e)]; });
    syncBulkBar();
    var msg = rows.length + ' live entries · ' + order.length + ' projects';
    if (meta.truncated) {
      msg += ' ⚠ scanned ' + meta.scanned + ' and truncated; list incomplete (Clear all still covers everything)';
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
    $('#bulk-count').textContent = es.length + ' selected / ' + nScopes + ' projects';
    var gainers = es.filter(function (e) { return wouldGain(e, ttl); });
    var extendBtn = $('#extend-selected');
    var note = $('#extend-note');
    var parts = [];
    var warn = false;
    // Disabled when the request would provably fail — the server would refuse
    // it anyway, and a button that 400s is worse than one that explains itself.
    extendBtn.disabled = nScopes !== 1 || gainers.length === 0;
    if (nScopes !== 1) {
      parts.push('Extend works on one host · project at a time; narrow the selection (revoke has no such limit)');
      warn = true;
    } else if (gainers.length === 0) {
      // The common trap: extension is absolute, so a rung shorter than the time
      // already on the clock does nothing. Name the smallest rung that would work.
      var longest = 0;
      es.forEach(function (e) { var left = e.expires_ms - now(); if (left > longest) longest = left; });
      var need = smallestUsefulTtl(es);
      parts.push(ttlLabel(ttl) + ' would not take effect: longest remaining is '
        + fmtRemaining(longest) + ' (extend resets to approval time + duration, it does not add)'
        + (need ? '; pick ' + ttlLabel(need) + ' or longer' : ''));
      warn = true;
    } else {
      if (gainers.length < es.length) {
        parts.push('only ' + gainers.length + ' / ' + es.length + ' would be extended (the rest already last longer)');
        warn = true;
      }
      // A multi-day pick is a materially larger exposure than a workday one. The
      // approval page states it too, but say it before the request is even made.
      if (ttlIsLong(ttl)) {
        parts.push('⚠ for ' + ttlLabel(ttl) + ' these ' + gainers.length + ' records decrypt without phone approval (same host token + project)');
        warn = true;
      }
      parts.push('on approval expiry resets to approval time + ' + ttlLabel(ttl) + '; can be extended again');
    }
    note.textContent = parts.join('; ');
    note.className = warn ? 'hint warn' : 'hint';
  }

  // ── Detail sheet ─────────────────────────────────────────────────────────

  var addDetail = vt.dialog.addRow;

  function openDetail(e) {
    var d = vt.dialog.open({ title: 'Cache entry' });
    var dl = d.dl;
    addDetail(dl, 'Host', e.host);
    addDetail(dl, 'User', e.user);
    addDetail(dl, 'Project', e.project, true);
    dl.appendChild(el('dt', null, 'Record'));
    dl.appendChild(el('dd', null)).appendChild(vt.recordList([e.record], render));
    addDetail(dl, 'Approved from IP', e.ip ? e.ip + ' (audit only, not part of the binding)' : '');
    addDetail(dl, 'Cache TTL', typeof e.ttl_s === 'number' ? ttlLabel(e.ttl_s) : '');
    addDetail(dl, 'Created', fmtTime(e.created_ms) || 'unknown');
    addDetail(dl, 'Expires', fmtTime(e.expires_ms) + ' (' + fmtRemaining(e.expires_ms - now()) + ' left)');
    addDetail(dl, 'Host token', e.token_id, true);
    addDetail(dl, 'Origin approval', e.origin_token_id, true);
  }

  // ── Load ──────────────────────────────────────────────────────────────────

  async function load() {
    setStatus('Loading…');
    try {
      var resp = await vt.apiFetch(API, { headers: { 'Accept': 'application/json' } });
      if (resp.status === 401) return; // the shell shows the login view
      if (!resp.ok) { setStatus('Load failed: HTTP ' + resp.status, 'error'); return; }
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
      setStatus('Network error: ' + (e.message || e), 'error');
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
    if (!es.length) { setStatus('Nothing selected', 'error'); return; }
    if (!confirm('Revoke ' + es.length + ' cache entries? Decrypting these records will need phone approval again.')) return;
    btn.disabled = true;
    setStatus('Revoking…');
    try {
      var resp = await vt.postJson('cache-clear-entries', { entries: es.map(refOf) });
      if (!resp.ok) { setStatus('Revoke failed: HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      selected = {};
      // Refresh FIRST, then report — load() renders its own status line.
      await load();
      setStatus('✓ Revoked ' + (json && json.cleared != null ? json.cleared : '?') + ' entries', 'ok');
    } catch (e) {
      setStatus('Network error: ' + (e.message || e), 'error');
    } finally {
      btn.disabled = false;
    }
  }

  // ── Extend (Passkey-gated) ────────────────────────────────────────────────

  // Step 1: ask the Worker to mint a ceremony. This grants nothing on its own —
  // the response is a pending challenge that expires in ~5 minutes if untouched.
  async function requestExtend(es, btn) {
    var ttl = selectedTtl();
    if (!ttl) { setStatus('Pick an extension duration', 'error'); return; }
    var targets = es.filter(function (e) { return wouldGain(e, ttl); });
    if (!targets.length) {
      var need = smallestUsefulTtl(es);
      setStatus(ttlLabel(ttl) + ' is shorter than the remaining time and would not take effect'
        + (need ? '; pick ' + ttlLabel(need) + ' or longer' : ''), 'error');
      return;
    }
    btn.disabled = true;
    setStatus('Creating approval request…');
    try {
      var resp = await vt.postJson('cache-extend-request', { entries: targets.map(refOf), ttl_s: ttl });
      if (resp.status === 401) return; // the shell shows the login view
      if (resp.status === 409) {
        // Refresh FIRST, then report — load() re-renders and would otherwise
        // overwrite the message.
        var why = null;
        try { why = (await resp.json()).rejected; } catch (e) { /* keep generic */ }
        await load();
        setStatus('Nothing to extend' + reasonSummary(why), 'error');
        return;
      }
      if (!resp.ok) { setStatus('Create failed: HTTP ' + resp.status, 'error'); return; }
      openCeremony(await resp.json(), targets[0], ttl);
    } catch (e) {
      setStatus('Network error: ' + (e.message || e), 'error');
    } finally {
      btn.disabled = false;
    }
  }

  function reasonSummary(rejected) {
    if (!rejected || !rejected.length) return '';
    var counts = {};
    rejected.forEach(function (r) { counts[r.reason] = (counts[r.reason] || 0) + 1; });
    return ': ' + Object.keys(counts).map(function (k) { return (REASON_TEXT[k] || k) + ' ×' + counts[k]; }).join('; ');
  }

  // Step 2: mount the standard approval ceremony for that challenge in the shared
  // dialog. The data comes from the public capability endpoint /api/page/:token —
  // exactly what the audit tab does for a pending row — so there is one ceremony
  // implementation, not two.
  function openCeremony(req, scope, ttl) {
    var d = vt.dialog.open({
      title: 'Extend DEK cache',
      warn: '⚠️ Approving extends the approval-free decrypt window of these caches. Check host, project and records.',
    });
    var dl = d.dl;
    var targets = req.targets || [];
    addDetail(dl, 'Scope', scopeLabel(scope) + ' · ' + targets.length + ' entries');
    addDetail(dl, 'Project', scope.project, true);
    addDetail(dl, 'Records', targets.map(function (salt) {
      var e = byId[scopeOf(scope) + '\u0000' + salt];
      return e ? vt.recordLabel(e.record) : salt.slice(0, 8) + '…';
    }).join(', '));
    addDetail(dl, 'Extend by', ttlLabel(ttl) + ' (from approval time)');
    addDetail(dl, 'Effect', 'expiry resets to approval time + ' + ttlLabel(ttl) + ', replacing the current one');
    if (req.rejected && req.rejected.length) addDetail(dl, 'Skipped', reasonSummary(req.rejected).slice(2));
    var box = d.approve;
    box.innerHTML = '';
    if (!vt.mountApprove) {
      setStatus('Passkey component not loaded; cannot extend', 'error');
      return;
    }
    setStatus('Waiting for Passkey approval…');
    fetch('/api/page/' + encodeURIComponent(req.approve_token), { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data) { setStatus('Approval request expired, try again', 'error'); return; }
        vt.mountApprove({
          data: data,
          root: box,
          showMeta: false,   // the dl above already states the intent
          onSettled: function (outcome) {
            setTimeout(function () {
              vt.dialog.close();
              if (outcome === 'approved') {
                selected = {};
                setStatus('✓ Extension approved, refreshing…', 'ok');
              } else {
                setStatus('Rejected; cache expiry unchanged');
              }
              load();
            }, 800);
          },
        });
      })
      .catch(function (e) { setStatus('Network error: ' + (e.message || e), 'error'); });
  }

  // ── Wiring ────────────────────────────────────────────────────────────────

  $('.refresh').addEventListener('click', function () { load(); });
  $('.f-host').addEventListener('input', render);
  $('.f-project').addEventListener('input', render);
  // Re-run the note so the multi-day warning appears the moment 1d/2d/1w is picked.
  $('#extend-ttl').addEventListener('change', syncBulkBar);

  $('#pick-all').addEventListener('change', function () {
    var on = this.checked;
    visibleEntries().forEach(function (e) { if (on) selected[idOf(e)] = true; else delete selected[idOf(e)]; });
    render();
  });

  $('#revoke-selected').addEventListener('click', function () { revoke(selectedEntries(), this); });
  $('#extend-selected').addEventListener('click', function () { requestExtend(selectedEntries(), this); });

  $('.clear-all-cache').addEventListener('click', async function () {
    if (!confirm('Clear every cached DEK? Decrypts will need phone approval again.')) return;
    setStatus('Clearing…');
    try {
      var resp = await vt.postJson('clear-cache');
      if (!resp.ok) { setStatus('Clear failed: HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      selected = {};
      await load();
      setStatus('✓ Cleared ' + (json && json.cleared != null ? json.cleared : '?') + ' DEK cache entries', 'ok');
    } catch (e) {
      setStatus('Network error: ' + (e.message || e), 'error');
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
