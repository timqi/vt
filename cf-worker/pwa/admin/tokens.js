'use strict';

// Hosts tab. One row per enrolled host credential, from
// /{seg}/api/tokens. Read-only rendering via textContent; the only mutation is
// revoke — authority-REDUCING, one POST, immediate (same rule as cache clears).
// Countdowns run against the SERVER clock (now_ms from the listing).

vt.tabs.tokens = function (panel) {
  var $ = function (sel) { return panel.querySelector(sel); };
  var API = vt.api('tokens');
  var setStatus = vt.statusLine($('.status'));
  var el = vt.el, fmtTime = vt.fmtTime, fmtRemaining = vt.fmtRemaining;

  var tokens = [];
  var serverNowMs = 0;
  var localRefMs = 0;
  function now() { return serverNowMs + (Date.now() - localRefMs); }

  function isLive(t) { return t.revoked_ms == null && t.expires_ms > now(); }

  var list = vt.list($('.table-wrap'));   // rows on a phone, the table on desktop

  function cell(main, sub) {
    var td = document.createElement('td');
    td.appendChild(el('div', 'cell-main', main));
    if (sub) td.appendChild(el('div', 'cell-sub', sub));
    return td;
  }

  function renderRow(t) {
    var live = isLive(t);
    var issued = (t.origin || '') + (t.origin ? ' · ' : '') + 'issued ' + fmtTime(t.created_ms);
    var lastIp = (t.last_ip && t.last_ip !== t.enroll_ip) ? 'IP ' + t.last_ip : '';
    var state = t.revoked_ms != null ? 'revoked ' + fmtTime(t.revoked_ms) : fmtRemaining(t.expires_ms - now());
    var btn = null;
    if (live) {
      btn = el('button', 'danger small', 'Revoke');
      btn.type = 'button';
      btn.addEventListener('click', function () { revoke(t, btn); });
    }
    return list.item({
      cls: live ? '' : 'expired',
      cells: function () {
        var td = document.createElement('td');
        if (btn) td.appendChild(btn);
        return [cell(t.host || '?', (t.user ? t.user + ' · ' : '') + t.token_id),
          cell(t.enroll_ip || '', issued), cell(fmtTime(t.last_used_ms), lastIp),
          cell(state, t.revoked_ms == null ? fmtTime(t.expires_ms) : ''), td];
      },
      row: function () {
        return {
          main: t.host || '?',
          sub: [el('div', null, (t.user ? t.user + ' · ' : '') + t.token_id),
            el('div', null, (t.enroll_ip || '') + ' · ' + issued),
            el('div', null, 'last used ' + (fmtTime(t.last_used_ms) || '—') + (lastIp ? ' · ' + lastIp : '')
              + (t.revoked_ms == null ? ' · expires ' + fmtTime(t.expires_ms) : ''))],
          trail: state, actions: btn ? [btn] : [],
        };
      },
    });
  }

  function render() {
    list.clear();
    var onlyLive = $('.f-live').value === 'live';
    var hostQ = ($('.f-host').value || '').trim().toLowerCase();
    var shown = 0;
    tokens.forEach(function (t) {
      if (onlyLive && !isLive(t)) return;
      if (hostQ && String(t.host || '').toLowerCase().indexOf(hostQ) < 0) return;
      shown++;
      list.body().appendChild(renderRow(t));
    });
    if (shown === 0) list.empty(onlyLive ? 'No live tokens (switch to All for history)' : 'No tokens');
  }

  async function revoke(t, btn) {
    if (!confirm('Revoke the token of ' + (t.host || t.token_id) + '? The host must vt enroll again.')) return;
    btn.disabled = true;
    try {
      var resp = await vt.apiFetch(vt.api('tokens-revoke'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token_id: t.token_id }),
      });
      if (!resp.ok) { setStatus('Revoke failed: HTTP ' + resp.status, 'error'); btn.disabled = false; return; }
      var json = await resp.json();
      setStatus(json.revoked ? 'Revoked ' + (t.host || t.token_id) : 'Token was already inactive', json.revoked ? 'ok' : '');
      await load();
    } catch (e) {
      setStatus('Revoke failed: ' + (e.message || e), 'error');
      btn.disabled = false;
    }
  }

  async function load() {
    setStatus('Loading…');
    try {
      var resp = await vt.apiFetch(API, { headers: { 'Accept': 'application/json' } });
      if (resp.status === 401) return; // the shell shows the login view
      if (!resp.ok) { setStatus('Load failed: HTTP ' + resp.status, 'error'); return; }
      var json = await resp.json();
      tokens = (json && json.tokens) || [];
      serverNowMs = typeof json.now_ms === 'number' ? json.now_ms : Date.now();
      localRefMs = Date.now();
      render();
      var live = tokens.filter(isLive).length;
      setStatus(live + ' live / ' + tokens.length + ' total' +
        (json.truncated ? ' (list truncated)' : ''), json.truncated ? 'error' : '');
    } catch (e) {
      setStatus('Load failed: ' + (e.message || e), 'error');
    }
  }

  $('.refresh').addEventListener('click', function () { load(); });
  $('.f-live').addEventListener('change', render);
  $('.f-host').addEventListener('input', render);
  vt.onLayout(render);
  setInterval(render, 60000);
  load();
};
