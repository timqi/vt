'use strict';

// The admin shell (docs/design/ui-ux.md). One page, one state from VT_DATA,
// one tab strip; each tab is a <section class="tab-panel" id="tab-…"> whose
// script registers `vt.tabs.<key> = function (panel, data)` and is initialised
// on first activation. Ids are document-unique; anything that exists once per
// tab (.status, .rows, .filters, .f-host, …) is a class the tab script looks up
// inside its own panel. Loaded before the tab scripts; boots on DOMContentLoaded.
//
// Shared here (admin-only): the API base and its 401 handling, the login
// ceremony, the phone/desktop layout switch (vt.phone, vt.onLayout, vt.list),
// the detail sheet, the hovercard and the command summariser. Cross-shell
// helpers live in common.js (vt.*).

(function () {
  vt.api = function (path) { return '/api/admin/' + path; };
  vt.tabs = {};
  vt.views = {};

  // Every admin request goes through here: a 401 means the session is gone
  // (expired, epoch bumped by a revocation, cookie cleared), and the shell
  // returns to the login view rather than any tab rendering on stale data.
  vt.apiFetch = async function (url, init) {
    var resp = await fetch(url, init);
    if (resp.status === 401) vt.showLogin('Session expired, please log in again');
    return resp;
  };
  vt.postJson = function (path, body) {
    return vt.apiFetch(vt.api(path), {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body == null ? {} : body),
    });
  };

  // ── Command summary (audit + cache list columns) ──────────────────────────
  // Cosmetic, FRONTEND-ONLY: if the command's leading program is an absolute
  // path (`/usr/bin/foo …`), show just its basename (`foo …`). The stored
  // command keeps the full path — the detail dialog renders it verbatim. Only
  // argv[0] is trimmed; path-valued args stay intact so the command remains
  // unambiguous. Prefers the `cmd:` line of the multi-line body the CLI builds
  // (`op: …\ncmd: …\nreason: …`), else the first line.
  function basenameLeadingProgram(s) {
    var m = /^(\s*)(\/\S*)(.*)$/.exec(s);
    if (!m) return s;
    var prog = m[2];
    var base = prog.slice(prog.lastIndexOf('/') + 1);
    if (base === '') return s;           // "/" or trailing-slash — leave untouched
    return m[1] + base + m[3];
  }
  vt.commandSummary = function (cmd, max) {
    if (!cmd) return '';
    var lines = String(cmd).split('\n');
    var pick = lines[0];
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf('cmd:') === 0) { pick = lines[i].slice(4).trim(); break; }
    }
    var v = basenameLeadingProgram(pick);
    return v.length > max ? v.slice(0, max) + '…' : v;
  };

  // ── Layout: rows on a phone, tables at ≥ 768px ───────────────────────────
  // One breakpoint for every list (admin.css). Tabs register their full render
  // with vt.onLayout so a resize across it re-renders from the same data.
  vt.phone = window.matchMedia('(max-width: 767px)');
  var layoutFns = [];
  vt.onLayout = function (fn) { layoutFns.push(fn); };
  vt.phone.addEventListener('change', function () { layoutFns.forEach(function (f) { f(); }); });

  function fill(node, content) {
    if (content == null) return node;
    (Array.isArray(content) ? content : [content]).forEach(function (c) {
      if (c == null || c === '') return;
      if (typeof c === 'string' || typeof c === 'number') node.appendChild(document.createTextNode(String(c)));
      else node.appendChild(c);
    });
    return node;
  }

  // A list bound to one .table-wrap: `body()` is the container to append to
  // (the <tbody> or the <ul class="row-list"> the helper adds), `item(spec)`
  // builds one entry for the current layout — `spec.cells()` returns the <td>s,
  // `spec.row()` returns { lead, main, sub, trail, actions } — so a tab
  // describes both from one data object and one set of handlers. `cls`,
  // `attrs` (data-*) and `click` apply to either element.
  vt.list = function (wrap) {
    var tbody = wrap.querySelector('tbody');
    var ul = vt.el('ul', 'row-list');
    wrap.appendChild(ul);
    var cols = wrap.querySelectorAll('th').length || 1;
    return {
      body: function () { return vt.phone.matches ? ul : tbody; },
      clear: function () { tbody.innerHTML = ''; ul.innerHTML = ''; },
      item: function (spec) {
        var phone = vt.phone.matches;
        var e = document.createElement(phone ? 'li' : 'tr');
        e.className = (phone ? 'row ' : '') + (spec.cls || '');
        Object.keys(spec.attrs || {}).forEach(function (k) { e.setAttribute('data-' + k, spec.attrs[k]); });
        if (spec.click) {
          // A clickable entry is a keyboard target too: Tab to it, Enter opens.
          e.tabIndex = 0;
          e.addEventListener('click', spec.click);
          e.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' && ev.target === e) spec.click(ev); });
        }
        if (!phone) { spec.cells().forEach(function (td) { e.appendChild(td); }); return e; }
        var r = spec.row();
        if (r.lead) e.appendChild(fill(vt.el('div', 'row-lead'), r.lead));
        var body = vt.el('div', 'row-body');
        body.appendChild(fill(vt.el('div', 'row-main'), r.main));
        if (r.sub) body.appendChild(fill(vt.el('div', 'cell-sub'), r.sub));
        e.appendChild(body);
        if (r.trail) e.appendChild(fill(vt.el('div', 'row-trail'), r.trail));
        if (r.actions && r.actions.length) e.appendChild(fill(vt.el('div', 'row-actions'), r.actions));
        return e;
      },
      // One muted line when there is nothing to list.
      empty: function (text) {
        if (vt.phone.matches) { ul.appendChild(vt.el('li', 'row')).appendChild(vt.el('div', 'row-empty', text)); return; }
        var td = vt.el('td', null, text);
        td.colSpan = cols;
        tbody.appendChild(document.createElement('tr')).appendChild(td);
      },
    };
  };

  // ── Record names (audit Records column + dialog, cache rows) ─────────────────
  // One record's label: the operator-owned name, else the client's claim marked
  // claimed, else the salt's first 8 chars — a handle that matches across rows
  // (mirrors account_names.nameLabel).
  function isSaltLabel(r) { return !r.name && !r.claimed; }
  vt.recordLabel = function (r) {
    return r.name || (r.claimed ? r.claimed + ' (claimed)' : (r.salt_b64u || '').slice(0, 8) + '…');
  };

  // Column content: the labels joined (a salt handle in <code>), or `N records` for
  // a row that stored no records; null when there is nothing to show.
  vt.recordsSummary = function (records, n) {
    if (!records || !records.length) return n > 0 ? vt.el('span', null, n + ' records') : null;
    var span = vt.el('span', 'rec-summary');
    records.forEach(function (r, i) {
      if (i) span.appendChild(document.createTextNode(', '));
      span.appendChild(isSaltLabel(r) ? vt.el('code', null, vt.recordLabel(r))
        : document.createTextNode(vt.recordLabel(r)));
    });
    return span;
  };

  // The project shown beside a host: the repository's directory name (the
  // project is its common git dir, so `/…/vt/.git` reads `vt`).
  vt.projectName = function (p) {
    var parts = String(p || '').replace(/\/\.git$/, '').split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1] : '';
  };

  // Renameable list. Clicking a name opens an input in place; Enter saves via
  // PUT /api/admin/names ('' deletes), Escape or blur cancels. `records` is
  // mutated on success so the caller's row state stays current; `onSaved` lets
  // it re-render. Past `max` items the rest sit behind a 「+N」 toggle.
  vt.recordList = function (records, onSaved, max) {
    var ul = vt.el('ul', 'record-list');
    var limit = max || records.length;
    var expanded = false;
    function render() {
      ul.innerHTML = '';
      records.forEach(function (r, i) {
        if (!expanded && i >= limit) return;
        var li = document.createElement('li');
        var btn = vt.el('button', 'rec-name' + (r.name ? '' : ' unnamed') + (isSaltLabel(r) ? ' salt' : ''), vt.recordLabel(r));
        btn.type = 'button';
        btn.title = 'Click to rename';
        btn.addEventListener('click', function (e) { e.stopPropagation(); edit(li, r); });
        li.appendChild(btn);
        if (r.name && r.claimed && r.claimed !== r.name) li.appendChild(vt.el('span', 'cell-sub', 'client calls it ' + r.claimed));
        ul.appendChild(li);
      });
      if (!expanded && records.length > limit) {
        var more = vt.el('button', 'rec-name more', '+' + (records.length - limit) + ' more');
        more.type = 'button';
        more.addEventListener('click', function (e) { e.stopPropagation(); expanded = true; render(); });
        ul.appendChild(vt.el('li', null)).appendChild(more);
      }
    }
    function edit(li, r) {
      var input = document.createElement('input');
      input.type = 'text'; input.maxLength = 40; input.value = r.name || r.claimed || '';
      input.className = 'rec-edit';
      input.setAttribute('aria-label', 'Record name');
      input.addEventListener('click', function (e) { e.stopPropagation(); });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') { e.stopPropagation(); render(); }
        if (e.key === 'Enter') { e.preventDefault(); save(); }
      });
      input.addEventListener('blur', function () { if (!saving) render(); });
      var saving = false;
      async function save() {
        saving = true;
        input.disabled = true;
        var name = input.value.trim();
        try {
          var resp = await vt.apiFetch(vt.api('names'), {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ salt_b64u: r.salt_b64u, name: name }),
          });
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          r.name = name || null;
          r.source = name ? 'manual' : null;
          if (onSaved) onSaved(r);
        } catch (e) {
          input.disabled = false; saving = false;
          input.setCustomValidity('Save failed: ' + (e.message || e));
          input.reportValidity();
          return;
        }
        render();
      }
      li.innerHTML = '';
      li.appendChild(input);
      input.focus(); input.select();
    }
    render();
    return ul;
  };

  // ── Detail sheet ──────────────────────────────────────────────────────────
  // #detail is one native <dialog> in the shell: a bottom sheet on a phone
  // (swipe down to dismiss), a centred card on desktop. open() fills the
  // heading, the warning and hands back the empty <dl> plus the ceremony box;
  // it never clears the ceremony box (a live re-render must not disturb a
  // mounted ceremony) — close() does. Escape (the dialog's own cancel), the
  // close control and a backdrop tap close; focus returns to the opener.
  var dialog = document.getElementById('detail');
  var sheetBody = document.getElementById('detail-body');
  var dialogTitle = document.getElementById('detail-title');
  var dialogWarn = document.getElementById('detail-warn');
  var dialogDl = document.getElementById('detail-dl');
  var dialogApprove = document.getElementById('detail-approve');
  var dialogOnClose = null;
  var dialogOpener = null;

  vt.dialog = {
    open: function (opts) {
      opts = opts || {};
      dialogTitle.hidden = !opts.title;
      dialogTitle.textContent = opts.title || '';
      dialogWarn.hidden = !opts.warn;
      dialogWarn.textContent = opts.warn || '';
      dialogDl.innerHTML = '';
      dialogOnClose = opts.onClose || null;
      if (!dialog.open) {
        dialogOpener = document.activeElement;
        sheetBody.scrollTop = 0;
        dialog.showModal();
      }
      return { dl: dialogDl, approve: dialogApprove };
    },
    close: function () { if (dialog.open) dialog.close(); },
    isOpen: function () { return dialog.open; },
    // A <dt>/<dd> pair; skipped for an empty value. `mono` marks paths/commands.
    addRow: function (dl, label, value, mono) {
      if (value === null || value === undefined || value === '') return;
      dl.appendChild(vt.el('dt', null, label));
      dl.appendChild(vt.el('dd', mono ? 'mono' : null, String(value)));
    },
  };
  // Logical close happens here (also for Escape); the exit transition continues.
  dialog.addEventListener('close', function () {
    dialogApprove.innerHTML = '';
    var cb = dialogOnClose; dialogOnClose = null;
    if (cb) cb();
    if (dialogOpener && dialogOpener.focus) dialogOpener.focus();
    dialogOpener = null;
  });
  document.getElementById('detail-close').addEventListener('click', vt.dialog.close);
  // A click whose target is the dialog element itself landed on ::backdrop —
  // the sheet's content is wrapped, so its own padding never counts.
  dialog.addEventListener('click', function (e) { if (e.target === dialog) vt.dialog.close(); });

  // Swipe down (phone): follow the finger via element.style.transform (CSSOM)
  // from the sheet's top, release past 90px closes, else it springs back.
  var swipeY = 0, swiping = false;
  dialog.addEventListener('touchstart', function (e) {
    swipeY = e.touches[0].clientY;
    swiping = vt.phone.matches && sheetBody.scrollTop <= 0;
  }, { passive: true });
  dialog.addEventListener('touchmove', function (e) {
    if (!swiping) return;
    var dy = e.touches[0].clientY - swipeY;
    if (dy <= 0) { swiping = false; dialog.classList.remove('dragging'); dialog.style.transform = ''; return; }
    e.preventDefault();
    dialog.classList.add('dragging');
    dialog.style.transform = 'translateY(' + dy + 'px)';
  }, { passive: false });
  dialog.addEventListener('touchend', function (e) {
    if (!swiping) return;
    swiping = false;
    var dy = e.changedTouches[0].clientY - swipeY;
    dialog.classList.remove('dragging');
    dialog.style.transform = '';
    if (dy > 90) vt.dialog.close();
  });

  // ── Hover card ────────────────────────────────────────────────────────────
  // The native `title` tooltip is the wrong tool for a bound directory or an
  // exact command: ~1s delay, tiny system font, no wrapping, multi-line
  // collapsed. Cells marked data-hover get a real popup: ~90ms, wrapping,
  // monospace, multi-line preserved; tap-to-inspect where there is no hover.
  //
  // Positioned by assigning to element.style.* (CSSOM), which is NOT an inline
  // style attribute and so is allowed under `style-src 'self'` — do not switch
  // this to setAttribute('style', …), which the CSP would block.
  var hoverCard = null;
  var hoverTimer = null;

  function showHover(target, text) {
    if (!hoverCard) {
      hoverCard = vt.el('div', 'hovercard');
      hoverCard.hidden = true;
      document.body.appendChild(hoverCard);
    }
    hoverCard.textContent = text;
    hoverCard.hidden = false;
    // Measure after the text is in, then place: below the cell by default,
    // flipped above when it would overflow the viewport, clamped horizontally.
    var r = target.getBoundingClientRect();
    var cw = hoverCard.offsetWidth, ch = hoverCard.offsetHeight;
    var pad = 8;
    var left = Math.min(Math.max(pad, r.left), window.innerWidth - cw - pad);
    var top = r.bottom + 6;
    if (top + ch > window.innerHeight - pad) top = Math.max(pad, r.top - ch - 6);
    hoverCard.style.left = left + 'px';
    hoverCard.style.top = top + 'px';
  }

  function hideHover() {
    if (hoverTimer) { clearTimeout(hoverTimer); hoverTimer = null; }
    if (hoverCard) { hoverCard.hidden = true; hoverCard.textContent = ''; }
  }

  // Delegated, so re-rendering rows on a ticker never leaves stale listeners.
  vt.hovercard = { attach: function (scope) {
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
    scope.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target.closest('[data-hover]') : null;
      if (!t) { hideHover(); return; }
      if (hoverCard && !hoverCard.hidden) { hideHover(); return; }
      showHover(t, t.getAttribute('data-hover') || '');
    });
  } };
  window.addEventListener('scroll', hideHover, true);
  window.addEventListener('resize', hideHover);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') hideHover(); });

  // ── Tab bar ───────────────────────────────────────────────────────────────
  // Tab in the URL hash (/{seg}#audit), first tab default. A panel's script
  // runs once, on first activation, so a hidden tab costs nothing until opened.
  // Marks are single Unicode glyphs (no icon set); the label sits under the
  // mark on a phone, beside it on desktop.
  var TABS = [
    ['audit', 'Audit', '≣'], ['cache', 'DEK Cache', '◷'], ['tokens', 'Hosts', '⌂'],
    ['setup', 'Passkey', '⚷'], ['settings', 'Settings', '⚙\uFE0E'],
  ];
  var started = {};

  function activate(data) {
    var key = location.hash.slice(1).split('?')[0];
    if (!TABS.some(function (t) { return t[0] === key; })) key = TABS[0][0];
    TABS.forEach(function (t) {
      var on = t[0] === key;
      var panel = document.getElementById('tab-' + t[0]);
      var link = document.getElementById('tab-link-' + t[0]);
      panel.hidden = !on;
      link.classList.toggle('active', on);
      if (on) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
      if (on && !started[key]) {
        started[key] = true;
        if (vt.tabs[key]) vt.tabs[key](panel, data);
      }
    });
    var title = TABS.filter(function (t) { return t[0] === key; })[0][1];
    document.getElementById('page-title').textContent = title;
    document.title = 'VT — ' + title;
  }

  // Phone: the bar shrinks to marks while the content scrolls down and
  // restores on scroll up or when scrolling stops (admin.css .compact).
  function scrollShrink(nav) {
    var lastY = window.scrollY, stop = null;
    window.addEventListener('scroll', function () {
      var y = window.scrollY;
      if (y > lastY + 4 && y > 40) nav.classList.add('compact');
      else if (y < lastY - 4) nav.classList.remove('compact');
      lastY = y;
      clearTimeout(stop);
      stop = setTimeout(function () { nav.classList.remove('compact'); }, 400);
    }, { passive: true });
  }

  function bootConsole(data) {
    var nav = document.getElementById('tabs');
    TABS.forEach(function (t) {
      var a = vt.el('a', 'tab');
      a.id = 'tab-link-' + t[0];
      a.href = '#' + t[0];
      var mark = vt.el('span', 'tab-mark', t[2]);
      mark.setAttribute('aria-hidden', 'true');
      a.appendChild(mark);
      a.appendChild(vt.el('span', 'tab-label', t[1]));
      nav.appendChild(a);
    });
    document.getElementById('page-head').hidden = false;
    document.getElementById('console').hidden = false;
    window.addEventListener('hashchange', function () { activate(data); });
    scrollShrink(nav);
    activate(data);
  }

  // ── Shell states ──────────────────────────────────────────────────────────
  // Exactly one of setup / login / console is visible. A 401 anywhere flips to
  // login; a successful login or bootstrap reloads so the console renders from
  // the state the Worker reports, never from what the page assumed.
  function show(id) {
    ['setup-view', 'login-view', 'console', 'page-head'].forEach(function (v) {
      document.getElementById(v).hidden = (v !== id && !(id === 'console' && v === 'page-head'));
    });
  }

  var loginShown = false;
  vt.showLogin = function (reason) {
    show('login-view');
    vt.dialog.close();
    var view = document.getElementById('login-view');
    var setStatus = vt.statusLine(view.querySelector('.status'));
    if (reason) setStatus(reason, 'error');
    if (loginShown) return;
    loginShown = true;
    var btn = document.getElementById('login-run');
    btn.addEventListener('click', async function () {
      btn.disabled = true;
      try {
        var ch = await vt.postJson('login-challenge');
        if (!ch.ok) throw new Error(ch.status === 429 ? 'Too many login attempts, try again later' : 'HTTP ' + ch.status);
        var c = await ch.json();
        setStatus('Complete the Passkey prompt…');
        // No allowCredentials: registration required resident keys, so the
        // authenticator discovers the credential and the page lists nothing.
        var a = await navigator.credentials.get({ publicKey: {
          challenge: vt.b64uDec(c.challenge_b64u), rpId: c.rp_id, userVerification: 'required',
        } });
        if (!a) throw new Error('Verification cancelled');
        var r = a.response;
        var resp = await vt.postJson('login', {
          challenge_id: c.challenge_id,
          credential_id_b64u: vt.b64uEnc(new Uint8Array(a.rawId)),
          client_data_json_b64u: vt.b64uEnc(new Uint8Array(r.clientDataJSON)),
          authenticator_data_b64u: vt.b64uEnc(new Uint8Array(r.authenticatorData)),
          signature_b64u: vt.b64uEnc(new Uint8Array(r.signature)),
        });
        if (resp.status !== 204) throw new Error(resp.status === 401 ? 'Login failed: Passkey not registered or verification failed' : 'HTTP ' + resp.status);
        setStatus('Logged in', 'ok');
        location.reload();
      } catch (e) {
        var msg = (e && e.message) ? e.message : String(e);
        if (/NotAllowed|not allowed/i.test(msg)) msg = 'No matching Passkey, or the prompt was cancelled';
        setStatus(msg, 'error');
      } finally { btn.disabled = false; }
    });
  };

  document.addEventListener('DOMContentLoaded', function () {
    var shellStatus = vt.statusLine(document.getElementById('shell-status'));
    var data = vt.bootData();
    if (!data) { shellStatus('Page init failed: vt-data missing or unparsable', 'error'); return; }
    switch (data.state) {
      case 'console': show('console'); bootConsole(data); break;
      case 'login': vt.showLogin(''); break;
      case 'setup': show('setup-view'); vt.views.setup(document.getElementById('setup-view'), data); break;
      default: shellStatus('Unknown page state: ' + String(data.state), 'error');
    }
  });
})();
