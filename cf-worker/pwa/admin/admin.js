'use strict';

// The admin shell (docs/design/ui-ux.md). One page, one state from VT_DATA,
// one tab strip; each tab is a <section class="tab-panel" id="tab-…"> whose
// script registers `vt.tabs.<key> = function (panel, data)` and is initialised
// on first activation. Ids are document-unique; anything that exists once per
// tab (.status, .rows, .filters, .f-host, …) is a class the tab script looks up
// inside its own panel. Loaded before the tab scripts; boots on DOMContentLoaded.
//
// Shared here (admin-only): the API base, the detail dialog, the hovercard and
// the command summariser. Cross-shell helpers live in common.js (vt.*).

(function () {
  // The admin segment from the current path (/{seg}); Cloudflare Access gates it.
  var seg = location.pathname.split('/')[1] || '';
  vt.api = function (path) { return '/' + seg + '/api/' + path; };
  vt.AUTH_EXPIRED = '未授权（Cloudflare Access 会话可能已过期，请刷新登录）';
  vt.tabs = {};

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

  // ── Detail dialog ─────────────────────────────────────────────────────────
  // #detail-backdrop / #detail-card exist once in the shell. open() fills the
  // heading, the warning and hands back the empty <dl> plus the ceremony box;
  // it never clears the ceremony box (a live re-render must not disturb a
  // mounted ceremony) — close() does. Escape, the close control and a backdrop
  // tap close; focus returns to the opener on dismissal.
  var backdrop = document.getElementById('detail-backdrop');
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
      if (backdrop.hidden) dialogOpener = document.activeElement;
      dialogOnClose = opts.onClose || null;
      backdrop.hidden = false;
      return { dl: dialogDl, approve: dialogApprove };
    },
    close: function () {
      if (backdrop.hidden) return;
      backdrop.hidden = true;
      dialogApprove.innerHTML = '';
      var cb = dialogOnClose; dialogOnClose = null;
      if (cb) cb();
      if (dialogOpener && dialogOpener.focus) dialogOpener.focus();
      dialogOpener = null;
    },
    isOpen: function () { return !backdrop.hidden; },
    // A <dt>/<dd> pair; skipped for an empty value. `mono` marks paths/commands.
    addRow: function (dl, label, value, mono) {
      if (value === null || value === undefined || value === '') return;
      dl.appendChild(vt.el('dt', null, label));
      dl.appendChild(vt.el('dd', mono ? 'mono' : null, String(value)));
    },
  };
  document.getElementById('detail-close').addEventListener('click', vt.dialog.close);
  backdrop.addEventListener('click', function (e) { if (e.target === backdrop) vt.dialog.close(); });

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
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    hideHover();
    vt.dialog.close();
  });

  // ── Tab strip ─────────────────────────────────────────────────────────────
  // Tab in the URL hash (/{seg}#audit), first tab default. A panel's script
  // runs once, on first activation, so a hidden tab costs nothing until opened.
  var TABS = [
    ['audit', '审计'], ['cache', 'DEK 缓存'], ['tokens', '主机令牌'],
    ['setup', 'Passkey'], ['settings', '设置'],
  ];
  var started = {};

  function activate(data) {
    var key = location.hash.slice(1);
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
    document.title = 'VT — ' + TABS.filter(function (t) { return t[0] === key; })[0][1];
  }

  function bootConsole(data) {
    var nav = document.getElementById('tabs');
    TABS.forEach(function (t) {
      var a = vt.el('a', 'tab', t[1]);
      a.id = 'tab-link-' + t[0];
      a.href = '#' + t[0];
      nav.appendChild(a);
    });
    document.getElementById('page-head').hidden = false;
    document.getElementById('console').hidden = false;
    window.addEventListener('hashchange', function () { activate(data); });
    activate(data);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var shellStatus = vt.statusLine(document.getElementById('shell-status'));
    var data = vt.bootData();
    if (!data) { shellStatus('页面初始化失败：缺少或无法解析 vt-data', 'error'); return; }
    // The shell renders exactly one state. `setup` and `login` arrive with the
    // passkey admin auth of docs/worker-slim.md §3; until then Cloudflare Access
    // gates the page and the Worker only ever sends `console`.
    switch (data.state) {
      case 'console': bootConsole(data); break;
      default: shellStatus('未知页面状态：' + String(data.state), 'error');
    }
  });
})();
