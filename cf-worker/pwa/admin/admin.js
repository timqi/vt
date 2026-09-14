'use strict';

// The admin shell (docs/design/ui-ux.md). One page, one state from VT_DATA,
// one tab strip; each tab is a <section class="tab-panel" id="tab-…"> whose
// script registers `vt.tabs.<key> = function (panel, data)` and is initialised
// on first activation. Ids are document-unique; anything that exists once per
// tab (.status, .rows, .filters, .f-host, …) is a class the tab script looks up
// inside its own panel. Loaded before the tab scripts; boots on DOMContentLoaded.
//
// Shared here (admin-only): the API base and its 401 handling, the login
// ceremony, the detail dialog, the hovercard and the command summariser.
// Cross-shell helpers live in common.js (vt.*).

(function () {
  vt.api = function (path) { return '/api/admin/' + path; };
  vt.tabs = {};
  vt.views = {};

  // Every admin request goes through here: a 401 means the session is gone
  // (expired, epoch bumped by a revocation, cookie cleared), and the shell
  // returns to the login view rather than any tab rendering on stale data.
  vt.apiFetch = async function (url, init) {
    var resp = await fetch(url, init);
    if (resp.status === 401) vt.showLogin('会话已失效，请重新登录');
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

  // ── Record names (audit 记录 column + dialog, cache rows) ─────────────────
  // One record's label: the operator-owned name, else the client's claim marked
  // 自报, else 未命名 (mirrors account_names.nameLabel).
  vt.recordLabel = function (r) {
    return r.name || (r.claimed ? r.claimed + '（自报）' : '未命名');
  };

  // Column text: the labels joined, or `N 条` for a row that stored no records.
  vt.recordsSummary = function (records, n) {
    if (!records || !records.length) return n > 0 ? n + ' 条' : '';
    return records.map(vt.recordLabel).join(', ');
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
        var btn = vt.el('button', 'rec-name' + (r.name ? '' : ' unnamed'), vt.recordLabel(r));
        btn.type = 'button';
        btn.title = '点击重命名';
        btn.addEventListener('click', function (e) { e.stopPropagation(); edit(li, r); });
        li.appendChild(btn);
        if (r.name && r.claimed && r.claimed !== r.name) li.appendChild(vt.el('span', 'cell-sub', '客户端称 ' + r.claimed));
        ul.appendChild(li);
      });
      if (!expanded && records.length > limit) {
        var more = vt.el('button', 'rec-name more', '+' + (records.length - limit) + ' 条');
        more.type = 'button';
        more.addEventListener('click', function (e) { e.stopPropagation(); expanded = true; render(); });
        ul.appendChild(vt.el('li', null)).appendChild(more);
      }
    }
    function edit(li, r) {
      var input = document.createElement('input');
      input.type = 'text'; input.maxLength = 40; input.value = r.name || r.claimed || '';
      input.className = 'rec-edit';
      input.setAttribute('aria-label', '记录名');
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
          input.setCustomValidity('保存失败：' + (e.message || e));
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
        if (!ch.ok) throw new Error(ch.status === 429 ? '登录尝试过多，请稍后再试' : 'HTTP ' + ch.status);
        var c = await ch.json();
        setStatus('请完成 Passkey 验证…');
        // No allowCredentials: registration required resident keys, so the
        // authenticator discovers the credential and the page lists nothing.
        var a = await navigator.credentials.get({ publicKey: {
          challenge: vt.b64uDec(c.challenge_b64u), rpId: c.rp_id, userVerification: 'required',
        } });
        if (!a) throw new Error('验证被取消');
        var r = a.response;
        var resp = await vt.postJson('login', {
          challenge_id: c.challenge_id,
          credential_id_b64u: vt.b64uEnc(new Uint8Array(a.rawId)),
          client_data_json_b64u: vt.b64uEnc(new Uint8Array(r.clientDataJSON)),
          authenticator_data_b64u: vt.b64uEnc(new Uint8Array(r.authenticatorData)),
          signature_b64u: vt.b64uEnc(new Uint8Array(r.signature)),
        });
        if (resp.status !== 204) throw new Error(resp.status === 401 ? '登录失败：Passkey 未注册或验证未通过' : 'HTTP ' + resp.status);
        setStatus('已登录', 'ok');
        location.reload();
      } catch (e) {
        var msg = (e && e.message) ? e.message : String(e);
        if (/NotAllowed|not allowed/i.test(msg)) msg = '未找到匹配 Passkey 或操作被取消';
        setStatus(msg, 'error');
      } finally { btn.disabled = false; }
    });
  };

  document.addEventListener('DOMContentLoaded', function () {
    var shellStatus = vt.statusLine(document.getElementById('shell-status'));
    var data = vt.bootData();
    if (!data) { shellStatus('页面初始化失败：缺少或无法解析 vt-data', 'error'); return; }
    switch (data.state) {
      case 'console': show('console'); bootConsole(data); break;
      case 'login': vt.showLogin(''); break;
      case 'setup': show('setup-view'); vt.views.setup(document.getElementById('setup-view'), data); break;
      default: shellStatus('未知页面状态：' + String(data.state), 'error');
    }
  });
})();
