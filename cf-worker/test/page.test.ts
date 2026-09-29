// Unit tests for the page-shell helpers: the placeholder substitution that
// replaced the inline HTML template literals, the JSON escaping the shells
// depend on, and the shells themselves rendering with exactly the variables
// their routes build. All pure string functions, so they run under plain vitest
// with no workerd. (That the public /pwa/* route serves pwa/admin/* is a route
// behaviour, tested in test/do_account.admin_shell.test.ts.)

import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { renderTemplate, escapeJsonForHtml, pageVars, type PageChrome } from '../src/page';

const pwa = (p: string) => readFileSync(new URL(`../pwa/${p}`, import.meta.url), 'utf8');

describe('notification cleanup on PWA visits', () => {
  function setup(statuses: Array<number | Error>, visibilityState = 'visible') {
    const notifications = statuses.map((_, i) => ({
      tag: 'a:' + String(i).padStart(16, '0'), close: vi.fn(),
    }));
    const other = { tag: 'cache:host', close: vi.fn() };
    const listeners: Record<string, () => void> = {};
    const document = { visibilityState, addEventListener: (name: string, fn: () => void) => { listeners[name] = fn; } };
    const fetch = vi.fn(async (path: string, _options: unknown) => {
      const status = statuses[Number(path.split('/').pop())];
      if (status instanceof Error) throw status;
      return { status, json: async () => ({ error: status === 410 ? 'gone' : 'not_found' }) };
    });
    const getNotifications = vi.fn(async () => [...notifications, other]);
    const context = {
      document, TextEncoder, fetch,
      navigator: { serviceWorker: { addEventListener() {}, ready: Promise.resolve({ getNotifications }) } },
      window: { addEventListener: (name: string, fn: () => void) => { listeners[name] = fn; } },
    };
    runInNewContext(pwa('common.js'), context);
    return { notifications, other, listeners, document, fetch, getNotifications };
  }

  it('closes ended and removed requests, preserving pending, unavailable and unrelated notices', async () => {
    const h = setup([410, 404, 200, 503, new Error('offline')]);
    await vi.waitFor(() => expect(h.fetch).toHaveBeenCalledTimes(5));
    expect(h.notifications.map(n => n.close.mock.calls.length)).toEqual([1, 1, 0, 0, 0]);
    expect(h.other.close).not.toHaveBeenCalled();
    expect(h.fetch).toHaveBeenCalledWith('/api/page/0000000000000000', { cache: 'no-store', redirect: 'error' });
  });

  it('retains notifications on malformed or unrelated error responses and retries on the next visit', async () => {
    const h = setup([410, 404], 'hidden');
    h.fetch.mockImplementationOnce(async () => ({ status: 410, json: async () => { throw new Error('invalid JSON'); } }));
    h.fetch.mockImplementationOnce(async () => ({ status: 404, json: async () => ({ error: 'upstream_failure' }) }));
    await Promise.resolve();
    h.document.visibilityState = 'visible';
    await h.listeners.visibilitychange();
    expect(h.notifications.every(n => n.close.mock.calls.length === 0)).toBe(true);
    expect(h.fetch).toHaveBeenCalledTimes(2);
    await h.listeners.pageshow();
    expect(h.notifications.map(n => n.close.mock.calls.length)).toEqual([1, 1]);
  });

  it('checks on return to the foreground and on restored pages, without overlapping sweeps', async () => {
    const h = setup([410], 'hidden');
    await Promise.resolve();
    expect(h.getNotifications).not.toHaveBeenCalled();
    h.document.visibilityState = 'visible';
    h.listeners.visibilitychange();
    h.listeners.pageshow();
    await vi.waitFor(() => expect(h.notifications[0].close).toHaveBeenCalledTimes(1));
    expect(h.getNotifications).toHaveBeenCalledTimes(1);
    h.listeners.pageshow();
    await vi.waitFor(() => expect(h.getNotifications).toHaveBeenCalledTimes(2));
  });
});

// A notification tap reaches an open page as a service-worker message. The
// console answers it in its own sheet (admin.js vt.openApprovalSheet); anything
// else loads the standalone /a/<token> document.
describe('notification hand-off', () => {
  const URL_ = 'https://vt.test/a/0123456789abcdef';

  function setup(opts: { sheet?: () => boolean; ceremonyOnScreen?: boolean; pathname?: string } = {}) {
    const listeners: Record<string, (e: unknown) => void> = {};
    const replace = vi.fn();
    const context: Record<string, unknown> = {
      document: {
        addEventListener() {}, visibilityState: 'hidden',
        querySelector: () => (opts.ceremonyOnScreen ? {} : null),
      },
      location: { origin: 'https://vt.test', pathname: opts.pathname ?? '/admin', replace },
      addEventListener() {},
      URL, TextEncoder, crypto, fetch: vi.fn(),
      navigator: {
        serviceWorker: {
          addEventListener: (name: string, fn: (e: unknown) => void) => { listeners[name] = fn; },
          ready: new Promise(() => {}),   // never resolves: no notification sweep here
        },
      },
    };
    context.window = context;
    runInNewContext(pwa('common.js'), context);
    const sheet = opts.sheet ? vi.fn(opts.sheet) : undefined;
    if (sheet) (context.vt as Record<string, unknown>).openApprovalSheet = sheet;
    const send = (url: unknown = URL_) => listeners.message({ data: { type: 'vt-navigate', url } });
    return { send, replace, sheet };
  }

  it('hands the token to a console that can mount it, instead of navigating', () => {
    const h = setup({ sheet: () => true });
    h.send();
    expect(h.sheet).toHaveBeenCalledWith('0123456789abcdef');
    expect(h.replace).not.toHaveBeenCalled();
  });

  it('navigates when no console claims it', () => {
    const none = setup();
    none.send();
    expect(none.replace).toHaveBeenCalledWith(URL_);

    const refused = setup({ sheet: () => false });
    refused.send();
    expect(refused.replace).toHaveBeenCalledWith(URL_);
  });

  it('leaves a running ceremony, this page, and foreign or non-approval URLs alone', () => {
    const busy = setup({ sheet: () => true, ceremonyOnScreen: true });
    busy.send();
    expect(busy.sheet).not.toHaveBeenCalled();
    expect(busy.replace).not.toHaveBeenCalled();

    const here = setup({ sheet: () => true, pathname: '/a/0123456789abcdef' });
    here.send();
    expect(here.sheet).not.toHaveBeenCalled();
    expect(here.replace).not.toHaveBeenCalled();

    const off = setup({ sheet: () => true });
    off.send('https://evil.test/a/0123456789abcdef');
    off.send('https://vt.test/admin#audit');
    expect(off.sheet).not.toHaveBeenCalled();
    expect(off.replace).not.toHaveBeenCalled();
  });
});

// The ceremony builds its DOM through a handful of calls; a tree stub is enough
// to check where the duration control lands and what it reveals.
describe('approval ceremony layout', () => {
  class Node_ {
    children: Node_[] = []; parentNode: Node_ | null = null;
    className = ''; hidden = false; textContent = ''; id = ''; type = ''; name = ''; value = ''; checked = false;
    attrs: Record<string, string> = {};
    listeners: Record<string, Array<() => void>> = {};
    classList = { add: (c: string) => { this.className += ' ' + c; } };
    style = { setProperty() {} };
    constructor(public tag: string) {}
    set innerHTML(_: string) { this.children = []; }
    get firstChild() { return this.children[0] ?? null; }
    appendChild(c: Node_) { c.parentNode = this; this.children.push(c); return c; }
    insertBefore(c: Node_, ref: Node_ | null) {
      c.parentNode = this;
      const i = ref ? this.children.indexOf(ref) : -1;
      if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
      return c;
    }
    setAttribute(k: string, v: string) { this.attrs[k] = v; }
    removeAttribute(k: string) { delete this.attrs[k]; }
    addEventListener(n: string, fn: () => void) { (this.listeners[n] ??= []).push(fn); }
    all(): Node_[] { return this.children.flatMap(c => [c, ...c.all()]); }
    querySelectorAll(sel: string) { return sel === 'input' ? this.all().filter(n => n.tag === 'input') : []; }
    querySelector(sel: string) {
      return sel === 'input[name="cache-ttl"]:checked'
        ? this.all().find(n => n.name === 'cache-ttl' && n.checked) ?? null : null;
    }
    has(cls: string) { return this.className.split(/\s+/).includes(cls); }
    find(cls: string) { return this.all().find(n => n.has(cls))!; }
  }

  function mount(opts: { project?: string; showMeta?: boolean; data?: Record<string, unknown> } = {}) {
    const context: Record<string, unknown> = {
      document: {
        createElement: (t: string) => new Node_(t), createTextNode: (t: string) => { const n = new Node_('#text'); n.textContent = t; return n; },
        getElementById: () => null, addEventListener() {},
      },
      location: { pathname: '/admin', hash: '' }, addEventListener() {},
      navigator: {}, TextEncoder, crypto, console,
    };
    context.window = context;
    runInNewContext(pwa('common.js'), context);
    runInNewContext(pwa('approve.js'), context);
    const root = new Node_('div');
    (context.vt as { mountApprove: (o: unknown) => void }).mountApprove({
      root, showMeta: opts.showMeta ?? true,
      data: {
        metadata: { op_kind: 'decrypt', project: opts.project ?? '/srv/app/.git', pwd: '/srv/app/sub' }, records: [],
        cache_options_s: [0, 1200, 7200], cache_pubkey_b64u: 'AA',
        ...opts.data,
      },
    });
    const radios = root.all().filter(n => n.name === 'cache-ttl');
    const group = root.find('seg');
    const pick = (i: number) => {
      radios.forEach((r, k) => { r.checked = k === i; });
      group.listeners.change.forEach(fn => fn());
    };
    const text = (n: Node_) => n.all().map(c => c.textContent).join('');
    return { root, radios, group, pick, text };
  }

  it('puts the labelled duration control in the action bar, above Approve / Reject', () => {
    const { root, radios, group } = mount();
    const bar = root.find('vt-ap-bar');
    const cache = root.find('vt-ap-cache');
    expect(cache.parentNode).toBe(bar);
    expect(cache.hidden).toBe(false);
    expect(bar.children.indexOf(cache)).toBeLessThan(bar.children.indexOf(root.find('vt-ap-actions')));
    expect(radios.map(r => [r.value, r.checked])).toEqual([['0', true], ['1200', false], ['7200', false]]);
    const label = root.find('vt-ap-cache-label');
    expect(label.textContent).toBe('Cache decrypt authorization');
    expect(label.hidden).toBe(false);
    expect(group.attrs['aria-labelledby']).toBe(label.id);
  });

  it('states and describes the reuse scope only while a duration is picked', () => {
    const { root, group, pick, text } = mount();
    const scope = root.find('cache-scope');
    expect(scope.hidden).toBe(true);
    expect(group.attrs['aria-describedby']).toBeUndefined();
    expect(text(scope)).toContain('/srv/app/.git');
    pick(1);
    expect(scope.hidden).toBe(false);
    expect(group.attrs['aria-describedby']).toBe(scope.id);
    pick(0);
    expect(scope.hidden).toBe(true);
    expect(group.attrs['aria-describedby']).toBeUndefined();
  });

  it('states the host-token scope a picked duration arms without a project', () => {
    const { root, pick, text } = mount({ project: '' });
    const scope = root.find('cache-scope');
    pick(2);
    expect(scope.hidden).toBe(false);
    expect(text(scope)).toContain('same host token (verified), requests reporting no project');
  });

  it('keeps the duration control in the bar when the host shows the request itself', () => {
    const { root, pick } = mount({ showMeta: false });
    expect(root.all().some(n => n.has('vt-ap-meta-section'))).toBe(false);
    expect(root.find('vt-ap-cache').parentNode).toBe(root.find('vt-ap-bar'));
    expect(root.find('vt-ap-cache').hidden).toBe(false);
    pick(1);
    expect(root.find('cache-scope').hidden).toBe(false);
  });

  it.each([
    ['no cache key', { cache_pubkey_b64u: '' }],
    ['only No cache', { cache_options_s: [0] }],
    ['no options', { cache_options_s: undefined }],
  ])('hides the duration control with %s', (_, data) => {
    const { root, radios } = mount({ data });
    expect(root.find('vt-ap-cache').hidden).toBe(true);
    expect(radios).toEqual([]);
  });
});

describe('cache creation time rendering', () => {
  class Element {
    children: Element[] = [];
    textContent = '';
    className = '';
    hidden = false;
    classList = { add() {}, toggle() {} };
    appendChild(child: Element) { this.children.push(child); return child; }
    setAttribute() {}
    addEventListener() {}
    querySelector() { return new Element(); }
    querySelectorAll() { return []; }
  }

  // The tab script registers vt.tabs.cache; run it against a stub panel with
  // the real common.js + admin.js helpers, cut before its wiring so no fetch,
  // timer or listener starts, and reach the row renderer through the cut.
  const source = pwa('admin/cache.js');
  const wiring = source.indexOf("  $('.refresh').addEventListener");
  expect(wiring).toBeGreaterThan(0);
  const context: Record<string, unknown> = {
    location: { pathname: '/admin', hash: '' },
    document: {
      getElementById: () => new Element(), createElement: () => new Element(),
      addEventListener() {}, body: new Element(),
    },
    addEventListener() {},
    matchMedia: () => ({ matches: false, addEventListener() {} }),   // desktop: the table branch
    navigator: {},   // no serviceWorker: common.js skips the notification hand-off
    TextEncoder, crypto,
  };
  context.window = context; // common.js publishes `window.vt`; scripts read the global `vt`
  runInNewContext(pwa('common.js'), context);
  runInNewContext(pwa('admin/admin.js'), context);
  runInNewContext(source.slice(0, wiring) + 'globalThis.renderRow = renderRow; };', context);
  (context.vt as { tabs: { cache: (panel: Element) => void } }).tabs.cache(new Element());
  const renderRow = context.renderRow as (entry: Record<string, unknown>) => Element;
  const entry = (over: Record<string, unknown>) => ({
    token_id: 'testtoken0000000', project: '/srv/app/.git', salt_b64u: 'K0g8nyJ5aGVsbG8gd29ybA',
    record: { salt_b64u: 'K0g8nyJ5aGVsbG8gd29ybA', name: null, claimed: '', source: null },
    host: 'h', user: 'u', ip: '', created_ms: 1, expires_ms: Date.now() + 60_000, ttl_s: 1200, origin_token_id: 'o',
    ...over,
  });

  function creationLine(created: number | null, expires: number) {
    const row = renderRow(entry({ created_ms: created, expires_ms: expires }));
    return row.children[2].children.at(-1)!.textContent;
  }

  it('shows the original creation timestamp before and after extension', () => {
    const created = new Date(2026, 0, 2, 3, 4, 5).getTime();
    for (const expires of [Date.now() + 60_000, Date.now() + 86_400_000]) {
      expect(creationLine(created, expires)).toBe('created 2026-01-02 03:04:05');
    }
  });

  it('labels legacy entries without a creation timestamp as unknown', () => {
    expect(creationLine(null, Date.now() + 60_000)).toBe('created unknown');
  });
});

// No browser here: the shell scripts are loaded into a stub DOM to prove they
// parse, boot the state the Worker reports, and only look up ids the shell
// declares.
// Real WebAuthn, cookies and the installed PWA are checked by hand
// (docs/design/ui-ux.md#validation).
describe('admin shell scripts against the shell markup', () => {
  const html = pwa('admin/admin.html');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));

  it('declares every id the tab and shell scripts query', () => {
    for (const js of ['admin/admin.js', 'admin/audit.js', 'admin/cache.js', 'admin/tokens.js', 'admin/setup.js', 'admin/settings.js']) {
      // `'tab-' + key` builds panel ids; the literal ones are what matter here.
      const wanted = [...pwa(js).matchAll(/(?:\$\(|getElementById\()'#?([a-z][a-z0-9-]*[a-z0-9])'/g)].map(m => m[1]);
      const missing = wanted.filter(id => !ids.has(id));
      expect(missing, js).toEqual([]);
    }
  });

  // admin.js boots from VT_DATA.state (fired on DOMContentLoaded): exactly one
  // of setup / login / console is shown, and an unknown state is reported
  // rather than guessed. setup.js and settings.js load too, so a parse error in
  // either fails here.
  function boot(state: string) {
    class Element {
      hidden = false; textContent = ''; className = ''; innerHTML = ''; value = ''; id = ''; href = '';
      classList = { add() {}, toggle() {} };
      appendChild(c: unknown) { return c; } setAttribute() {} removeAttribute() {} addEventListener() {}
      querySelector() { return new Element(); } querySelectorAll() { return []; }
    }
    const byId = new Map<string, Element>();
    const el = (id: string) => { if (!byId.has(id)) byId.set(id, new Element()); return byId.get(id)!; };
    el('vt-data').textContent = JSON.stringify({ state });
    let ready = () => {};
    const context: Record<string, unknown> = {
      location: { pathname: '/admin', hash: '' },
      document: {
        getElementById: el, createElement: () => new Element(), body: new Element(),
        addEventListener: (name: string, fn: () => void) => { if (name === 'DOMContentLoaded') ready = fn; },
      },
      addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }),
      navigator: {},   // no serviceWorker: common.js skips the notification hand-off
      TextEncoder, crypto, console,
    };
    context.window = context;
    for (const js of ['common.js', 'admin/admin.js', 'admin/setup.js', 'admin/settings.js']) runInNewContext(pwa(js), context);
    const vt = context.vt as { views: Record<string, unknown>; tabs: Record<string, unknown> };
    const setupView = vi.fn();
    const auditTab = vi.fn();
    vt.views.setup = setupView;
    vt.tabs.audit = auditTab;
    ready();
    const shown = ['setup-view', 'login-view', 'console', 'page-head'].filter(id => !el(id).hidden);
    return { el, shown, setupView, auditTab };
  }

  it.each([
    ['setup', ['setup-view']],
    ['login', ['login-view']],
    ['console', ['console', 'page-head']],
  ])('boots the %s state into exactly its view', (state, want) => {
    const h = boot(state);
    expect(h.shown).toEqual(want);
    expect(h.setupView.mock.calls.length).toBe(state === 'setup' ? 1 : 0);
    expect(h.auditTab.mock.calls.length).toBe(state === 'console' ? 1 : 0);
  });

  it('reports an unknown state and boots nothing', () => {
    const h = boot('bogus');
    expect(h.el('shell-status').textContent).toBe('Unknown page state: bogus');
    expect(h.el('shell-status').className).toContain('error');
    expect(h.setupView).not.toHaveBeenCalled();
    expect(h.auditTab).not.toHaveBeenCalled();
  });
});

describe('renderTemplate', () => {
  it('substitutes every occurrence of a placeholder', () => {
    expect(renderTemplate('a{{X}}b{{X}}c', { X: '-' })).toBe('a-b-c');
  });

  it('leaves anything that is not an UPPERCASE placeholder alone', () => {
    const tpl = '{{lower}} {{Mixed}} { {X} } ${X} {{X-Y}}';
    expect(renderTemplate(tpl, {})).toBe(tpl);
  });

  // The string form of String.replace expands $&, $1, $` and $' in the
  // replacement. Values here are server data (escaped JSON, a rendered tab
  // bar), so that would corrupt them — a function replacement must be used.
  it('treats $ patterns in a value as literal text', () => {
    expect(renderTemplate('[{{V}}]', { V: "$& $1 $` $' $$" })).toBe("[$& $1 $` $' $$]");
  });

  // One pass: a value that happens to contain a placeholder must be emitted
  // literally, never resolved against another variable.
  it('does not re-scan substituted values', () => {
    expect(renderTemplate('{{A}}', { A: '{{B}}' })).toBe('{{B}}');
    // Even when B *is* a real variable, the {{B}} A injected stays literal —
    // only the template's own {{B}} slot is filled.
    expect(renderTemplate('{{A}}|{{B}}', { A: '{{B}}', B: 'x' })).toBe('{{B}}|x');
  });

  // Fails closed in both directions: a shell placeholder with no value would
  // otherwise ship "{{RP_ID}}" to the browser, and a value with no placeholder
  // means server data silently dropped from the page.
  it('throws when a placeholder has no value', () => {
    expect(() => renderTemplate('{{RP_ID}}', {})).toThrow(/no value for \{\{RP_ID\}\}/);
  });

  it('throws when a value has no placeholder', () => {
    expect(() => renderTemplate('nothing here', { VT_DATA: '{}' })).toThrow(/unused value VT_DATA/);
  });

  it('accepts an empty value (a conditional fragment that renders to nothing)', () => {
    expect(renderTemplate('<div{{H}}>', { H: '' })).toBe('<div>');
  });
});

describe('escapeJsonForHtml', () => {
  it('escapes the characters that could break out of a JSON script block', () => {
    const out = escapeJsonForHtml({ s: '</script><img src=x onerror=alert(1)>&\u2028\u2029' });
    expect(out).not.toContain('<');
    expect(out).not.toContain('>');
    expect(out).not.toContain('&');
    expect(out).not.toContain('\u2028');
    expect(out).not.toContain('\u2029');
    expect(out.toLowerCase()).not.toContain('</script');
  });

  it('still parses back to the original value', () => {
    const value = { rp_id: 'vt.example.com', credentials: '{"v":1,"c":[]}', x: '<&>\u2028' };
    expect(JSON.parse(escapeJsonForHtml(value))).toEqual(value);
  });
});

// The shells are real files now, so a typo'd or renamed placeholder is a
// deploy-time 500 rather than a compile error. Rendering each one with the
// exact variable map its route builds turns that into a test failure:
// renderTemplate throws on both an unfilled placeholder and an unused value.
describe('page shells', () => {
  const CHROME: PageChrome = {
    assetVer: '20260101-abc1234',
    faviconTags: '<link rel="icon" href="/pwa/icon.svg" type="image/svg+xml">',
  };
  const render = (path: string, vars: Record<string, string>) => renderTemplate(pwa(path), vars);

  it('renders the approval page', () => {
    const html = render('approve.html', {
      ...pageVars(CHROME),
      VT_DATA: escapeJsonForHtml({ approve_token: 'tok', meta: {} }),
    });
    expect(html).toContain('<script type="application/json" id="vt-data">');
    expect(html).toContain('/pwa/approve.js?v=20260101-abc1234');
    expect(html).toContain('/pwa/admin/admin.css?v=20260101-abc1234');
  });

  // First paint must not wait for the big stylesheet: boot.css is the only
  // render-blocking link, admin.css is parked at media="print" and promoted by
  // approve.js, and the loading state ships in the shell's markup.
  it('paints a loading state before admin.css', () => {
    const raw = pwa('approve.html');
    expect(raw).toMatch(/<link rel="stylesheet" href="\/pwa\/boot\.css\?v=\{\{ASSET_VER\}\}">/);
    expect(raw).toMatch(/<link rel="stylesheet" id="vt-css" media="print" href="\/pwa\/admin\/admin\.css/);
    expect(raw).toContain('class="vt-boot"');
  });

  it('renders the admin shell with its state and rp_id', () => {
    const html = render('admin/admin.html', {
      ...pageVars(CHROME),
      VT_DATA: escapeJsonForHtml({ state: 'console', rp_id: 'vt.example.com' }),
    });
    expect(html).toContain('"state":"console"');
    expect(html).toContain('vt.example.com');
    for (const js of ['admin', 'audit', 'cache', 'tokens', 'setup', 'settings']) {
      expect(html).toContain(`/pwa/admin/${js}.js?v=20260101-abc1234`);
    }
  });

  // The admin shell is a public asset, so the file on disk must hold nothing
  // but markup: every value arrives through the gated route's placeholders.
  it('keeps the raw admin shell data-free', () => {
    const raw = pwa('admin/admin.html');
    const placeholders = new Set([...raw.matchAll(/\{\{([A-Z0-9_]+)\}\}/g)].map(m => m[1]));
    expect([...placeholders].sort()).toEqual(['ASSET_VER', 'FAVICON_TAGS', 'VT_DATA']);
    expect(raw).toContain('id="vt-data">{{VT_DATA}}</script>');
  });
});
