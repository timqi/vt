// Unit tests for the page-shell helpers: the placeholder substitution that
// replaced the inline HTML template literals, the JSON escaping the shells
// depend on, and the shells themselves rendering with exactly the variables
// their routes build. All pure string functions, so they run under plain vitest
// with no workerd. (That the public /pwa/* route serves pwa/admin/* is a route
// behaviour, tested in test/do_account.admin_shell.test.ts.)

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { renderTemplate, escapeJsonForHtml, pageVars, type PageChrome } from '../src/page';

const pwa = (p: string) => readFileSync(new URL(`../pwa/${p}`, import.meta.url), 'utf8');

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

  it('renders the three table cells at desktop width', () => {
    expect(renderRow(entry({})).children).toHaveLength(3);
  });

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
// parse, register their entry points, and only look up ids the shell declares.
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

  it('registers the three shell states and the API base', () => {
    class Element {
      hidden = false; textContent = ''; className = ''; innerHTML = ''; value = '';
      classList = { add() {}, toggle() {} };
      appendChild() {} setAttribute() {} removeAttribute() {} addEventListener() {}
      querySelector() { return new Element(); } querySelectorAll() { return []; }
    }
    const context: Record<string, unknown> = {
      location: { pathname: '/admin', hash: '' },
      document: { getElementById: () => new Element(), createElement: () => new Element(), addEventListener() {}, body: new Element() },
      addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }),
      TextEncoder, crypto, console,
    };
    context.window = context;
    for (const js of ['common.js', 'admin/admin.js', 'admin/setup.js', 'admin/settings.js']) runInNewContext(pwa(js), context);
    const vt = context.vt as { api: (p: string) => string; views: Record<string, unknown>; tabs: Record<string, unknown>; showLogin: unknown; apiFetch: unknown };
    expect(vt.api('credentials')).toBe('/api/admin/credentials');
    expect(typeof vt.views.setup).toBe('function');
    expect(typeof vt.tabs.setup).toBe('function');
    expect(typeof vt.tabs.settings).toBe('function');
    expect(typeof vt.showLogin).toBe('function');
    expect(typeof vt.apiFetch).toBe('function');
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

  // Guards the actual embedding: shell + escaped JSON must leave exactly one
  // </script> — the shell's own closing tag.
  it('cannot close the surrounding script element', () => {
    const html = renderTemplate('<script type="application/json" id="vt-data">{{VT_DATA}}</script>',
      { VT_DATA: escapeJsonForHtml({ evil: '</script><script>alert(1)</script>' }) });
    expect(html.match(/<\/script>/gi)).toHaveLength(1);
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

  it('leaves no unsubstituted placeholder in any shell', () => {
    // Sanity net over the renders above: nothing of the form {{NAME}} survives.
    const rendered = [
      render('approve.html', { ...pageVars(CHROME), VT_DATA: '{}' }),
      render('admin/admin.html', { ...pageVars(CHROME), VT_DATA: '{}' }),
      render('manifest.webmanifest', {}),
    ];
    for (const html of rendered) expect(html).not.toMatch(/\{\{[A-Z0-9_]+\}\}/);
  });
});
