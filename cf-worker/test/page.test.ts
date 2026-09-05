// Unit tests for the page-shell helpers: the placeholder substitution that
// replaced the inline HTML template literals, the JSON escaping the shells
// depend on, and the admin-folder guard on the public /pwa/* route. All pure
// string functions, so they run under plain vitest with no workerd.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  renderTemplate, escapeJsonForHtml, isAdminAssetPath,
  pageVars, adminVars, adminTabs, channelVars, type PageChrome, type AdminTab,
} from '../src/page';

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

describe('isAdminAssetPath', () => {
  it('matches the admin asset folder', () => {
    for (const p of ['/admin/audit', '/admin/audit.html', '/admin/admin.css', '/admin']) {
      expect(isAdminAssetPath(p)).toBe(true);
    }
  });

  // Workers Assets percent-decodes when it resolves a path, so /pwa/admin%2Fx
  // reaches /admin/x — a plain startsWith('/admin/') would miss it. Case and
  // repeated leading slashes are covered for the same reason.
  it('matches encoded and odd-cased forms', () => {
    for (const p of ['/admin%2Faudit', '/admin%2fadmin.css', '/%61dmin/audit', '//admin/audit', '/ADMIN/audit']) {
      expect(isAdminAssetPath(p)).toBe(true);
    }
  });

  it('does not match the public assets', () => {
    for (const p of ['/', '/approve', '/common.js', '/libsodium.js', '/icon.svg', '/administrator.js', '/x/admin/y']) {
      expect(isAdminAssetPath(p)).toBe(false);
    }
  });

  it('does not throw on a malformed percent escape', () => {
    expect(isAdminAssetPath('/%zz/admin')).toBe(false);
  });
});

// The shells are real files now, so a typo'd or renamed placeholder is a
// deploy-time 500 rather than a compile error. Rendering each one with the
// exact variable map its route builds turns that into a test failure:
// renderTemplate throws on both an unfilled placeholder and an unused value.
describe('page shells', () => {
  const CHROME: PageChrome = {
    adminSeg: 'kestrel',
    assetVer: '20260101-abc1234',
    faviconTags: '<link rel="icon" href="/pwa/icon.svg" type="image/svg+xml">',
  };
  const shell = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');

  const render = (path: string, vars: Record<string, string>) => renderTemplate(shell(path), vars);

  it('renders the approval page', () => {
    const html = render('pwa/approve.html', {
      ...pageVars(CHROME),
      VT_DATA: escapeJsonForHtml({ approve_token: 'tok', meta: {} }),
    });
    expect(html).toContain('<script type="application/json" id="vt-data">');
    expect(html).toContain('/pwa/approve.js?v=20260101-abc1234');
  });

  it('renders the data-free admin shells', () => {
    for (const tab of ['audit', 'cache'] as AdminTab[]) {
      const html = render(`pwa/admin/${tab}.html`, adminVars(CHROME, tab));
      expect(html).toContain(`href="/kestrel/${tab}" aria-current="page"`);
      expect(html).toContain('/kestrel/pwa/admin.css?v=20260101-abc1234');
    }
  });

  it('renders the setup shell with RP_ID + CREDENTIALS_JSON', () => {
    const html = render('pwa/admin/setup.html', {
      ...adminVars(CHROME, 'setup'),
      VT_DATA: escapeJsonForHtml({ rp_id: 'vt.example.com', credentials: '{"v":1,"epoch":0,"c":[]}' }),
    });
    expect(html).toContain('vt.example.com');
    expect(html).toContain('/kestrel/pwa/setup.js?v=20260101-abc1234');
  });

  it('renders the channels shell for every configured/not-configured combination', () => {
    for (let bits = 0; bits < 16; bits++) {
      const [po, sl, sa, fs] = [1, 2, 4, 8].map(m => (bits & m) !== 0) as [boolean, boolean, boolean, boolean];
      const html = render('pwa/admin/channels.html', {
        ...adminVars(CHROME, 'channels'),
        VT_DATA: escapeJsonForHtml({ pushover_set: po, slack_set: sl, slackapp_set: sa, feishu_set: fs }),
        ...channelVars('PUSHOVER', po), ...channelVars('SLACK', sl),
        ...channelVars('SLACKAPP', sa), ...channelVars('FEISHU', fs),
      });
      const configured = [po, sl, sa, fs].filter(Boolean).length;
      expect(html.match(/已配置<\/span>/g) ?? []).toHaveLength(configured);
      expect(html.match(/ checked>/g) ?? []).toHaveLength(configured);
      // A not-configured card starts collapsed.
      expect(html.match(/class="channel-body"[^>]* hidden>/g) ?? []).toHaveLength(4 - configured);
    }
  });

  it('leaves no unsubstituted placeholder in any shell', () => {
    // Sanity net over the renders above: nothing of the form {{NAME}} survives.
    const rendered = [
      render('pwa/approve.html', { ...pageVars(CHROME), VT_DATA: '{}' }),
      render('pwa/admin/audit.html', adminVars(CHROME, 'audit')),
      render('pwa/admin/cache.html', adminVars(CHROME, 'cache')),
      render('pwa/admin/setup.html', { ...adminVars(CHROME, 'setup'), VT_DATA: '{}' }),
      render('pwa/admin/channels.html', {
        ...adminVars(CHROME, 'channels'), VT_DATA: '{}',
        ...channelVars('PUSHOVER', true), ...channelVars('SLACK', false),
        ...channelVars('SLACKAPP', true), ...channelVars('FEISHU', false),
      }),
    ];
    for (const html of rendered) expect(html).not.toMatch(/\{\{[A-Z0-9_]+\}\}/);
  });
});

describe('adminTabs', () => {
  it('marks exactly one tab active and links the rest', () => {
    const nav = adminTabs({ adminSeg: 'kestrel', assetVer: 'v', faviconTags: '' }, 'cache');
    expect(nav.match(/class="tab active"/g)).toHaveLength(1);
    expect(nav.match(/aria-current="page"/g)).toHaveLength(1);
    expect(nav).toContain('href="/kestrel/cache" aria-current="page"');
    expect(nav.match(/<a /g)).toHaveLength(4);
  });

  it('follows ADMIN_SEG', () => {
    const nav = adminTabs({ adminSeg: 'other', assetVer: 'v', faviconTags: '' }, 'audit');
    expect(nav).not.toContain('/kestrel/');
    expect(nav).toContain('href="/other/audit"');
  });
});
