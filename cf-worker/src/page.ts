// Page-shell helpers: the pure string functions behind the HTML the Worker
// serves. The shells themselves live as real files under pwa/ and pwa/admin/
// and are read through the ASSETS binding inside the (Access-gated) route
// handlers; everything the server has to inject is a `{{NAME}}` placeholder
// substituted here. Kept free of Worker/Hono types so it unit-tests as plain
// TypeScript (test/page.test.ts).

// Escape a JSON string for safe embedding in a <script type="application/json"> block.
export function escapeJsonForHtml(obj: unknown): string {
  return JSON.stringify(obj)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

// `{{NAME}}` — uppercase/digits/underscore only, so nothing in the page markup
// (CSS, JS, Chinese copy) can be mistaken for a placeholder.
const PLACEHOLDER_RE = /\{\{([A-Z0-9_]+)\}\}/g;

/**
 * Substitute `{{NAME}}` placeholders in a page shell.
 *
 * Deliberate properties, each covered by a test:
 *  • ONE pass — String.replace scans the template left to right and never
 *    re-examines what a replacement inserted, so a value that happens to
 *    contain `{{FOO}}` is emitted literally and can't reach another slot.
 *  • Function replacement, so `$&` / `$1` / `$'` inside a value stay literal
 *    (the string form of replace() would expand them).
 *  • Fails closed both ways: a placeholder with no value throws (a typo can
 *    never ship `{{RP_ID}}` to a browser) and a value with no placeholder
 *    throws (server data silently dropped from a page is the same bug seen
 *    from the other side).
 *
 * Values are inserted verbatim: this helper does no escaping and must not be
 * given untrusted input. Callers pass either Worker-owned constants
 * (ASSET_VER, the admin base, the tab bar) or `escapeJsonForHtml(...)` output
 * — the same escaping the inline templates used.
 */
export function renderTemplate(template: string, vars: Readonly<Record<string, string>>): string {
  const used = new Set<string>();
  const out = template.replace(PLACEHOLDER_RE, (_match, name: string) => {
    const value = vars[name];
    if (value === undefined) throw new Error(`template: no value for {{${name}}}`);
    used.add(name);
    return value;
  });
  for (const name of Object.keys(vars)) {
    if (!used.has(name)) throw new Error(`template: unused value ${name}`);
  }
  return out;
}

// ── Placeholder values ────────────────────────────────────────────────────
//
// The Worker-owned chrome every shell needs. Passed in rather than imported so
// these builders stay pure and testable (ADMIN_SEG / ASSET_VER / FAVICON_TAGS
// live in index.ts, next to the routes that depend on them).
export interface PageChrome {
  adminSeg: string;
  assetVer: string;
  faviconTags: string;
}

export type AdminTab = 'audit' | 'cache' | 'setup' | 'channels';

// Placeholders common to every shell, admin or public.
export function pageVars(chrome: PageChrome): Record<string, string> {
  return { FAVICON_TAGS: chrome.faviconTags, ASSET_VER: chrome.assetVer };
}

// Tab bar shared by all admin pages. Every tab carries equal weight; `active`
// marks the current one.
export function adminTabs(chrome: PageChrome, active: AdminTab): string {
  const seg = chrome.adminSeg;
  const tab = (href: string, key: AdminTab, label: string) =>
    `<a class="tab${key === active ? ' active' : ''}" href="${href}"${key === active ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<nav class="tabs">${tab(`/${seg}/audit`, 'audit', '审计')}${tab(`/${seg}/cache`, 'cache', 'DEK 缓存')}${tab(`/${seg}/setup`, 'setup', 'Passkey')}${tab(`/${seg}/channels`, 'channels', '推送渠道')}</nav>`;
}

// Placeholders every admin shell carries.
export function adminVars(chrome: PageChrome, active: AdminTab): Record<string, string> {
  return {
    ...pageVars(chrome),
    ADMIN_BASE: `/${chrome.adminSeg}`,
    ADMIN_TABS: adminTabs(chrome, active),
  };
}

// Per-channel placeholders on the channels shell. The live secrets are NEVER
// injected — only whether each parses as configured, which decides a badge, the
// enable switch's checked state, whether the card body starts expanded, and the
// "already configured" note.
export function channelVars(
  key: 'PUSHOVER' | 'SLACK' | 'SLACKAPP' | 'FEISHU',
  set: boolean,
): Record<string, string> {
  return {
    [`${key}_BADGE`]: set ? `<span class="badge badge-approved">已配置</span>` : `<span class="badge">未配置</span>`,
    [`${key}_CHECKED`]: set ? ' checked' : '',
    [`${key}_HIDDEN`]: set ? '' : ' hidden',
    [`${key}_KEEP_NOTE`]: set ? '<p class="hint keep-note">✓ 当前已配置：留空点「生成」保持不变，填入新值则覆盖。</p>' : '',
  };
}

/**
 * True when an asset path resolves inside the ADMIN asset folder (pwa/admin/).
 *
 * That folder holds admin.css, the per-tab .js, and — since the page shells
 * moved out of TypeScript — the admin HTML itself. It must be reachable ONLY
 * through the Cloudflare-Access-gated /{ADMIN_SEG}/pwa/* mount, so the public
 * /pwa/* route refuses anything this returns true for.
 *
 * The argument is the path already sliced for the ASSETS binding (`/pwa/admin/x`
 * → `/admin/x`). `..` segments are collapsed by the URL parser before the slice,
 * but percent-encoding survives it and Workers Assets decodes when it resolves a
 * path — a plain `startsWith('/admin/')` would let `/pwa/admin%2Fx` through — so
 * the decoded forms are checked too.
 */
export function isAdminAssetPath(assetPath: string): boolean {
  const isAdmin = (p: string) => /^\/+admin(\/|$)/i.test(p);
  let p = assetPath;
  for (let i = 0; i < 4; i++) {
    if (isAdmin(p)) return true;
    let next: string;
    try { next = decodeURIComponent(p); }
    catch { return false; } // malformed % — ASSETS won't resolve it either
    if (next === p) return false;
    p = next;
  }
  return isAdmin(p);
}
