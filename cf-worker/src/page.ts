// Page-shell helpers: the pure string functions behind the HTML the Worker
// serves. The two shells (pwa/approve.html, pwa/admin/admin.html) are public
// static assets that carry no data; the Worker reads them through the ASSETS
// binding inside the route handler and fills every `{{NAME}}` placeholder here
// — for the admin shell with the state the DO reported. Kept free of Worker/Hono
// types so it unit-tests as plain TypeScript (test/page.test.ts).

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
 * (ASSET_VER, the admin base) or `escapeJsonForHtml(...)` output.
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

// Where a cache-hit push lands: the admin shell on its audit tab (the ledger).
export const ADMIN_AUDIT_PATH = '/admin#audit';

// ── Placeholder values ────────────────────────────────────────────────────
//
// The Worker-owned chrome every shell needs. Passed in rather than imported so
// this builder stays pure and testable (ASSET_VER / FAVICON_TAGS live in
// index.ts, next to the routes that depend on them).
export interface PageChrome {
  assetVer: string;
  faviconTags: string;
}

// Placeholders common to both shells; each adds its own VT_DATA.
export function pageVars(chrome: PageChrome): Record<string, string> {
  return { FAVICON_TAGS: chrome.faviconTags, ASSET_VER: chrome.assetVer };
}
