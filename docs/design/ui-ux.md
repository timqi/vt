# VT PWA — UI/UX contract

The presentation contract for `cf-worker/pwa/`: the approve shell and the
admin shell. Tags (`ported`, `changed`, `vt`) name each section's relation to
pier's `docs/design/06-ui-ux.md` (ported for the Worker slim; [worker-slim.md](../worker-slim.md)).
[approval-transparency.md](../approval-transparency.md) owns what an approval
shows and in which order and wins over this file. An explicit user requirement
wins over a convention; a changed convention updates this file.

## Hierarchy `ported`

- Rounded shapes, layered materials, natural transitions (iOS/macOS 26) within
  the web platform. Readability, clear state and responsive interaction first.
- Primary content (the request, the table) on stable reading surfaces;
  controls on lighter floating layers; metadata never competes with the decision.
- Hierarchy by spacing, size, placement and contrast — not opacity.
- Light and dark coherent; visible focus; status conveyed beyond color.

## Materials `ported`

- **Solid**: request fields, tables, cards, the detail dialog, the hovercard.
- **Glass + hairline + shadow**: the tab strip only. One token set — canvas
  one step darker than the panel, neutral translucent hairline (light in dark
  mode), top-edge highlight, two-part shadow (wide ambient + tight contact).
- Corner radii coordinate with nesting: 12px cards and dialog, 10px table
  frame and bars, 8px controls, 999px badges.
- One palette, the `admin.css` variables: `--bg --panel --panel-2 --fg --muted
  --accent --ok --err --warn --border --mono`. Light default, dark only on
  `prefers-color-scheme: dark`; `color-scheme: light dark` on both shells.
- Canvas: `--bg` is the page edge and the `theme-color` meta in both themes,
  including startup of the installed app.
- Type: system sans with `PingFang SC`; `--mono` for identifiers, paths and
  commands only.
- One shared stylesheet; `.vt-ap-*` and every control below exist once. No
  page-specific styles `vt`.

## Layout

- **Page head** `ported`: the tab strip is a slim 8px-inset rounded glass
  strip floating over the content, which pads its top by what covers it. On a
  phone it hides the title and wraps the tabs.
- **Tables** `vt`: a tab's `.table-wrap` owns horizontal scrolling; a long value
  truncates (`.trunc`, `.cell-main`/`.cell-sub`) and lives whole in the detail
  dialog or hovercard, never only in a `title`. Two lines per cell before a
  seventh column.
- **Detail dialog** `vt`: `#detail-card` in `#detail-backdrop`, solid, 680px
  max, `role="dialog" aria-modal="true"`, labeled close control, Escape and
  backdrop tap close without activating what is beneath, focus returns on
  dismissal. Below 640px the `dt`/`dd` grid stacks.
- Phone breakpoint 640px; the approve shell is one 420px column at every width.

## Approve shell `vt`

Used on a phone, one hand, under time pressure. Field set and order come from
[approval-transparency.md](../approval-transparency.md) §C; this adds presentation.

- Agent-derived truth lines precede every client-reported line; trust is in
  the label (`主机（已验证）`, `IP（已验证）`) and the footnote under the fields
  names what is client-reported, so a hostile caller pads only its own region.
- The pairing code (`.vt-ap-pair`) is the largest element on an enroll
  approval; nothing else on the page is bold monospace.
- The cache scope sentence (`缓存范围（项目）`) sits directly above the duration
  control; the first option is `不缓存` and is checked by default.
- `同意` is the primary fill at 2fr, `拒绝` the muted fill at 1fr, never below
  44px; both disable while a ceremony runs.
- One status line (`role="status" aria-live="polite"`) carries progress,
  success and error; errors name the cause in Chinese and never echo client data.
- Every await before `navigator.credentials.get` is resolved at load; iOS
  Safari drops the user gesture at the first real async boundary.
- A settled decision stays visible ≥ 800ms before the tab or dialog closes.
- The same `vt.mountApprove` renders inline in the audit dialog with
  `showMeta: false`; no second ceremony DOM.

## Audit rows `changed`

- Status is a text label plus a `.badge-*` class (`pending approved rejected
  expired`), never color or a glyph alone.
- Time is absolute (`YYYY-MM-DD HH:MM:SS`); relative (`fmtRemaining`) beside it
  when space allows, re-rendered on a ticker so it is never stale.
- Nothing that happened disappears: a cleared table says so, a truncated
  listing reports `truncated`, an extended row shows approved TTL and actual expiry.
- The live indicator has three states, text plus color: `● 实时` `● 同步中`
  `● 已断开`; a live update never disturbs an open dialog's mounted ceremony.
- A pending row opens its approval inline; every cache-armed row keeps its
  revoke button.

## Editing and forms `ported`

- Primary actions belong with the page head or the filter bar's right edge,
  destructive ones (`.danger`) grouped so they wrap together.
- Visible labels above controls, one grid (`.field`); filter controls share
  one height. Active filters are always discoverable.
- Background refreshes preserve input, focus, scroll and in-progress
  interactions. Long labels or paths never set the page's width (`overflow-wrap: anywhere`).
- Destructive actions confirm with native `confirm()` naming the effect
  (`此后解密将重新需要手机审批`); authority-granting controls (the bulk bar)
  appear only once something is selected `vt`.
- Secrets never round-trip through the page: configured state is a badge, not the value `vt`.

## Motion `ported`

- Brief, restrained, interruptible; explains feedback and spatial relations.
  No global suppression. Reuse existing easing and browser primitives.
- Logical state changes immediately even while a visual exit continues:
  closing controls stop accepting input; cleanup never leaves an invisible
  blocking layer; rapid reversals continue from the visible state.
- Animate deliberate changes, not stream pushes, refreshes or restored rows.
  Preserve the reader's position.
- Reduced motion: short fades, less movement. Reduced transparency / increased
  contrast: solid surfaces. Unsupported features fall back to instant changes
  keeping content, semantics and keyboard access.

## Foundations

- One source of truth `ported`: rows render from the API shapes; no parallel
  presentation records.
- Native controls and semantics, readable contrast, visible focus
  (`:focus-visible` outline in `--accent`), 44px touch targets `ported`.
- Icons `changed`: no icon set, no build step. A Unicode mark (`✓ ● ⚠️`)
  accompanies text and never replaces it; a control keeps its text or `aria-label`.
- CSP `vt`: `script-src 'self'; style-src 'self'` — no inline scripts, styles
  or handlers; DOM is built with `createElement`/`textContent`, positioning
  through CSSOM; page data enters only through the `#vt-data` JSON block.
- UI strings are Chinese; identifiers, status values, env names and CLI verbs
  stay verbatim in `code` `vt`.
- Safe areas (`viewport-fit=cover`) and software keyboards accounted for;
  content panels own scrolling; nothing scrolls the page horizontally `ported`.

## Shells and states `vt`

- **`pwa/approve.html`** at `/a/:token`: header, `#vt-approve-root`, the
  ceremony. Unchanged by the slim.
- **`pwa/admin/admin.html`** at `/admin` renders one of three states from
  `VT_DATA.state`: **setup** — the bootstrap form of worker-slim §3.3 (label,
  `vt secret export` blob + passphrase, one `注册并登录` action; a `409` shows
  the first registration's time and IP with the one-line reset hint; a
  `reset` flag warns that an unreadable configuration will be replaced);
  **login** — one primary button `使用 Passkey 登录` and the status line;
  **console** — the tab strip 审计 · DEK 缓存 · 主机令牌 · Passkey · 设置, tab
  in the URL hash (`/admin#audit`), first tab default.
- 审计: filter bar, table, `加载更多`, live indicator, detail dialog with
  inline approval. DEK 缓存: filter bar, bulk bar, table, extend dialog.
  主机令牌: filter bar, table with per-row `吊销`. Passkey: current list,
  segmented `新增 / 吊销`, `自检`. 设置: session (`退出登录`, `退出所有会话`),
  caching and hit-notify switches, UV policy JSON, push subscriptions
  (`开启推送`, per-row test/remove).
- A `401` on any admin request returns the shell to the login state with the
  reason on the status line; the console never renders on stale data.

## Shared controls — one implementation each `vt`

| Control | Where |
| --- | --- |
| Tab strip, page head | `admin.js` |
| `.hint`, `.warn`, `.card`/`.card-head`, `.field` | `admin.css` |
| Buttons: primary, `.ghost`, `.danger`, `.small` | `admin.css` |
| `.badge`, `.badge-*`, `.reason-badge` | `admin.css` |
| `.switch`, segmented `#modes` | `admin.css` |
| Filter bar, `#bulkbar`, table + `.trunc`/`.cell-*` | `admin.css` |
| Detail dialog (`vt.dialog`), hovercard (`vt.hovercard`), `vt.commandSummary`, `vt.api` | `admin.js` |
| Status line: `vt.statusLine(el)` returns the tab's `setStatus` | `common.js` |
| `fmtTime`, `fmtRemaining`, `ttlLabel`, `el` | `common.js` (`vt.*`) |
| Passkey ceremony | `approve.js` (`vt.mountApprove`) |

A second copy of any row is a bug (AGENTS.md Budgets rule 3).

## Validation `ported`

- Exercise normal use, failure, cancellation, expiry (`410`), loading,
  reconnection; keyboard, pointer, touch; 375px and 1000px; light and dark;
  reduced motion and transparency. Check rapid interaction and real hit
  targets — screenshots alone do not establish correctness.
- Isolated mock data only; never a real approval, host token or production Worker.
- Report actual browser coverage (glass, dialogs, WebAuthn, native controls).
  Chromium emulation is not Safari / iOS; the installed PWA on an iPhone is
  the target. Record gaps and fix them within the affected controls.
