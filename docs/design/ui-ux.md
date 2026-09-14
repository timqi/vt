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

## Materials `vt` (Liquid Glass, macOS/iOS 26)

- Three layers, no fourth: **canvas** (`--bg`, solid), **content** (cards,
  tables, dialog, sheet — solid `--panel`), **chrome** (glass: the tab bar, the
  approve action bar, segmented controls, floating buttons). Content is never
  glass; readability wins.
- Glass token, one class `.glass`: `backdrop-filter: blur(20px) saturate(180%)`
  over a translucent `--panel` tint, 1px translucent hairline, top-edge
  specular highlight (`inset 0 1px 0 rgba(255,255,255,.35)`, weaker in dark),
  two-part shadow (wide ambient + tight contact). Under
  `prefers-reduced-transparency` or without `backdrop-filter` support it is
  solid `--panel` with the same hairline.
- Concentric radii: a nested radius equals the container's minus the padding.
  Cards and sheets 20px, bars and segmented controls 16px, controls 12px,
  badges 999px. Chrome that floats keeps a full-height pill shape.
- Colors via `light-dark()` and `color-mix()`; one palette, the `admin.css`
  variables `--bg --panel --panel-2 --fg --muted --accent --ok --err --warn
  --border --mono`; `color-scheme: light dark` on both shells. Accent tints
  glass (`color-mix(in oklab, var(--accent) 12%, var(--panel))`) only on the
  selected segment and the primary action.
- Canvas: `--bg` is the page edge and the `theme-color` meta in both themes,
  including startup of the installed app.
- Type: `-apple-system, system-ui` with `PingFang SC`; sizes from the iOS
  scale (34/28/22 titles, 17 body, 15 secondary, 13 caption); `--mono` for
  identifiers, paths and commands only.
- One shared stylesheet; `.vt-ap-*`, `.glass` and every control below exist
  once. No page-specific styles.

## Layout `vt`

- **Phone first** (< 768px): the admin tab bar is a bottom glass pill inset
  by 12px and `env(safe-area-inset-bottom)`, five items, label under mark;
  it shrinks to marks only while the content scrolls down and restores on
  scroll up or stop. The page head is the tab's title only. On desktop
  (≥ 768px) the same strip floats at the top, 8px inset, title at its left.
- **Rows, not tables, on a phone**: each list renders as `.row` items — first
  line the identity (host, record name), second line the secondary facts
  (`.cell-sub`), trailing status badge or remaining time. Tables (`.table-wrap`,
  `.trunc`, `.cell-main`/`.cell-sub`) appear at ≥ 768px only. Both render from
  the same data and the same click handler; a long value lives whole in the
  detail sheet, never only in a `title`.
- **Detail sheet** (`vt.dialog`): native `<dialog>`; on a phone a bottom sheet
  with a grab handle, rounded top 20px, max 92vh, scrolls inside, dismissed by
  the close control, Escape, backdrop tap or swipe down; on desktop a centered
  680px solid card. `aria-modal`, labeled close, focus returns on dismissal.
  The `dt`/`dd` grid stacks below 640px.
- Content pads for what floats over it (bottom bar height + safe area on a
  phone, strip height on desktop); nothing hides under chrome.

## Approve shell `vt`

Used on a phone, one hand, under time pressure. Field set and order come from
[approval-transparency.md](../approval-transparency.md) §C; this adds presentation.

- One solid card, 420px column at every width. The decision line is first and
  largest (22px): the operation and the record count (`decrypt · 记录 3 条`);
  the record names sit directly under it at body size (server-owned first,
  read-only; an unnamed record is a 44px name input `.vt-ap-name` (`记录名`,
  40 chars) beside a `.chip` `客户端称 X` that fills it in one tap; inputs are
  read at the 同意 tap, so they never sit between the gesture and the
  ceremony); then
  `主机（已验证）@用户` and 命令. Everything else sits in a closed `<details>`
  详情 (目录, 项目, 父进程, IP with 上次, 原因).
- Agent-derived truth lines precede every client-reported line; trust is in
  the label (`主机（已验证）`, `IP（已验证）`) and the footnote under the fields
  names what is client-reported, so a hostile caller pads only its own region.
- The pairing code (`.vt-ap-pair`) is the largest element on an enroll
  approval; nothing else on the page is bold monospace.
- The cache scope sentence (`缓存范围（项目）`) sits directly above the duration
  control, a glass segmented control; the first option is `不缓存` and is
  selected by default.
- `同意` and `拒绝` live in a bottom glass action bar (`.vt-ap-bar`) above the
  safe area: `同意` primary fill at 2fr, `拒绝` muted at 1fr, 50px tall; both
  disable while a ceremony runs. The card pads its bottom by the bar. Inline in
  the sheet the same bar sticks to the sheet's bottom.
- One status line (`role="status" aria-live="polite"`) sits in the bar above
  the buttons, so progress, success and error stay in view while the card
  scrolls; errors name the cause in Chinese and never echo client data.
- Every await before `navigator.credentials.get` is resolved at load; iOS
  Safari drops the user gesture at the first real async boundary.
- A settled decision stays visible ≥ 800ms before the tab or dialog closes.
- The same `vt.mountApprove` renders inline in the audit sheet with
  `showMeta: false`; no second ceremony DOM.

## Audit rows `changed`

- Status is a text label plus a `.badge-*` class (`pending approved rejected
  expired`), never color or a glyph alone.
- Time is absolute (`YYYY-MM-DD HH:MM:SS`); relative (`fmtRemaining`) beside it
  when space allows, re-rendered on a ticker so it is never stale.
- Nothing that happened disappears: the audit table is never cleared (retention
  only), a truncated listing reports `truncated`, an extended row shows approved
  TTL and actual expiry.
- The live indicator has three states, text plus color: `● 实时` `● 同步中`
  `● 已断开`; a live update never disturbs an open dialog's mounted ceremony.
- A pending row opens its approval inline; every cache-armed row links to the
  DEK 缓存 tab filtered to its 主机 · 项目 (`查看缓存 →`) — the audit tab
  revokes nothing.

## Editing and forms `ported`

- Primary actions belong with the page head or the filter bar's right edge,
  destructive ones (`.danger`) grouped so they wrap together.
- Visible labels above controls, one grid (`.field`); filter controls share
  one height. A `<select>` is always wrapped in `.select` (the markup emits
  the span; no script wraps it) so it carries the control skin and a drawn
  chevron while the popup stays native. Active filters are always discoverable.
- Background refreshes preserve input, focus, scroll and in-progress
  interactions. Long labels or paths never set the page's width (`overflow-wrap: anywhere`).
- Destructive actions confirm with native `confirm()` naming the effect
  (`此后解密将重新需要手机审批`); authority-granting controls (the bulk bar)
  appear only once something is selected `vt`.
- Secrets never round-trip through the page: configured state is a badge, not the value `vt`.

## Motion `vt`

- One easing `cubic-bezier(.2,.8,.2,1)`, 200ms (sheet 280ms); only
  `transform` and `opacity` animate — never `backdrop-filter`, size or layout.
- Brief, restrained, interruptible; explains feedback and spatial relations:
  the sheet rises from the bottom, the tab bar shrinks in place, a selected
  segment slides. Nothing animates on stream pushes, refreshes or restored rows.
- Logical state changes immediately even while a visual exit continues:
  closing controls stop accepting input; cleanup never leaves an invisible
  blocking layer; rapid reversals continue from the visible state.
- Reduced motion: opacity fades ≤ 120ms, no movement. Reduced transparency /
  increased contrast: solid surfaces. Unsupported features fall back to
  instant changes keeping content, semantics and keyboard access.

## Foundations

- One source of truth `ported`: rows render from the API shapes; no parallel
  presentation records.
- Native controls and semantics, readable contrast, visible focus
  (`:focus-visible` outline in `--accent`), 44px touch targets `ported`.
- Icons `vt`: no icon set, no build step. Tab marks are single Unicode
  glyphs (text, `currentColor`); elsewhere a mark (`✓ ● ⚠️`) accompanies text
  and never replaces it; a control keeps its text or `aria-label`.
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
- 审计: filter bar, list/table (时间 / 状态 / 主机 / 项目 / 记录 / 缓存 / 操作;
  项目 is the directory name, `vt.projectName`, the path in the sheet),
  `加载更多` with `已加载 N 条`, live indicator, detail sheet with inline
  approval and record rename. DEK 缓存: filter bar (主机 / 项目, filled by
  `#cache?host=…&project=…`), list/table of live entries (记录 / 剩余 · 到期)
  under collapsible `.group-head` rows (主机 · 项目, checkbox selects the
  project), bulk bar (延长 · 撤销), entry sheet, extend sheet. A record name
  is a control (`vt.recordList`): click → input, Enter saves, Escape/blur
  cancels. 主机令牌: filter bar, list/table with per-row `吊销`. Passkey:
  current list/table (标签 / 凭据 ID / 注册日期), segmented `新增 / 吊销`,
  `自检`. 设置: session (`退出登录`, `退出所有会话`), hit-notify switch, UV
  policy JSON, push subscriptions list/table (`开启推送`, per-row test/remove).
- A `401` on any admin request returns the shell to the login state with the
  reason on the status line; the console never renders on stale data.

## Shared controls — one implementation each `vt`

| Control | Where |
| --- | --- |
| Tab bar (bottom pill / top strip), page head | `admin.js` |
| `.hint`, `.warn`, `.card`/`.card-head`, `.field` | `admin.css` |
| Buttons: primary, `.ghost`, `.danger`, `.small` | `admin.css` |
| `.badge`, `.badge-*`, `.reason-badge` | `admin.css` |
| `.glass`, `.switch`, segmented control (`.seg`; its sliding thumb `vt.seg`) | `admin.css`, `common.js` |
| `.select` (a `span` around every native `<select>`: CSS chevron, ring on the wrapper), `.chip` | `admin.css` |
| Filter bar, `#bulkbar`, `.row` list + table + `.trunc`/`.cell-*`, `.group-head`, `.cache-link` | `admin.css` |
| Row/table switch: `vt.phone`, `vt.onLayout`, `vt.list(wrap)` (`item({cells, row})`, `body`, `clear`, `empty`) | `admin.js` |
| Detail sheet (`vt.dialog`), hovercard (`vt.hovercard`), `vt.commandSummary`, `vt.api` | `admin.js` |
| Status line: `vt.statusLine(el)` returns the tab's `setStatus` | `common.js` |
| `fmtTime`, `fmtRemaining`, `ttlLabel`, `el` | `common.js` (`vt.*`) |
| Passkey ceremony | `approve.js` (`vt.mountApprove`) |
| Record names: `vt.recordLabel` (name, `X（自报）`, else salt prefix in `code`), `vt.recordsSummary`, renameable `vt.recordList`; `vt.projectName` | `admin.js` |

A second copy of any row is a bug (AGENTS.md Budgets rule 3).

## Validation `ported`

- Exercise normal use, failure, cancellation, expiry (`410`), loading,
  reconnection; keyboard, pointer, touch; 375px and 1000px; light and dark;
  reduced motion and transparency; installed (standalone) and in-browser on
  iOS — the bottom bar, safe areas and the sheet's swipe differ. Check rapid interaction and real hit
  targets — screenshots alone do not establish correctness.
- Isolated mock data only; never a real approval, host token or production Worker.
- Report actual browser coverage (glass, dialogs, WebAuthn, native controls).
  Chromium emulation is not Safari / iOS; the installed PWA on an iPhone is
  the target. Record gaps and fix them within the affected controls.
