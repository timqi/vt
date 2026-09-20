# PWA interaction principles

The PWA lets a person make an informed approval on a phone and inspect or revoke
standing authority in the admin console. Decision clarity takes priority over
visual effects. [Approval transparency](../approval-transparency.md) owns trust
labels and required decision information.

## Visual hierarchy

- Keep primary content on stable, readable surfaces; reserve translucent
  materials for controls and navigation.
- Establish hierarchy through placement, spacing, size, and contrast; metadata
  must not compete with the decision.
- Light/dark themes, visible focus, and text status must remain coherent;
  color or icons alone cannot convey meaning.
- CSS tokens, dimensions, and component classes belong in
  [admin.css](../../cf-worker/pwa/admin/admin.css), not a parallel specification.
- The approval page paints a loading state from the small render-blocking
  [boot.css](../../cf-worker/pwa/boot.css) and promotes admin.css afterwards; a
  slow network must never show a blank page or an unstyled ceremony.

## Phone use

- Approval must work one-handed under time pressure; keep the decision, scope,
  duration, status, and actions reachable without hunting through metadata.
- Give enrollment's pairing code visual priority.
- Lists must remain readable on narrow screens; full values belong in an
  accessible detail view, never only a hover tooltip.
- Floating controls, safe areas, and software keyboards must not hide content
  or actions; long paths cannot force horizontal page scrolling.
- Keep touch targets usable, text readable, and dialogs dismissible by keyboard
  and touch; return focus to the invoking control.

## Interaction

- Background updates preserve input, focus, scroll, selection, and active
  approval ceremonies.
- Disable duplicate submissions while an operation is pending; show progress,
  success, and actionable failure where the user is looking.
- Complete prerequisites before invoking WebAuthn from a user gesture;
  asynchronous work must not consume Safari's gesture allowance.
- Confirm destructive actions with their concrete effect. An unconfirmed or
  failed revocation must not appear successful.
- Expired sessions return to login; cached console data must not imply current
  authorization.
- Configured secrets are represented by state, not echoed back as values.
- UI text is English; technical identifiers retain their spelling.

## Motion and accessibility

Motion explains a state change and remains brief, interruptible, and compatible
with rapid reversal. Background refreshes do not animate unrelated content.
Logical state changes immediately; a visual exit must not leave an invisible
blocking layer.

Respect reduced motion, reduced transparency, and increased contrast. Unsupported
visual effects fall back without losing content, semantics, or keyboard access.
Use native controls, visible labels, and announced status/error messages.

## Validation

Exercise normal use, failure, cancellation, expiry, reconnect, and rapid repeated
input with keyboard and touch, narrow/wide layouts, both themes, and accessibility
preferences. Screenshots alone do not verify behavior.

Use isolated mock data. Report actual browser coverage; Chromium emulation does
not establish Safari/iOS behavior. Verify the installed iPhone PWA's safe areas,
WebAuthn gestures, and notification navigation on the device.

Shared interaction code lives in [common.js](../../cf-worker/pwa/common.js),
[approve.js](../../cf-worker/pwa/approve.js), and
[admin.js](../../cf-worker/pwa/admin/admin.js).
