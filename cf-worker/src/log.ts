// Tiny structured logger — one JSON line per event so CF Logs can filter on
// the `event` field. Never log raw tokens, sealed bytes, or credential
// material; use tokenPrefix() for correlation.

export function log(event: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ event, ...fields }));
}

export function logErr(event: string, err: unknown, fields: Record<string, unknown> = {}): void {
  const e = err as { message?: string; stack?: string };
  console.error(JSON.stringify({
    event,
    err: e?.message ?? String(err),
    stack: e?.stack,
    ...fields,
  }));
}

// First 8 chars of a base64url token — enough to correlate requests in logs
// without persisting the full token (which grants access to the approval URL).
export function tokenPrefix(t: string | undefined | null): string {
  return typeof t === 'string' ? t.slice(0, 8) : '';
}
