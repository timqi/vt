// Slack notification channel (Incoming Webhook): config parsing + delivery.

// Bound the outbound webhook fetch — see pushover.ts (notifyApproval is awaited
// on the ceremony path, so a hung endpoint must not stall it indefinitely).
const NOTIFY_TIMEOUT_MS = 6000;

export interface SlackConfig {
  webhookUrl: string;
}

// Parse the SLACK_JSON secret. Same tri-state contract as parsePushoverConfig:
// absent → not enabled; present-but-bad → error; valid → config.
export function parseSlackConfig(raw: string | undefined): {
  config: SlackConfig | null;
  error: string | null;
} {
  if (!raw || !raw.trim()) return { config: null, error: null };
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { return { config: null, error: 'invalid JSON' }; }
  if (typeof obj !== 'object' || obj === null) return { config: null, error: 'not an object' };
  const url = (obj as Record<string, unknown>)['webhook_url'];
  if (typeof url !== 'string' || !url) return { config: null, error: 'missing webhook_url' };
  // Bind to Slack's webhook host so a misconfigured secret can't turn this into
  // an SSRF primitive that POSTs the approval payload to an arbitrary origin.
  let parsed: URL;
  try { parsed = new URL(url); } catch { return { config: null, error: 'webhook_url not a URL' }; }
  if (parsed.protocol !== 'https:') return { config: null, error: 'webhook_url must be https' };
  if (parsed.hostname !== 'hooks.slack.com') return { config: null, error: 'webhook_url must be on hooks.slack.com' };
  return { config: { webhookUrl: url }, error: null };
}

// Slack requires &, <, > escaped in message text; other mrkdwn chars are left
// as-is (close enough for an operator-facing approval notice).
function escapeSlack(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Deliver one notification via Incoming Webhook. Returns '' on success or a
// short error description on non-fatal failure.
export async function notifySlack(
  config: SlackConfig,
  title: string,
  body: string,
): Promise<string> {
  const text = `*${escapeSlack(title)}*\n${escapeSlack(body)}`;
  let resp: Response;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), NOTIFY_TIMEOUT_MS);
  try {
    resp = await fetch(config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: ctl.signal,
    });
  } catch (e) {
    return `transport error: ${e}`;
  } finally {
    clearTimeout(timer);
  }
  const respText = (await resp.text()).trim();
  // Don't echo the webhook response body into the logged warning; the status
  // code is enough to diagnose without surfacing endpoint internals.
  if (resp.status < 200 || resp.status >= 300) return `http ${resp.status}`;
  // A healthy Incoming Webhook returns the literal body "ok".
  if (respText !== 'ok') return 'unexpected response';
  return '';
}
