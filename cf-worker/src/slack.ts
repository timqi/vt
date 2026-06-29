// Slack notification channel (Incoming Webhook): config parsing + delivery.

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
  let host: string;
  try { host = new URL(url).hostname; } catch { return { config: null, error: 'webhook_url not a URL' }; }
  if (host !== 'hooks.slack.com') return { config: null, error: 'webhook_url must be on hooks.slack.com' };
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
  try {
    resp = await fetch(config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
  } catch (e) {
    return `transport error: ${e}`;
  }
  const respText = (await resp.text()).trim();
  if (resp.status < 200 || resp.status >= 300) return `http ${resp.status}: ${respText}`;
  // A healthy Incoming Webhook returns the literal body "ok".
  if (respText !== 'ok') return `unexpected response: ${respText}`;
  return '';
}
