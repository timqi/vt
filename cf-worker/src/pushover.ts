// Pushover notification channel: config parsing + delivery.

function pctEncode(s: string): string {
  let out = '';
  for (const b of new TextEncoder().encode(s)) {
    if ((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) ||
        (b >= 0x30 && b <= 0x39) || b === 0x2d || b === 0x5f || b === 0x2e || b === 0x7e) {
      out += String.fromCharCode(b);
    } else {
      out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}

function buildFormBody(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${pctEncode(v)}`)
    .join('&');
}

export interface PushoverConfig {
  appToken: string;
  userKey: string;
}

// Parse the PUSHOVER_JSON secret. Returns {config:null,error:null} when the
// secret is absent (channel simply not enabled), {config:null,error:…} when it
// is present but malformed, and {config,error:null} on success.
export function parsePushoverConfig(raw: string | undefined): {
  config: PushoverConfig | null;
  error: string | null;
} {
  if (!raw || !raw.trim()) return { config: null, error: null };
  let obj: unknown;
  try { obj = JSON.parse(raw); } catch { return { config: null, error: 'invalid JSON' }; }
  if (typeof obj !== 'object' || obj === null) return { config: null, error: 'not an object' };
  const o = obj as Record<string, unknown>;
  const appToken = o['app_token'];
  const userKey = o['user_key'];
  if (typeof appToken !== 'string' || !appToken) return { config: null, error: 'missing app_token' };
  if (typeof userKey !== 'string' || !userKey) return { config: null, error: 'missing user_key' };
  return { config: { appToken, userKey }, error: null };
}

// Returns [status, body] on HTTP success; throws on transport error.
async function sendPush(
  appToken: string,
  userKey: string,
  title: string,
  message: string,
): Promise<[number, string]> {
  const body = buildFormBody({ token: appToken, user: userKey, title, message });
  const resp = await fetch('https://api.pushover.net/1/messages.json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const text = await resp.text();
  return [resp.status, text];
}

// Deliver one notification. Returns '' on success or a short error description
// on non-fatal failure (HTTP error, delivery warning, bad response).
export async function notifyPushover(
  config: PushoverConfig,
  title: string,
  body: string,
): Promise<string> {
  let status: number, text: string;
  try {
    [status, text] = await sendPush(config.appToken, config.userKey, title, body);
  } catch (e) {
    return `transport error: ${e}`;
  }
  if (status < 200 || status >= 300) return `http ${status}: ${text}`;
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(text); } catch { return `invalid json: ${text}`; }
  if (parsed['status'] !== 1) return `status != 1: ${text}`;
  const info = parsed['info'];
  if (typeof info === 'string' && info) return `delivery warning: ${info}`;
  return '';
}
