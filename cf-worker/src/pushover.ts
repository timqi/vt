// Pushover notification delivery.

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

// Returns [status, body] on HTTP success; throws on transport error.
export async function sendPush(
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

export interface PushoverSecrets {
  appToken: string;
  userToken: string;
}

// Fire a Pushover notification. Returns an empty string on success or an error
// description on non-fatal failure (missing secrets, HTTP error, no devices).
export async function notifyApproval(
  secrets: PushoverSecrets | null,
  opKind: string,
  meta: { command: string; host: string; ip: string; reason: string },
  approveUrl: string,
): Promise<string> {
  if (!secrets) return 'missing Pushover secrets';

  const title = opKind ? `VT 审批: ${opKind}` : 'VT 审批请求';
  const lines: string[] = [];
  if (meta.command) lines.push(`cmd: ${meta.command}`);
  if (meta.host) lines.push(`host: ${meta.host}`);
  if (meta.ip) lines.push(`ip: ${meta.ip}`);
  if (meta.reason) lines.push(`reason: ${meta.reason}`);
  lines.push(approveUrl);
  const message = lines.join('\n');

  let status: number, body: string;
  try {
    [status, body] = await sendPush(secrets.appToken, secrets.userToken, title, message);
  } catch (e) {
    return `pushover transport error: ${e}`;
  }

  if (status < 200 || status >= 300) return `pushover http ${status}: ${body}`;
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(body); } catch { return `pushover invalid json: ${body}`; }
  if (parsed['status'] !== 1) return `pushover status != 1: ${body}`;
  const info = parsed['info'];
  if (typeof info === 'string' && info) return `pushover delivery warning: ${info}`;
  return '';
}
