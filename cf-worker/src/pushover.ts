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

// Truncate untrusted strings before they're surfaced upstream.
function truncate(s: string, max = 256): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

// Fire a Pushover notification. Returns an empty string on success or an error
// description on non-fatal failure (missing secrets, HTTP error, no devices).
export async function notifyApproval(
  secrets: PushoverSecrets | null,
  opKind: string,
  meta: {
    command: string;
    host: string;
    user?: string;
    pwd?: string;
    ssh_client?: string;
    ip: string;
    reason: string;
  },
  approveUrl: string,
): Promise<string> {
  if (!secrets) return truncate('missing Pushover secrets');

  const title = opKind ? `VT 审批: ${opKind}` : 'VT 审批请求';
  const who = [meta.user, meta.host].filter(Boolean).join('@');
  const lines: string[] = [];
  if (who) lines.push(who);
  if (meta.pwd) lines.push(`pwd: ${meta.pwd}`);
  if (meta.command) {
    // The CLI now sends `command` as a self-labelled multi-line body
    // (`op: …\nfile: …\ncmd: …\nreason: …`); prefixing with another `cmd:`
    // would just duplicate the labels. Inline single-line legacy commands.
    lines.push(meta.command.includes('\n') ? meta.command : `cmd: ${meta.command}`);
  }
  if (meta.ssh_client) lines.push(`ssh: ${meta.ssh_client}`);
  if (meta.ip) lines.push(`ip: ${meta.ip}`);
  if (meta.reason) lines.push(`reason: ${meta.reason}`);
  lines.push(approveUrl);
  const message = lines.join('\n');

  let status: number, body: string;
  try {
    [status, body] = await sendPush(secrets.appToken, secrets.userToken, title, message);
  } catch (e) {
    return truncate(`pushover transport error: ${e}`);
  }

  if (status < 200 || status >= 300) return truncate(`pushover http ${status}: ${body}`);
  let parsed: Record<string, unknown>;
  try { parsed = JSON.parse(body); } catch { return truncate(`pushover invalid json: ${body}`); }
  if (parsed['status'] !== 1) return truncate(`pushover status != 1: ${body}`);
  const info = parsed['info'];
  if (typeof info === 'string' && info) return truncate(`pushover delivery warning: ${info}`);
  return '';
}
