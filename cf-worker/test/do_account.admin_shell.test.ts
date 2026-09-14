// The admin surface's two halves, over HTTP through the real router and the
// real ASSETS binding (wrangler.test.toml serves pwa/ like production):
//   • assets are public — pwa/admin/* is plain markup and script with no data,
//     so the shell's scripts load before any session exists;
//   • data is gated — the rendered shell (VT_DATA) and every /api/* route sit
//     behind Cloudflare Access, which wrangler.test.toml leaves unconfigured so
//     the gate fails closed.
import { describe, it, expect } from 'vitest';
import { SELF } from 'cloudflare:test';

const ORIGIN = 'https://vt.test.invalid';

describe('admin shell', () => {
  it('serves /pwa/admin/admin.js to anyone', async () => {
    const resp = await SELF.fetch(`${ORIGIN}/pwa/admin/admin.js`);
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Content-Type')).toMatch(/javascript/);
    expect(await resp.text()).toContain('vt.tabs = {}');
  });

  it('serves the shared stylesheet the approve page also loads', async () => {
    const resp = await SELF.fetch(`${ORIGIN}/pwa/admin/admin.css`);
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Content-Type')).toMatch(/text\/css/);
  });

  it('renders the shell (the only place VT_DATA appears) behind the gate', async () => {
    const resp = await SELF.fetch(`${ORIGIN}/kestrel`);
    expect(resp.status).toBe(403);
    expect(await resp.text()).not.toContain('vt-data');
  });

  it('points the manifest at the shell', async () => {
    const resp = await SELF.fetch(`${ORIGIN}/manifest.webmanifest`);
    expect(resp.status).toBe(200);
    expect((await resp.json() as { start_url: string }).start_url).toBe('/kestrel');
  });
});
