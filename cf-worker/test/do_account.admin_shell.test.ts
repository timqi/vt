// The admin surface's two halves, over HTTP through the real router and the
// real ASSETS binding (wrangler.test.toml serves pwa/ like production):
//   • assets are public — pwa/admin/* is plain markup and script with no data,
//     so the shell's scripts load before any session exists;
//   • data is gated — the rendered shell reports setup / login / console for
//     THIS request's cookie, and every /api/admin/* route sits behind the
//     session the DO verifies.
import { describe, it, expect } from 'vitest';
import { SELF } from 'cloudflare:test';
import { adminHeaders, bootstrap, inDO, makeChallenge } from './do_helpers';

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

  // The approval page's first paint hangs off this one: a 404 here is a blank
  // page for as long as the big stylesheet takes to arrive.
  it('serves the approve page boot stylesheet', async () => {
    const resp = await SELF.fetch(`${ORIGIN}/pwa/boot.css`);
    expect(resp.status).toBe(200);
    expect(resp.headers.get('Content-Type')).toMatch(/text\/css/);
    expect(await resp.text()).toContain('.vt-boot');
  });

  it('renders setup before bootstrap, then login without a cookie and console with one', async () => {
    const setup = await SELF.fetch(`${ORIGIN}/admin`);
    expect(setup.status).toBe(200);
    expect(setup.headers.get('Content-Security-Policy')).toContain("script-src 'self'");
    const setupHtml = await setup.text();
    expect(setupHtml).toContain('"state":"setup"');
    expect(setupHtml).toContain('"rp_id":"vt.test.invalid"');
    expect(setupHtml).toContain('"reset":false');

    await bootstrap();
    const login = await SELF.fetch(`${ORIGIN}/admin`);
    expect(await login.text()).toContain('"state":"login"');
    const console_ = await SELF.fetch(`${ORIGIN}/admin`, { headers: adminHeaders() });
    expect(await console_.text()).toContain('"state":"console"');
  });

  it('answers 404 for an unknown admin op and 503 on data routes before bootstrap', async () => {
    expect((await SELF.fetch(`${ORIGIN}/api/admin/nope`)).status).toBe(404);
    const tokens = await SELF.fetch(`${ORIGIN}/api/admin/tokens`);
    expect(tokens.status).toBe(503);
    expect(await tokens.json()).toEqual({ error: 'not_configured' });
    const page = await SELF.fetch(`${ORIGIN}/a/sometoken12345`);
    expect(page.status).toBe(503);
    await page.text();
  });

  // W-11: ceremony data is never cacheable, as HTML or as JSON.
  it('serves the approval page and its JSON twin with no-store', async () => {
    await bootstrap();
    const ch = makeChallenge();
    await inDO(({ state }) => state.storage.put(`ch:${ch.approve_token}`, ch));
    const page = await SELF.fetch(`${ORIGIN}/a/${ch.approve_token}`);
    expect(page.status).toBe(200);
    expect(page.headers.get('Cache-Control')).toBe('no-store');
    await page.text();
    const json = await SELF.fetch(`${ORIGIN}/api/page/${ch.approve_token}`);
    expect(json.status).toBe(200);
    expect(json.headers.get('Cache-Control')).toBe('no-store');
    await json.text();
    const shell = await SELF.fetch(`${ORIGIN}/admin`);
    expect(shell.headers.get('Cache-Control')).toBe('no-store');
    await shell.text();
  });

  it('points the manifest at the shell', async () => {
    const resp = await SELF.fetch(`${ORIGIN}/manifest.webmanifest`);
    expect(resp.status).toBe(200);
    expect((await resp.json() as { start_url: string }).start_url).toBe('/admin');
  });
});
