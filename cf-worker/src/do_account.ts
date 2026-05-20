// AccountDO — singleton Durable Object managing all in-flight challenges.
//
// Storage keys:
//   ch:{approve_token}  →  Challenge JSON
//   pt:{poll_token}     →  approve_token (WS tag routing)
//   ib:{inbox_token}    →  approve_token
//
// WebSocket hibernation: WS clients connect via Worker GET /api/dek, which
// forwards to the DO. The DO hibernates the WS tagged with the poll_token so
// it wakes on the approval HTTP request.
//
// Alarm: sweeps challenges older than 5 minutes every 5 minutes.

import { DurableObject } from 'cloudflare:workers';
import { Env, Challenge, ApprovePageData, DoCreateOp, DoApproveOp, DoRejectOp, WsMessage } from './types';
import { b64uDec, b64uEnc } from './crypto';
import { parseCredentials, lookupByCredentialId } from './credentials';
import { verifyAssertion } from './webauthn';

const TTL_MS = 5 * 60 * 1000;

export class AccountDO extends DurableObject<Env> {
  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    // Schedule initial alarm if none set
    this.ctx.storage.getAlarm().then(a => {
      if (a == null) this.ctx.storage.setAlarm(Date.now() + TTL_MS);
    });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // WebSocket upgrade — client polls for DEK delivery
    if (request.headers.get('Upgrade') === 'websocket') {
      return this.handleWsUpgrade(url);
    }

    const op = url.pathname.split('/').pop();
    switch (op) {
      case 'create':  return this.opCreate(request);
      case 'approve': return this.opApprove(request);
      case 'reject':  return this.opReject(request);
      case 'page':    return this.opPageData(url);
      default:        return new Response('unknown op', { status: 400 });
    }
  }

  // ── WebSocket ──────────────────────────────────────────────────────────

  private async handleWsUpgrade(url: URL): Promise<Response> {
    const pollToken = url.searchParams.get('poll_token') ?? '';
    if (!pollToken) return new Response('missing poll_token', { status: 400 });

    // Look up approve_token for this poll_token
    const approveToken = await this.ctx.storage.get<string>(`pt:${pollToken}`);
    if (!approveToken) return new Response('unknown poll_token', { status: 404 });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    // Tag by poll_token so opApprove can wake the right WS
    this.ctx.acceptWebSocket(server, [`pt:${pollToken}`]);
    // Send initial "waiting" message immediately
    server.send(JSON.stringify({ status: 'waiting' } satisfies WsMessage));

    // If challenge already terminal (race: user approved before WS connected),
    // send the result now.
    const ch = await this.ctx.storage.get<Challenge>(`ch:${approveToken}`);
    if (ch) {
      if (ch.status === 'approved' && ch.sealed_deks_b64u) {
        server.send(JSON.stringify({ status: 'approved', sealed_deks_b64u: ch.sealed_deks_b64u } satisfies WsMessage));
        server.close(1000, 'approved');
      } else if (ch.status === 'rejected') {
        server.send(JSON.stringify({ status: 'rejected' } satisfies WsMessage));
        server.close(1000, 'rejected');
      } else if (ch.status === 'expired') {
        server.send(JSON.stringify({ status: 'expired' } satisfies WsMessage));
        server.close(1000, 'expired');
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(_ws: WebSocket, _message: string | ArrayBuffer): void {
    // No client-to-server messages expected; heartbeats are silently ignored.
  }

  webSocketClose(_ws: WebSocket, _code: number, _reason: string): void {}
  webSocketError(_ws: WebSocket, _error: unknown): void {}

  // ── Alarm — sweep expired challenges ───────────────────────────────────

  async alarm(): Promise<void> {
    const now = Date.now();
    const list = await this.ctx.storage.list<Challenge>({ prefix: 'ch:' });
    for (const [key, ch] of list) {
      if (ch.status === 'pending' && now - ch.created_ms >= TTL_MS) {
        ch.status = 'expired';
        await this.ctx.storage.put(key, ch);
        // Notify any waiting WS
        const wss = this.ctx.getWebSockets(`pt:${ch.poll_token}`);
        for (const ws of wss) {
          try { ws.send(JSON.stringify({ status: 'expired' } satisfies WsMessage)); ws.close(1000, 'expired'); } catch {}
        }
      }
    }
    // Reschedule
    await this.ctx.storage.setAlarm(Date.now() + TTL_MS);
  }

  // ── HTTP ops ──────────────────────────────────────────────────────────

  private async opCreate(request: Request): Promise<Response> {
    const { challenge } = await request.json() as DoCreateOp;
    await this.ctx.storage.put(`ch:${challenge.approve_token}`, challenge);
    await this.ctx.storage.put(`pt:${challenge.poll_token}`, challenge.approve_token);
    await this.ctx.storage.put(`ib:${challenge.inbox_token}`, challenge.approve_token);
    return new Response('ok');
  }

  private async opApprove(request: Request): Promise<Response> {
    const body = await request.json() as DoApproveOp;

    const ch = await this.ctx.storage.get<Challenge>(`ch:${body.approve_token}`);
    if (!ch) return new Response('not found', { status: 404 });
    if (ch.status !== 'pending') {
      // Idempotent re-delivery: if already approved return the existing sealed result
      if (ch.status === 'approved' && ch.sealed_deks_b64u) {
        return Response.json({ sealed_deks_b64u: ch.sealed_deks_b64u });
      }
      return new Response('challenge not pending', { status: 410 });
    }

    // Verify WebAuthn assertion
    let creds;
    try {
      creds = parseCredentials(this.env.CREDENTIALS_JSON);
    } catch (e) {
      console.error('credentials parse error:', e);
      return new Response('server error', { status: 500 });
    }
    const credId = b64uDec(body.credential_id_b64u);
    const entry = await lookupByCredentialId(creds, credId);
    if (!entry) return new Response('unknown credential', { status: 401 });

    const coseKey = b64uDec(entry.p);
    const challengeHash = b64uDec(ch.challenge_hash_b64u);
    try {
      await verifyAssertion({
        cosePublicKey: coseKey,
        clientDataJson: b64uDec(body.client_data_json_b64u),
        authenticatorData: b64uDec(body.authenticator_data_b64u),
        signature: b64uDec(body.signature_b64u),
        expectedChallenge: challengeHash,
        rpId: this.env.RP_ID,
      });
    } catch (e) {
      console.error('webauthn verify failed:', e);
      return new Response('assertion verification failed', { status: 401 });
    }

    // Mark approved and store sealed DEKs
    ch.status = 'approved';
    ch.sealed_deks_b64u = body.sealed_deks_b64u;
    await this.ctx.storage.put(`ch:${ch.approve_token}`, ch);

    // Wake waiting WS clients
    const wss = this.ctx.getWebSockets(`pt:${ch.poll_token}`);
    const wsMsg = JSON.stringify({ status: 'approved', sealed_deks_b64u: body.sealed_deks_b64u } satisfies WsMessage);
    for (const ws of wss) {
      try { ws.send(wsMsg); ws.close(1000, 'approved'); } catch {}
    }

    return Response.json({ sealed_deks_b64u: body.sealed_deks_b64u });
  }

  private async opReject(request: Request): Promise<Response> {
    const body = await request.json() as DoRejectOp;

    const ch = await this.ctx.storage.get<Challenge>(`ch:${body.approve_token}`);
    if (!ch) return new Response('not found', { status: 404 });
    if (ch.status !== 'pending') return new Response('challenge not pending', { status: 410 });

    // Verify WebAuthn assertion (reject also requires physical presence)
    let creds;
    try {
      creds = parseCredentials(this.env.CREDENTIALS_JSON);
    } catch {
      return new Response('server error', { status: 500 });
    }
    const credId = b64uDec(body.credential_id_b64u);
    const entry = await lookupByCredentialId(creds, credId);
    if (!entry) return new Response('unknown credential', { status: 401 });

    try {
      await verifyAssertion({
        cosePublicKey: b64uDec(entry.p),
        clientDataJson: b64uDec(body.client_data_json_b64u),
        authenticatorData: b64uDec(body.authenticator_data_b64u),
        signature: b64uDec(body.signature_b64u),
        expectedChallenge: b64uDec(ch.challenge_hash_b64u),
        rpId: this.env.RP_ID,
      });
    } catch {
      return new Response('assertion verification failed', { status: 401 });
    }

    ch.status = 'rejected';
    await this.ctx.storage.put(`ch:${ch.approve_token}`, ch);

    const wss = this.ctx.getWebSockets(`pt:${ch.poll_token}`);
    for (const ws of wss) {
      try { ws.send(JSON.stringify({ status: 'rejected' } satisfies WsMessage)); ws.close(1000, 'rejected'); } catch {}
    }

    return new Response('ok');
  }

  // Returns the data the approval page needs: challenge + credential info for allowCredentials.
  private async opPageData(url: URL): Promise<Response> {
    const approveToken = url.searchParams.get('approve_token') ?? '';
    if (!approveToken) return new Response('missing approve_token', { status: 400 });

    const ch = await this.ctx.storage.get<Challenge>(`ch:${approveToken}`);
    if (!ch) return new Response('not found', { status: 404 });
    if (ch.status !== 'pending') return new Response('challenge not pending', { status: 410 });

    let creds;
    try {
      creds = parseCredentials(this.env.CREDENTIALS_JSON);
    } catch {
      return new Response('server error', { status: 500 });
    }

    const pageData: ApprovePageData = {
      approve_token: approveToken,
      challenge_b64u: ch.challenge_hash_b64u,
      daemon_pubkey_b64u: ch.daemon_pubkey_b64u,
      salts_b64u: ch.salts_b64u,
      rp_id: this.env.RP_ID,
      allow_credentials: creds.c.map(e => ({ id_b64u: e.i, h_b64u: e.h, k_b64u: e.k })),
      metadata: ch.meta,
    };
    return Response.json(pageData);
  }
}
