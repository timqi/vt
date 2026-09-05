import { describe, it, expect, vi } from 'vitest';
import { AccountNotifications } from '../src/account_notifications';
import * as feishu from '../src/feishu';
import * as slackApp from '../src/slack_app';
import * as notify from '../src/notify';
import type { Challenge, Env, DoAuditIngestOp } from '../src/types';
import { inDO, makeChallenge, makeMeta } from './do_helpers';

const FEISHU_JSON = JSON.stringify({
  app_id: 'test-app', app_secret: 'synthetic-test-value', receive_id: 'test-user',
});
const SLACK_APP_JSON = JSON.stringify({ bot_token: 'synthetic-test-value', channel: 'test-channel' });

async function withNotifications(
  test: (h: {
    notifications: AccountNotifications;
    state: DurableObjectState;
    vars: Env;
    tasks: Promise<unknown>[];
    feishuSend: ReturnType<typeof vi.spyOn<typeof feishu, 'sendApprovalCard'>>;
    slackSend: ReturnType<typeof vi.spyOn<typeof slackApp, 'sendApprovalCard'>>;
    feishuEdit: ReturnType<typeof vi.spyOn<typeof feishu, 'editCard'>>;
    slackEdit: ReturnType<typeof vi.spyOn<typeof slackApp, 'editCard'>>;
    statelessHit: ReturnType<typeof vi.spyOn<typeof notify, 'notifyCacheHit'>>;
    feishuHit: ReturnType<typeof vi.spyOn<typeof feishu, 'sendCacheHitNotice'>>;
    slackHit: ReturnType<typeof vi.spyOn<typeof slackApp, 'sendCacheHitNotice'>>;
  }) => Promise<void> | void,
): Promise<void> {
  await inDO(async ({ inst, state }) => {
    const tasks: Promise<unknown>[] = [];
    const vars: Env = { ...inst.env, FEISHU_JSON, SLACK_APP_JSON, CACHE_HIT_NOTIFY: '' };
    const notifications = new AccountNotifications({
      storage: state.storage, waitUntil(task: Promise<unknown>) { tasks.push(task); },
    }, vars);
    const feishuSend = vi.spyOn(feishu, 'sendApprovalCard').mockResolvedValue('test-message');
    const slackSend = vi.spyOn(slackApp, 'sendApprovalCard').mockResolvedValue({ channel: 'test-channel', ts: '1.0' });
    const feishuEdit = vi.spyOn(feishu, 'editCard').mockResolvedValue('');
    const slackEdit = vi.spyOn(slackApp, 'editCard').mockResolvedValue('');
    const statelessHit = vi.spyOn(notify, 'notifyCacheHit').mockResolvedValue('');
    const feishuHit = vi.spyOn(feishu, 'sendCacheHitNotice').mockResolvedValue('');
    const slackHit = vi.spyOn(slackApp, 'sendCacheHitNotice').mockResolvedValue('');
    try {
      await test({
        notifications, state, vars, tasks, feishuSend, slackSend,
        feishuEdit, slackEdit, statelessHit, feishuHit, slackHit,
      });
      await Promise.all(tasks);
    } finally {
      vi.restoreAllMocks();
    }
  });
}

describe('AccountNotifications delivery contract', () => {
  it('serializes reference writes and follows a decision that raced ahead of sending', async () => {
    await withNotifications(async ({ notifications, state, tasks, feishuSend, slackSend, feishuEdit, slackEdit }) => {
      const ch = makeChallenge();
      await state.storage.put(`ch:${ch.approve_token}`, ch);
      let finishSend!: (id: string) => void;
      feishuSend.mockImplementationOnce(() => new Promise(resolve => { finishSend = resolve; }));
      notifications.approval(ch);
      expect(tasks).toHaveLength(1);
      expect(feishuSend).toHaveBeenCalledOnce();
      expect(slackSend).not.toHaveBeenCalled();
      const approved: Challenge = {
        ...ch, status: 'approved', finalized_ms: ch.created_ms + 123,
        sealed_deks_b64u: 'synthetic-sealed-result', pwa_pk_b64u: 'synthetic-public-key',
        binding_tag_b64u: 'synthetic-binding-tag',
      };
      await state.storage.put(`ch:${ch.approve_token}`, approved);
      finishSend('test-message');
      await Promise.all(tasks);
      expect(slackSend).toHaveBeenCalledOnce();
      expect(await state.storage.get(`ch:${ch.approve_token}`)).toEqual({
        ...approved, feishu_message_id: 'test-message', slackapp: { channel: 'test-channel', ts: '1.0' },
      });
      expect(feishuEdit.mock.calls[0]![4]).toBe('approved');
      expect(slackEdit.mock.calls[0]![2]).toBe('approved');
      expect(state.storage.sql.exec('SELECT * FROM audit').toArray()).toEqual([]);
    });
  });

  it.each(['feishu', 'slackapp'] as const)('merges only the %s reference into the latest terminal challenge', async (channel) => {
    await withNotifications(async ({ notifications, state, vars, tasks, feishuSend, slackSend, feishuEdit, slackEdit }) => {
      if (channel === 'feishu') vars.SLACK_APP_JSON = '';
      else vars.FEISHU_JSON = '';
      const ch = makeChallenge({
        feishu_message_id: 'previous-feishu', slackapp: { channel: 'previous-channel', ts: '0.0' },
      });
      const key = `ch:${ch.approve_token}`;
      await state.storage.put(key, ch);
      let finishSend!: () => void;
      if (channel === 'feishu') {
        feishuSend.mockImplementationOnce(() => new Promise(resolve => {
          finishSend = () => resolve('test-message');
        }));
      } else {
        slackSend.mockImplementationOnce(() => new Promise(resolve => {
          finishSend = () => resolve({ channel: 'test-channel', ts: '1.0' });
        }));
      }
      notifications.approval(ch);
      const latest: Challenge = {
        ...ch, status: 'rejected', finalized_ms: ch.created_ms + 456,
        meta: { ...ch.meta, command: 'latest command', host: 'latest-host' },
      };
      await state.storage.put(key, latest);
      finishSend();
      await Promise.all(tasks);
      const reference = channel === 'feishu'
        ? { feishu_message_id: 'test-message' }
        : { slackapp: { channel: 'test-channel', ts: '1.0' } };
      expect(await state.storage.get(key)).toEqual({ ...latest, ...reference });
      if (channel === 'feishu') {
        expect(slackEdit).not.toHaveBeenCalled();
        expect(feishuEdit).toHaveBeenCalledOnce();
        expect(feishuEdit.mock.calls[0]!.slice(4)).toEqual([
          'rejected', latest.meta.op_kind, latest.meta, { latencyMs: 456 }, latest.salts_b64u.length,
        ]);
      } else {
        expect(feishuEdit).not.toHaveBeenCalled();
        expect(slackEdit).toHaveBeenCalledOnce();
        expect(slackEdit.mock.calls[0]!.slice(2)).toEqual([
          'rejected', latest.meta.op_kind, latest.meta, { latencyMs: 456 }, latest.salts_b64u.length,
        ]);
      }
    });
  });

  it.each([
    ['feishu', 'get'], ['feishu', 'put'], ['slackapp', 'get'], ['slackapp', 'put'],
  ] as const)('isolates %s reference %s failures from the sibling channel', async (channel, operation) => {
    await withNotifications(async ({ notifications, state, tasks, feishuSend, slackSend, feishuEdit, slackEdit }) => {
      const ch = makeChallenge();
      const key = `ch:${ch.approve_token}`;
      await state.storage.put(key, ch);
      const failReference = () => {
        vi.spyOn(state.storage, operation).mockRejectedValueOnce(new Error(`synthetic reference ${operation} failure`));
      };
      if (channel === 'feishu') {
        feishuSend.mockImplementationOnce(async () => { failReference(); return 'test-message'; });
      } else {
        slackSend.mockImplementationOnce(async () => {
          failReference();
          return { channel: 'test-channel', ts: '1.0' };
        });
      }
      notifications.approval(ch);
      await expect(Promise.all(tasks)).resolves.toBeDefined();
      expect(feishuSend).toHaveBeenCalledOnce();
      expect(slackSend).toHaveBeenCalledOnce();
      const siblingReference = channel === 'feishu'
        ? { slackapp: { channel: 'test-channel', ts: '1.0' } }
        : { feishu_message_id: 'test-message' };
      expect(await state.storage.get(key)).toEqual({ ...ch, ...siblingReference });
      expect(feishuEdit).not.toHaveBeenCalled();
      expect(slackEdit).not.toHaveBeenCalled();
    });
  });

  it('does not block the sibling channel when one send fails', async () => {
    await withNotifications(async ({ notifications, state, tasks, feishuSend, slackSend }) => {
      const ch = makeChallenge();
      await state.storage.put(`ch:${ch.approve_token}`, ch);
      feishuSend.mockRejectedValueOnce(new Error('synthetic send failure'));
      notifications.approval(ch);
      await expect(Promise.all(tasks)).resolves.toBeDefined();
      expect(slackSend).toHaveBeenCalledOnce();
      expect(await state.storage.get(`ch:${ch.approve_token}`)).toEqual({
        ...ch, slackapp: { channel: 'test-channel', ts: '1.0' },
      });
    });
  });

  it.each(['feishu', 'slackapp'] as const)('never recreates a challenge swept while %s delivery was pending', async (channel) => {
    await withNotifications(async ({ notifications, state, tasks, feishuSend, slackSend, feishuEdit, slackEdit }) => {
      const ch = makeChallenge();
      await state.storage.put(`ch:${ch.approve_token}`, ch);
      let finishSend!: () => void;
      let markStarted!: () => void;
      const sendStarted = new Promise<void>(resolve => { markStarted = resolve; });
      if (channel === 'feishu') {
        feishuSend.mockImplementationOnce(() => new Promise(resolve => {
          finishSend = () => resolve('test-message');
          markStarted();
        }));
      } else {
        slackSend.mockImplementationOnce(() => new Promise(resolve => {
          finishSend = () => resolve({ channel: 'test-channel', ts: '1.0' });
          markStarted();
        }));
      }
      notifications.approval(ch);
      await sendStarted;
      await state.storage.delete(`ch:${ch.approve_token}`);
      finishSend();
      await Promise.all(tasks);
      expect(await state.storage.get(`ch:${ch.approve_token}`)).toBeUndefined();
      expect(feishuEdit).not.toHaveBeenCalled();
      expect(slackEdit).not.toHaveBeenCalled();
    });
  });

  it('keeps extension ceremonies console-only and malformed channels disabled', async () => {
    await withNotifications(({ notifications, vars, tasks, feishuSend, slackSend }) => {
      notifications.approval(makeChallenge({ extend: {
        group_ids: [], ttl_s: 1200, requested_by: 'admin@example.invalid', preview: [],
      } }));
      expect(tasks).toEqual([]);
      vars.FEISHU_JSON = '{';
      vars.SLACK_APP_JSON = '{';
      notifications.approval(makeChallenge());
      expect(tasks).toEqual([]);
      expect(feishuSend).not.toHaveBeenCalled();
      expect(slackSend).not.toHaveBeenCalled();
    });
  });

  it('reuses sweep configuration and isolates edit failures', async () => {
    await withNotifications(async ({ notifications, vars, tasks, feishuEdit, slackEdit }) => {
      const channels = notifications.channels();
      const ch = makeChallenge({ feishu_message_id: 'test-message', slackapp: { channel: 'test-channel', ts: '1.0' } });
      vars.FEISHU_JSON = '';
      vars.SLACK_APP_JSON = '';
      feishuEdit.mockRejectedValueOnce(new Error('synthetic edit failure'));
      notifications.edit(ch, 'expired', {}, channels);
      await expect(Promise.all(tasks)).resolves.toBeDefined();
      expect(feishuEdit).toHaveBeenCalledOnce();
      expect(slackEdit).toHaveBeenCalledOnce();
      const disabled = notifications.channels();
      vars.FEISHU_JSON = FEISHU_JSON;
      vars.SLACK_APP_JSON = SLACK_APP_JSON;
      notifications.edit(ch, 'expired', {}, disabled);
      expect(feishuEdit).toHaveBeenCalledOnce();
      expect(slackEdit).toHaveBeenCalledOnce();
    });
  });

  it('keeps cache-hit delivery opt-in, isolated, and throttled by operation and host', async () => {
    await withNotifications(async ({ notifications, vars, tasks, statelessHit, feishuHit, slackHit }) => {
      notifications.cacheHit(makeMeta(), 2);
      expect(tasks).toEqual([]);
      vars.CACHE_HIT_NOTIFY = 'yes';
      const clock = vi.spyOn(Date, 'now').mockReturnValue(120_000);
      const op: DoAuditIngestOp = {
        token_id: 'synthetic-agent-event', ts_ms: Date.now(), outcome: 'cache_hit',
        salts: 0, latency_ms: 1, meta: makeMeta({ op_kind: 'sign' }),
        peer_exe: null, key_fp: null, dest: null, scope_family: null,
        scope_label: null, grant_ttl_s: null, relayed: null,
      };
      statelessHit.mockRejectedValue(new Error('synthetic delivery failure'));
      notifications.agentCacheHit(op);
      notifications.agentCacheHit(op);
      expect(statelessHit).toHaveBeenCalledTimes(1);
      notifications.agentCacheHit({ ...op, meta: { ...op.meta, host: 'another-host' } });
      notifications.agentCacheHit({ ...op, meta: { ...op.meta, op_kind: 'decrypt' } });
      expect(statelessHit).toHaveBeenCalledTimes(3);
      clock.mockReturnValue(180_000);
      notifications.agentCacheHit(op);
      await expect(Promise.all(tasks)).resolves.toBeDefined();
      expect(statelessHit).toHaveBeenCalledTimes(4);
      expect(feishuHit).toHaveBeenCalledTimes(4);
      expect(slackHit).toHaveBeenCalledTimes(4);
      expect(statelessHit.mock.calls[0]![3]).toBe('缓存命中，免 Touch ID');
    });
  });
});
