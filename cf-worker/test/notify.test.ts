// Unit tests for the notification text builders behind the Web Push payload.
// Pure string builders, so they run under plain vitest with no workerd.

import { describe, it, expect } from 'vitest';
import { metaLines, buildApprovalMessage, buildCacheHitMessage } from '../src/notify';

const meta = {
  op_kind: 'decrypt',
  command: 'op: inject\nfile: .env',
  host: 'devbox',
  user: 'qiqi',
  pwd: '/repo',
  ppid_cmd: 'zsh -c deploy.sh',
  ip: '203.0.113.9',
  reason: 'release',
};

describe('metaLines', () => {
  it('renders who · N 条 head, then pwd/cmd/via/ip/reason in order', () => {
    const lines = metaLines(meta, 3);
    expect(lines[0]).toBe('qiqi@devbox · 3 条');
    expect(lines.slice(1)).toEqual([
      'pwd: /repo',
      'op: inject\nfile: .env', // self-labelled multi-line command, no cmd: prefix
      'via: zsh -c deploy.sh',
      'ip: 203.0.113.9',
      'reason: release',
    ]);
  });

  it('flags an IP change on the host-token path', () => {
    const lines = metaLines({ ...meta, ip_prev: '198.51.100.7' });
    expect(lines).toContain('ip: 203.0.113.9（上次 198.51.100.7）');
  });

  it('drops the batch segment at salts=0 and keeps a bare count when who is empty', () => {
    expect(metaLines(meta)[0]).toBe('qiqi@devbox');
    const anon = { ...meta, user: '', host: '' };
    expect(metaLines(anon, 2)[0]).toBe('2 条');
    // No head line at all when both are absent.
    expect(metaLines(anon)[0]).toBe('pwd: /repo');
  });

  it('prefixes single-line commands and skips empty fields', () => {
    const lines = metaLines({ ...meta, command: 'vt read foo', ppid_cmd: '', reason: '' });
    expect(lines).toContain('cmd: vt read foo');
    expect(lines.some((l) => l.startsWith('via:'))).toBe(false);
    expect(lines.some((l) => l.startsWith('reason:'))).toBe(false);
  });
});

describe('buildApprovalMessage', () => {
  it('carries the batch size and no URL (the payload carries it separately)', () => {
    const { title, body } = buildApprovalMessage('decrypt', meta, 5);
    expect(title).toBe('VT 审批: decrypt');
    expect(body.startsWith('qiqi@devbox · 5 条\n')).toBe(true);
    expect(body).not.toMatch(/https?:/);
    expect(buildApprovalMessage('', meta).title).toBe('VT 审批请求');
  });
});

describe('buildCacheHitMessage', () => {
  it('stays compact: who · N 条 · note, pwd, cmd — no via/ssh/ip/reason', () => {
    const { title, body } = buildCacheHitMessage(meta, 2);
    expect(title).toBe('VT 缓存命中(免审批): decrypt');
    expect(body.split('\n')[0]).toBe('qiqi@devbox · 2 条 · 缓存命中，无手机审批');
    expect(body).not.toMatch(/via:|ssh:|ip:|reason:/);
  });
});
