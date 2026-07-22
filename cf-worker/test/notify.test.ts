// Unit tests for the shared notification builders — the context block every
// channel (Pushover / Slack webhook / Slack App / Feishu) renders. These are
// pure string builders, so they run under plain vitest with no workerd.

import { describe, it, expect } from 'vitest';
import { metaLines, buildApprovalMessage, buildCacheHitLines } from '../src/notify';

const meta = {
  op_kind: 'decrypt',
  command: 'op: inject\nfile: .env',
  host: 'devbox',
  user: 'qiqi',
  pwd: '/repo',
  ppid_cmd: 'zsh -c deploy.sh',
  ssh_client: '10.0.0.2 51000 22',
  ip: '203.0.113.9',
  reason: 'release',
};

describe('metaLines', () => {
  it('renders who · N 条 head, then pwd/cmd/via/ssh/ip/reason in order', () => {
    const lines = metaLines(meta, 3);
    expect(lines[0]).toBe('qiqi@devbox · 3 条');
    expect(lines.slice(1)).toEqual([
      'pwd: /repo',
      'op: inject\nfile: .env', // self-labelled multi-line command, no cmd: prefix
      'via: zsh -c deploy.sh',
      'ssh: 10.0.0.2 51000 22',
      'ip: 203.0.113.9',
      'reason: release',
    ]);
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
  it('carries the batch size and ends with the approve URL', () => {
    const { title, body } = buildApprovalMessage('decrypt', meta, 'https://w/a/tok', 5);
    expect(title).toBe('VT 审批: decrypt');
    expect(body.startsWith('qiqi@devbox · 5 条\n')).toBe(true);
    expect(body.endsWith('\nhttps://w/a/tok')).toBe(true);
  });
});

describe('buildCacheHitLines', () => {
  it('stays compact: who · N 条 · note, pwd, cmd — no via/ssh/ip/reason', () => {
    const { title, lines } = buildCacheHitLines(meta, 2);
    expect(title).toBe('VT 缓存命中(免审批): decrypt');
    expect(lines[0]).toBe('qiqi@devbox · 2 条 · 缓存命中，无手机审批');
    expect(lines.join('\n')).not.toMatch(/via:|ssh:|ip:|reason:/);
  });
});
