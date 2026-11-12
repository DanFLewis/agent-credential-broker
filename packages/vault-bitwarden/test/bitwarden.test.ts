import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BitwardenVault, resolveBw } from '../src/index.js';
import type { Runner } from '../src/index.js';

const SESSION = 'fake-session-token-test-only';
const MASTER = 'fake-master-pw-test-only';
const PW = 'correct-horse-test-only';

const login = (id: string, name: string, uris: Array<string | null>, extra: object = {}) => ({
  id,
  name,
  type: 1,
  login: { username: 'test-user', password: PW, uris: uris.map((uri) => ({ match: null, uri })) },
  ...extra,
});

const ITEMS = [
  login('11111111-aaaa', 'Test login page', ['http://127.0.0.1:8765/login']),
  login('22222222-bbbb', 'Alt account', ['http://127.0.0.1:8765/']),
  login('33333333-cccc', 'Bank', ['https://bank.example.test/signin', 'not a url']),
  login('44444444-dddd', 'Lookalike', ['https://evil.bank.example.test/']),
  login('55555555-eeee', 'Plain http bank', ['http://bank.example.test/']),
  { id: '66666666-ffff', name: 'Note', type: 2, notes: 'x', login: undefined },
  { id: '77777777-0000', name: 'Card', type: 3, login: { uris: [{ uri: 'https://bank.example.test/' }] } },
];

interface Call {
  args: string[];
  env: Record<string, string>;
}

function fakeRunner(overrides: Partial<Record<string, { code: number; stdout: string; stderr?: string }>> = {}) {
  const calls: Call[] = [];
  const run: Runner = async (args, env) => {
    calls.push({ args, env });
    const key = args[0] === 'get' ? 'get' : args[0]!;
    const o = overrides[key];
    if (o) return { code: o.code, stdout: o.stdout, stderr: o.stderr ?? '' };
    switch (key) {
      case 'status':
        return { code: 0, stdout: JSON.stringify({ serverUrl: null, status: env.BW_SESSION ? 'unlocked' : 'locked' }), stderr: '' };
      case 'unlock':
        return { code: 0, stdout: SESSION, stderr: '' };
      case 'list':
        return { code: 0, stdout: JSON.stringify(ITEMS), stderr: '' };
      case 'get':
        return { code: 0, stdout: JSON.stringify(ITEMS.find((i) => i.id === args[2]) ?? {}), stderr: '' };
    }
    return { code: 1, stdout: '', stderr: 'unknown' };
  };
  return { run, calls };
}

describe('BitwardenVault', () => {
  it('puts the session in env only, never argv', async () => {
    const { run, calls } = fakeRunner();
    const v = new BitwardenVault({ session: SESSION, run });
    await v.status();
    await v.find(undefined, 'http://127.0.0.1:8765');
    await v.getSecret('11111111-aaaa');
    expect(calls).toHaveLength(3);
    for (const c of calls) {
      expect(c.env.BW_SESSION).toBe(SESSION);
      expect(c.args.join(' ')).not.toContain(SESSION);
      expect(c.args).not.toContain('--session');
    }
  });

  it('status requires both unlocked and a session', async () => {
    const { run } = fakeRunner({ status: { code: 0, stdout: '{"status":"unlocked"}' } });
    expect(await new BitwardenVault({ run }).status()).toBe('locked');
    expect(await new BitwardenVault({ run, session: SESSION }).status()).toBe('unlocked');
    expect(await new BitwardenVault({ run: fakeRunner({ status: { code: 0, stdout: '{"status":"unauthenticated"}' } }).run }).status()).toBe('unavailable');
    expect(await new BitwardenVault({ run: fakeRunner({ status: { code: 1, stdout: '' } }).run }).status()).toBe('unavailable');
    expect(await new BitwardenVault({ run: fakeRunner({ status: { code: 0, stdout: 'garbage' } }).run }).status()).toBe('unavailable');
  });

  it('unlock passes the master password via env and --passwordenv, not argv', async () => {
    const { run, calls } = fakeRunner();
    const v = new BitwardenVault({ run });
    await v.unlock(MASTER);
    const c = calls[0]!;
    expect(c.args).toEqual(['unlock', '--raw', '--passwordenv', 'ACB_BW_PASSWORD']);
    expect(c.env.ACB_BW_PASSWORD).toBe(MASTER);
    expect(c.args.join(' ')).not.toContain(MASTER);
    expect(await v.status()).toBe('unlocked');
    expect(calls[1]!.env.BW_SESSION).toBe(SESSION);
    expect(calls[1]!.env.ACB_BW_PASSWORD).toBeUndefined();
  });

  it('matches by exact origin only, never uses --url, ignores non-logins', async () => {
    const { run, calls } = fakeRunner();
    const v = new BitwardenVault({ session: SESSION, run });
    const ids = async (site: string) => (await v.find(undefined, site)).map((i) => i.itemId);

    expect(await ids('http://127.0.0.1:8765')).toEqual(['11111111-aaaa', '22222222-bbbb']);
    expect(await ids('https://bank.example.test')).toEqual(['33333333-cccc']); // not look-alike, not http, not card
    expect(await ids('http://bank.example.test')).toEqual(['55555555-eeee']);
    expect(await ids('https://example.test')).toEqual([]);
    expect((await v.getItem('33333333-cccc'))!.origins).toEqual(['https://bank.example.test']); // bad uri dropped
    expect(await v.getItem('66666666-ffff')).toBeNull();
    expect(await v.getItem('77777777-0000')).toBeNull();
    expect(calls.flatMap((c) => c.args)).not.toContain('--url');
  });

  it('hint only reorders', async () => {
    const { run } = fakeRunner();
    const v = new BitwardenVault({ session: SESSION, run });
    const site = 'http://127.0.0.1:8765';
    const plain = (await v.find(undefined, site)).map((i) => i.itemId);
    const hinted = (await v.find('ALT', site)).map((i) => i.itemId);
    expect(hinted).toEqual(['22222222-bbbb', '11111111-aaaa']);
    expect([...hinted].sort()).toEqual([...plain].sort());
    // A hint naming an item at another origin does not pull it in.
    expect(await v.find('bank', site)).toHaveLength(2);
  });

  it('caches metadata for 60s without passwords', async () => {
    let t = 1000;
    const { run, calls } = fakeRunner();
    const v = new BitwardenVault({ session: SESSION, run, now: () => t });
    await v.find(undefined, 'http://127.0.0.1:8765');
    await v.find(undefined, 'http://127.0.0.1:8765');
    await v.getItem('11111111-aaaa');
    expect(calls.filter((c) => c.args[0] === 'list')).toHaveLength(1);
    await v.getSecret('11111111-aaaa'); // fetching a secret must not populate the cache with it
    const dump = JSON.stringify(v, (_k, val) => val) + JSON.stringify(Object.values(v as object));
    expect(dump).not.toContain(PW);
    expect(dump).not.toContain('test-user');
    expect(dump).toContain('Test login page');
    t += 60_001;
    await v.find(undefined, 'http://127.0.0.1:8765');
    expect(calls.filter((c) => c.args[0] === 'list')).toHaveLength(2);
  });

  it('getSecret returns redacted Secret and rejects non-logins and odd ids', async () => {
    const { run, calls } = fakeRunner();
    const v = new BitwardenVault({ session: SESSION, run });
    const s = await v.getSecret('11111111-aaaa');
    expect(s.username).toBe('test-user');
    expect(s.password).toBe(PW);
    expect(JSON.stringify(s)).not.toContain(PW);
    expect(calls[0]!.args).toEqual(['get', 'item', '11111111-aaaa']);
    await expect(v.getSecret('66666666-ffff')).rejects.toThrow();
    await expect(v.getSecret('--help')).rejects.toThrow('invalid item id');
    expect(calls).toHaveLength(2);
  });

  it('errors never include stdout or stderr content', async () => {
    const leak = { code: 1, stdout: `{"password":"${PW}"}`, stderr: `boom ${PW} ${MASTER}` };
    const v = new BitwardenVault({
      session: SESSION,
      run: fakeRunner({ list: leak, get: leak, unlock: leak }).run,
    });
    const errors: string[] = [];
    for (const p of [v.find(undefined, 'http://127.0.0.1:8765'), v.getSecret('11111111-aaaa'), v.unlock(MASTER)]) {
      await p.catch((e: Error) => errors.push(e.message));
    }
    expect(errors).toHaveLength(3);
    for (const m of errors) {
      expect(m).not.toContain(PW);
      expect(m).not.toContain(MASTER);
      expect(m).not.toContain('boom');
    }
    // Success exit code but a payload that fails to parse: still no payload in the message.
    const bad = new BitwardenVault({ session: SESSION, run: fakeRunner({ get: { code: 0, stdout: `not json ${PW}` } }).run });
    await expect(bad.getSecret('11111111-aaaa')).rejects.not.toThrow(PW);
    // A thrown runner error is replaced too.
    const thrower = new BitwardenVault({ session: SESSION, run: async () => { throw new Error(`spawn ${PW}`); } });
    await thrower.getSecret('11111111-aaaa').catch((e: Error) => expect(e.message).not.toContain(PW));
  });
});

describe('resolveBw (Windows)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'acb-bw-'));
  const touch = (n: string) => writeFileSync(join(dir, n), '');

  it('prefers bw.exe on PATH, explains a lone bw.cmd, passes explicit paths', () => {
    touch('bw.cmd');
    expect(() => resolveBw('bw', 'win32', dir)).toThrow(/bw\.exe/);
    expect(() => resolveBw('C:\\x\\bw.cmd', 'win32', dir)).toThrow(/bw\.exe/);
    touch('bw.exe');
    expect(resolveBw('bw', 'win32', dir)).toBe(join(dir, 'bw.exe'));
    expect(resolveBw('C:\\x\\bw.exe', 'win32', dir)).toBe('C:\\x\\bw.exe');
    expect(resolveBw('bw', 'linux', dir)).toBe('bw');
  });
});
