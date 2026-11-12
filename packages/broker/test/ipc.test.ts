import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PROTOCOL_VERSION, assertNoSecret, openSecret, secretAad } from '@acb/core';
import { ExtensionFiller } from '../src/filler.js';
import { IpcServer } from '../src/ipc.js';
import { BrokerService } from '../src/service.js';
import { GrantStore } from '../src/store.js';
import { T_PASS, T_USER, TestNotifier, TestVault, item, newExtensionKey } from './helpers.js';

const SITE = 'https://example.com';

/** Minimal raw NDJSON client so the tests do not depend on connectBroker. */
class Client {
  messages: any[] = [];
  closed = false;
  private waiters: Array<(m: any) => void> = [];
  private buf = '';
  readonly closedP: Promise<void>;
  private constructor(readonly sock: net.Socket) {
    sock.setEncoding('utf8');
    sock.on('data', (d: string) => {
      this.buf += d;
      let i: number;
      while ((i = this.buf.indexOf('\n')) >= 0) {
        const m = JSON.parse(this.buf.slice(0, i));
        this.buf = this.buf.slice(i + 1);
        this.messages.push(m);
        this.waiters.shift()?.(m);
      }
    });
    sock.on('error', () => undefined);
    this.closedP = new Promise((r) => sock.on('close', () => { this.closed = true; r(); }));
  }
  static connect(p: string): Promise<Client> {
    return new Promise((resolve, reject) => {
      const s = net.connect(p, () => resolve(new Client(s)));
      s.once('error', reject);
    });
  }
  send(o: unknown) { this.sock.write(JSON.stringify(o) + '\n'); }
  raw(s: string) { this.sock.write(s); }
  next(): Promise<any> {
    const queued = this.messages.length - this.consumed;
    if (queued > 0) return Promise.resolve(this.messages[this.consumed++]);
    return new Promise((r) => this.waiters.push((m) => { this.consumed++; r(m); }));
  }
  private consumed = 0;
  async hello(role: 'agent' | 'filler', agentId?: string) {
    this.send({ type: 'hello', role, protocolVersion: PROTOCOL_VERSION, agentId });
    expect((await this.next()).type).toBe('hello_ok');
    return this;
  }
  async rpc(method: string, params: unknown = {}) {
    const id = randomBytes(4).toString('hex');
    this.send({ type: 'rpc', id, method, params });
    for (;;) {
      const m = await this.next();
      if (m.id === id) return m;
    }
  }
}

let dir: string;
let sockPath: string;
let store: GrantStore;
let vault: TestVault;
let filler: ExtensionFiller;
let notifier: TestNotifier;
let service: BrokerService;
let server: IpcServer;
const clients: Client[] = [];
const connect = async (role?: 'agent' | 'filler', agentId?: string) => {
  const c = await Client.connect(sockPath);
  clients.push(c);
  return role ? c.hello(role, agentId) : c;
};

beforeEach(async () => {
  dir = mkdtempSync(path.join(os.tmpdir(), 'acb-ipc-'));
  sockPath = process.platform === 'win32' ? `\\\\.\\pipe\\acb-test-${randomBytes(6).toString('hex')}` : path.join(dir, 'b.sock');
  store = new GrantStore(':memory:');
  vault = new TestVault([item('i1', 'Example', SITE)]);
  filler = new ExtensionFiller();
  notifier = new TestNotifier();
  service = new BrokerService({ store, vault, filler, notifier });
  server = new IpcServer({ path: sockPath, service, filler });
  await server.listen();
});

afterEach(async () => {
  for (const c of clients.splice(0)) c.sock.destroy();
  await server.close();
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('hello handshake', () => {
  it('destroys the socket when the first line is not a valid hello', async () => {
    for (const first of [
      { type: 'rpc', id: '1', method: 'listGrants', params: {} },
      { type: 'hello', role: 'admin', protocolVersion: PROTOCOL_VERSION },
      { type: 'hello', role: 'agent', protocolVersion: 999 },
    ]) {
      const c = await connect();
      c.send(first);
      await c.closedP;
      expect(c.messages).toEqual([]);
    }
    const g = await connect();
    g.raw('not json\n');
    await g.closedP;
  });

  it('destroys the socket on an oversized message', async () => {
    const c = await connect('agent', 'a');
    c.raw('x'.repeat(1024 * 1024 + 10)); // no newline, over the 1 MiB cap
    await c.closedP;
  });

  it('destroys the socket on a malformed rpc after hello', async () => {
    const c = await connect('agent', 'a');
    c.send({ type: 'rpc', method: 5 });
    await c.closedP;
  });
});

describe('role checks', () => {
  it('agent calling filler methods gets rpc_error', async () => {
    const a = await connect('agent', 'agent-a');
    for (const m of ['claimSecret', 'pair', 'fillResult']) {
      const r = await a.rpc(m, { jobId: 'x', publicKey: 'x' });
      expect(r).toMatchObject({ type: 'rpc_error', error: { code: 'forbidden' } });
    }
  });

  it('filler calling agent methods gets rpc_error', async () => {
    const f = await connect('filler');
    for (const m of ['requestLogin', 'grantStatus', 'listGrants', 'approve', 'constructor']) {
      const r = await f.rpc(m, { site: SITE, requestId: 'x' });
      expect(r).toMatchObject({ type: 'rpc_error', error: { code: 'forbidden' } });
    }
    expect(store.listAudit().some((e) => e.event === 'request')).toBe(false);
  });

  it('agent can request, poll and list; agentId comes from hello and is sanitised', async () => {
    const a = await connect('agent', 'agent-a\x1b[31m');
    const r = await a.rpc('requestLogin', { site: SITE, hint: 'hi' });
    expect(r.result).toMatchObject({ status: 'pending' });
    expect(service.listPendingRequests()[0]?.agentId).toBe('agent-a__31m');
    expect((await a.rpc('grantStatus', { requestId: r.result.requestId })).result.status).toBe('pending');
    expect((await a.rpc('listGrants')).result).toEqual([]);
  });

  it('rpc errors carry only a generic code and message (no stack)', async () => {
    vault.find = async () => { throw new Error(`boom ${T_PASS} at C:\\secret\\path`); };
    const a = await connect('agent', 'a');
    const r = await a.rpc('requestLogin', { site: SITE });
    expect(r).toEqual({ type: 'rpc_error', id: r.id, error: { code: 'internal', message: 'Internal error.' } });
    expect((await a.rpc('requestLogin', { site: 5 })).error.code).toBe('bad_params');
  });
});

describe('filler connection', () => {
  it('a newer filler replaces the older one', async () => {
    const f1 = await connect('filler');
    expect(filler.isAvailable()).toBe(true);
    const f2 = await connect('filler');
    await f1.closedP;
    expect(filler.isAvailable()).toBe(true);
    f2.sock.destroy();
    await f2.closedP;
    await new Promise((r) => setTimeout(r, 20));
    expect(filler.isAvailable()).toBe(false);
  });

  it('fill() times out and reports a timeout error when the filler never answers', async () => {
    const f = await connect('filler');
    const res = await filler.fill({ jobId: 'j1', origin: SITE }, { jobId: 'j1' }, 50);
    expect(res).toEqual({ status: 'error', code: 'timeout' });
    expect(await f.next()).toMatchObject({ type: 'fill_job', jobId: 'j1', origin: SITE });
  });
});

describe('full flow over the pipe', () => {
  it('request -> approve -> fill_job -> sealed claim -> fillResult, with no plaintext anywhere', async () => {
    const kp = await newExtensionKey();
    const agent = await connect('agent', 'agent-a');
    const fl = await connect('filler');

    // Pair, human confirms.
    const pair = await fl.rpc('pair', { publicKey: kp.publicKey });
    expect(pair.result.status).toBe('pending');
    await service.confirmPairing(pair.result.pairingCode);

    // First request is pending; human approves.
    const first = await agent.rpc('requestLogin', { site: SITE });
    expect(first.result.status).toBe('pending');
    service.approve(first.result.requestId, 'i1', '1h');

    // Second request triggers a fill job; the filler claims and reports.
    const second = agent.rpc('requestLogin', { site: SITE, waitMs: 5000 });
    const job = await fl.next();
    expect(job).toMatchObject({ type: 'fill_job', origin: SITE });
    const claim = await fl.rpc('claimSecret', { jobId: job.jobId, tabOrigin: SITE, documentId: 'doc-9' });
    const opened = await openSecret(kp.privateKey, claim.result.sealed, secretAad(job.jobId, SITE, 'doc-9'));
    expect(opened).toEqual({ username: T_USER, password: T_PASS });
    expect((await fl.rpc('fillResult', { jobId: job.jobId, status: 'submitted' })).result).toEqual({ accepted: true });
    const done = await second;
    expect(done.result).toMatchObject({ status: 'submitted', usesLeft: null });

    // The same job cannot be claimed twice.
    expect((await fl.rpc('claimSecret', { jobId: job.jobId, tabOrigin: SITE, documentId: 'doc-9' })).error.code).toBe('job_expired');

    const secrets = [T_PASS, T_USER];
    // Every message either side received (including the sealed claim) is free of plaintext.
    assertNoSecret([agent.messages, fl.messages], secrets);
    assertNoSecret(store.listAudit(1000), secrets);
    assertNoSecret(done, secrets);
  });

  it('claimSecret is refused over the pipe when not paired', async () => {
    const fl = await connect('filler');
    const r = await fl.rpc('claimSecret', { jobId: 'a'.repeat(32), tabOrigin: SITE, documentId: 'd' });
    expect(r.error.code).toBe('not_paired');
  });
});
