// End-to-end check of the whole secret path, with fake parts only:
//   MCP client -> real MCP server -> named pipe -> real broker (FakeVault) -> named pipe -> simulated extension
//   -> local test login page.
// The simulated extension does what packages/extension does (pair, receive fill_job, claim, decrypt, submit),
// except that it POSTs the form itself instead of injecting into a real tab. The DOM side is covered by
// packages/extension/test/fill.test.ts. No real vault, site or credential is involved.
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { assertNoSecret, exportPublicKey, generateRecipientKeyPair, openSecret, pairingCode, secretAad } from '@acb/core';
import type { ClaimSecretResult, FillJobMessage, PairResult } from '@acb/core';
import { connectBroker, type BrokerConnection } from '@acb/core/node';
import { startBroker, type RunningBroker } from '@acb/broker';
import { FakeVault } from '@acb/vault-fake';
import { IpcBrokerApi, createServer } from '@acb/mcp-server';

const root = fileURLToPath(new URL('../../', import.meta.url));
const FIXTURE = path.join(root, 'packages/vault-fake/test/fixtures/fake-vault.json');
const DASH_PW = 'dashboard-pw-test-only';
const SITE = 'http://127.0.0.1:8765'; // origin of the fixture item; the page itself runs on a free port
// Everything that must never reach the agent: fake credential values, item names and item ids.
const NEVER_TO_AGENT = [
  'test-user', 'correct-horse-test-only', 'alt-user', 'alt-horse-test-only',
  'Test login page', 'fake-1', 'fake-2', DASH_PW,
];

const freePort = () =>
  new Promise<number>((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address() as net.AddressInfo;
      s.close(() => resolve(port));
    });
  });

/** Minimal dashboard client: what the human does in the browser, through the same HTTP API. */
class Human {
  private cookie = '';
  private csrf = '';
  constructor(private readonly base: string) {}

  async req(method: string, p: string, body?: object) {
    const headers: Record<string, string> = { origin: this.base, 'content-type': 'application/json', cookie: this.cookie };
    if (this.csrf) headers['x-acb-csrf'] = this.csrf;
    const r = await fetch(this.base + p, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const setCookie = r.headers.get('set-cookie');
    if (setCookie) this.cookie = setCookie.split(';')[0];
    return { status: r.status, json: (await r.json()) as any };
  }
  async login() {
    const r = await this.req('POST', '/api/login', { password: DASH_PW });
    this.csrf = r.json.csrf;
  }
}

/** Plays the extension's part. Holds its own key pair, like the extension's IndexedDB key. */
class SimulatedExtension {
  conn!: BrokerConnection;
  keys!: CryptoKeyPair;
  loginPageStatuses: number[] = [];
  claimOrigin: ((jobOrigin: string) => string) | null = null; // lets a test lie about the tab origin

  async start(pipe: string, pagePort: number) {
    this.keys ??= await generateRecipientKeyPair(); // survives reconnects, like the IndexedDB key
    this.conn = await connectBroker({ role: 'filler', path: pipe });
    this.conn.onPush((m) => {
      if (m.type === 'fill_job') void this.onJob(m, pagePort);
    });
  }
  async pair(): Promise<PairResult> {
    return (await this.conn.call('pair', { publicKey: await exportPublicKey(this.keys.publicKey) })) as PairResult;
  }
  private async onJob(job: FillJobMessage, pagePort: number) {
    const documentId = 'doc-' + randomBytes(4).toString('hex');
    const tabOrigin = this.claimOrigin ? this.claimOrigin(job.origin) : job.origin;
    let claim: ClaimSecretResult;
    try {
      claim = (await this.conn.call('claimSecret', { jobId: job.jobId, tabOrigin, documentId })) as ClaimSecretResult;
    } catch (e) {
      const code = (e as { code?: string }).code ?? 'timeout';
      this.conn.send({ type: 'rpc', id: 'r-' + job.jobId, method: 'fillResult', params: { jobId: job.jobId, status: 'error', code } });
      return;
    }
    let creds: { username: string; password: string };
    try {
      creds = await openSecret(this.keys.privateKey, claim.sealed, secretAad(job.jobId, job.origin, documentId));
    } catch {
      await this.conn.call('fillResult', { jobId: job.jobId, status: 'error', code: 'decrypt_failed' });
      return;
    }
    const r = await fetch(`http://127.0.0.1:${pagePort}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(creds).toString(),
    });
    this.loginPageStatuses.push(r.status);
    await this.conn.call('fillResult', { jobId: job.jobId, status: r.ok ? 'submitted' : 'error', ...(r.ok ? {} : { code: 'submit_failed' }) });
  }
}

describe('end to end with the fake vault and the local test login page', { timeout: 30_000 }, () => {
  let dir: string;
  let page: ChildProcess;
  let pagePort: number;
  let broker: RunningBroker;
  let human: Human;
  let ext: SimulatedExtension;
  let agent: Client;
  const agentSaw: unknown[] = [];

  const tool = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await agent.callTool({ name, arguments: args });
    agentSaw.push(r);
    return r.structuredContent as any;
  };

  beforeAll(async () => {
    dir = mkdtempSync(path.join(os.tmpdir(), 'acb-e2e-'));
    writeFileSync(path.join(dir, 'index.html'), 'ok');
    pagePort = await freePort();
    page = spawn(process.execPath, [path.join(root, 'test/login-page/server.mjs')], {
      env: { ...process.env, ACB_TEST_PAGE_PORT: String(pagePort) },
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    await new Promise<void>((resolve) => page.stdout!.once('data', () => resolve()));

    const pipe = process.platform === 'win32' ? `\\\\.\\pipe\\acb-e2e-${randomBytes(6).toString('hex')}` : path.join(dir, 'b.sock');
    broker = await startBroker({
      home: dir, vault: FakeVault.fromFixture(FIXTURE), pipePath: pipe, dashboardPort: 0,
      dashboardPassword: DASH_PW, publicDir: dir, notifier: { requestApproval: async () => {}, notifyUse: async () => {} },
    });
    human = new Human(broker.dashboardUrl);
    await human.login();

    ext = new SimulatedExtension();
    await ext.start(pipe, pagePort);

    process.env.ACB_PIPE = pipe;
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await createServer(new IpcBrokerApi('e2e-agent')).connect(st);
    agent = new Client({ name: 'e2e', version: '0' });
    await agent.connect(ct);
  });

  afterAll(async () => {
    await agent?.close();
    ext?.conn.close();
    await broker?.stop();
    page?.kill();
    delete process.env.ACB_PIPE;
    rmSync(dir, { recursive: true, force: true });
  });

  it('pairs only after the human confirms the matching code with the password', async () => {
    const first = await ext.pair();
    expect(first.status).toBe('pending');
    expect(first.pairingCode).toBe(await pairingCode(await exportPublicKey(ext.keys.publicKey)));
    expect((await human.req('GET', '/api/pairing')).json).toEqual({ status: 'pending', pairingCode: first.pairingCode });

    const shown = first.pairingCode;
    expect((await human.req('POST', '/api/pairing/confirm', { password: 'wrong', pairingCode: shown })).status).toBe(401);
    expect((await human.req('POST', '/api/pairing/confirm', { password: DASH_PW, pairingCode: shown })).status).toBe(200);
    expect((await ext.pair()).status).toBe('paired'); // repeated pair calls are idempotent
  });

  it('a second filler with another key cannot take over the pairing', async () => {
    const rogue = await generateRecipientKeyPair();
    const conn = await connectBroker({ role: 'filler', path: process.env.ACB_PIPE });
    try {
      await expect(conn.call('pair', { publicKey: await exportPublicKey(rogue.publicKey) })).rejects.toMatchObject({ code: 'already_paired' });
    } finally {
      conn.close();
    }
    // The rogue connection replaced ours; reconnect the real one like the extension would.
    ext.conn.close();
    await ext.start(process.env.ACB_PIPE!, pagePort);
    expect((await ext.pair()).status).toBe('paired');
  });

  it('first request goes to the human; the agent gets a requestId and nothing else', async () => {
    const r = await tool('request_login', { site: SITE, hint: 'please log me in' });
    expect(r).toMatchObject({ status: 'pending' });
    expect((await tool('grant_status', { request_id: r.requestId })).status).toBe('pending');

    // The same request again is deduplicated, not a second approval prompt.
    expect((await tool('request_login', { site: SITE })).requestId).toBe(r.requestId);

    const pending = (await human.req('GET', '/api/requests')).json;
    expect(pending).toHaveLength(1);
    expect(pending[0].candidates.map((c: any) => c.name).sort()).toEqual(['Test login page', 'Test login page (alt account)']);
    expect(pending[0].insecureHttp).toBe(true);

    const approve = (pw: string) => human.req('POST', `/api/requests/${r.requestId}/approve`, { itemId: 'fake-1', duration: '1h', password: pw });
    expect((await approve('wrong')).status).toBe(401);
    expect((await approve(DASH_PW)).status).toBe(200);
    expect((await tool('grant_status', { request_id: r.requestId })).status).toBe('approved');
  });

  it('with a grant, the broker fills via the extension and the login page accepts the fake credential', async () => {
    const r = await tool('request_login', { site: SITE });
    expect(r).toMatchObject({ status: 'submitted', usesLeft: null });
    expect(ext.loginPageStatuses).toEqual([200]);

    const grants = await tool('list_grants');
    expect(grants.grants).toEqual([expect.objectContaining({ origin: SITE, agentId: 'e2e-agent' })]);
  });

  it('a filler that reports a different tab origin gets no secret', async () => {
    ext.claimOrigin = () => 'http://127.0.0.1:8766';
    try {
      expect(await tool('request_login', { site: SITE })).toMatchObject({ status: 'error', code: 'origin_mismatch' });
    } finally {
      ext.claimOrigin = null;
    }
    expect(ext.loginPageStatuses).toEqual([200]);
  });

  it('other agents do not inherit the grant, and look-alike origins never match', async () => {
    expect(await tool('request_login', { site: 'http://127.0.0.1:8765.evil.test' })).toMatchObject({ status: 'error' });
    expect(await tool('request_login', { site: 'https://127.0.0.1:8765' })).toMatchObject({ status: 'error', code: 'no_match' });
    expect(await tool('request_login', { site: 'http://user@127.0.0.1:8765' })).toMatchObject({ status: 'error', code: 'invalid_site' });

    const other = await broker.service.requestLogin({ site: SITE }, 'other-agent');
    expect(other.status).toBe('pending');
  });

  it('after revoke-all the agent is back to pending', async () => {
    expect((await human.req('POST', '/api/grants/revoke-all', {})).json.revoked).toBe(1);
    expect(await tool('request_login', { site: SITE })).toMatchObject({ status: 'pending' });
    expect(await tool('list_grants')).toEqual({ grants: [] });
  });

  it('nothing the agent saw, and nothing in the audit log, contains a credential', async () => {
    expect(agentSaw.length).toBeGreaterThan(8);
    assertNoSecret(agentSaw, NEVER_TO_AGENT);
    const audit = (await human.req('GET', '/api/audit')).json;
    assertNoSecret(audit, ['correct-horse-test-only', 'alt-horse-test-only', 'test-user', DASH_PW]);
    expect(audit.map((a: any) => a.event)).toEqual(expect.arrayContaining(['pair_confirm', 'approve', 'secret_released', 'fill_result', 'revoke_all']));
  });
});
