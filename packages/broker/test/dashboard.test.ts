import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { assertNoSecret } from '@acb/core';
import { hashPassword } from '../src/auth.js';
import { DashboardServer, PASSWORD_SETTING } from '../src/dashboard-server.js';
import { grantFor, item, makeCtx, newExtensionKey, pendingFor, type Ctx } from './helpers.js';

const PW = 'correct-horse-test-only';
const SITE = 'https://example.com';

interface Res { status: number; headers: http.IncomingHttpHeaders; text: string; json: any }
interface Opts { host?: string; origin?: string | null; cookie?: string; csrf?: string; body?: unknown }

let root: string;
let ctx: Ctx;
let server: DashboardServer;
let port: number;

/** Raw HTTP so tests can control Host/Origin and send un-normalised paths. */
function call(method: string, p: string, o: Opts = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { Host: o.host ?? `127.0.0.1:${port}` };
    if (o.origin !== null && (method === 'POST' || method === 'PUT')) headers.Origin = o.origin ?? `http://127.0.0.1:${port}`;
    if (o.cookie) headers.Cookie = o.cookie;
    if (o.csrf) headers['X-ACB-CSRF'] = o.csrf;
    const payload = o.body === undefined ? undefined : JSON.stringify(o.body);
    if (payload) headers['Content-Type'] = 'application/json';
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers, setHost: false }, (res) => {
      let text = '';
      res.on('data', (d) => (text += d));
      res.on('end', () => {
        let json: unknown;
        try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    req.end(payload);
  });
}

async function login(password = PW) {
  const r = await call('POST', '/api/login', { body: { password } });
  const cookie = (r.headers['set-cookie']?.[0] ?? '').split(';')[0] ?? '';
  return { r, cookie, csrf: r.json?.csrf as string };
}

/** Authenticated helper bound to one session. */
async function session() {
  const { cookie, csrf } = await login();
  return {
    cookie, csrf,
    get: (p: string, o: Opts = {}) => call('GET', p, { cookie, ...o }),
    post: (p: string, body: unknown = {}, o: Opts = {}) => call('POST', p, { cookie, csrf, body, ...o }),
    put: (p: string, body: unknown = {}, o: Opts = {}) => call('PUT', p, { cookie, csrf, body, ...o }),
  };
}

beforeEach(async () => {
  root = mkdtempSync(path.join(os.tmpdir(), 'acb-dash-'));
  mkdirSync(path.join(root, 'public'));
  writeFileSync(path.join(root, 'public', 'index.html'), '<!doctype html><title>t</title>');
  writeFileSync(path.join(root, 'public', 'app.js'), 'console.log(1)');
  writeFileSync(path.join(root, 'secret.txt'), 'TOP-SECRET-OUTSIDE-PUBLIC');
  writeFileSync(path.join(root, 'public-evil.txt'), 'TOP-SECRET-SIBLING-PREFIX'); // shares the "public" name prefix
  ctx = makeCtx([item('i1', 'Example', SITE), item('i2', 'Example 2', SITE)]);
  ctx.store.setSetting(PASSWORD_SETTING, hashPassword(PW));
  server = new DashboardServer({ service: ctx.service, store: ctx.store, publicDir: path.join(root, 'public'), port: 0, clock: () => ctx.clock.now });
  port = await server.listen();
});

afterEach(async () => {
  await server.close();
  rmSync(root, { recursive: true, force: true });
});

describe('host, static files and headers', () => {
  it('returns 421 for a wrong Host header', async () => {
    for (const host of ['evil.example', `127.0.0.1:${port + 1}`, '127.0.0.1', `evil.example:${port}`, '']) {
      expect((await call('GET', '/api/session', { host })).status).toBe(421);
    }
    expect((await call('GET', '/api/session', { host: `localhost:${port}` })).status).toBe(200);
  });

  it('serves static files with CSP and hardening headers', async () => {
    const r = await call('GET', '/');
    expect(r.status).toBe(200);
    expect(r.text).toContain('<title>t</title>');
    expect(r.headers['content-security-policy']).toBe("default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['referrer-policy']).toBe('no-referrer');
    expect((await call('GET', '/app.js')).headers['content-type']).toContain('javascript');
    expect((await call('GET', '/missing.js')).status).toBe(404);
  });

  it('blocks path traversal', async () => {
    const attempts = [
      '/../secret.txt', '/%2e%2e/secret.txt', '/..%2fsecret.txt', '/%2e%2e%2fsecret.txt', '/%2e%2e%2f%2e%2e%2fsecret.txt',
      '/..\\secret.txt', '/%5c..%5csecret.txt', '/..%5csecret.txt', '/../public-evil.txt', '/%2e%2e/public-evil.txt',
      '/app.js%00', '/%00/../secret.txt', '/....//secret.txt', '//secret.txt', '/C:/Windows/win.ini',
    ];
    for (const a of attempts) {
      const r = await call('GET', a);
      expect(r.text, a).not.toContain('TOP-SECRET');
      expect(r.status, a).not.toBe(200);
    }
  });

  it('only allows GET/HEAD for static paths and sets security headers on API errors too', async () => {
    expect((await call('POST', '/index.html', { body: {} })).status).toBe(405);
    const r = await call('GET', '/api/status');
    expect(r.headers['x-content-type-options']).toBe('nosniff');
  });
});

describe('login, cookie and session', () => {
  it('rejects unauthenticated API access', async () => {
    expect((await call('GET', '/api/session')).json).toEqual({ authenticated: false });
    for (const p of ['/api/status', '/api/requests', '/api/grants', '/api/audit', '/api/items', '/api/pairing']) {
      expect((await call('GET', p)).status, p).toBe(401);
    }
  });

  it('sets a 256-bit HttpOnly SameSite=Strict cookie and returns a csrf token', async () => {
    const { r, cookie, csrf } = await login();
    expect(r.status).toBe(200);
    const sc = r.headers['set-cookie']?.[0] ?? '';
    expect(sc).toMatch(/^acb_session=[A-Za-z0-9_-]{43};/);
    expect(sc).toContain('HttpOnly');
    expect(sc).toContain('SameSite=Strict');
    expect(sc).toContain('Path=/');
    expect(csrf).toBeTruthy();
    expect((await call('GET', '/api/session', { cookie })).json).toEqual({ authenticated: true, csrf });
    expect(ctx.store.listAudit().map((e) => e.event)).toContain('dashboard_login');
  });

  it('login still enforces the Origin check', async () => {
    expect((await call('POST', '/api/login', { body: { password: PW }, origin: 'http://evil.example' })).status).toBe(403);
    expect((await call('POST', '/api/login', { body: { password: PW }, origin: null })).status).toBe(403);
    expect((await call('POST', '/api/login', { body: { password: PW }, origin: `http://localhost:${port}` })).status).toBe(200);
  });

  it('wrong password -> 401 + audit (without the attempt); 6th attempt -> 429; recovers after a minute', async () => {
    for (let i = 0; i < 5; i++) expect((await login(`wrong-password-${i}`)).r.status).toBe(401);
    const fails = ctx.store.listAudit().filter((e) => e.event === 'dashboard_auth_fail');
    expect(fails).toHaveLength(5);
    assertNoSecret(fails, ['wrong-password-0', 'wrong-password-4']);
    expect((await login()).r.status).toBe(429); // even the correct password is refused while limited
    ctx.clock.now += 61_000;
    expect((await login()).r.status).toBe(200);
  });

  it('logout invalidates the session; idle (30m) and absolute (8h) expiry apply', async () => {
    const s = await session();
    expect((await s.post('/api/logout')).status).toBe(200);
    expect((await s.get('/api/status')).status).toBe(401);

    const idle = await session();
    ctx.clock.now += 31 * 60 * 1000;
    expect((await idle.get('/api/status')).status).toBe(401);

    const long = await session();
    for (let i = 0; i < 9; i++) {
      ctx.clock.now += 29 * 60 * 1000;
      if (i < 8) expect((await long.get('/api/status')).status).toBe(200);
    }
    ctx.clock.now += 29 * 60 * 1000; // > 8h since login although never idle
    expect((await long.get('/api/status')).status).toBe(401);
  });
});

describe('mutation protection (Origin + CSRF)', () => {
  it('needs the right Origin and the session CSRF token', async () => {
    const s = await session();
    const id = await pendingFor(ctx, SITE);
    const deny = `/api/requests/${id}/deny`;
    expect((await s.post(deny, {}, { origin: 'http://evil.example' })).status).toBe(403);
    expect((await s.post(deny, {}, { origin: null })).status).toBe(403);
    expect((await s.post(deny, {}, { origin: `http://127.0.0.1:${port + 1}` })).status).toBe(403);
    expect((await s.post(deny, {}, { csrf: undefined })).status).toBe(403);
    expect((await s.post(deny, {}, { csrf: 'x'.repeat(s.csrf.length) })).status).toBe(403);
    expect(ctx.service.listPendingRequests()).toHaveLength(1);
    expect((await s.post(deny)).json).toEqual({ ok: true });
    expect(ctx.service.listPendingRequests()).toHaveLength(0);
  });

  it("another session's CSRF token does not work", async () => {
    const a = await session();
    const b = await session();
    expect((await a.post('/api/grants/revoke-all', {}, { csrf: b.csrf })).status).toBe(403);
  });

  it('unauthenticated mutation -> 401', async () => {
    expect((await call('POST', '/api/grants/revoke-all', { body: {} })).status).toBe(401);
  });
});

describe('approve and the password requirement', () => {
  it('lists pending requests with policy and allowed durations; hint is data only', async () => {
    const s = await session();
    await ctx.service.requestLogin({ site: SITE, hint: '<img src=x onerror=alert(1)>' }, 'agent-a');
    ctx.service.setPolicy('i2', 'never-long-grant');
    const list = (await s.get('/api/requests')).json;
    expect(list).toHaveLength(1);
    expect(list[0].hint).toBe('<img src=x onerror=alert(1)>');
    const byId = Object.fromEntries(list[0].candidates.map((c: any) => [c.itemId, c]));
    expect(byId.i1).toMatchObject({ policy: 'normal', allowedDurations: ['once', '1h', '1d', '7d', '30d'] });
    expect(byId.i2).toMatchObject({ policy: 'never-long-grant', allowedDurations: ['once'] });
  });

  it('requires the password; a session alone cannot approve', async () => {
    const s = await session();
    const id = await pendingFor(ctx, SITE);
    const url = `/api/requests/${id}/approve`;
    expect((await s.post(url, { itemId: 'i1', duration: '1h' })).status).toBe(401);
    expect((await s.post(url, { itemId: 'i1', duration: '1h', password: 'nope' })).status).toBe(401);
    expect(ctx.store.getRequest(id)?.status).toBe('pending');
    const ok = await s.post(url, { itemId: 'i1', duration: '1h', password: PW });
    expect(ok.status).toBe(200);
    expect(ok.json.grant).toMatchObject({ itemId: 'i1', origin: SITE, agentId: 'agent-a', maxUses: null });
    expect(ctx.store.getRequest(id)?.status).toBe('approved');
  });

  it('wrong passwords on approve are rate limited too', async () => {
    const s = await session();
    const id = await pendingFor(ctx, SITE);
    const url = `/api/requests/${id}/approve`;
    for (let i = 0; i < 5; i++) await s.post(url, { itemId: 'i1', duration: '1h', password: 'bad' });
    expect((await s.post(url, { itemId: 'i1', duration: '1h', password: PW })).status).toBe(429);
  });

  it('validates itemId (must be a candidate), duration and allowed durations', async () => {
    const s = await session();
    ctx.service.setPolicy('i2', 'never-long-grant');
    const id = await pendingFor(ctx, SITE);
    const url = `/api/requests/${id}/approve`;
    const body = (b: object) => ({ password: PW, ...b });
    expect((await s.post(url, body({ itemId: 'zzz', duration: '1h' }))).status).toBe(400);
    expect((await s.post(url, body({ itemId: 'i1', duration: '99y' }))).status).toBe(400);
    expect((await s.post(url, body({ itemId: 'i1' }))).status).toBe(400);
    expect((await s.post(url, body({ itemId: 'i2', duration: '7d' }))).status).toBe(400);
    expect((await s.post('/api/requests/unknown/approve', body({ itemId: 'i1', duration: '1h' }))).status).toBe(404);
    expect((await s.post(url, body({ itemId: 'i2', duration: 'once' }))).status).toBe(200);
    expect((await s.post(url, body({ itemId: 'i2', duration: 'once' }))).status).toBe(409); // no longer pending
  });

  it('30d approvals expire in at most 30 days', async () => {
    const s = await session();
    const id = await pendingFor(ctx, SITE);
    const g = (await s.post(`/api/requests/${id}/approve`, { itemId: 'i1', duration: '30d', password: PW })).json.grant;
    expect(g.expiresAt - g.createdAt).toBeLessThanOrEqual(30 * 24 * 60 * 60 * 1000);
  });
});

describe('grants, revoke, items and policy', () => {
  it('lists active and recently expired grants; revoke and revoke-all need no password', async () => {
    const s = await session();
    const g1 = await grantFor(ctx, SITE, '1h');
    const g2 = await grantFor(ctx, SITE, '1d', 'agent-b');
    expect((await s.get('/api/grants')).json).toHaveLength(2);
    expect((await s.post(`/api/grants/${g1.id}/revoke`)).json).toEqual({ ok: true });
    expect(ctx.store.getGrant(g1.id)?.revokedAt).not.toBeNull();
    expect((await s.post('/api/grants/revoke-all')).json).toEqual({ revoked: 1 });
    expect(ctx.store.getGrant(g2.id)?.revokedAt).not.toBeNull();
    expect((await s.post('/api/grants/nope/revoke')).status).toBe(404);
    ctx.clock.now += 9 * 24 * 60 * 60 * 1000;
    expect((await (await session()).get('/api/grants')).json).toHaveLength(0); // older than 7 days after expiry
  });

  it('policy change needs the password and revokes now-disallowed grants', async () => {
    const s = await session();
    const g = await grantFor(ctx, SITE, '7d');
    expect((await s.get('/api/items')).json).toEqual(expect.arrayContaining([{ itemId: 'i1', name: 'Example', policy: 'normal', fillConfig: { submit: { kind: 'requestSubmit' } } }]));
    expect((await s.put('/api/items/i1/policy', { policy: 'blocked' })).status).toBe(401);
    expect((await s.put('/api/items/i1/policy', { policy: 'weird', password: PW })).status).toBe(400);
    expect((await s.put('/api/items/nope/policy', { policy: 'blocked', password: PW })).status).toBe(404);
    expect(ctx.store.getGrant(g.id)?.revokedAt).toBeNull();
    expect((await s.put('/api/items/i1/policy', { policy: 'never-long-grant', password: PW })).json).toEqual({ ok: true });
    expect(ctx.store.getGrant(g.id)?.revokedAt).not.toBeNull();
    expect(ctx.store.getPolicy('i1')).toBe('never-long-grant');
  });

  it('fill-config needs the password and a well-formed config', async () => {
    const s = await session();
    await pendingFor(ctx, SITE);
    const url = '/api/items/i1/fill-config';
    const good = { submit: { kind: 'click', selector: '#login' }, usernameSelector: '#u' };
    expect((await s.put(url, { fillConfig: good })).status).toBe(401);
    for (const bad of [{ submit: { kind: 'click' } }, { submit: { kind: 'eval' } }, { submit: { kind: 'enter' }, passwordSelector: 5 }, 'x', null]) {
      expect((await s.put(url, { fillConfig: bad, password: PW })).status).toBe(400);
    }
    expect((await s.put(url, { fillConfig: { ...good, extra: '<script>' }, password: PW })).json).toEqual({ ok: true });
    expect(ctx.store.getFillConfig('i1')).toEqual(good); // unknown fields dropped
  });
});

describe('pairing, status and audit', () => {
  it('pairing confirm/reset need the password', async () => {
    const s = await session();
    const kp = await newExtensionKey();
    expect((await s.get('/api/pairing')).json).toEqual({ status: 'none' });
    const { pairingCode } = await ctx.service.requestPairing(kp.publicKey);
    expect((await s.get('/api/pairing')).json).toEqual({ status: 'pending', pairingCode });
    expect((await s.post('/api/pairing/confirm')).status).toBe(401);
    expect(ctx.service.pairedPublicKey()).toBeNull();
    expect((await s.post('/api/pairing/confirm', { password: PW })).json).toEqual({ ok: true });
    expect((await s.get('/api/status')).json).toEqual({ vault: 'unlocked', fillerConnected: true, pairing: 'paired' });
    expect((await s.post('/api/pairing/reset')).status).toBe(401);
    expect((await s.post('/api/pairing/reset', { password: PW })).json).toEqual({ ok: true });
    expect(ctx.service.pairedPublicKey()).toBeNull();
  });

  it('audit is newest first, honours limit, and contains no password', async () => {
    const s = await session();
    await login('wrong-password-xyz');
    const id = await pendingFor(ctx, SITE);
    await s.post(`/api/requests/${id}/approve`, { itemId: 'i1', duration: '1h', password: PW });
    const all = (await s.get('/api/audit')).json;
    expect(all[0].event).toBe('approve');
    expect(all.map((e: any) => e.event)).toEqual(expect.arrayContaining(['request', 'dashboard_login', 'dashboard_auth_fail']));
    expect((await s.get('/api/audit?limit=2')).json).toHaveLength(2);
    assertNoSecret(all, [PW, 'wrong-password-xyz']);
  });

  it('unknown routes and malformed bodies', async () => {
    const s = await session();
    expect((await s.get('/api/nope')).status).toBe(404);
    expect((await call('POST', '/api/login', { body: ['x'] })).status).toBe(400);
  });
});
