// DashboardServer: loopback-only HTTP server for the static dashboard UI and its JSON API.
//
// Defences, in the order they run:
//   1. Host header must be exactly 127.0.0.1:<port> or localhost:<port>  (421, defeats DNS rebinding)
//   2. POST/PUT need an Origin of the same two forms                      (403, defeats cross-site requests)
//   3. a valid session cookie                                             (401)
//   4. POST/PUT need the X-ACB-CSRF token matching the session            (403)
//   5. approve / policy / fill-config / pairing need the password again   (401, 429 when rate limited)
// The session cookie alone can therefore only read; it cannot approve anything.

import { timingSafeEqual } from 'node:crypto';
import { createReadStream, promises as fsp } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import type { FillConfig, GrantDuration, ItemPolicy } from '@acb/core';
import { FailureLimiter, SESSION_MAX_MS, SessionStore, parseCookies, verifyPassword, type Session } from './auth.js';
import { BrokerError, type BrokerService } from './service.js';
import type { GrantStore } from './store.js';

export const PASSWORD_SETTING = 'dashboard_password';
const MAX_BODY = 64 * 1024;
const COOKIE = 'acb_session';

const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'";
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
};

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(code);
  }
}

const POLICIES: ItemPolicy[] = ['normal', 'never-long-grant', 'blocked'];
const DURATIONS: GrantDuration[] = ['once', '1h', '1d', '7d', '30d'];
const BROKER_STATUS: Record<string, number> = { not_found: 404, request_not_pending: 409 };

export interface DashboardServerOptions {
  service: BrokerService;
  store: GrantStore;
  publicDir: string;
  /** Port to bind on 127.0.0.1; 0 picks a free one (tests). */
  port: number;
  clock?: () => number;
}

export class DashboardServer {
  private readonly server: http.Server;
  private readonly sessions: SessionStore;
  /**
   * Separate buckets: an unauthenticated local process spamming /api/login must not lock the human
   * (who already has a session) out of approvals. Password checks behind a session need the cookie
   * and CSRF token, so only a session holder can fill that bucket.
   */
  private readonly loginLimiter: FailureLimiter;
  private readonly sessionLimiter: FailureLimiter;
  private readonly clock: () => number;
  private boundPort = 0;

  constructor(private readonly opts: DashboardServerOptions) {
    this.clock = opts.clock ?? Date.now;
    this.sessions = new SessionStore(this.clock);
    this.loginLimiter = new FailureLimiter(this.clock);
    this.sessionLimiter = new FailureLimiter(this.clock);
    this.server = http.createServer((req, res) => void this.handle(req, res));
  }

  get port(): number {
    return this.boundPort;
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.opts.port, '127.0.0.1', () => {
        this.server.off('error', reject);
        resolve();
      });
    });
    this.boundPort = (this.server.address() as { port: number }).port;
    return this.boundPort;
  }

  close(): Promise<void> {
    this.server.closeAllConnections();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  // ------------------------------------------------------------------ plumbing

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    res.setHeader('Content-Security-Policy', CSP);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    try {
      const host = (req.headers.host ?? '').toLowerCase();
      if (host !== `127.0.0.1:${this.port}` && host !== `localhost:${this.port}`) throw new HttpError(421, 'bad_host');
      if (!req.url?.startsWith('/')) throw new HttpError(400, 'bad_path');
      const url = new URL('http://localhost' + req.url); // prefix so a leading "//" stays a path
      if (url.pathname.startsWith('/api/')) await this.api(req, res, url);
      else await this.serveStatic(req, res, url.pathname);
    } catch (e) {
      if (e instanceof HttpError) json(res, e.status, { error: e.code });
      else if (e instanceof BrokerError) json(res, BROKER_STATUS[e.code] ?? 400, { error: e.code });
      else if (!res.headersSent) json(res, 500, { error: 'internal' });
      else res.destroy();
    }
  }

  private async api(req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<void> {
    const method = req.method ?? 'GET';
    const mutating = method === 'POST' || method === 'PUT';
    if (mutating) {
      const origin = req.headers.origin;
      if (origin !== `http://127.0.0.1:${this.port}` && origin !== `http://localhost:${this.port}`) throw new HttpError(403, 'bad_origin');
    }
    const session = this.sessions.get(parseCookies(req.headers.cookie)[COOKIE]);
    const route = `${method} ${url.pathname}`;

    if (route === 'GET /api/session') return json(res, 200, session ? { authenticated: true, csrf: session.csrf } : { authenticated: false });
    if (route === 'POST /api/login') {
      const body = await readBody(req);
      this.checkPassword(body, 'login');
      const s = this.sessions.create();
      this.opts.store.audit('dashboard_login');
      res.setHeader('Set-Cookie', `${COOKIE}=${s.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_MS / 1000}`);
      return json(res, 200, { csrf: s.csrf });
    }

    if (!session) throw new HttpError(401, 'unauthenticated');
    if (mutating && !safeEqual(req.headers['x-acb-csrf'], session.csrf)) throw new HttpError(403, 'bad_csrf');
    const body = mutating ? await readBody(req) : {};
    return this.authed(res, method, url, session, body, route);
  }

  private async authed(res: http.ServerResponse, method: string, url: URL, session: Session, body: Body, route: string): Promise<void> {
    const svc = this.opts.service;

    if (route === 'POST /api/logout') {
      this.sessions.delete(session.id);
      res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
      return json(res, 200, { ok: true });
    }
    if (route === 'GET /api/status') {
      const pairing = await svc.pairingState();
      return json(res, 200, { vault: await svc.vaultStatus(), fillerConnected: svc.fillerConnected(), pairing: pairing.status });
    }
    if (route === 'GET /api/requests') return json(res, 200, svc.listPendingRequests());
    if (route === 'GET /api/grants') return json(res, 200, svc.listDashboardGrants());
    if (route === 'POST /api/grants/revoke-all') return json(res, 200, { revoked: svc.revokeAll() });
    if (route === 'GET /api/audit') {
      const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') ?? '200', 10) || 200, 1), 1000);
      return json(res, 200, this.opts.store.listAudit(limit));
    }
    if (route === 'GET /api/items') return json(res, 200, svc.listItems());
    if (route === 'GET /api/pairing') return json(res, 200, await svc.pairingState());
    if (route === 'POST /api/pairing/confirm') {
      this.checkPassword(body, url.pathname);
      if (typeof body.pairingCode !== 'string') throw new HttpError(400, 'bad_request');
      await svc.confirmPairing(body.pairingCode);
      return json(res, 200, { ok: true });
    }
    if (route === 'POST /api/pairing/reset') {
      this.checkPassword(body, url.pathname);
      svc.resetPairing();
      return json(res, 200, { ok: true });
    }

    let m: RegExpMatchArray | null;
    if ((m = url.pathname.match(/^\/api\/requests\/([^/]+)\/(approve|deny)$/)) && method === 'POST') {
      const id = param(m[1]);
      if (m[2] === 'deny') {
        svc.deny(id);
        return json(res, 200, { ok: true });
      }
      const { itemId, duration } = body;
      if (typeof itemId !== 'string' || typeof duration !== 'string' || !DURATIONS.includes(duration as GrantDuration)) throw new HttpError(400, 'bad_params');
      this.checkPassword(body, url.pathname);
      return json(res, 200, { grant: svc.approve(id, itemId, duration as GrantDuration) });
    }
    if ((m = url.pathname.match(/^\/api\/grants\/([^/]+)\/revoke$/)) && method === 'POST') {
      svc.revoke(param(m[1]));
      return json(res, 200, { ok: true });
    }
    if ((m = url.pathname.match(/^\/api\/items\/([^/]+)\/(policy|fill-config)$/)) && method === 'PUT') {
      const itemId = param(m[1]);
      if (m[2] === 'policy') {
        if (!POLICIES.includes(body.policy as ItemPolicy)) throw new HttpError(400, 'bad_params');
        this.checkPassword(body, url.pathname);
        if (!svc.hasItem(itemId)) throw new HttpError(404, 'not_found');
        svc.setPolicy(itemId, body.policy as ItemPolicy);
      } else {
        const cfg = parseFillConfig(body.fillConfig);
        if (!cfg) throw new HttpError(400, 'bad_params');
        this.checkPassword(body, url.pathname);
        if (!svc.hasItem(itemId)) throw new HttpError(404, 'not_found');
        svc.setFillConfig(itemId, cfg);
      }
      return json(res, 200, { ok: true });
    }
    throw new HttpError(404, 'not_found');
  }

  /** Verifies body.password with rate limiting. Throws 429 / 401 and audits failures. */
  private checkPassword(body: Body, where: string): void {
    const limiter = where === 'login' ? this.loginLimiter : this.sessionLimiter;
    if (limiter.blocked()) throw new HttpError(429, 'rate_limited');
    const stored = this.opts.store.getSetting(PASSWORD_SETTING);
    if (!stored) throw new HttpError(503, 'password_not_set');
    if (typeof body.password !== 'string' || !verifyPassword(body.password, stored)) {
      limiter.recordFailure();
      this.opts.store.audit('dashboard_auth_fail', { detail: { where } }); // never the attempted password
      throw new HttpError(401, 'bad_password');
    }
  }

  // ------------------------------------------------------------------ static files

  private async serveStatic(req: http.IncomingMessage, res: http.ServerResponse, pathname: string): Promise<void> {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
    let rel: string;
    try {
      rel = decodeURIComponent(pathname);
    } catch {
      throw new HttpError(400, 'bad_path');
    }
    if (rel.includes('\0')) throw new HttpError(400, 'bad_path');
    if (rel === '/') rel = '/index.html';

    // Path traversal guard: resolve (and follow symlinks), then require the result to stay under publicDir.
    let root: string;
    let file: string;
    try {
      root = await fsp.realpath(this.opts.publicDir);
      file = await fsp.realpath(path.resolve(root, '.' + rel));
    } catch {
      throw new HttpError(404, 'not_found');
    }
    if (!file.startsWith(root + path.sep)) throw new HttpError(404, 'not_found');
    const st = await fsp.stat(file);
    if (!st.isFile()) throw new HttpError(404, 'not_found');

    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] ?? 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': 'no-cache',
    });
    if (req.method === 'HEAD') return void res.end();
    createReadStream(file).pipe(res);
  }
}

// ---------------------------------------------------------------------- helpers

type Body = Record<string, unknown>;

function json(res: http.ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

async function readBody(req: http.IncomingMessage): Promise<Body> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, 'too_large');
    chunks.push(c as Buffer);
  }
  if (size === 0) return {};
  try {
    const v: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (v && typeof v === 'object' && !Array.isArray(v)) return v as Body;
  } catch {
    /* fall through */
  }
  throw new HttpError(400, 'bad_json');
}

function param(s: string | undefined): string {
  try {
    return decodeURIComponent(s ?? '');
  } catch {
    throw new HttpError(400, 'bad_path');
  }
}

function safeEqual(a: string | string[] | undefined, b: string): boolean {
  if (typeof a !== 'string') return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Rebuilds a FillConfig from untrusted JSON, keeping only known, well-typed fields. */
function parseFillConfig(v: unknown): FillConfig | null {
  const c = v as { submit?: { kind?: unknown; selector?: unknown }; usernameSelector?: unknown; passwordSelector?: unknown } | null;
  if (!c || typeof c !== 'object' || !c.submit) return null;
  const sel = (x: unknown) => (typeof x === 'string' && x.length > 0 && x.length <= 500 ? x : null);
  let submit: FillConfig['submit'];
  if (c.submit.kind === 'requestSubmit' || c.submit.kind === 'enter') submit = { kind: c.submit.kind };
  else if (c.submit.kind === 'click' && sel(c.submit.selector)) submit = { kind: 'click', selector: c.submit.selector as string };
  else return null;
  const out: FillConfig = { submit };
  for (const k of ['usernameSelector', 'passwordSelector'] as const) {
    if (c[k] === undefined) continue;
    const s = sel(c[k]);
    if (!s) return null;
    out[k] = s;
  }
  return out;
}
