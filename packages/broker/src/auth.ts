// Dashboard authentication primitives: scrypt password hashing, in-memory sessions with CSRF
// tokens, and a failure rate limiter. Nothing here is persisted except the password hash string.

import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const KEYLEN = 32;
const SCRYPT = { N: 16384, r: 8, p: 1 };

/** Format: scrypt$N$r$p$saltB64$hashB64 */
export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, SCRYPT);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), hash.toString('base64')].join('$');
}

export function verifyPassword(password: string, stored: string | null): boolean {
  if (!stored) return false;
  const [kind, n, r, p, saltB64, hashB64] = stored.split('$');
  if (kind !== 'scrypt' || !n || !r || !p || !saltB64 || !hashB64) return false;
  const expected = Buffer.from(hashB64, 'base64');
  const actual = scryptSync(password, Buffer.from(saltB64, 'base64'), expected.length, { N: +n, r: +r, p: +p });
  return timingSafeEqual(actual, expected); // constant-time compare
}

export const SESSION_MAX_MS = 8 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 30 * 60 * 1000;

export interface Session {
  id: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();
  constructor(private readonly clock: () => number = Date.now) {}

  create(): Session {
    const now = this.clock();
    const s: Session = { id: randomBytes(32).toString('base64url'), csrf: randomBytes(32).toString('base64url'), createdAt: now, lastSeen: now };
    this.sessions.set(s.id, s);
    return s;
  }

  /** Returns the live session (and refreshes its idle timer), or null if unknown/expired. */
  get(id: string | undefined): Session | null {
    if (!id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    const now = this.clock();
    if (now - s.createdAt >= SESSION_MAX_MS || now - s.lastSeen >= SESSION_IDLE_MS) {
      this.sessions.delete(id);
      return null;
    }
    s.lastSeen = now;
    return s;
  }

  delete(id: string): void {
    this.sessions.delete(id);
  }
}

/** Counts password failures in a sliding window. The dashboard is loopback-only, so one global bucket suffices. */
export class FailureLimiter {
  private failures: number[] = [];
  constructor(private readonly clock: () => number = Date.now, private readonly max = 5, private readonly windowMs = 60_000) {}

  blocked(): boolean {
    const cutoff = this.clock() - this.windowMs;
    this.failures = this.failures.filter((t) => t > cutoff);
    return this.failures.length >= this.max;
  }

  recordFailure(): void {
    this.failures.push(this.clock());
  }
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
