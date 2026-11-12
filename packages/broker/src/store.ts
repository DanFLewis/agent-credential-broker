// SQLite data access (node:sqlite). Holds grants, approval requests, the audit log, per-item
// policy/fill config, the single pairing row and settings (dashboard password hash).
// Nothing in here ever receives secret material.

import { DatabaseSync } from 'node:sqlite';
import type {
  ApprovalRequest,
  AuditEntry,
  AuditEvent,
  FillConfig,
  Grant,
  ItemPolicy,
  RequestStatus,
  VaultItemRef,
} from '@acb/core';
import { DEFAULT_FILL_CONFIG } from '@acb/core';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, item_id TEXT NOT NULL, item_name TEXT NOT NULL, origin TEXT NOT NULL,
  agent_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  max_uses INTEGER, uses INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, origin TEXT NOT NULL, hint TEXT,
  created_at INTEGER NOT NULL, status TEXT NOT NULL, candidates TEXT NOT NULL,
  grant_id TEXT, insecure_http INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, event TEXT NOT NULL,
  agent_id TEXT, origin TEXT, item_id TEXT, grant_id TEXT, request_id TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS item_policy (item_id TEXT PRIMARY KEY, policy TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS item_fill_config (item_id TEXT PRIMARY KEY, config TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pairing (
  id INTEGER PRIMARY KEY CHECK (id = 1), public_key TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

type Row = Record<string, unknown>;

export interface AuditFields {
  agentId?: string | null;
  origin?: string | null;
  itemId?: string | null;
  grantId?: string | null;
  requestId?: string | null;
  detail?: Record<string, unknown> | null;
}

export interface PairingRow {
  publicKey: string;
  status: 'pending' | 'paired';
  createdAt: number;
}

export class GrantStore {
  private readonly db: DatabaseSync;

  /** `path` is a file path, or ':memory:' for tests. */
  constructor(path: string, private readonly clock: () => number = Date.now) {
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
  }

  close(): void {
    this.db.close();
  }

  // ---- audit ----
  audit(event: AuditEvent, f: AuditFields = {}): void {
    this.db
      .prepare('INSERT INTO audit (ts,event,agent_id,origin,item_id,grant_id,request_id,detail) VALUES (?,?,?,?,?,?,?,?)')
      .run(
        this.clock(), event, f.agentId ?? null, f.origin ?? null, f.itemId ?? null,
        f.grantId ?? null, f.requestId ?? null, f.detail ? JSON.stringify(f.detail) : null,
      );
  }

  listAudit(limit = 200): AuditEntry[] {
    const rows = this.db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT ?').all(limit) as Row[];
    return rows.map((r) => ({
      id: r.id as number,
      ts: r.ts as number,
      event: r.event as AuditEvent,
      agentId: (r.agent_id as string | null) ?? null,
      origin: (r.origin as string | null) ?? null,
      itemId: (r.item_id as string | null) ?? null,
      grantId: (r.grant_id as string | null) ?? null,
      requestId: (r.request_id as string | null) ?? null,
      detail: r.detail ? (JSON.parse(r.detail as string) as Record<string, unknown>) : null,
    }));
  }

  // ---- grants ----
  insertGrant(g: Grant): void {
    this.db
      .prepare('INSERT INTO grants (id,item_id,item_name,origin,agent_id,created_at,expires_at,max_uses,uses,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(g.id, g.itemId, g.itemName, g.origin, g.agentId, g.createdAt, g.expiresAt, g.maxUses, g.uses, g.revokedAt);
  }

  getGrant(id: string): Grant | null {
    const r = this.db.prepare('SELECT * FROM grants WHERE id = ?').get(id) as Row | undefined;
    return r ? toGrant(r) : null;
  }

  /** Grants not revoked and not yet expired (use counts are checked by isGrantUsable). */
  listActiveGrants(now: number): Grant[] {
    const rows = this.db.prepare('SELECT * FROM grants WHERE revoked_at IS NULL AND expires_at > ?').all(now) as Row[];
    return rows.map(toGrant);
  }

  /** Active grants plus anything that expired or was revoked since `since`. */
  listGrantsSince(since: number): Grant[] {
    const rows = this.db.prepare('SELECT * FROM grants WHERE expires_at >= ? ORDER BY created_at DESC').all(since) as Row[];
    return rows.map(toGrant);
  }

  listAllGrants(): Grant[] {
    return (this.db.prepare('SELECT * FROM grants').all() as Row[]).map(toGrant);
  }

  /**
   * Atomically consumes one use. The usability conditions live in the UPDATE itself so a grant
   * revoked, expired or exhausted at this instant can never be consumed (no check-then-act gap).
   */
  consumeUse(id: string, now: number): boolean {
    const res = this.db
      .prepare('UPDATE grants SET uses = uses + 1 WHERE id = ? AND revoked_at IS NULL AND expires_at > ? AND (max_uses IS NULL OR uses < max_uses)')
      .run(id, now);
    return Number(res.changes) === 1;
  }

  revokeGrant(id: string, now: number): boolean {
    const res = this.db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL').run(now, id);
    return Number(res.changes) === 1;
  }

  // ---- requests ----
  insertRequest(r: ApprovalRequest): void {
    this.db
      .prepare('INSERT INTO requests (id,agent_id,origin,hint,created_at,status,candidates,grant_id,insecure_http) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(r.id, r.agentId, r.origin, r.hint, r.createdAt, r.status, JSON.stringify(r.candidates), r.grantId, r.insecureHttp ? 1 : 0);
  }

  getRequest(id: string): ApprovalRequest | null {
    const r = this.db.prepare('SELECT * FROM requests WHERE id = ?').get(id) as Row | undefined;
    return r ? toRequest(r) : null;
  }

  /** Pending requests created at or after `notBefore` (older ones are treated as expired). */
  listPendingRequests(notBefore: number): ApprovalRequest[] {
    const rows = this.db
      .prepare("SELECT * FROM requests WHERE status = 'pending' AND created_at >= ? ORDER BY created_at ASC")
      .all(notBefore) as Row[];
    return rows.map(toRequest);
  }

  listAllRequests(): ApprovalRequest[] {
    return (this.db.prepare('SELECT * FROM requests ORDER BY created_at ASC').all() as Row[]).map(toRequest);
  }

  setRequestStatus(id: string, status: RequestStatus, grantId: string | null = null): void {
    this.db.prepare('UPDATE requests SET status = ?, grant_id = ? WHERE id = ?').run(status, grantId, id);
  }

  expireRequestsBefore(notBefore: number): void {
    this.db.prepare("UPDATE requests SET status = 'expired' WHERE status = 'pending' AND created_at < ?").run(notBefore);
  }

  // ---- item policy / fill config ----
  getPolicy(itemId: string): ItemPolicy {
    const r = this.db.prepare('SELECT policy FROM item_policy WHERE item_id = ?').get(itemId) as Row | undefined;
    return (r?.policy as ItemPolicy | undefined) ?? 'normal';
  }

  setPolicy(itemId: string, policy: ItemPolicy): void {
    this.db
      .prepare('INSERT INTO item_policy (item_id,policy) VALUES (?,?) ON CONFLICT(item_id) DO UPDATE SET policy = excluded.policy')
      .run(itemId, policy);
  }

  getFillConfig(itemId: string): FillConfig {
    const r = this.db.prepare('SELECT config FROM item_fill_config WHERE item_id = ?').get(itemId) as Row | undefined;
    return r ? (JSON.parse(r.config as string) as FillConfig) : DEFAULT_FILL_CONFIG;
  }

  setFillConfig(itemId: string, cfg: FillConfig): void {
    this.db
      .prepare('INSERT INTO item_fill_config (item_id,config) VALUES (?,?) ON CONFLICT(item_id) DO UPDATE SET config = excluded.config')
      .run(itemId, JSON.stringify(cfg));
  }

  // ---- pairing ----
  getPairing(): PairingRow | null {
    const r = this.db.prepare('SELECT * FROM pairing WHERE id = 1').get() as Row | undefined;
    return r ? { publicKey: r.public_key as string, status: r.status as 'pending' | 'paired', createdAt: r.created_at as number } : null;
  }

  setPairing(publicKey: string, status: 'pending' | 'paired', createdAt: number): void {
    this.db
      .prepare('INSERT INTO pairing (id,public_key,status,created_at) VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET public_key = excluded.public_key, status = excluded.status, created_at = excluded.created_at')
      .run(publicKey, status, createdAt);
  }

  clearPairing(): void {
    this.db.prepare('DELETE FROM pairing').run();
  }

  // ---- settings ----
  getSetting(key: string): string | null {
    const r = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as Row | undefined;
    return (r?.value as string | undefined) ?? null;
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(key, value);
  }
}

function toGrant(r: Row): Grant {
  return {
    id: r.id as string,
    itemId: r.item_id as string,
    itemName: r.item_name as string,
    origin: r.origin as string,
    agentId: r.agent_id as string,
    createdAt: r.created_at as number,
    expiresAt: r.expires_at as number,
    maxUses: (r.max_uses as number | null) ?? null,
    uses: r.uses as number,
    revokedAt: (r.revoked_at as number | null) ?? null,
  };
}

function toRequest(r: Row): ApprovalRequest {
  return {
    id: r.id as string,
    agentId: r.agent_id as string,
    origin: r.origin as string,
    hint: (r.hint as string | null) ?? null,
    createdAt: r.created_at as number,
    status: r.status as RequestStatus,
    candidates: JSON.parse(r.candidates as string) as VaultItemRef[],
    grantId: (r.grant_id as string | null) ?? null,
    insecureHttp: r.insecure_http === 1,
  };
}
