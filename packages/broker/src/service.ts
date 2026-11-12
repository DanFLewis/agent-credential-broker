// BrokerService: the policy engine. Agent-facing (requestLogin/grantStatus/listGrants),
// filler-facing (claimSecret, pairing) and dashboard-facing (approve, revoke, policy, ...) methods.
//
// Security notes:
//  - Secrets exist only inside claimSecret(), between vault.getSecret() and sealSecret().
//  - Nothing here puts item names or ids into an agent-facing result.
//  - Audit detail never includes hints, credentials or sealed data.

import { randomBytes, randomUUID } from 'node:crypto';
import {
  MAX_GRANT_MS,
  allowedDurations,
  classifyOrigin,
  computeExpiry,
  findUsableGrant,
  isGrantUsable,
  normalizeOrigin,
  pairingCode,
  sealSecret,
  secretAad,
  toGrantSummary,
  usesLeft,
} from '@acb/core';
import type {
  ApprovalRequest,
  BrokerAgentApi,
  ClaimSecretParams,
  ClaimSecretResult,
  FillConfig,
  Filler,
  Grant,
  GrantDuration,
  GrantStatusResult,
  GrantSummary,
  ItemPolicy,
  LoginResult,
  Notifier,
  Origin,
  PairResult,
  VaultAdapter,
  VaultStatus,
} from '@acb/core';
import type { GrantStore } from './store.js';

export const REQUEST_TTL_MS = 24 * 60 * 60 * 1000;
export const JOB_TTL_MS = 60 * 1000;
export const MAX_PENDING_PER_AGENT = 3;
/** Agent ids are self-asserted, so the per-agent cap alone can be dodged by rotating ids. */
export const MAX_PENDING_TOTAL = 10;
const DEFAULT_WAIT_MS = 20_000;
const MAX_WAIT_MS = 60_000;
const MAX_HINT_LEN = 500;

/** An error with a stable machine code and a generic, secret-free message. */
export class BrokerError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'BrokerError';
  }
}

interface FillJob {
  grantId: string;
  itemId: string;
  origin: Origin;
  agentId: string;
  expiresAt: number;
  claimed: boolean;
}

export interface BrokerServiceOptions {
  store: GrantStore;
  vault: VaultAdapter;
  filler: Filler;
  notifier: Notifier;
  clock?: () => number;
}

export interface ItemInfo {
  itemId: string;
  name: string;
  policy: ItemPolicy;
  fillConfig: FillConfig;
}

export class BrokerService implements BrokerAgentApi {
  private readonly store: GrantStore;
  private readonly vault: VaultAdapter;
  private readonly filler: Filler;
  private readonly notifier: Notifier;
  private readonly clock: () => number;
  private readonly jobs = new Map<string, FillJob>();

  constructor(opts: BrokerServiceOptions) {
    this.store = opts.store;
    this.vault = opts.vault;
    this.filler = opts.filler;
    this.notifier = opts.notifier;
    this.clock = opts.clock ?? Date.now;
  }

  // ------------------------------------------------------------------ agent API

  async requestLogin(params: { site: string; hint?: string; waitMs?: number }, agentId = 'unknown'): Promise<LoginResult> {
    const fail = (code: Extract<LoginResult, { status: 'error' }>['code'], message: string): LoginResult => ({ status: 'error', code, message });
    const now = this.clock();

    const origin = normalizeOrigin(params.site);
    if (!origin) return fail('invalid_site', 'Site must be an http(s) origin without credentials.');
    const cls = classifyOrigin(origin);
    if (cls === 'http-public') return fail('insecure_site', 'Plain http is only allowed for local network hosts.');

    if ((await this.vaultStatus()) !== 'unlocked') return fail('vault_locked', 'The vault is locked.');

    const hint = typeof params.hint === 'string' ? params.hint.slice(0, MAX_HINT_LEN) : undefined;
    // Belt and braces: the adapter must exact-match, but we re-check here.
    const found = (await this.vault.find(hint, origin)).filter((c) => c.origins.includes(origin));
    if (found.length === 0) return fail('no_match', 'No vault item matches this site.');
    const candidates = found.filter((c) => this.store.getPolicy(c.itemId) !== 'blocked');
    if (candidates.length === 0) return fail('blocked', 'Logins for this site are blocked by the user.');

    const grant = findUsableGrant(
      this.store.listActiveGrants(now),
      { origin, agentId, itemIds: candidates.map((c) => c.itemId) },
      now,
    );
    if (grant) return this.fillWithGrant(grant, origin, agentId, params.waitMs);

    // No grant: ask the human. Dedupe per (agent, origin) and cap pending requests per agent.
    const allPending = this.store.listPendingRequests(now - REQUEST_TTL_MS);
    const pending = allPending.filter((r) => r.agentId === agentId);
    const existing = pending.find((r) => r.origin === origin);
    if (existing) {
      this.store.audit('request_deduped', { agentId, origin, requestId: existing.id });
      return pendingResult(existing.id);
    }
    if (pending.length >= MAX_PENDING_PER_AGENT || allPending.length >= MAX_PENDING_TOTAL) return fail('too_many_pending', 'Too many requests are waiting for approval.');

    const req: ApprovalRequest = {
      id: randomUUID(), agentId, origin, hint: hint ?? null, createdAt: now, status: 'pending',
      candidates, grantId: null, insecureHttp: cls === 'http-lan',
    };
    this.store.insertRequest(req);
    this.store.audit('request', { agentId, origin, requestId: req.id, detail: { candidates: candidates.length } });
    await this.notifier.requestApproval(req).catch(() => undefined);
    return pendingResult(req.id);
  }

  private async fillWithGrant(grant: Grant, origin: Origin, agentId: string, waitMs?: number): Promise<LoginResult> {
    if (!this.filler.isAvailable()) {
      return { status: 'error', code: 'no_filler', message: 'The browser extension is not connected.' };
    }
    const now = this.clock();
    const jobId = randomBytes(16).toString('hex'); // 128-bit, unguessable
    this.pruneJobs(now);
    this.jobs.set(jobId, { grantId: grant.id, itemId: grant.itemId, origin, agentId, expiresAt: now + JOB_TTL_MS, claimed: false });
    this.store.audit('fill_job', { agentId, origin, itemId: grant.itemId, grantId: grant.id, detail: { jobId } });

    const timeout = Math.min(Math.max(waitMs ?? DEFAULT_WAIT_MS, 1), MAX_WAIT_MS);
    let result;
    try {
      result = await this.filler.fill({ jobId, origin }, { jobId }, timeout);
    } finally {
      this.jobs.delete(jobId);
    }
    this.store.audit('fill_result', {
      agentId, origin, itemId: grant.itemId, grantId: grant.id,
      detail: result.status === 'submitted' ? { status: 'submitted' } : { status: 'error', code: result.code },
    });
    if (result.status === 'error') return { status: 'error', code: result.code, message: 'The browser extension could not fill the login form.' };

    const fresh = this.store.getGrant(grant.id) ?? grant;
    await this.notifier
      .notifyUse({ grantId: grant.id, itemName: grant.itemName, origin, agentId, at: this.clock(), result })
      .catch(() => undefined);
    return { status: 'submitted', grantExpiresAt: fresh.expiresAt, usesLeft: usesLeft(fresh) };
  }

  async grantStatus(params: { requestId: string }, agentId = 'unknown'): Promise<GrantStatusResult> {
    const req = this.store.getRequest(params.requestId);
    // Another agent's request id is indistinguishable from a nonexistent one.
    if (!req || req.agentId !== agentId) return { requestId: params.requestId, status: 'unknown' };
    if (req.status === 'pending' && req.createdAt < this.clock() - REQUEST_TTL_MS) return { requestId: req.id, status: 'expired' };
    if (req.status === 'approved' && req.grantId) {
      const g = this.store.getGrant(req.grantId);
      return g ? { requestId: req.id, status: 'approved', grantExpiresAt: g.expiresAt } : { requestId: req.id, status: 'approved' };
    }
    return { requestId: req.id, status: req.status };
  }

  /** Only the calling agent's currently usable grants, without item names or ids. */
  async listGrants(agentId = 'unknown'): Promise<GrantSummary[]> {
    const now = this.clock();
    return this.store
      .listActiveGrants(now)
      .filter((g) => g.agentId === agentId && isGrantUsable(g, now))
      .map(toGrantSummary);
  }

  // ------------------------------------------------------------------ filler API

  /**
   * Releases a secret, sealed to the paired extension key, for exactly one fill job.
   * All checks run before the job is marked claimed, so a bogus claim cannot burn a real job.
   */
  async claimSecret(params: ClaimSecretParams, pairedPublicKey: string | null): Promise<ClaimSecretResult> {
    if (!pairedPublicKey) throw new BrokerError('not_paired', 'The extension is not paired.');
    if (typeof params?.jobId !== 'string' || typeof params.tabOrigin !== 'string' || typeof params.documentId !== 'string' || !params.documentId) {
      throw new BrokerError('bad_params', 'Invalid parameters.');
    }
    const now = this.clock();
    const job = this.jobs.get(params.jobId);
    if (!job || job.claimed || now >= job.expiresAt) throw new BrokerError('job_expired', 'Unknown, used or expired job.');
    // Re-normalise: never trust the extension's string to be canonical.
    if (normalizeOrigin(params.tabOrigin) !== job.origin) throw new BrokerError('origin_mismatch', 'Tab origin does not match the job.');

    job.claimed = true; // synchronous with the checks above: single use even under concurrency
    // Atomic "grant still usable" check + use increment (revoked/expired/exhausted since job creation -> refused).
    if (!this.store.consumeUse(job.grantId, now)) throw new BrokerError('grant_revoked', 'The grant is no longer usable.');

    let sealed;
    try {
      const secret = await this.vault.getSecret(job.itemId);
      sealed = await sealSecret(
        pairedPublicKey,
        { username: secret.username, password: secret.password },
        secretAad(params.jobId, job.origin, params.documentId),
      );
    } catch {
      throw new BrokerError('vault_error', 'Could not release the secret.'); // generic: the cause may mention secrets
    }
    this.store.audit('secret_released', { agentId: job.agentId, origin: job.origin, itemId: job.itemId, grantId: job.grantId, detail: { jobId: params.jobId } });
    return { jobId: params.jobId, sealed, fillConfig: this.store.getFillConfig(job.itemId) };
  }

  // ------------------------------------------------------------------ pairing

  async requestPairing(publicKey: string): Promise<PairResult> {
    if (typeof publicKey !== 'string' || !/^[A-Za-z0-9_-]{20,200}$/.test(publicKey)) throw new BrokerError('bad_params', 'Invalid public key.');
    const cur = this.store.getPairing();
    if (cur?.status === 'paired' && cur.publicKey !== publicKey) {
      // A rogue filler must not displace a confirmed key; the human resets pairing first.
      throw new BrokerError('already_paired', 'Already paired with a different key.');
    }
    const code = await pairingCode(publicKey);
    if (cur?.status === 'paired') return { status: 'paired', pairingCode: code };
    if (cur?.publicKey !== publicKey) {
      this.store.setPairing(publicKey, 'pending', this.clock());
      this.store.audit('pair_request', { detail: { pairingCode: code } });
    }
    return { status: 'pending', pairingCode: code };
  }

  async pairingState(): Promise<{ status: 'none' | 'pending' | 'paired'; pairingCode?: string }> {
    const p = this.store.getPairing();
    return p ? { status: p.status, pairingCode: await pairingCode(p.publicKey) } : { status: 'none' };
  }

  pairedPublicKey(): string | null {
    const p = this.store.getPairing();
    return p?.status === 'paired' ? p.publicKey : null;
  }

  /**
   * Confirms the pending key only if its code equals the one the human compared. Without this
   * binding, a process on the pipe could swap in its own pending key while the human types the
   * password, and the click would pair the attacker's key.
   */
  async confirmPairing(expectedCode: string): Promise<void> {
    const p = this.store.getPairing();
    if (p?.status !== 'pending') throw new BrokerError('no_pending_pairing', 'No pairing is waiting for confirmation.');
    const code = await pairingCode(p.publicKey);
    // Re-read after the await: the pending row must be the same one we hashed.
    const now = this.store.getPairing();
    if (typeof expectedCode !== 'string' || code !== expectedCode || now?.publicKey !== p.publicKey || now.status !== 'pending') {
      this.store.audit('pair_confirm_mismatch');
      throw new BrokerError('pairing_changed', 'The pending pairing code changed. Compare the codes again.');
    }
    this.store.setPairing(p.publicKey, 'paired', p.createdAt);
    this.store.audit('pair_confirm', { detail: { pairingCode: code } });
  }

  resetPairing(): void {
    this.store.clearPairing();
    this.store.audit('pair_reset');
  }

  // ------------------------------------------------------------------ dashboard API

  async vaultStatus(): Promise<VaultStatus> {
    try {
      return await this.vault.status();
    } catch {
      return 'unavailable';
    }
  }

  fillerConnected(): boolean {
    return this.filler.isAvailable();
  }

  /** Pending, unexpired requests; each candidate carries its policy and the durations the human may pick. */
  listPendingRequests() {
    const now = this.clock();
    this.store.expireRequestsBefore(now - REQUEST_TTL_MS);
    return this.store.listPendingRequests(now - REQUEST_TTL_MS).map((r) => ({
      ...r,
      candidates: r.candidates.map((c) => {
        const policy = this.store.getPolicy(c.itemId);
        return { ...c, policy, allowedDurations: allowedDurations(policy) };
      }),
    }));
  }

  approve(requestId: string, itemId: string, duration: GrantDuration): Grant {
    const now = this.clock();
    const req = this.store.getRequest(requestId);
    if (!req) throw new BrokerError('not_found', 'Unknown request.');
    if (req.status !== 'pending' || req.createdAt < now - REQUEST_TTL_MS) throw new BrokerError('request_not_pending', 'Request is no longer pending.');
    // The itemId must come from the candidate list fixed at request time.
    const item = req.candidates.find((c) => c.itemId === itemId);
    if (!item) throw new BrokerError('invalid_item', 'Item is not a candidate for this request.');
    const policy = this.store.getPolicy(itemId);
    if (!allowedDurations(policy).includes(duration)) throw new BrokerError('invalid_duration', 'Duration not allowed by the item policy.');

    const exp = computeExpiry(duration, now);
    const grant: Grant = {
      id: randomUUID(), itemId, itemName: item.name, origin: req.origin, agentId: req.agentId,
      createdAt: now, expiresAt: Math.min(exp.expiresAt, now + MAX_GRANT_MS), maxUses: exp.maxUses, uses: 0, revokedAt: null,
    };
    this.store.insertGrant(grant);
    this.store.setRequestStatus(req.id, 'approved', grant.id);
    this.store.audit('approve', {
      agentId: req.agentId, origin: req.origin, itemId, grantId: grant.id, requestId: req.id,
      detail: { duration, expiresAt: grant.expiresAt },
    });
    return grant;
  }

  deny(requestId: string): void {
    const req = this.store.getRequest(requestId);
    if (!req) throw new BrokerError('not_found', 'Unknown request.');
    if (req.status !== 'pending') throw new BrokerError('request_not_pending', 'Request is no longer pending.');
    this.store.setRequestStatus(req.id, 'denied');
    this.store.audit('deny', { agentId: req.agentId, origin: req.origin, requestId: req.id });
  }

  /** Dashboard view: active grants and those that expired within the last 7 days. */
  listDashboardGrants(): Grant[] {
    return this.store.listGrantsSince(this.clock() - 7 * 24 * 60 * 60 * 1000);
  }

  revoke(grantId: string): void {
    const g = this.store.getGrant(grantId);
    if (!g) throw new BrokerError('not_found', 'Unknown grant.');
    if (this.store.revokeGrant(grantId, this.clock())) {
      this.store.audit('revoke', { agentId: g.agentId, origin: g.origin, itemId: g.itemId, grantId });
    }
  }

  revokeAll(): number {
    const now = this.clock();
    const active = this.store.listActiveGrants(now);
    let n = 0;
    for (const g of active) if (this.store.revokeGrant(g.id, now)) n++;
    this.store.audit('revoke_all', { detail: { revoked: n } });
    return n;
  }

  /** Items the broker has seen in requests or grants, with their policy and fill config. */
  listItems(): ItemInfo[] {
    const names = new Map<string, string>();
    for (const r of this.store.listAllRequests()) for (const c of r.candidates) names.set(c.itemId, c.name);
    for (const g of this.store.listAllGrants()) names.set(g.itemId, g.itemName);
    return [...names].map(([itemId, name]) => ({
      itemId, name, policy: this.store.getPolicy(itemId), fillConfig: this.store.getFillConfig(itemId),
    }));
  }

  hasItem(itemId: string): boolean {
    return this.listItems().some((i) => i.itemId === itemId);
  }

  /** Sets the policy and revokes the item's grants that the new policy no longer allows. Returns the revoked count. */
  setPolicy(itemId: string, policy: ItemPolicy): number {
    const now = this.clock();
    this.store.setPolicy(itemId, policy);
    this.store.audit('policy_change', { itemId, detail: { policy } });
    const allowed = allowedDurations(policy);
    let n = 0;
    for (const g of this.store.listActiveGrants(now)) {
      if (g.itemId !== itemId) continue;
      // A grant is "once" when it has a single use; anything else is a long grant.
      const stillAllowed = allowed.includes(g.maxUses === 1 ? 'once' : '1h');
      if (!stillAllowed && this.store.revokeGrant(g.id, now)) {
        n++;
        this.store.audit('revoke', { agentId: g.agentId, origin: g.origin, itemId, grantId: g.id, detail: { reason: 'policy' } });
      }
    }
    return n;
  }

  setFillConfig(itemId: string, cfg: FillConfig): void {
    this.store.setFillConfig(itemId, cfg);
    this.store.audit('fill_config_change', { itemId, detail: { submit: cfg.submit.kind } });
  }

  private pruneJobs(now: number): void {
    for (const [id, j] of this.jobs) if (now >= j.expiresAt) this.jobs.delete(id);
  }
}

function pendingResult(requestId: string): LoginResult {
  return {
    status: 'pending', requestId,
    message: 'Waiting for the user to approve this login on the broker dashboard. Retry or check grant_status later.',
  };
}
