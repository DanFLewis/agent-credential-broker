// Shared domain types and plug-in interfaces for the Agent Credential Broker.
// This file is the contract between packages. It must stay free of Node-only imports
// because the browser extension bundles @acb/core too.

/** Normalised origin: "scheme://host[:port]" as produced by `normalizeOrigin()`. */
export type Origin = string;

/** Self-asserted agent label (from ACB_AGENT_ID). Used for audit/display; not authentication. */
export type AgentId = string;

export type ItemPolicy = 'normal' | 'never-long-grant' | 'blocked';

/** Grant durations a human can pick on the dashboard. 'once' = single use, short expiry. */
export type GrantDuration = 'once' | '1h' | '1d' | '7d' | '30d';

export const MAX_GRANT_MS = 30 * 24 * 60 * 60 * 1000;
/** Expiry window used for 'once' grants. */
export const ONCE_GRANT_MS = 15 * 60 * 1000;

/** Vault item metadata. Never contains secret material. */
export interface VaultItemRef {
  itemId: string;
  name: string;
  /** Exact origins derived from the item's URIs (unparseable URIs are dropped by the adapter). */
  origins: Origin[];
}

/**
 * Secret material. Only ever exists inside the broker process between `getSecret()` and
 * `sealSecret()`. Implementations must make toJSON()/inspect redact the values.
 */
export interface SecretMaterial {
  readonly username: string;
  readonly password: string;
}

export type VaultStatus = 'unlocked' | 'locked' | 'unavailable';

export interface VaultAdapter {
  readonly id: string;
  status(): Promise<VaultStatus>;
  /** Items whose origins contain `site` exactly. `hint` may only rank results, never widen the match. */
  find(hint: string | undefined, site: Origin): Promise<VaultItemRef[]>;
  /** Metadata for one item, or null. */
  getItem(itemId: string): Promise<VaultItemRef | null>;
  /** Broker-internal only. Never call from a frontend. */
  getSecret(itemId: string): Promise<SecretMaterial>;
}

/** How the injected script submits the form. Configured per item by the human, never by the agent. */
export type SubmitStrategy =
  | { kind: 'requestSubmit' }
  | { kind: 'enter' }
  | { kind: 'click'; selector: string };

export interface FillConfig {
  submit: SubmitStrategy;
  /** Optional CSS selectors; when absent the script finds the visible password field and the
   *  nearest preceding text/email input. */
  usernameSelector?: string;
  passwordSelector?: string;
}

export const DEFAULT_FILL_CONFIG: FillConfig = { submit: { kind: 'requestSubmit' } };

/** Opaque reference to a secret; resolved only by the broker on `claimSecret`. */
export interface SecretHandle {
  jobId: string;
}

export interface FillTarget {
  jobId: string;
  origin: Origin;
}

export type FillErrorCode =
  | 'no_filler'
  | 'not_paired'
  | 'no_tab'
  | 'ambiguous_tab'
  | 'origin_mismatch'
  | 'not_top_frame'
  | 'no_form'
  | 'cross_origin_action'
  | 'submit_failed'
  | 'injection_failed'
  | 'decrypt_failed'
  | 'job_expired'
  | 'timeout';

export type FillResult = { status: 'submitted' } | { status: 'error'; code: FillErrorCode; message?: string };

export interface Filler {
  readonly id: string;
  /** True when a filler (e.g. the browser extension via the native host) is connected. */
  isAvailable(): boolean;
  /** Dispatches the job and resolves with the filler's outcome (or a timeout error). */
  fill(target: FillTarget, secret: SecretHandle, timeoutMs: number): Promise<FillResult>;
}

export interface Grant {
  id: string;
  itemId: string;
  /** Snapshot of the item name at approval time (dashboard display only). */
  itemName: string;
  origin: Origin;
  agentId: AgentId;
  createdAt: number; // epoch ms
  expiresAt: number; // epoch ms, <= createdAt + MAX_GRANT_MS
  maxUses: number | null;
  uses: number;
  revokedAt: number | null;
}

export type RequestStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalRequest {
  id: string;
  agentId: AgentId;
  origin: Origin;
  /** Untrusted agent-supplied text. Display escaped. Never used for matching. */
  hint: string | null;
  createdAt: number;
  status: RequestStatus;
  /** Candidate items, fixed server-side at request time. Never sent to the agent. */
  candidates: VaultItemRef[];
  /** Set when approved. */
  grantId: string | null;
  /** True when origin is http: (allowed only for LAN hosts). Dashboard shows a warning. */
  insecureHttp: boolean;
}

export interface UseEvent {
  grantId: string;
  itemName: string;
  origin: Origin;
  agentId: AgentId;
  at: number;
  result: FillResult;
}

export interface Notifier {
  readonly id: string;
  requestApproval(req: ApprovalRequest): Promise<void>;
  notifyUse(ev: UseEvent): Promise<void>;
}

export type AuditEvent =
  | 'request'
  | 'request_deduped'
  | 'approve'
  | 'deny'
  | 'fill_job'
  | 'secret_released'
  | 'fill_result'
  | 'revoke'
  | 'revoke_all'
  | 'policy_change'
  | 'fill_config_change'
  | 'pair_request'
  | 'pair_confirm'
  | 'pair_confirm_mismatch'
  | 'pair_reset'
  | 'vault_unlock'
  | 'dashboard_login'
  | 'dashboard_auth_fail';

export interface AuditEntry {
  id: number;
  ts: number;
  event: AuditEvent;
  agentId: AgentId | null;
  origin: Origin | null;
  itemId: string | null;
  grantId: string | null;
  requestId: string | null;
  /** Free-form metadata. Must never contain secret material. */
  detail: Record<string, unknown> | null;
}

// ---------- Agent-facing results (what MCP tools return). Metadata only. ----------

export type LoginErrorCode =
  | FillErrorCode
  | 'invalid_site'
  | 'insecure_site'
  | 'no_match'
  | 'blocked'
  | 'vault_locked'
  | 'too_many_pending';

export type LoginResult =
  | { status: 'submitted'; grantExpiresAt: number; usesLeft: number | null }
  | { status: 'pending'; requestId: string; message: string }
  | { status: 'denied'; requestId: string }
  | { status: 'error'; code: LoginErrorCode; message: string };

export type GrantStatusResult =
  | { requestId: string; status: RequestStatus; grantExpiresAt?: number }
  | { requestId: string; status: 'unknown' };

/** What `list_grants` returns. Deliberately excludes item names and ids. */
export interface GrantSummary {
  origin: Origin;
  agentId: AgentId;
  expiresAt: number;
  usesLeft: number | null;
}

/** The surface an agent frontend (MCP, later HTTP/CLI) can call. Every method returns metadata only. */
export interface BrokerAgentApi {
  requestLogin(params: { site: string; hint?: string; waitMs?: number }): Promise<LoginResult>;
  grantStatus(params: { requestId: string }): Promise<GrantStatusResult>;
  listGrants(): Promise<GrantSummary[]>;
}

export interface AgentFrontend {
  readonly id: string;
  start(api: BrokerAgentApi): Promise<void>;
  stop(): Promise<void>;
}
