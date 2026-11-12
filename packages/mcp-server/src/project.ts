// Allow-list projections. Every agent-visible value is rebuilt field by field from known keys,
// with types coerced, so anything unexpected in the broker's answer (a buggy or compromised
// broker, a future field, a secret in an unknown key) is dropped before it reaches the model.
import type { GrantStatusResult, GrantSummary, LoginErrorCode, LoginResult, RequestStatus } from '@acb/core';

const LOGIN_ERROR_CODES: ReadonlySet<string> = new Set<LoginErrorCode>([
  'no_filler', 'not_paired', 'no_tab', 'ambiguous_tab', 'origin_mismatch', 'not_top_frame', 'no_form',
  'cross_origin_action', 'submit_failed', 'injection_failed', 'decrypt_failed', 'job_expired', 'timeout',
  'invalid_site', 'insecure_site', 'no_match', 'blocked', 'vault_locked', 'too_many_pending',
]);
const REQUEST_STATUSES: ReadonlySet<string> = new Set<RequestStatus>(['pending', 'approved', 'denied', 'expired']);
const MAX_TEXT = 300;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): string => (typeof v === 'string' ? v : '').slice(0, MAX_TEXT);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

const malformed = (): LoginResult => ({ status: 'error', code: 'no_filler', message: 'Unexpected response from broker' });

export function projectLoginResult(raw: unknown): LoginResult {
  if (!isObj(raw)) return malformed();
  switch (raw.status) {
    case 'submitted': {
      const grantExpiresAt = num(raw.grantExpiresAt);
      if (grantExpiresAt === null) return malformed();
      return { status: 'submitted', grantExpiresAt, usesLeft: num(raw.usesLeft) };
    }
    case 'pending':
      return { status: 'pending', requestId: text(raw.requestId), message: text(raw.message) };
    case 'denied':
      return { status: 'denied', requestId: text(raw.requestId) };
    case 'error': {
      const code = typeof raw.code === 'string' && LOGIN_ERROR_CODES.has(raw.code) ? (raw.code as LoginErrorCode) : null;
      if (!code) return malformed();
      return { status: 'error', code, message: text(raw.message) };
    }
    default:
      return malformed();
  }
}

export function projectGrantStatus(raw: unknown): GrantStatusResult {
  const requestId = isObj(raw) ? text(raw.requestId) : '';
  if (!isObj(raw) || typeof raw.status !== 'string' || !REQUEST_STATUSES.has(raw.status)) {
    return { requestId, status: 'unknown' };
  }
  const out: GrantStatusResult = { requestId, status: raw.status as RequestStatus };
  const exp = num(raw.grantExpiresAt);
  if (exp !== null) out.grantExpiresAt = exp;
  return out;
}

export function projectGrantSummaries(raw: unknown): GrantSummary[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(isObj).map((g) => ({
    origin: text(g.origin),
    agentId: text(g.agentId),
    expiresAt: num(g.expiresAt) ?? 0,
    usesLeft: num(g.usesLeft),
  }));
}
