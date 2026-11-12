// Allow-list projections. Every agent-visible value is rebuilt field by field from known keys,
// with types coerced, so anything unexpected in the broker's answer (a buggy or compromised
// broker, a future field, a secret in an unknown key) is dropped before it reaches the model.
import type { GrantStatusResult, GrantSummary, LoginErrorCode, LoginResult, RequestStatus } from '@acb/core';

const LOGIN_ERROR_CODES: ReadonlySet<string> = new Set<LoginErrorCode>([
  'no_filler', 'not_paired', 'no_tab', 'ambiguous_tab', 'origin_mismatch', 'not_top_frame', 'no_form',
  'cross_origin_action', 'submit_failed', 'injection_failed', 'decrypt_failed', 'job_expired', 'timeout',
  'invalid_site', 'insecure_site', 'no_match', 'blocked', 'vault_locked', 'too_many_pending',
]);
// Agent-visible text comes from this fixed table, never from the broker or the extension, so no
// free-text channel exists from the secret side to the model.
const ERROR_TEXT: Record<LoginErrorCode, string> = {
  no_filler: 'The browser extension is not connected.',
  not_paired: 'The browser extension is not paired with the broker.',
  no_tab: 'No open tab has this exact origin. Ask the user to open the login page.',
  ambiguous_tab: 'More than one tab has this origin. Ask the user to close the extras.',
  origin_mismatch: 'The tab origin did not match the approved origin.',
  not_top_frame: 'The login form is inside a frame; filling was refused.',
  no_form: 'No login form was found on the page.',
  cross_origin_action: 'The form submits to another origin; filling was refused.',
  submit_failed: 'The form could not be submitted.',
  injection_failed: 'The extension could not run in the tab.',
  decrypt_failed: 'The extension could not decrypt the credential.',
  job_expired: 'The fill job expired.',
  timeout: 'The fill did not finish in time.',
  invalid_site: 'Site must be an http(s) origin without credentials.',
  insecure_site: 'Plain http is only allowed for local network hosts.',
  no_match: 'No vault item matches this site.',
  blocked: 'Logins for this site are blocked by the user.',
  vault_locked: 'The vault is locked.',
  too_many_pending: 'Too many requests are waiting for approval.',
};
const PENDING_TEXT = 'Waiting for the user to approve this login on the broker dashboard.';
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const id = (v: unknown): string => (typeof v === 'string' && ID_RE.test(v) ? v : '');

const REQUEST_STATUSES: ReadonlySet<string> = new Set<RequestStatus>(['pending', 'approved', 'denied', 'expired']);
const MAX_TEXT = 300;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): string => (typeof v === 'string' ? v : '').slice(0, MAX_TEXT);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

const malformed = (): LoginResult => ({ status: 'error', code: 'no_filler', message: 'Unexpected response from the broker.' });

export function projectLoginResult(raw: unknown): LoginResult {
  if (!isObj(raw)) return malformed();
  switch (raw.status) {
    case 'submitted': {
      const grantExpiresAt = num(raw.grantExpiresAt);
      if (grantExpiresAt === null) return malformed();
      return { status: 'submitted', grantExpiresAt, usesLeft: num(raw.usesLeft) };
    }
    case 'pending':
      return { status: 'pending', requestId: id(raw.requestId), message: PENDING_TEXT };
    case 'denied':
      return { status: 'denied', requestId: id(raw.requestId) };
    case 'error': {
      const code = typeof raw.code === 'string' && LOGIN_ERROR_CODES.has(raw.code) ? (raw.code as LoginErrorCode) : null;
      if (!code) return malformed();
      return { status: 'error', code, message: ERROR_TEXT[code] };
    }
    default:
      return malformed();
  }
}

export function projectGrantStatus(raw: unknown): GrantStatusResult {
  const requestId = isObj(raw) ? id(raw.requestId) : '';
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
