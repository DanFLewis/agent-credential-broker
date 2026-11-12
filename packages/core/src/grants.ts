// Pure grant logic: expiry computation, policy -> allowed durations, matching.

import type { AgentId, Grant, GrantDuration, GrantSummary, ItemPolicy, Origin } from './types.js';
import { MAX_GRANT_MS, ONCE_GRANT_MS } from './types.js';

const HOUR = 60 * 60 * 1000;
const DURATION_MS: Record<Exclude<GrantDuration, 'once'>, number> = {
  '1h': HOUR,
  '1d': 24 * HOUR,
  '7d': 7 * 24 * HOUR,
  '30d': 30 * 24 * HOUR,
};

export function computeExpiry(duration: GrantDuration, now: number): { expiresAt: number; maxUses: number | null } {
  const ms = duration === 'once' ? ONCE_GRANT_MS : DURATION_MS[duration];
  return {
    expiresAt: now + Math.min(ms, MAX_GRANT_MS), // hard cap, whatever the table says
    maxUses: duration === 'once' ? 1 : null,
  };
}

export function allowedDurations(policy: ItemPolicy): GrantDuration[] {
  switch (policy) {
    case 'normal':
      return ['once', '1h', '1d', '7d', '30d'];
    case 'never-long-grant':
      return ['once'];
    case 'blocked':
      return [];
  }
}

export function isGrantUsable(g: Grant, now: number): boolean {
  return g.revokedAt === null && now < g.expiresAt && (g.maxUses === null || g.uses < g.maxUses);
}

/** Origin must match exactly (both already normalised) and the agent must be the same. */
export function findUsableGrant(
  grants: Grant[],
  q: { origin: Origin; agentId: AgentId; itemIds?: string[] },
  now: number,
): Grant | null {
  let best: Grant | null = null;
  for (const g of grants) {
    if (g.origin !== q.origin || g.agentId !== q.agentId) continue;
    if (q.itemIds && !q.itemIds.includes(g.itemId)) continue;
    if (!isGrantUsable(g, now)) continue;
    if (best === null || g.expiresAt < best.expiresAt) best = g;
  }
  return best;
}

export function usesLeft(g: Grant): number | null {
  return g.maxUses === null ? null : Math.max(0, g.maxUses - g.uses);
}

/** Agent-visible projection. Copies named fields only, so no item id or name can leak. */
export function toGrantSummary(g: Grant): GrantSummary {
  return { origin: g.origin, agentId: g.agentId, expiresAt: g.expiresAt, usesLeft: usesLeft(g) };
}
