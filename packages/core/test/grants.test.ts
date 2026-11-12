import { describe, expect, it } from 'vitest';
import {
  allowedDurations,
  computeExpiry,
  findUsableGrant,
  isGrantUsable,
  toGrantSummary,
  usesLeft,
} from '../src/grants.js';
import { MAX_GRANT_MS, ONCE_GRANT_MS } from '../src/types.js';
import type { Grant } from '../src/types.js';

const NOW = 1_700_000_000_000;
const H = 3_600_000;
const D = 24 * H;

function grant(over: Partial<Grant> = {}): Grant {
  return {
    id: 'g1',
    itemId: 'item-1',
    itemName: 'Router admin',
    origin: 'http://192.168.50.1',
    agentId: 'claude-code',
    createdAt: NOW - H,
    expiresAt: NOW + H,
    maxUses: null,
    uses: 0,
    revokedAt: null,
    ...over,
  };
}

describe('computeExpiry', () => {
  it.each([
    ['once', ONCE_GRANT_MS, 1],
    ['1h', H, null],
    ['1d', D, null],
    ['7d', 7 * D, null],
    ['30d', 30 * D, null],
  ] as const)('%s', (duration, ms, maxUses) => {
    expect(computeExpiry(duration, NOW)).toEqual({ expiresAt: NOW + ms, maxUses });
  });

  it('never exceeds the 30 day cap', () => {
    for (const d of ['once', '1h', '1d', '7d', '30d'] as const) {
      expect(computeExpiry(d, NOW).expiresAt).toBeLessThanOrEqual(NOW + MAX_GRANT_MS);
    }
    expect(computeExpiry('30d', NOW).expiresAt).toBe(NOW + MAX_GRANT_MS);
  });
});

describe('allowedDurations', () => {
  it('normal allows everything', () => {
    expect(allowedDurations('normal')).toEqual(['once', '1h', '1d', '7d', '30d']);
  });
  it('never-long-grant allows only once', () => {
    expect(allowedDurations('never-long-grant')).toEqual(['once']);
  });
  it('blocked allows nothing', () => {
    expect(allowedDurations('blocked')).toEqual([]);
  });
});

describe('isGrantUsable', () => {
  it('is usable just before expiresAt and not at expiresAt', () => {
    const g = grant({ expiresAt: NOW + 1000 });
    expect(isGrantUsable(g, NOW + 999)).toBe(true);
    expect(isGrantUsable(g, NOW + 1000)).toBe(false);
    expect(isGrantUsable(g, NOW + 1001)).toBe(false);
  });
  it('rejects revoked grants', () => {
    expect(isGrantUsable(grant({ revokedAt: NOW - 1 }), NOW)).toBe(false);
    expect(isGrantUsable(grant({ revokedAt: 0 }), NOW)).toBe(false);
  });
  it('enforces use limits', () => {
    expect(isGrantUsable(grant({ maxUses: 1, uses: 0 }), NOW)).toBe(true);
    expect(isGrantUsable(grant({ maxUses: 1, uses: 1 }), NOW)).toBe(false);
    expect(isGrantUsable(grant({ maxUses: 3, uses: 2 }), NOW)).toBe(true);
    expect(isGrantUsable(grant({ maxUses: 3, uses: 4 }), NOW)).toBe(false);
    expect(isGrantUsable(grant({ maxUses: null, uses: 1000 }), NOW)).toBe(true);
  });
});

describe('usesLeft', () => {
  it('is null when unlimited and never negative', () => {
    expect(usesLeft(grant())).toBeNull();
    expect(usesLeft(grant({ maxUses: 3, uses: 1 }))).toBe(2);
    expect(usesLeft(grant({ maxUses: 1, uses: 5 }))).toBe(0);
  });
});

describe('findUsableGrant', () => {
  const q = { origin: 'http://192.168.50.1', agentId: 'claude-code' };

  it('requires exact origin match', () => {
    expect(findUsableGrant([grant()], q, NOW)?.id).toBe('g1');
    expect(findUsableGrant([grant({ origin: 'https://192.168.50.1' })], q, NOW)).toBeNull();
    expect(findUsableGrant([grant({ origin: 'http://192.168.50.1:8080' })], q, NOW)).toBeNull();
    expect(findUsableGrant([grant({ origin: 'http://192.168.50.1.evil.com' })], q, NOW)).toBeNull();
  });

  it('requires the same agent', () => {
    expect(findUsableGrant([grant({ agentId: 'other-agent' })], q, NOW)).toBeNull();
  });

  it('filters by itemIds when given', () => {
    const grants = [grant({ id: 'a', itemId: 'x' }), grant({ id: 'b', itemId: 'y' })];
    expect(findUsableGrant(grants, { ...q, itemIds: ['y'] }, NOW)?.id).toBe('b');
    expect(findUsableGrant(grants, { ...q, itemIds: ['z'] }, NOW)).toBeNull();
    expect(findUsableGrant(grants, { ...q, itemIds: [] }, NOW)).toBeNull();
    expect(findUsableGrant(grants, q, NOW)).not.toBeNull();
  });

  it('skips unusable grants', () => {
    const grants = [
      grant({ id: 'expired', expiresAt: NOW }),
      grant({ id: 'revoked', revokedAt: NOW - 5 }),
      grant({ id: 'spent', maxUses: 1, uses: 1 }),
      grant({ id: 'ok', expiresAt: NOW + 5 * D }),
    ];
    expect(findUsableGrant(grants, q, NOW)?.id).toBe('ok');
  });

  it('picks the soonest-expiring qualifying grant', () => {
    const grants = [
      grant({ id: 'late', expiresAt: NOW + 7 * D }),
      grant({ id: 'soon', expiresAt: NOW + H }),
      grant({ id: 'mid', expiresAt: NOW + D }),
    ];
    expect(findUsableGrant(grants, q, NOW)?.id).toBe('soon');
  });

  it('returns null for an empty list', () => {
    expect(findUsableGrant([], q, NOW)).toBeNull();
  });
});

describe('toGrantSummary', () => {
  it('contains exactly origin, agentId, expiresAt and usesLeft', () => {
    const s = toGrantSummary(grant({ maxUses: 2, uses: 1 }));
    expect(s).toEqual({
      origin: 'http://192.168.50.1',
      agentId: 'claude-code',
      expiresAt: NOW + H,
      usesLeft: 1,
    });
    expect(Object.keys(s).sort()).toEqual(['agentId', 'expiresAt', 'origin', 'usesLeft']);
    const json = JSON.stringify(s);
    expect(json).not.toContain('item-1');
    expect(json).not.toContain('Router admin');
  });
});
