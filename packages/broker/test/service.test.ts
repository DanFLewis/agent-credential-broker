import { describe, expect, it } from 'vitest';
import { assertNoSecret, openSecret, secretAad } from '@acb/core';
import { MAX_PENDING_TOTAL, BrokerError } from '../src/service.js';
import { T_PASS, T_USER, grantFor, item, makeCtx, newExtensionKey, pendingFor } from './helpers.js';

const SITE = 'https://example.com';
const DAY = 24 * 60 * 60 * 1000;
const code = async (p: Promise<unknown> | (() => unknown)) => {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return (e as BrokerError).code;
  }
  return 'none';
};

describe('requestLogin pre-checks', () => {
  it('rejects bad sites, public http, locked vault, no match, blocked', async () => {
    const c = makeCtx();
    expect(await c.service.requestLogin({ site: 'example.com' }, 'a')).toMatchObject({ status: 'error', code: 'invalid_site' });
    expect(await c.service.requestLogin({ site: 'http://example.com' }, 'a')).toMatchObject({ code: 'insecure_site' });
    c.vault.status_ = 'locked';
    expect(await c.service.requestLogin({ site: SITE }, 'a')).toMatchObject({ code: 'vault_locked' });
    c.vault.status_ = 'unlocked';
    expect(await c.service.requestLogin({ site: 'https://nomatch.test' }, 'a')).toMatchObject({ code: 'no_match' });
    await pendingFor(c, SITE);
    c.service.setPolicy('i1', 'blocked');
    expect(await c.service.requestLogin({ site: SITE }, 'b')).toMatchObject({ code: 'blocked' });
  });

  it('allows http on LAN hosts and flags it', async () => {
    const c = makeCtx([item('r1', 'Router', 'http://192.168.50.1')]);
    await pendingFor(c, 'http://192.168.50.1');
    expect(c.notifier.requests[0]?.insecureHttp).toBe(true);
  });

  it('dedupes pending per (agent, origin) and caps at 3 per agent', async () => {
    const origins = ['https://a.test', 'https://b.test', 'https://c.test', 'https://d.test'];
    const c = makeCtx(origins.map((o, i) => item(`i${i}`, `n${i}`, o)));
    const id = await pendingFor(c, origins[0]!);
    expect(await pendingFor(c, origins[0]!)).toBe(id);
    expect(c.store.listAudit().some((e) => e.event === 'request_deduped')).toBe(true);
    await pendingFor(c, origins[1]!);
    await pendingFor(c, origins[2]!);
    expect(await c.service.requestLogin({ site: origins[3]! }, 'agent-a')).toMatchObject({ code: 'too_many_pending' });
    expect(await c.service.requestLogin({ site: origins[3]! }, 'agent-b')).toMatchObject({ status: 'pending' });
  });

  it('caps pending requests globally, so rotating self-asserted agent ids does not help', async () => {
    const c = makeCtx([item('i0', 'n0', 'https://a.test')]);
    for (let i = 0; i < MAX_PENDING_TOTAL; i++) {
      expect(await c.service.requestLogin({ site: 'https://a.test' }, `agent-${i}`)).toMatchObject({ status: 'pending' });
    }
    expect(await c.service.requestLogin({ site: 'https://a.test' }, 'agent-new')).toMatchObject({ code: 'too_many_pending' });
  });

  it('never shows item names or ids to the agent', async () => {
    const c = makeCtx();
    const r = await c.service.requestLogin({ site: SITE }, 'a');
    expect(JSON.stringify(r)).not.toMatch(/Example|i1/);
  });
});

describe('grant matching through requestLogin', () => {
  it('reuses a usable grant (fill job, submitted, grant metadata)', async () => {
    const c = makeCtx();
    const g = await grantFor(c, SITE, '1h');
    const r = await c.service.requestLogin({ site: SITE }, 'agent-a');
    expect(r).toEqual({ status: 'submitted', grantExpiresAt: g.expiresAt, usesLeft: null });
    expect(c.filler.fills).toHaveLength(1);
    expect(c.notifier.uses).toHaveLength(1);
    expect(c.store.listAudit().map((e) => e.event)).toEqual(expect.arrayContaining(['approve', 'fill_job', 'fill_result']));
  });

  it('a different agent gets pending', async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    expect(await c.service.requestLogin({ site: SITE }, 'agent-b')).toMatchObject({ status: 'pending' });
    expect(c.filler.fills).toHaveLength(0);
  });

  it('a different origin gets pending', async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    expect(await c.service.requestLogin({ site: 'https://other.example.com' }, 'agent-a')).toMatchObject({ status: 'pending' });
  });

  it('an expired grant gets pending', async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    c.clock.now += 61 * 60 * 1000;
    expect(await c.service.requestLogin({ site: SITE }, 'agent-a')).toMatchObject({ status: 'pending' });
  });

  it('a revoked grant gets pending', async () => {
    const c = makeCtx();
    const g = await grantFor(c, SITE, '1d');
    c.service.revoke(g.id);
    expect(await c.service.requestLogin({ site: SITE }, 'agent-a')).toMatchObject({ status: 'pending' });
  });

  it('returns no_filler when a grant exists but no filler is connected', async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    c.filler.available = false;
    expect(await c.service.requestLogin({ site: SITE }, 'agent-a')).toMatchObject({ status: 'error', code: 'no_filler' });
  });

  it('propagates filler errors', async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    c.filler.onFill = async () => ({ status: 'error', code: 'no_tab' });
    expect(await c.service.requestLogin({ site: SITE }, 'agent-a')).toMatchObject({ status: 'error', code: 'no_tab' });
  });

  it('a "once" grant is spent after one claimed fill', async () => {
    const c = makeCtx();
    const { publicKey } = await newExtensionKey();
    await grantFor(c, SITE, 'once');
    c.filler.onFill = async (t) => {
      await c.service.claimSecret({ jobId: t.jobId, tabOrigin: SITE, documentId: 'doc1' }, publicKey);
      return { status: 'submitted' };
    };
    expect(await c.service.requestLogin({ site: SITE }, 'agent-a')).toMatchObject({ status: 'submitted', usesLeft: 0 });
    expect(await c.service.requestLogin({ site: SITE }, 'agent-a')).toMatchObject({ status: 'pending' });
  });
});

describe('approve', () => {
  it('requires a candidate item, an allowed duration, a pending request', async () => {
    const c = makeCtx([item('i1', 'A', SITE), item('i2', 'B', SITE)]);
    const id = await pendingFor(c, SITE);
    expect(await code(() => c.service.approve(id, 'not-a-candidate', '1h'))).toBe('invalid_item');
    expect(await code(() => c.service.approve('nope', 'i1', '1h'))).toBe('not_found');
    c.service.setPolicy('i1', 'never-long-grant');
    expect(await code(() => c.service.approve(id, 'i1', '7d'))).toBe('invalid_duration');
    expect(await code(() => c.service.approve(id, 'i1', 'forever' as never))).toBe('invalid_duration');
    expect(c.service.approve(id, 'i1', 'once').maxUses).toBe(1);
    expect(await code(() => c.service.approve(id, 'i1', 'once'))).toBe('request_not_pending');
  });

  it('refuses everything for a blocked item', async () => {
    const c = makeCtx();
    const id = await pendingFor(c, SITE);
    c.service.setPolicy('i1', 'blocked');
    expect(await code(() => c.service.approve(id, 'i1', 'once'))).toBe('invalid_duration');
  });

  it('caps expiry at 30 days and takes agent/origin from the request', async () => {
    const c = makeCtx();
    const g = await grantFor(c, SITE, '30d');
    expect(g.expiresAt - g.createdAt).toBeLessThanOrEqual(30 * DAY);
    expect(g).toMatchObject({ origin: SITE, agentId: 'agent-a', itemName: 'Example', uses: 0, revokedAt: null });
  });

  it('requests expire after 24h', async () => {
    const c = makeCtx();
    const id = await pendingFor(c, SITE);
    c.clock.now += DAY + 1;
    expect(await code(() => c.service.approve(id, 'i1', '1h'))).toBe('request_not_pending');
    expect(await c.service.grantStatus({ requestId: id }, 'agent-a')).toMatchObject({ status: 'expired' });
    expect(c.service.listPendingRequests()).toHaveLength(0);
  });

  it("grantStatus only reveals the caller's own requests", async () => {
    const c = makeCtx();
    const id = await pendingFor(c, SITE);
    expect(await c.service.grantStatus({ requestId: id }, 'agent-b')).toEqual({ requestId: id, status: 'unknown' });
    const g = c.service.approve(id, 'i1', '1h');
    expect(await c.service.grantStatus({ requestId: id }, 'agent-a')).toEqual({ requestId: id, status: 'approved', grantExpiresAt: g.expiresAt });
  });

  it("listGrants shows only the caller's usable grants, without item info", async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    const list = await c.service.listGrants('agent-a');
    expect(list).toHaveLength(1);
    expect(Object.keys(list[0]!).sort()).toEqual(['agentId', 'expiresAt', 'origin', 'usesLeft']);
    expect(await c.service.listGrants('agent-b')).toHaveLength(0);
  });
});

describe('policy changes revoke now-disallowed grants', () => {
  it('blocked revokes all, never-long-grant keeps only once grants', async () => {
    const c = makeCtx([item('i1', 'A', SITE, 'https://x.test')]);
    const long = await grantFor(c, SITE, '7d');
    const once = await grantFor(c, 'https://x.test', 'once');
    expect(c.service.setPolicy('i1', 'never-long-grant')).toBe(1);
    expect(c.store.getGrant(long.id)?.revokedAt).not.toBeNull();
    expect(c.store.getGrant(once.id)?.revokedAt).toBeNull();
    expect(c.service.setPolicy('i1', 'blocked')).toBe(1);
    expect(c.store.getGrant(once.id)?.revokedAt).not.toBeNull();
  });

  it('revokeAll revokes every active grant', async () => {
    const c = makeCtx();
    await grantFor(c, SITE, '1h');
    await grantFor(c, 'https://other.example.com', '1h');
    expect(c.service.revokeAll()).toBe(2);
    expect(c.service.revokeAll()).toBe(0);
  });
});

describe('claimSecret', () => {
  /** Runs requestLogin against a fresh grant; `claim` runs while the fill job is outstanding. */
  async function withJob(claim: (c: ReturnType<typeof makeCtx>, jobId: string, grantId: string, key: string) => Promise<void>) {
    const c = makeCtx();
    const { publicKey } = await newExtensionKey();
    const g = await grantFor(c, SITE, '1h');
    c.filler.onFill = async (t) => {
      await claim(c, t.jobId, g.id, publicKey);
      return { status: 'submitted' };
    };
    await c.service.requestLogin({ site: SITE }, 'agent-a');
    return { c, g };
  }

  it('seals the secret to the paired key with the job-bound AAD, and increments uses once', async () => {
    const kp = await newExtensionKey();
    const c = makeCtx();
    const g = await grantFor(c, SITE, '1h');
    c.filler.onFill = async (t) => {
      // Non-canonical tabOrigin is re-normalised before comparing.
      const res = await c.service.claimSecret({ jobId: t.jobId, tabOrigin: 'HTTPS://EXAMPLE.com/some/path', documentId: 'doc-1' }, kp.publicKey);
      expect(await openSecret(kp.privateKey, res.sealed, secretAad(t.jobId, SITE, 'doc-1'))).toEqual({ username: T_USER, password: T_PASS });
      await expect(openSecret(kp.privateKey, res.sealed, secretAad(t.jobId, SITE, 'doc-2'))).rejects.toThrow(); // wrong documentId
      expect(res.fillConfig.submit.kind).toBe('requestSubmit');
      return { status: 'submitted' };
    };
    await c.service.requestLogin({ site: SITE }, 'agent-a');
    expect(c.store.getGrant(g.id)?.uses).toBe(1);
    expect(c.store.listAudit().some((e) => e.event === 'secret_released')).toBe(true);
  });

  it('is single use', async () => {
    let second = '';
    await withJob(async (c, jobId, _g, key) => {
      await c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, key);
      second = await code(c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, key));
    });
    expect(second).toBe('job_expired');
  });

  it('refuses an unknown job and an expired job', async () => {
    let unknown = '';
    let expired = '';
    await withJob(async (c, jobId, _g, key) => {
      unknown = await code(c.service.claimSecret({ jobId: 'f'.repeat(32), tabOrigin: SITE, documentId: 'd' }, key));
      c.clock.now += 60_001;
      expired = await code(c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, key));
    });
    expect([unknown, expired]).toEqual(['job_expired', 'job_expired']);
  });

  it('refuses a mismatched tabOrigin (http vs https too) without burning the job', async () => {
    const out: string[] = [];
    const { c, g } = await withJob(async (c, jobId, _g, key) => {
      out.push(await code(c.service.claimSecret({ jobId, tabOrigin: 'https://evil.test', documentId: 'd' }, key)));
      out.push(await code(c.service.claimSecret({ jobId, tabOrigin: 'http://example.com', documentId: 'd' }, key)));
      out.push(await code(c.service.claimSecret({ jobId, tabOrigin: 'not a url', documentId: 'd' }, key)));
      await c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, key); // still claimable
    });
    expect(out).toEqual(['origin_mismatch', 'origin_mismatch', 'origin_mismatch']);
    expect(c.store.getGrant(g.id)?.uses).toBe(1);
  });

  it('refuses when not paired', async () => {
    let r = '';
    await withJob(async (c, jobId) => {
      r = await code(c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, null));
    });
    expect(r).toBe('not_paired');
  });

  it('refuses when the grant was revoked between job creation and claim', async () => {
    let r = '';
    const { c, g } = await withJob(async (c, jobId, gid, key) => {
      c.service.revoke(gid);
      r = await code(c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, key));
    });
    expect(r).toBe('grant_revoked');
    expect(c.store.getGrant(g.id)?.uses).toBe(0);
    expect(c.store.listAudit().some((e) => e.event === 'secret_released')).toBe(false);
  });

  it('concurrent claims of one job release the secret only once', async () => {
    const out: string[] = [];
    const { c, g } = await withJob(async (c, jobId, _g, key) => {
      const claim = () => code(c.service.claimSecret({ jobId, tabOrigin: SITE, documentId: 'd' }, key));
      out.push(...(await Promise.all([claim(), claim(), claim()])));
    });
    expect(out.filter((x) => x === 'none')).toHaveLength(1);
    expect(c.store.getGrant(g.id)?.uses).toBe(1);
  });
});

describe('pairing', () => {
  it('pending -> confirm -> paired; a different key cannot displace a paired key', async () => {
    const c = makeCtx();
    const a = await newExtensionKey();
    const b = await newExtensionKey();
    const r = await c.service.requestPairing(a.publicKey);
    expect(r.status).toBe('pending');
    expect(c.service.pairedPublicKey()).toBeNull();
    expect((await c.service.pairingState()).pairingCode).toBe(r.pairingCode);
    await c.service.confirmPairing(r.pairingCode);
    expect(c.service.pairedPublicKey()).toBe(a.publicKey);
    await expect(c.service.requestPairing(b.publicKey)).rejects.toMatchObject({ code: 'already_paired' });
    expect((await c.service.requestPairing(a.publicKey)).status).toBe('paired');
    c.service.resetPairing();
    expect(c.service.pairedPublicKey()).toBeNull();
    expect((await c.service.requestPairing(b.publicKey)).status).toBe('pending');
  });

  it('rejects malformed keys and confirming with nothing pending', async () => {
    const c = makeCtx();
    await expect(c.service.requestPairing('x y')).rejects.toMatchObject({ code: 'bad_params' });
    await expect(c.service.confirmPairing('AAAA-AAAA-AAAA-AAAA')).rejects.toMatchObject({ code: 'no_pending_pairing' });
  });

  it('confirm is bound to the code the human compared: a key swapped in meanwhile is not paired', async () => {
    const c = makeCtx();
    const real = await newExtensionKey();
    const rogue = await newExtensionKey();
    const shown = (await c.service.requestPairing(real.publicKey)).pairingCode;
    await c.service.requestPairing(rogue.publicKey); // rogue filler races in while the human types
    await expect(c.service.confirmPairing(shown)).rejects.toMatchObject({ code: 'pairing_changed' });
    expect(c.service.pairedPublicKey()).toBeNull();
    expect(c.store.listAudit().some((e) => e.event === 'pair_confirm_mismatch')).toBe(true);
    // The real extension re-registers; the human compares again and confirms.
    await c.service.requestPairing(real.publicKey);
    await c.service.confirmPairing(shown);
    expect(c.service.pairedPublicKey()).toBe(real.publicKey);
  });
});

describe('no plaintext secret leaks', () => {
  it('requestLogin -> sealed claim: password absent from audit table, result and notifier', async () => {
    const c = makeCtx();
    const kp = await newExtensionKey();
    await c.service.confirmPairing((await c.service.requestPairing(kp.publicKey)).pairingCode);
    await grantFor(c, SITE, '1h');
    const claimed: unknown[] = [];
    c.filler.onFill = async (t) => {
      claimed.push(await c.service.claimSecret({ jobId: t.jobId, tabOrigin: SITE, documentId: 'd' }, c.service.pairedPublicKey()));
      return { status: 'submitted' };
    };
    const result = await c.service.requestLogin({ site: SITE, hint: 'log me in' }, 'agent-a');
    expect(result.status).toBe('submitted');
    const secrets = [T_PASS, T_USER];
    assertNoSecret(result, secrets);
    assertNoSecret(c.store.listAudit(1000), secrets);
    assertNoSecret(claimed, secrets); // sealed ciphertext only
    assertNoSecret([c.notifier.requests, c.notifier.uses], secrets);
    expect(c.store.listAudit().map((e) => e.event)).toContain('secret_released');
  });
});
