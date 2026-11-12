import { describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { assertNoSecret } from '@acb/core';
import type { BrokerAgentApi } from '@acb/core';
import { createServer } from '../src/server.js';

const SECRETS = ['test-user', 'correct-horse-test-only', 'item-id-123', 'Bank Login Item'];
const stuff = {
  password: SECRETS[1],
  username: SECRETS[0],
  secret: SECRETS[1],
  itemName: SECRETS[3],
  itemId: SECRETS[2],
  nested: { password: SECRETS[1], deep: { username: SECRETS[0] } },
  weird_key: `x ${SECRETS[1]} y`,
};

// A hostile broker: every answer is padded with secrets in known and unknown keys.
const evil: BrokerAgentApi = {
  requestLogin: async (p) =>
    (p.site === 'https://pending.test'
      ? { status: 'pending', requestId: 'r1', message: 'Approve it', ...stuff }
      : { status: 'submitted', grantExpiresAt: 123, usesLeft: 2, ...stuff }) as never,
  grantStatus: async () => ({ requestId: 'r1', status: 'approved', grantExpiresAt: 99, ...stuff }) as never,
  listGrants: async () => [{ origin: 'https://a.test', agentId: 'x', expiresAt: 5, usesLeft: null, ...stuff }] as never,
};

async function connect(api: BrokerAgentApi) {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await createServer(api).connect(st);
  const client = new Client({ name: 't', version: '0' });
  await client.connect(ct);
  return client;
}

const ALLOWED_LOGIN = ['status', 'grantExpiresAt', 'usesLeft', 'requestId', 'message'];
const ALLOWED_STATUS = ['requestId', 'status', 'grantExpiresAt'];
const ALLOWED_GRANT = ['origin', 'agentId', 'expiresAt', 'usesLeft'];
const keysOf = (o: unknown) => Object.keys(o as object);

describe('no secret in MCP responses', () => {
  it('lists exactly the three tools', async () => {
    const { tools } = await (await connect(evil)).listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['grant_status', 'list_grants', 'request_login']);
  });

  it('request_login (submitted and pending) is projected', async () => {
    const c = await connect(evil);
    for (const site of ['https://ok.test', 'https://pending.test']) {
      const r = await c.callTool({ name: 'request_login', arguments: { site } });
      assertNoSecret(r, SECRETS);
      const sc = r.structuredContent as Record<string, unknown>;
      keysOf(sc).forEach((k) => expect(ALLOWED_LOGIN).toContain(k));
      expect(JSON.parse((r.content as { text: string }[])[0].text)).toEqual(sc);
    }
  });

  it('grant_status is projected', async () => {
    const r = await (await connect(evil)).callTool({ name: 'grant_status', arguments: { request_id: 'r1' } });
    assertNoSecret(r, SECRETS);
    expect(r.structuredContent).toEqual({ requestId: 'r1', status: 'approved', grantExpiresAt: 99 });
    keysOf(r.structuredContent).forEach((k) => expect(ALLOWED_STATUS).toContain(k));
  });

  it('list_grants is projected', async () => {
    const r = await (await connect(evil)).callTool({ name: 'list_grants', arguments: {} });
    assertNoSecret(r, SECRETS);
    const grants = (r.structuredContent as { grants: unknown[] }).grants;
    expect(grants).toEqual([{ origin: 'https://a.test', agentId: 'x', expiresAt: 5, usesLeft: null }]);
    grants.forEach((g) => keysOf(g).forEach((k) => expect(ALLOWED_GRANT).toContain(k)));
  });

  it('garbage from the broker becomes a safe result', async () => {
    const api: BrokerAgentApi = {
      requestLogin: async () => ({ status: 'error', code: SECRETS[1], message: 'm', password: SECRETS[1] }) as never,
      grantStatus: async () => 'junk' as never,
      listGrants: async () => 'junk' as never,
    };
    const c = await connect(api);
    const calls = [
      ['request_login', { site: 'https://a.test' }],
      ['grant_status', { request_id: 'x' }],
      ['list_grants', {}],
    ] as const;
    for (const [name, args] of calls) assertNoSecret(await c.callTool({ name, arguments: args }), SECRETS);
  });

  it('thrown errors do not leak their message', async () => {
    const api: BrokerAgentApi = {
      ...evil,
      listGrants: async () => {
        throw new Error(`boom ${SECRETS[1]}`);
      },
    };
    const r = await (await connect(api)).callTool({ name: 'list_grants', arguments: {} });
    expect(r.isError).toBe(true);
    assertNoSecret(r, SECRETS);
  });

  it('missing site yields an error result, not a crash', async () => {
    const c = await connect(evil);
    const r = await c.callTool({ name: 'request_login', arguments: {} }).catch(() => ({ isError: true }));
    expect(r.isError).toBe(true);
    // server is still alive afterwards
    expect((await c.callTool({ name: 'list_grants', arguments: {} })).isError).toBeFalsy();
  });
});
