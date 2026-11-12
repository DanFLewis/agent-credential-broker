// Shared test fixtures: in-memory store, tiny fake vault, fake filler, injected clock.

import type {
  ApprovalRequest, FillResult, FillTarget, Filler, Notifier, SecretHandle, SecretMaterial, UseEvent,
  VaultAdapter, VaultItemRef, VaultStatus,
} from '@acb/core';
import { exportPublicKey, generateRecipientKeyPair } from '@acb/core';
import { ExtensionFiller } from '../src/filler.js';
import { BrokerService } from '../src/service.js';
import { GrantStore } from '../src/store.js';

export const T_USER = 'test-user';
export const T_PASS = 'correct-horse-test-only';

export class TestVault implements VaultAdapter {
  readonly id = 'test';
  status_: VaultStatus = 'unlocked';
  constructor(public items: VaultItemRef[] = []) {}
  async status() { return this.status_; }
  async find(_hint: string | undefined, site: string) { return this.items.filter((i) => i.origins.includes(site)); }
  async getItem(id: string) { return this.items.find((i) => i.itemId === id) ?? null; }
  async getSecret(): Promise<SecretMaterial> { return { username: T_USER, password: T_PASS }; }
}

export class TestFiller implements Filler {
  readonly id = 'test-filler';
  available = true;
  onFill: (t: FillTarget) => Promise<FillResult> = async () => ({ status: 'submitted' });
  fills: FillTarget[] = [];
  isAvailable() { return this.available; }
  async fill(t: FillTarget, _s: SecretHandle, _timeout: number) { this.fills.push(t); return this.onFill(t); }
}

export class TestNotifier implements Notifier {
  readonly id = 'test-notifier';
  requests: ApprovalRequest[] = [];
  uses: UseEvent[] = [];
  async requestApproval(r: ApprovalRequest) { this.requests.push(r); }
  async notifyUse(e: UseEvent) { this.uses.push(e); }
}

export const item = (itemId: string, name: string, ...origins: string[]): VaultItemRef => ({ itemId, name, origins });

export function makeCtx(items: VaultItemRef[] = [item('i1', 'Example', 'https://example.com', 'https://other.example.com')]) {
  const clock = { now: 1_700_000_000_000 };
  const store = new GrantStore(':memory:', () => clock.now);
  const vault = new TestVault(items);
  const filler = new TestFiller();
  const notifier = new TestNotifier();
  const service = new BrokerService({ store, vault, filler, notifier, clock: () => clock.now });
  return { clock, store, vault, filler, notifier, service };
}
export type Ctx = ReturnType<typeof makeCtx>;

/** Creates a pending request via requestLogin and returns its id. */
export async function pendingFor(ctx: Ctx, site: string, agent = 'agent-a'): Promise<string> {
  const r = await ctx.service.requestLogin({ site }, agent);
  if (r.status !== 'pending') throw new Error(`expected pending, got ${JSON.stringify(r)}`);
  return r.requestId;
}

/** Requests, approves and returns the grant. */
export async function grantFor(ctx: Ctx, site: string, duration: Parameters<BrokerService['approve']>[2], agent = 'agent-a', itemId = 'i1') {
  return ctx.service.approve(await pendingFor(ctx, site, agent), itemId, duration);
}

/** A real extension key pair; returns the raw public key (base64url) and the private key. */
export async function newExtensionKey() {
  const kp = await generateRecipientKeyPair();
  return { publicKey: await exportPublicKey(kp.publicKey), privateKey: kp.privateKey };
}

export { ExtensionFiller };
