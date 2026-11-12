import { readFileSync } from 'node:fs';
import { normalizeOrigin, Secret } from '@acb/core';
import type { Origin, SecretMaterial, VaultAdapter, VaultItemRef, VaultStatus } from '@acb/core';

export interface FakeItem {
  itemId: string;
  name: string;
  uris: string[];
  username: string;
  password: string;
}

export interface FakeVaultOptions {
  items: FakeItem[];
  locked?: boolean;
}

/** In-memory vault for tests and demos. Holds only obviously fake credentials. */
export class FakeVault implements VaultAdapter {
  readonly id = 'fake';
  private locked: boolean;
  private readonly items: FakeItem[];

  constructor(opts: FakeVaultOptions) {
    this.items = opts.items;
    this.locked = opts.locked ?? false;
  }

  static fromFixture(path: string): FakeVault {
    const data = JSON.parse(readFileSync(path, 'utf8')) as FakeVaultOptions;
    return new FakeVault(data);
  }

  setLocked(locked: boolean): void {
    this.locked = locked;
  }

  async status(): Promise<VaultStatus> {
    return this.locked ? 'locked' : 'unlocked';
  }

  async find(_hint: string | undefined, site: Origin): Promise<VaultItemRef[]> {
    if (this.locked) return [];
    const refs = this.items.map(toRef).filter((r) => r.origins.includes(site));
    return refs; // hint is ignored: it may only rank, never widen
  }

  async getItem(itemId: string): Promise<VaultItemRef | null> {
    if (this.locked) return null;
    const item = this.items.find((i) => i.itemId === itemId);
    return item ? toRef(item) : null;
  }

  async getSecret(itemId: string): Promise<SecretMaterial> {
    const item = this.locked ? undefined : this.items.find((i) => i.itemId === itemId);
    if (!item) throw new Error('item_not_found');
    return new Secret(item.username, item.password);
  }
}

function toRef(i: FakeItem): VaultItemRef {
  const origins = i.uris.map((u) => normalizeOrigin(u)).filter((o): o is Origin => o !== null);
  return { itemId: i.itemId, name: i.name, origins };
}
