import { normalizeOrigin, Secret } from '@acb/core';
import type { Origin, SecretMaterial, VaultAdapter, VaultItemRef, VaultStatus } from '@acb/core';
import { defaultRunner } from './runner.js';
import type { Runner } from './runner.js';

export { defaultRunner, resolveBw } from './runner.js';
export type { Runner, RunResult } from './runner.js';

export interface BitwardenVaultOptions {
  bwPath?: string;
  /** Arguments placed before every bw argument, e.g. the script path when bwPath is `node`. */
  bwArgs?: string[];
  session?: string;
  run?: Runner;
  /** Clock for the metadata cache (tests). */
  now?: () => number;
}

const CACHE_MS = 60_000;
const BW_LOGIN_TYPE = 1;

/** Errors carry fixed text only. bw stdout/stderr can contain secrets or item data, so never forward them. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultError';
  }
}

interface BwItem {
  id?: unknown;
  name?: unknown;
  type?: unknown;
  login?: { uris?: Array<{ uri?: unknown } | null>; username?: unknown; password?: unknown } | null;
}

export class BitwardenVault implements VaultAdapter {
  readonly id = 'bitwarden';
  private readonly run: Runner;
  private readonly now: () => number;
  private session: string | undefined;
  /** Metadata only (id, name, origins). Passwords are never stored here. */
  private cache: { at: number; items: VaultItemRef[] } | null = null;

  constructor(opts: BitwardenVaultOptions = {}) {
    this.run = opts.run ?? defaultRunner(opts.bwPath ?? 'bw', opts.bwArgs);
    this.session = opts.session;
    this.now = opts.now ?? Date.now;
  }

  /** The session goes in the child env (BW_SESSION), never argv, which other processes can read. */
  private env(): Record<string, string> {
    return this.session ? { BW_SESSION: this.session } : {};
  }

  private async bw(args: string[], env: Record<string, string>, what: string): Promise<string> {
    let res;
    try {
      res = await this.run(args, env);
    } catch {
      throw new VaultError(`bitwarden ${what} failed: could not run bw`);
    }
    if (res.code !== 0) throw new VaultError(`bitwarden ${what} failed`);
    return res.stdout;
  }

  async status(): Promise<VaultStatus> {
    try {
      const out = await this.bw(['status'], this.env(), 'status');
      const status = (JSON.parse(out) as { status?: unknown }).status;
      if (status === 'unlocked' && this.session) return 'unlocked';
      return status === 'unlocked' || status === 'locked' ? 'locked' : 'unavailable';
    } catch {
      return 'unavailable';
    }
  }

  async unlock(masterPassword: string): Promise<void> {
    // The master password travels only in the child's environment, never argv.
    const out = await this.bw(
      ['unlock', '--raw', '--passwordenv', 'ACB_BW_PASSWORD'],
      { ACB_BW_PASSWORD: masterPassword },
      'unlock',
    );
    const session = out.trim();
    if (!session) throw new VaultError('bitwarden unlock failed');
    this.session = session;
    this.cache = null;
  }

  private async items(): Promise<VaultItemRef[]> {
    if (this.cache && this.now() - this.cache.at < CACHE_MS) return this.cache.items;
    const out = await this.bw(['list', 'items'], this.env(), 'list');
    let raw: unknown;
    try {
      raw = JSON.parse(out);
    } catch {
      throw new VaultError('bitwarden list failed: unexpected output');
    }
    if (!Array.isArray(raw)) throw new VaultError('bitwarden list failed: unexpected output');
    const items = (raw as BwItem[]).flatMap(toRef);
    this.cache = { at: this.now(), items };
    return items;
  }

  async find(hint: string | undefined, site: Origin): Promise<VaultItemRef[]> {
    // No `--url`: Bitwarden matches on base domain, which is wider than our exact-origin rule.
    const matches = (await this.items()).filter((i) => i.origins.includes(site));
    const h = hint?.trim().toLowerCase();
    if (!h) return matches;
    // The hint only reorders (stable: name matches first); it never adds or removes items.
    const hit = (i: VaultItemRef) => i.name.toLowerCase().includes(h);
    return [...matches.filter(hit), ...matches.filter((i) => !hit(i))];
  }

  async getItem(itemId: string): Promise<VaultItemRef | null> {
    return (await this.items()).find((i) => i.itemId === itemId) ?? null;
  }

  async getSecret(itemId: string): Promise<SecretMaterial> {
    // Ids are UUIDs; refuse anything that bw could parse as an option.
    if (!/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(itemId)) throw new VaultError('invalid item id');
    const out = await this.bw(['get', 'item', itemId], this.env(), 'get');
    let item: BwItem;
    try {
      item = JSON.parse(out) as BwItem;
    } catch {
      throw new VaultError('bitwarden get failed: unexpected output');
    }
    const { username, password } = item.login ?? {};
    if (item.type !== BW_LOGIN_TYPE || typeof username !== 'string' || typeof password !== 'string') {
      throw new VaultError('bitwarden get failed: item has no login credentials');
    }
    return new Secret(username, password);
  }
}

/** Login items only (type 1). URIs that don't normalise are dropped. */
function toRef(i: BwItem): VaultItemRef[] {
  if (i.type !== BW_LOGIN_TYPE || typeof i.id !== 'string' || typeof i.name !== 'string') return [];
  const origins: Origin[] = [];
  for (const u of i.login?.uris ?? []) {
    const o = typeof u?.uri === 'string' ? normalizeOrigin(u.uri) : null;
    if (o && !origins.includes(o)) origins.push(o);
  }
  return [{ itemId: i.id, name: i.name, origins }];
}
