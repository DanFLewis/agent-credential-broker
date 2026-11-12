import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { FakeVault } from '../src/index.js';

const fixture = fileURLToPath(new URL('./fixtures/fake-vault.json', import.meta.url));
const SITE = 'http://127.0.0.1:8765';

describe('FakeVault', () => {
  const vault = FakeVault.fromFixture(fixture);

  it('returns both accounts for the test page (ambiguous candidates)', async () => {
    const found = await vault.find(undefined, SITE);
    expect(found.map((f) => f.itemId)).toEqual(['fake-1', 'fake-2']);
    expect(found[0]!.origins).toEqual([SITE]);
  });

  it('matches exact origin only', async () => {
    expect(await vault.find(undefined, 'https://127.0.0.1:8765')).toEqual([]);
    expect(await vault.find(undefined, 'https://bank.example.test')).toHaveLength(1);
    expect(await vault.find(undefined, 'https://evil.bank.example.test')).toEqual([]);
  });

  it('ignores the hint for matching', async () => {
    expect(await vault.find('bank', SITE)).toHaveLength(2);
  });

  it('drops invalid uris', async () => {
    const v = new FakeVault({ items: [{ itemId: 'x', name: 'x', uris: ['not a url', 'ftp://a.b/', 'https://ok.test/p'], username: 'u', password: 'p' }] });
    expect((await v.getItem('x'))!.origins).toEqual(['https://ok.test']);
    expect(await v.getItem('nope')).toBeNull();
  });

  it('returns a redacted Secret', async () => {
    const s = await vault.getSecret('fake-1');
    expect(s.username).toBe('test-user');
    expect(s.password).toBe('correct-horse-test-only');
    expect(JSON.stringify(s)).not.toContain('correct-horse');
    expect(String(s)).not.toContain('correct-horse');
    await expect(vault.getSecret('missing')).rejects.toThrow('item_not_found');
  });

  it('honours locked', async () => {
    const v = new FakeVault({ items: [], locked: true });
    expect(await v.status()).toBe('locked');
    v.setLocked(false);
    expect(await v.status()).toBe('unlocked');
  });
});
