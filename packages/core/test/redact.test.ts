import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { Secret, assertNoSecret } from '../src/redact.js';

const USER = 'test-user';
const PASS = 'correct-horse-test-only';

describe('Secret', () => {
  const s = new Secret(USER, PASS);

  it('exposes values only through properties', () => {
    expect(s.username).toBe(USER);
    expect(s.password).toBe(PASS);
    expect(Object.keys(s)).toEqual([]);
  });

  it('is redacted by JSON.stringify, including when nested', () => {
    for (const out of [JSON.stringify(s), JSON.stringify({ a: [{ b: s }] })]) {
      expect(out).not.toContain(USER);
      expect(out).not.toContain(PASS);
      expect(out).toContain('[REDACTED]');
    }
  });

  it('is redacted by String() and template literals', () => {
    expect(String(s)).toBe('[REDACTED]');
    expect(`${s}`).toBe('[REDACTED]');
    expect(s.toString()).toBe('[REDACTED]');
  });

  it('is redacted by util.inspect, directly and nested', () => {
    for (const out of [inspect(s), inspect({ deep: { s } }, { depth: 5 }), inspect([s], { showHidden: true })]) {
      expect(out).not.toContain(USER);
      expect(out).not.toContain(PASS);
      expect(out).toContain('[REDACTED]');
    }
  });

  it('does not leak through spread or Object.entries', () => {
    expect(JSON.stringify({ ...s })).toBe('{}');
    expect(Object.entries(s)).toEqual([]);
  });
});

describe('assertNoSecret', () => {
  it('passes when the secret is absent', () => {
    expect(() => assertNoSecret({ status: 'pending', requestId: 'r1' }, [USER, PASS])).not.toThrow();
  });

  it('ignores empty secret strings', () => {
    expect(() => assertNoSecret({ a: 'anything' }, [''])).not.toThrow();
  });

  it('catches top-level, nested and array occurrences, and in keys', () => {
    expect(() => assertNoSecret(`login with ${PASS}`, [PASS])).toThrow();
    expect(() => assertNoSecret({ a: { b: [{ c: PASS }] } }, [PASS])).toThrow();
    expect(() => assertNoSecret({ [USER]: 1 }, [USER])).toThrow();
    expect(() => assertNoSecret([[['x', `pre-${PASS}-post`]]], [PASS])).toThrow();
  });

  it('catches secrets that JSON escapes', () => {
    const tricky = 'pa"ss\\word\n';
    expect(() => assertNoSecret({ m: tricky }, [tricky])).toThrow();
  });

  it('never repeats the secret in the error message', () => {
    try {
      assertNoSecret({ x: PASS }, [PASS]);
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain(PASS);
    }
  });

  it('treats a Secret instance as safe (it serialises redacted)', () => {
    expect(() => assertNoSecret({ s: new Secret(USER, PASS) }, [USER, PASS])).not.toThrow();
  });

  it('handles values JSON cannot serialise', () => {
    expect(() => assertNoSecret(undefined, [PASS])).not.toThrow();
  });
});
