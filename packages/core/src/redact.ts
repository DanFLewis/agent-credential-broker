// Helpers that keep secrets out of logs, JSON and error messages.

import type { SecretMaterial } from './types.js';

const REDACTED = '[REDACTED]';

/**
 * Credential holder. Values live in #private fields so they are invisible to Object.keys,
 * spread and console output; only the getters expose them.
 */
export class Secret implements SecretMaterial {
  readonly #username: string;
  readonly #password: string;

  constructor(username: string, password: string) {
    this.#username = username;
    this.#password = password;
  }
  get username(): string {
    return this.#username;
  }
  get password(): string {
    return this.#password;
  }
  toJSON(): string {
    return REDACTED;
  }
  toString(): string {
    return REDACTED;
  }
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return REDACTED;
  }
}

/**
 * Throws if any non-empty secret appears anywhere in the JSON form of `value`.
 * The message never contains the secret itself.
 */
export function assertNoSecret(value: unknown, secrets: string[]): void {
  const json = JSON.stringify(value) ?? '';
  for (const s of secrets) {
    if (s === '') continue;
    // Check the raw string and its JSON-escaped form (quotes, backslashes, unicode escapes).
    if (json.includes(s) || json.includes(JSON.stringify(s).slice(1, -1))) {
      throw new Error('assertNoSecret: a secret value was found in the serialised output');
    }
  }
}
