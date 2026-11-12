#!/usr/bin/env node
// acb-broker CLI:
//   acb-broker set-password
//   acb-broker start [--vault bitwarden|fake] [--fake-fixture <path>]
// Secrets (dashboard password, Bitwarden master password) are only ever read from a hidden console
// prompt or the environment, never over HTTP.

import path from 'node:path';
import type { VaultAdapter } from '@acb/core';
import { acbHome } from '@acb/core/node';
import { FakeVault } from '@acb/vault-fake';
import { BitwardenVault } from '@acb/vault-bitwarden';
import { hashPassword } from './auth.js';
import { PASSWORD_SETTING } from './dashboard-server.js';
import { startBroker } from './index.js';
import { GrantStore } from './store.js';

/** Reads a line from the console without echoing it. */
function promptHidden(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(question);
    if (!stdin.isTTY) {
      // Piped input (scripts): read one line, no echo concerns.
      stdin.setEncoding('utf8');
      stdin.once('data', (d: string) => resolve(d.split(/\r?\n/)[0] ?? ''));
      return;
    }
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') return done(() => resolve(value));
        if (c === '\u0003') return done(() => reject(new Error('Cancelled')));
        if (c === '\u007f' || c === '\b') value = value.slice(0, -1);
        else value += c;
      }
    };
    const done = (fn: () => void) => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stderr.write('\n');
      fn();
    };
    stdin.on('data', onData);
  });
}

async function setPassword(): Promise<void> {
  const pw = await promptHidden('New dashboard password (min 12 chars): ');
  if (pw.length < 12) throw new Error('Password must be at least 12 characters.');
  if (pw !== (await promptHidden('Repeat password: '))) throw new Error('Passwords do not match.');
  const home = acbHome();
  const { mkdirSync } = await import('node:fs');
  mkdirSync(home, { recursive: true });
  const store = new GrantStore(path.join(home, 'broker.db'));
  store.setSetting(PASSWORD_SETTING, hashPassword(pw));
  store.close();
  console.log('Dashboard password saved.');
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function createVault(args: string[]): Promise<{ vault: VaultAdapter; id: string }> {
  const kind = flag(args, '--vault') ?? 'bitwarden';
  if (kind === 'fake') {
    const fixture = flag(args, '--fake-fixture');
    if (!fixture) throw new Error('--vault fake needs --fake-fixture <path>');
    return { vault: FakeVault.fromFixture(fixture), id: 'fake' };
  }
  if (kind !== 'bitwarden') throw new Error(`Unknown vault "${kind}"`);
  const session = process.env.BW_SESSION;
  if (session) return { vault: new BitwardenVault({ session }), id: 'bitwarden' };
  const vault = new BitwardenVault();
  await vault.unlock(await promptHidden('Bitwarden master password: '));
  return { vault, id: 'bitwarden' };
}

async function start(args: string[]): Promise<void> {
  const { vault, id } = await createVault(args);
  const broker = await startBroker({ vault });
  if (!broker.store.getSetting(PASSWORD_SETTING)) {
    await broker.stop();
    throw new Error('No dashboard password set. Run "acb-broker set-password" first.');
  }
  broker.store.audit('vault_unlock', { detail: { vault: id } });
  console.log(`Broker running. Dashboard: ${broker.dashboardUrl}  IPC: ${broker.pipePath}`);
  const shutdown = () => void broker.stop().then(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const [cmd, ...rest] = process.argv.slice(2);
try {
  if (cmd === 'set-password') await setPassword();
  else if (cmd === 'start') await start(rest);
  else {
    console.error('Usage: acb-broker set-password | start [--vault bitwarden|fake] [--fake-fixture <path>]');
    process.exitCode = 1;
  }
} catch (e) {
  console.error((e as Error).message); // our own messages only; never a vault error body
  process.exitCode = 1;
}
