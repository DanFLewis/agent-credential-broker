import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { startBroker } from '../src/index.js';
import { TestVault, item } from './helpers.js';

it('startBroker wires store, IPC and dashboard, and stops cleanly', async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'acb-start-'));
  writeFileSync(path.join(dir, 'index.html'), 'ok');
  const pipePath = process.platform === 'win32' ? `\\\\.\\pipe\\acb-test-${randomBytes(6).toString('hex')}` : path.join(dir, 'b.sock');
  const b = await startBroker({
    home: dir, vault: new TestVault([item('i1', 'X', 'https://example.com')]), pipePath, dashboardPort: 0,
    dashboardPassword: 'correct-horse-test-only', publicDir: dir,
  });
  try {
    expect(b.dashboardUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(b.pipePath).toBe(pipePath);
    const r = await fetch(`${b.dashboardUrl}/api/session`);
    expect(await r.json()).toEqual({ authenticated: false });
    expect(await b.service.requestLogin({ site: 'https://example.com' }, 'a')).toMatchObject({ status: 'pending' });
  } finally {
    await b.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
