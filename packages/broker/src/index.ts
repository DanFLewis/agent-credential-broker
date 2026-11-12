// @acb/broker public surface, plus startBroker() which wires everything together (used by the CLI and the e2e harness).

import { mkdirSync } from 'node:fs';
import path from 'node:path';
import type { Notifier, VaultAdapter } from '@acb/core';
import { acbHome, pipePath as defaultPipePath } from '@acb/core/node';
import { PASSWORD_SETTING, DashboardServer } from './dashboard-server.js';
import { hashPassword } from './auth.js';
import { ExtensionFiller } from './filler.js';
import { IpcServer } from './ipc.js';
import { DashboardNotifier } from './notifier.js';
import { BrokerService } from './service.js';
import { GrantStore } from './store.js';

export { GrantStore } from './store.js';
export { BrokerService, BrokerError } from './service.js';
export { ExtensionFiller } from './filler.js';
export { DashboardNotifier } from './notifier.js';
export { IpcServer } from './ipc.js';
export { DashboardServer } from './dashboard-server.js';
export { hashPassword, verifyPassword } from './auth.js';

export interface StartBrokerOptions {
  /** Data directory (holds broker.db). Defaults to acbHome(). */
  home?: string;
  vault: VaultAdapter;
  pipePath?: string;
  /** 0 picks a free port. Defaults to ACB_DASHBOARD_PORT or 7414. */
  dashboardPort?: number;
  clock?: () => number;
  /** Sets (hashes and stores) the dashboard password; for harnesses. The CLI uses `set-password`. */
  dashboardPassword?: string;
  /** Override the static dashboard directory (defaults to @acb/dashboard's publicDir). */
  publicDir?: string;
  notifier?: Notifier;
}

export interface RunningBroker {
  stop(): Promise<void>;
  dashboardUrl: string;
  pipePath: string;
  service: BrokerService;
  store: GrantStore;
}

export async function startBroker(opts: StartBrokerOptions): Promise<RunningBroker> {
  const home = opts.home ?? acbHome();
  mkdirSync(home, { recursive: true });
  const store = new GrantStore(path.join(home, 'broker.db'), opts.clock);
  if (opts.dashboardPassword) store.setSetting(PASSWORD_SETTING, hashPassword(opts.dashboardPassword));

  const port = opts.dashboardPort ?? (process.env.ACB_DASHBOARD_PORT ? Number(process.env.ACB_DASHBOARD_PORT) : 7414);
  const pipe = opts.pipePath ?? defaultPipePath();
  const publicDir = opts.publicDir ?? (await import('@acb/dashboard')).publicDir;

  const filler = new ExtensionFiller(opts.clock);
  const placeholderUrl = `http://127.0.0.1:${port}`;
  const notifier = opts.notifier ?? new DashboardNotifier(placeholderUrl);
  const service = new BrokerService({ store, vault: opts.vault, filler, notifier, clock: opts.clock });
  const ipc = new IpcServer({ path: pipe, service, filler });
  const dashboard = new DashboardServer({ service, store, publicDir, port, clock: opts.clock });

  try {
    await ipc.listen();
    await dashboard.listen();
  } catch (e) {
    await Promise.allSettled([ipc.close(), dashboard.close()]);
    store.close();
    throw e;
  }
  return {
    dashboardUrl: `http://127.0.0.1:${dashboard.port}`,
    pipePath: pipe,
    service,
    store,
    async stop() {
      await Promise.allSettled([ipc.close(), dashboard.close()]);
      store.close();
    },
  };
}
