// DashboardNotifier: v1 notification is a console line. Toasts come later.

import type { ApprovalRequest, Notifier, UseEvent } from '@acb/core';

/** agentId and origin are agent-influenced; strip control characters (terminal escape injection). */
function printable(s: string): string {
  return s.replace(/[^\x20-\x7e]/g, '?').slice(0, 100);
}

export class DashboardNotifier implements Notifier {
  readonly id = 'dashboard-console';

  constructor(
    private readonly dashboardUrl = 'http://127.0.0.1:7414',
    private readonly write: (line: string) => void = (l) => process.stdout.write(l + '\n'),
  ) {}

  async requestApproval(req: ApprovalRequest): Promise<void> {
    this.write(`Approval needed: ${printable(req.origin)} from ${printable(req.agentId)}, open ${this.dashboardUrl}`);
  }

  async notifyUse(ev: UseEvent): Promise<void> {
    this.write(`Login used: ${printable(ev.origin)} by ${printable(ev.agentId)} (${ev.result.status})`);
  }
}
