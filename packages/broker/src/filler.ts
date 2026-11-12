// ExtensionFiller: dispatches fill jobs to the single connected filler connection (the native host
// relaying to the browser extension) and waits for that job's fillResult.

import type { FillResult, FillTarget, Filler, SecretHandle } from '@acb/core';
import type { FillJobMessage, FillResultParams } from '@acb/core';

/** What the filler needs from a connection: push a message and learn when it closes. */
export interface FillerChannel {
  send(msg: FillJobMessage): void;
}

interface Waiter {
  resolve: (r: FillResult) => void;
  timer: NodeJS.Timeout;
}

export class ExtensionFiller implements Filler {
  readonly id = 'extension';
  private channel: FillerChannel | null = null;
  private readonly waiters = new Map<string, Waiter>();

  constructor(private readonly clock: () => number = Date.now) {}

  isAvailable(): boolean {
    return this.channel !== null;
  }

  /** Registers the (single) filler connection. A newer one replaces the older. */
  attach(channel: FillerChannel): void {
    this.channel = channel;
  }

  /** Called when a connection closes; ignored if it has already been replaced. */
  detach(channel: FillerChannel): void {
    if (this.channel !== channel) return;
    this.channel = null;
    for (const [jobId, w] of this.waiters) this.settle(jobId, w, { status: 'error', code: 'no_filler', message: 'Filler disconnected.' });
  }

  fill(target: FillTarget, _secret: SecretHandle, timeoutMs: number): Promise<FillResult> {
    const channel = this.channel;
    if (!channel) return Promise.resolve({ status: 'error', code: 'no_filler' });
    return new Promise<FillResult>((resolve) => {
      const timer = setTimeout(() => {
        const w = this.waiters.get(target.jobId);
        if (w) this.settle(target.jobId, w, { status: 'error', code: 'timeout' });
      }, timeoutMs);
      timer.unref();
      this.waiters.set(target.jobId, { resolve, timer });
      channel.send({ type: 'fill_job', jobId: target.jobId, origin: target.origin, expiresAt: this.clock() + timeoutMs });
    });
  }

  /** Handles a filler's fillResult. Returns false for an unknown/finished job. */
  handleFillResult(p: FillResultParams): boolean {
    const w = this.waiters.get(p.jobId);
    if (!w) return false;
    const result: FillResult = p.status === 'submitted' ? { status: 'submitted' } : { status: 'error', code: p.code ?? 'injection_failed', message: p.message };
    this.settle(p.jobId, w, result);
    return true;
  }

  private settle(jobId: string, w: Waiter, r: FillResult): void {
    clearTimeout(w.timer);
    this.waiters.delete(jobId);
    w.resolve(r);
  }
}
