// BrokerAgentApi over the broker's named pipe. Connects lazily and reconnects after a drop.
import type { BrokerAgentApi, GrantStatusResult, GrantSummary, LoginResult } from '@acb/core';
import { connectBroker, type BrokerConnection } from '@acb/core/node';

export const BROKER_DOWN_MESSAGE = 'Broker is not running';

export class IpcBrokerApi implements BrokerAgentApi {
  private conn: Promise<BrokerConnection> | null = null;

  constructor(private readonly agentId: string = process.env.ACB_AGENT_ID || 'claude-code') {}

  private connection(): Promise<BrokerConnection> {
    if (this.conn) return this.conn;
    const p = connectBroker({ role: 'agent', agentId: this.agentId });
    this.conn = p;
    const reset = () => { if (this.conn === p) this.conn = null; };
    p.then((c) => c.onClose(reset), reset);
    return p;
  }

  private async call<T>(method: string, params: unknown, timeoutMs: number): Promise<T> {
    let c: BrokerConnection;
    try {
      c = await this.connection();
    } catch {
      throw new Error(BROKER_DOWN_MESSAGE);
    }
    return (await c.call(method, params, timeoutMs)) as T;
  }

  async requestLogin(params: { site: string; hint?: string; waitMs?: number }): Promise<LoginResult> {
    try {
      // RPC timeout must exceed the broker-side wait (capped at 60s) plus the fill timeout.
      return await this.call<LoginResult>('requestLogin', params, 100_000);
    } catch (e) {
      if (e instanceof Error && e.message === BROKER_DOWN_MESSAGE) {
        // LoginErrorCode has no "broker down" member; 'no_filler' is the closest ("cannot act yet").
        return { status: 'error', code: 'no_filler', message: BROKER_DOWN_MESSAGE };
      }
      throw e;
    }
  }

  grantStatus(params: { requestId: string }): Promise<GrantStatusResult> {
    return this.call('grantStatus', params, 10_000);
  }

  listGrants(): Promise<GrantSummary[]> {
    return this.call('listGrants', {}, 10_000);
  }
}
