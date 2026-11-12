// IpcServer: newline-delimited JSON over a named pipe / unix socket.
//  - The first line must be a valid hello, otherwise the socket is destroyed.
//  - Role "agent" may call requestLogin/grantStatus/listGrants; role "filler" may call
//    claimSecret/fillResult/pair. Anything else is an rpc_error.
//  - Only one filler at a time; a newer filler connection replaces the older one.
//  - RPC errors carry a code and a generic message only, never a stack or internal detail.

import { existsSync, unlinkSync } from 'node:fs';
import net from 'node:net';
import { PROTOCOL_VERSION } from '@acb/core';
import type { BrokerMessage, FillErrorCode, FillResultParams, HelloMessage, RpcRequest } from '@acb/core';
import type { ExtensionFiller, FillerChannel } from './filler.js';
import { BrokerError, type BrokerService } from './service.js';

const MAX_LINE = 1024 * 1024;
const HELLO_TIMEOUT_MS = 5000;

const AGENT_METHODS = new Set(['requestLogin', 'grantStatus', 'listGrants']);
const FILLER_METHODS = new Set(['claimSecret', 'fillResult', 'pair']);
const FILL_ERROR_CODES = new Set<string>([
  'no_filler', 'not_paired', 'no_tab', 'ambiguous_tab', 'origin_mismatch', 'not_top_frame', 'no_form',
  'cross_origin_action', 'submit_failed', 'injection_failed', 'decrypt_failed', 'job_expired', 'timeout',
] satisfies FillErrorCode[]);

export interface IpcServerOptions {
  path: string;
  service: BrokerService;
  filler: ExtensionFiller;
}

export class IpcServer {
  private readonly server: net.Server;
  private readonly sockets = new Set<net.Socket>();
  private fillerSocket: net.Socket | null = null;

  constructor(private readonly opts: IpcServerOptions) {
    this.server = net.createServer((s) => this.onConnection(s));
  }

  listen(): Promise<void> {
    // A stale unix socket file from a crashed run would make listen() fail with EADDRINUSE.
    if (process.platform !== 'win32' && existsSync(this.opts.path)) unlinkSync(this.opts.path);
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.opts.path, () => {
        this.server.off('error', reject);
        resolve();
      });
    });
  }

  close(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  private onConnection(socket: net.Socket): void {
    this.sockets.add(socket);
    let role: HelloMessage['role'] | null = null;
    let agentId = 'unknown';
    let channel: FillerChannel | null = null;
    let buf = '';

    const send = (m: BrokerMessage) => {
      if (!socket.destroyed) socket.write(JSON.stringify(m) + '\n');
    };
    const helloTimer = setTimeout(() => socket.destroy(), HELLO_TIMEOUT_MS);
    helloTimer.unref();

    const onLine = (line: string) => {
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        return socket.destroy();
      }
      if (!role) {
        const h = parseHello(msg);
        if (!h) return socket.destroy();
        clearTimeout(helloTimer);
        role = h.role;
        if (role === 'agent') agentId = sanitizeAgentId(h.agentId);
        else {
          channel = { send: (m) => send(m) };
          this.fillerSocket?.destroy(); // newer filler replaces the older
          this.fillerSocket = socket;
          this.opts.filler.attach(channel);
        }
        return send({ type: 'hello_ok', protocolVersion: PROTOCOL_VERSION });
      }
      const rpc = msg as Partial<RpcRequest> | null;
      if (!rpc || rpc.type !== 'rpc' || typeof rpc.id !== 'string' || typeof rpc.method !== 'string') return socket.destroy();
      void this.handleRpc(role, agentId, rpc as RpcRequest).then(send);
    };

    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.length > MAX_LINE) return socket.destroy();
        if (line.trim()) onLine(line);
        if (socket.destroyed) return;
      }
      if (buf.length > MAX_LINE) socket.destroy(); // oversized line without newline
    });
    socket.on('error', () => undefined);
    socket.on('close', () => {
      clearTimeout(helloTimer);
      this.sockets.delete(socket);
      if (this.fillerSocket === socket) this.fillerSocket = null;
      if (channel) this.opts.filler.detach(channel);
    });
  }

  private async handleRpc(role: 'agent' | 'filler', agentId: string, req: RpcRequest): Promise<BrokerMessage> {
    const allowed = role === 'agent' ? AGENT_METHODS : FILLER_METHODS;
    if (!allowed.has(req.method)) return rpcError(req.id, 'forbidden', 'Method not allowed for this role.');
    try {
      return { type: 'rpc_result', id: req.id, result: await this.dispatch(req.method, req.params, agentId) };
    } catch (e) {
      // Only BrokerError messages are safe to forward; everything else becomes a generic error.
      return e instanceof BrokerError ? rpcError(req.id, e.code, e.message) : rpcError(req.id, 'internal', 'Internal error.');
    }
  }

  private async dispatch(method: string, raw: unknown, agentId: string): Promise<unknown> {
    const p = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const { service, filler } = this.opts;
    switch (method) {
      case 'requestLogin':
        if (typeof p.site !== 'string') throw new BrokerError('bad_params', 'site is required.');
        return service.requestLogin(
          {
            site: p.site,
            hint: typeof p.hint === 'string' ? p.hint : undefined,
            waitMs: typeof p.waitMs === 'number' && Number.isFinite(p.waitMs) ? p.waitMs : undefined,
          },
          agentId,
        );
      case 'grantStatus':
        if (typeof p.requestId !== 'string') throw new BrokerError('bad_params', 'requestId is required.');
        return service.grantStatus({ requestId: p.requestId }, agentId);
      case 'listGrants':
        return service.listGrants(agentId);
      case 'claimSecret':
        return service.claimSecret(p as unknown as Parameters<BrokerService['claimSecret']>[0], service.pairedPublicKey());
      case 'pair':
        return service.requestPairing(p.publicKey as string);
      case 'fillResult': {
        if (typeof p.jobId !== 'string' || (p.status !== 'submitted' && p.status !== 'error')) {
          throw new BrokerError('bad_params', 'Invalid fillResult.');
        }
        const params: FillResultParams = {
          jobId: p.jobId,
          status: p.status,
          code: typeof p.code === 'string' && FILL_ERROR_CODES.has(p.code) ? (p.code as FillErrorCode) : undefined,
          message: typeof p.message === 'string' ? p.message.slice(0, 200) : undefined,
        };
        return { accepted: filler.handleFillResult(params) };
      }
      default:
        throw new BrokerError('forbidden', 'Unknown method.');
    }
  }
}

function rpcError(id: string, code: string, message: string): BrokerMessage {
  return { type: 'rpc_error', id, error: { code, message } };
}

function parseHello(msg: unknown): HelloMessage | null {
  const m = msg as Partial<HelloMessage> | null;
  if (!m || m.type !== 'hello' || m.protocolVersion !== PROTOCOL_VERSION) return null;
  if (m.role !== 'agent' && m.role !== 'filler') return null;
  return m as HelloMessage;
}

/** The agent id is self-asserted and ends up in logs and the dashboard: keep it short and plain. */
function sanitizeAgentId(id: unknown): string {
  const s = typeof id === 'string' ? id.replace(/[^A-Za-z0-9._:@ -]/g, '_').slice(0, 64) : '';
  return s || 'unknown';
}
