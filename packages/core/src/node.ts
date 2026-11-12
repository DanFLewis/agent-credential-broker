/// <reference types="node" />
// Node-only helpers: paths, line framing, Chrome native-messaging framing and the broker IPC client.
// Exported as '@acb/core/node'; never import this from code that is bundled for the extension.

import { connect } from 'node:net';
import type { Socket } from 'node:net';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import { PROTOCOL_VERSION } from './protocol.js';
import type { BrokerMessage, ClientMessage } from './protocol.js';

/** Maximum size of one IPC line / native message, in either direction. */
export const MAX_MESSAGE_BYTES = 1024 * 1024;

export function acbHome(): string {
  if (process.env.ACB_HOME) return process.env.ACB_HOME;
  if (process.platform === 'win32') {
    return join(process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'acb');
  }
  return join(homedir(), '.acb');
}

export function pipePath(): string {
  if (process.env.ACB_PIPE) return process.env.ACB_PIPE;
  if (process.platform === 'win32') return `\\\\.\\pipe\\acb-broker-${userInfo().username}`;
  return join(acbHome(), 'broker.sock');
}

/**
 * Turns a stream of chunks into complete newline-delimited lines. A line longer than the limit
 * is dropped (the rest of it is skipped up to the next newline) and reported once via onError,
 * so a hostile peer cannot make us buffer unbounded data.
 */
export class LineSplitter {
  #pending: Buffer[] = [];
  #pendingLen = 0;
  #discarding = false;

  constructor(
    private readonly onLine: (line: string) => void,
    private readonly onError: (err: Error) => void = () => {},
    private readonly maxBytes = MAX_MESSAGE_BYTES,
  ) {}

  push(chunk: Buffer | string): void {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    let start = 0;
    while (start <= buf.length) {
      const nl = buf.indexOf(0x0a, start);
      const end = nl === -1 ? buf.length : nl;
      const segment = buf.subarray(start, end);
      if (!this.#discarding) {
        if (this.#pendingLen + segment.length > this.maxBytes) {
          this.#discarding = true;
          this.#pending = [];
          this.#pendingLen = 0;
          this.onError(new Error(`line exceeds ${this.maxBytes} bytes`));
        } else {
          this.#pending.push(segment);
          this.#pendingLen += segment.length;
        }
      }
      if (nl === -1) return;
      if (this.#discarding) {
        this.#discarding = false;
      } else {
        const line = Buffer.concat(this.#pending).toString('utf8').replace(/\r$/, '');
        this.#pending = [];
        this.#pendingLen = 0;
        this.onLine(line);
      }
      start = nl + 1;
    }
  }
}

/** Chrome native messaging framing: uint32 little-endian length, then UTF-8 JSON. */
export function encodeNativeMessage(obj: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  if (body.length > MAX_MESSAGE_BYTES) throw new Error('native message too large');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

/**
 * Incremental decoder for native messages. An oversize length prefix is unrecoverable (we cannot
 * resynchronise the stream), so the reader reports it once and ignores all further input.
 * The body of an oversize message is never buffered.
 */
export class NativeMessageReader {
  #buf: Buffer = Buffer.alloc(0);
  #failed = false;

  constructor(
    private readonly onMessage: (msg: unknown) => void,
    private readonly onError: (err: Error) => void = () => {},
  ) {}

  push(chunk: Buffer): void {
    if (this.#failed) return;
    this.#buf = this.#buf.length === 0 ? chunk : Buffer.concat([this.#buf, chunk]);
    while (this.#buf.length >= 4) {
      const len = this.#buf.readUInt32LE(0);
      if (len > MAX_MESSAGE_BYTES) {
        this.#failed = true;
        this.#buf = Buffer.alloc(0);
        this.onError(new Error('native message too large'));
        return;
      }
      if (this.#buf.length < 4 + len) return;
      const body = this.#buf.subarray(4, 4 + len);
      this.#buf = this.#buf.subarray(4 + len);
      let msg: unknown;
      try {
        msg = JSON.parse(body.toString('utf8'));
      } catch {
        this.onError(new Error('invalid JSON in native message')); // body deliberately not echoed
        continue;
      }
      this.onMessage(msg);
    }
  }
}

export interface BrokerConnection {
  call(method: string, params: unknown, timeoutMs?: number): Promise<unknown>;
  /** Messages from the broker that are not RPC responses (e.g. fill_job). */
  onPush(cb: (msg: BrokerMessage) => void): void;
  /** Writes one line. A string is sent as-is (already serialised); anything else is JSON-encoded. */
  send(raw: string | object): void;
  onClose(cb: () => void): void;
  close(): void;
}

const HELLO_TIMEOUT_MS = 5000;

function rpcError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

export function connectBroker(opts: {
  role: 'agent' | 'filler';
  agentId?: string;
  path?: string;
}): Promise<BrokerConnection> {
  return new Promise((resolve, reject) => {
    const socket: Socket = connect(opts.path ?? pipePath());
    const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
    const pushCbs: Array<(msg: BrokerMessage) => void> = [];
    const closeCbs: Array<() => void> = [];
    let ready = false;
    let nextId = 1;

    const write = (raw: string | object) => {
      socket.write((typeof raw === 'string' ? raw : JSON.stringify(raw)) + '\n');
    };

    const helloTimer = setTimeout(() => {
      socket.destroy();
      reject(rpcError('hello_timeout', 'broker did not answer hello'));
    }, HELLO_TIMEOUT_MS);

    const conn: BrokerConnection = {
      call(method, params, timeoutMs = 30000) {
        return new Promise((res, rej) => {
          if (socket.destroyed) return rej(rpcError('connection_closed', 'connection closed'));
          const id = String(nextId++);
          const timer = setTimeout(() => {
            pending.delete(id);
            rej(rpcError('timeout', `rpc ${method} timed out`));
          }, timeoutMs);
          pending.set(id, { resolve: res, reject: rej, timer });
          write({ type: 'rpc', id, method, params });
        });
      },
      onPush: (cb) => void pushCbs.push(cb),
      send: write,
      onClose: (cb) => void closeCbs.push(cb),
      close: () => void socket.end(),
    };

    const splitter = new LineSplitter(
      (line) => {
        let msg: BrokerMessage;
        try {
          msg = JSON.parse(line) as BrokerMessage;
        } catch {
          return; // ignore garbage lines
        }
        if (!ready) {
          if (msg.type === 'hello_ok') {
            ready = true;
            clearTimeout(helloTimer);
            resolve(conn);
          }
          return;
        }
        if (msg.type === 'rpc_result' || msg.type === 'rpc_error') {
          const p = pending.get(msg.id);
          if (!p) return;
          pending.delete(msg.id);
          clearTimeout(p.timer);
          if (msg.type === 'rpc_result') p.resolve(msg.result);
          else p.reject(rpcError(msg.error.code, msg.error.message));
        } else {
          for (const cb of pushCbs) cb(msg);
        }
      },
      () => socket.destroy(), // oversize line from the broker: treat the connection as broken
    );

    socket.on('data', (d) => splitter.push(d));
    socket.on('connect', () => {
      const hello: ClientMessage = { type: 'hello', role: opts.role, protocolVersion: PROTOCOL_VERSION };
      if (opts.agentId !== undefined) hello.agentId = opts.agentId;
      write(hello);
    });
    socket.on('error', (err) => {
      if (!ready) {
        clearTimeout(helloTimer);
        reject(err);
      }
    });
    socket.on('close', () => {
      clearTimeout(helloTimer);
      if (!ready) reject(rpcError('connection_closed', 'connection closed before hello_ok'));
      for (const p of pending.values()) {
        clearTimeout(p.timer);
        p.reject(rpcError('connection_closed', 'connection closed'));
      }
      pending.clear();
      for (const cb of closeCbs) cb();
    });
  });
}
