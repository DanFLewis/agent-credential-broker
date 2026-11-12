// Relay between Chrome's native-messaging channel and the broker connection. Kept free of process-level
// side effects so it can be tested with fake streams.
//
// Never log message bodies: they carry sealed secrets and origins. Diagnostics are one line to stderr
// with the message type and method only.
import type { Readable, Writable } from 'node:stream';
import { NativeMessageReader, encodeNativeMessage } from '@acb/core/node';
import type { BrokerConnection } from '@acb/core/node';

/** The part of BrokerConnection that the relay uses. */
export type BrokerLike = Pick<BrokerConnection, 'call' | 'onPush'>;

export interface Relay {
  /** Call with a fresh broker connection (or null when it dropped). Pushes (fill_job) go to the extension. */
  attach(conn: BrokerLike | null): void;
}

const RPC_TIMEOUT_MS = 30_000;
const BROKER_DOWN = 'broker_unavailable';

export function relay(
  extIn: Readable,
  extOut: Writable,
  initial: BrokerLike | null = null,
  diag: (line: string) => void = () => {},
): Relay {
  let broker: BrokerLike | null = null;
  const toExt = (msg: object): void => {
    extOut.write(encodeNativeMessage(msg));
  };
  const rpcError = (id: string, code: string, message: string): void =>
    toExt({ type: 'rpc_error', id, error: { code, message } });

  const attach = (conn: BrokerLike | null): void => {
    broker = conn;
    // Only forward pushes from the connection that is still current.
    conn?.onPush((msg) => {
      if (broker !== conn) return;
      diag(`broker->ext ${msg.type}`);
      toExt(msg);
    });
  };

  const onExtMessage = (msg: unknown): void => {
    const m = msg as { type?: unknown; id?: unknown; method?: unknown; params?: unknown } | null;
    if (!m || m.type !== 'rpc' || typeof m.id !== 'string' || typeof m.method !== 'string') {
      diag('ext->host ignored non-rpc message');
      return;
    }
    const { id, method } = m;
    diag(`ext->broker rpc ${method}`);
    const conn = broker;
    if (!conn) return rpcError(id, BROKER_DOWN, 'broker is not running');
    conn.call(method, m.params, RPC_TIMEOUT_MS).then(
      (result) => toExt({ type: 'rpc_result', id, result }),
      (err: { code?: unknown }) => {
        const code = typeof err?.code === 'string' ? err.code : 'rpc_failed';
        // connection_closed means the broker went away mid-call.
        rpcError(id, code === 'connection_closed' ? BROKER_DOWN : code, 'rpc failed');
      },
    );
  };

  const reader = new NativeMessageReader(onExtMessage, () => diag('ext->host framing error'));
  extIn.on('data', (chunk: Buffer) => reader.push(chunk));

  attach(initial);
  return { attach };
}
