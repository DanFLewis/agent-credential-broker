import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import type { Server, Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  LineSplitter,
  NativeMessageReader,
  acbHome,
  connectBroker,
  encodeNativeMessage,
  pipePath,
} from '../src/node.js';

describe('acbHome / pipePath', () => {
  it('honours the environment overrides', () => {
    const oldHome = process.env.ACB_HOME;
    const oldPipe = process.env.ACB_PIPE;
    try {
      process.env.ACB_HOME = join(tmpdir(), 'acb-home-test');
      process.env.ACB_PIPE = 'custom-pipe';
      expect(acbHome()).toBe(join(tmpdir(), 'acb-home-test'));
      expect(pipePath()).toBe('custom-pipe');
      delete process.env.ACB_PIPE;
      if (process.platform !== 'win32') {
        expect(pipePath()).toBe(join(tmpdir(), 'acb-home-test', 'broker.sock'));
      } else {
        expect(pipePath()).toMatch(/^\\\\\.\\pipe\\acb-broker-/);
      }
    } finally {
      if (oldHome === undefined) delete process.env.ACB_HOME;
      else process.env.ACB_HOME = oldHome;
      if (oldPipe === undefined) delete process.env.ACB_PIPE;
      else process.env.ACB_PIPE = oldPipe;
    }
  });
});

describe('LineSplitter', () => {
  function make(max?: number) {
    const lines: string[] = [];
    const errors: string[] = [];
    const s = new LineSplitter((l) => lines.push(l), (e) => errors.push(e.message), max);
    return { s, lines, errors };
  }

  it('splits lines across arbitrary chunk boundaries', () => {
    const { s, lines } = make();
    s.push(Buffer.from('{"a":1}\n{"b"'));
    s.push(Buffer.from(':2}\n\n{"c":3}'));
    expect(lines).toEqual(['{"a":1}', '{"b":2}', '']);
    s.push(Buffer.from('\n'));
    expect(lines).toEqual(['{"a":1}', '{"b":2}', '', '{"c":3}']);
  });

  it('handles multi-byte characters split across chunks and CRLF', () => {
    const { s, lines } = make();
    const bytes = Buffer.from('héllo 🔑\r\n');
    for (const b of bytes) s.push(Buffer.from([b]));
    expect(lines).toEqual(['héllo 🔑']);
  });

  it('accepts string chunks', () => {
    const { s, lines } = make();
    s.push('a\nb\n');
    expect(lines).toEqual(['a', 'b']);
  });

  it('drops an oversize line, reports once, and recovers on the next line', () => {
    const { s, lines, errors } = make(10);
    s.push(Buffer.from('ok1\n'));
    s.push(Buffer.from('x'.repeat(8)));
    s.push(Buffer.from('y'.repeat(8))); // crosses the limit mid-line
    s.push(Buffer.from('z'.repeat(50) + '\n'));
    s.push(Buffer.from('ok2\n'));
    expect(lines).toEqual(['ok1', 'ok2']);
    expect(errors).toHaveLength(1);
  });

  it('drops an oversize line that arrives in a single chunk', () => {
    const { s, lines, errors } = make(10);
    s.push(Buffer.from('x'.repeat(100) + '\nfine\n'));
    expect(lines).toEqual(['fine']);
    expect(errors).toHaveLength(1);
  });

  it('allows a line of exactly the limit', () => {
    const { s, lines, errors } = make(10);
    s.push(Buffer.from('x'.repeat(10) + '\n'));
    expect(lines).toEqual(['x'.repeat(10)]);
    expect(errors).toHaveLength(0);
  });
});

describe('native messaging framing', () => {
  it('encodes a uint32 LE length prefix', () => {
    const buf = encodeNativeMessage({ hi: 'there' });
    const body = JSON.stringify({ hi: 'there' });
    expect(buf.readUInt32LE(0)).toBe(Buffer.byteLength(body));
    expect(buf.subarray(4).toString('utf8')).toBe(body);
  });

  it('round-trips with 1-byte chunks and with coalesced chunks', () => {
    const msgs = [{ a: 1 }, { text: 'héllo 🔑' }, { nested: { x: [1, 2, 3] } }];
    const wire = Buffer.concat(msgs.map(encodeNativeMessage));

    const byByte: unknown[] = [];
    const r1 = new NativeMessageReader((m) => byByte.push(m));
    for (const b of wire) r1.push(Buffer.from([b]));
    expect(byByte).toEqual(msgs);

    const whole: unknown[] = [];
    new NativeMessageReader((m) => whole.push(m)).push(wire);
    expect(whole).toEqual(msgs);
  });

  it('rejects an oversize outgoing message', () => {
    expect(() => encodeNativeMessage({ big: 'x'.repeat(1024 * 1024) })).toThrow(/too large/);
  });

  it('rejects an oversize incoming length, reports it, and stops reading', () => {
    const got: unknown[] = [];
    const errors: string[] = [];
    const r = new NativeMessageReader((m) => got.push(m), (e) => errors.push(e.message));
    const header = Buffer.alloc(4);
    header.writeUInt32LE(1024 * 1024 + 1, 0);
    r.push(header);
    r.push(encodeNativeMessage({ after: true }));
    expect(errors).toHaveLength(1);
    expect(got).toEqual([]);
  });

  it('reports invalid JSON without echoing it and keeps going', () => {
    const got: unknown[] = [];
    const errors: string[] = [];
    const r = new NativeMessageReader((m) => got.push(m), (e) => errors.push(e.message));
    const bad = Buffer.from('not json SECRET');
    const header = Buffer.alloc(4);
    header.writeUInt32LE(bad.length, 0);
    r.push(Buffer.concat([header, bad, encodeNativeMessage({ ok: 1 })]));
    expect(got).toEqual([{ ok: 1 }]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).not.toContain('SECRET');
  });
});

describe('connectBroker', () => {
  const dirs: string[] = [];
  const servers: Server[] = [];

  afterEach(async () => {
    for (const s of servers.splice(0)) await new Promise((r) => s.close(r));
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  function tempPath(): string {
    if (process.platform === 'win32') return `\\\\.\\pipe\\acb-test-${process.pid}-${Math.random().toString(36).slice(2)}`;
    const dir = mkdtempSync(join(tmpdir(), 'acb-'));
    dirs.push(dir);
    return join(dir, 's.sock');
  }

  /** Tiny broker: requires hello, echoes `echo`, errors on `fail`, never answers `hang`. */
  async function startServer(onHello?: (msg: Record<string, unknown>, sock: Socket) => void) {
    const path = tempPath();
    const server = createServer((sock) => {
      let buf = '';
      sock.on('data', (d) => {
        buf += d.toString('utf8');
        let i: number;
        while ((i = buf.indexOf('\n')) >= 0) {
          const msg = JSON.parse(buf.slice(0, i)) as Record<string, any>;
          buf = buf.slice(i + 1);
          const send = (o: unknown) => sock.write(JSON.stringify(o) + '\n');
          if (msg.type === 'hello') {
            onHello?.(msg, sock);
            send({ type: 'hello_ok', protocolVersion: 1 });
            send({ type: 'fill_job', jobId: 'j1', origin: 'https://example.com', expiresAt: 1 });
          } else if (msg.method === 'echo') send({ type: 'rpc_result', id: msg.id, result: msg.params });
          else if (msg.method === 'fail')
            send({ type: 'rpc_error', id: msg.id, error: { code: 'origin_mismatch', message: 'nope' } });
          else if (msg.method === 'drop') sock.destroy();
        }
      });
    });
    servers.push(server);
    await new Promise<void>((r) => server.listen(path, r));
    return path;
  }

  it('sends hello, resolves rpc calls, delivers pushes and rpc errors', async () => {
    const hellos: Record<string, unknown>[] = [];
    const path = await startServer((m) => hellos.push(m));
    const pushes: unknown[] = [];
    const conn = await connectBroker({ role: 'agent', agentId: 'test-agent', path });
    conn.onPush((m) => pushes.push(m));

    expect(hellos[0]).toMatchObject({ type: 'hello', role: 'agent', agentId: 'test-agent', protocolVersion: 1 });
    expect(await conn.call('echo', { x: 1 }, 1000)).toEqual({ x: 1 });
    const err = await conn.call('fail', {}, 1000).catch((e: Error & { code?: string }) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error & { code: string }).code).toBe('origin_mismatch');
    conn.close();
  });

  it('delivers broker pushes (fill_job) to onPush listeners', async () => {
    // The server sends fill_job immediately after hello_ok, in the same tick as the resolve, so
    // the listener (registered synchronously after the await) still sees it.
    const path = await startServer();
    const conn = await connectBroker({ role: 'filler', path });
    const push = await new Promise<{ type: string; jobId: string }>((res) => conn.onPush(res as (m: unknown) => void));
    expect(push).toMatchObject({ type: 'fill_job', jobId: 'j1' });
    conn.close();
  });

  it('send() writes raw strings and objects as lines', async () => {
    const path = await startServer();
    const conn = await connectBroker({ role: 'filler', path });
    // Responses to raw sends are pushed through as non-matching rpc_results are ignored, so use
    // call() ids: send() frames must be valid lines the server can parse and answer.
    conn.send(JSON.stringify({ type: 'rpc', id: 'raw1', method: 'echo', params: 7 }));
    conn.send({ type: 'rpc', id: 'raw2', method: 'echo', params: 8 });
    expect(await conn.call('echo', 'still-framed', 1000)).toBe('still-framed');
    conn.close();
  });

  it('times out calls that get no answer', async () => {
    const path = await startServer();
    const conn = await connectBroker({ role: 'agent', path });
    const err = await conn.call('hang', {}, 50).catch((e: Error & { code?: string }) => e);
    expect((err as Error & { code: string }).code).toBe('timeout');
    conn.close();
  });

  it('rejects pending calls and fires onClose when the connection drops', async () => {
    const path = await startServer();
    const conn = await connectBroker({ role: 'agent', path });
    const closed = new Promise<void>((res) => conn.onClose(res));
    const err = await conn.call('drop', {}, 2000).catch((e: Error & { code?: string }) => e);
    expect((err as Error & { code: string }).code).toBe('connection_closed');
    await closed;
    const after = await conn.call('echo', {}, 100).catch((e: Error & { code?: string }) => e);
    expect((after as Error & { code: string }).code).toBe('connection_closed');
  });

  it('rejects when nothing is listening', async () => {
    await expect(connectBroker({ role: 'agent', path: tempPath() })).rejects.toThrow();
  });
});
