import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { NativeMessageReader, encodeNativeMessage } from '@acb/core/node';
import { relay } from '../src/relay.js';
import type { BrokerLike } from '../src/relay.js';

function harness(broker: BrokerLike | null) {
  const extIn = new PassThrough();
  const extOut = new PassThrough();
  const out: any[] = [];
  const reader = new NativeMessageReader((m) => out.push(m));
  extOut.on('data', (c: Buffer) => reader.push(c));
  const r = relay(extIn, extOut, broker);
  const send = (m: object) => extIn.write(encodeNativeMessage(m));
  const settle = () => new Promise((res) => setTimeout(res, 10));
  return { r, out, send, settle, extIn };
}

function fakeBroker(impl: BrokerLike['call']) {
  let push: ((m: any) => void) | undefined;
  const b: BrokerLike = { call: impl, onPush: (cb) => void (push = cb) };
  return { b, push: (m: object) => push?.(m) };
}

describe('native host relay', () => {
  it('answers broker_unavailable when no broker connection exists', async () => {
    const h = harness(null);
    h.send({ type: 'rpc', id: 'a1', method: 'pair', params: { publicKey: 'x' } });
    await h.settle();
    expect(h.out).toEqual([
      { type: 'rpc_error', id: 'a1', error: { code: 'broker_unavailable', message: 'broker is not running' } },
    ]);
  });

  it('relays rpc to the broker and wraps the result with the extension id', async () => {
    const calls: unknown[] = [];
    const { b } = fakeBroker(async (method, params) => {
      calls.push([method, params]);
      return { status: 'pending', pairingCode: 'ABCD-EFGH' };
    });
    const h = harness(b);
    h.send({ type: 'rpc', id: 'x9', method: 'pair', params: { publicKey: 'k' } });
    await h.settle();
    expect(calls).toEqual([['pair', { publicKey: 'k' }]]);
    expect(h.out).toEqual([{ type: 'rpc_result', id: 'x9', result: { status: 'pending', pairingCode: 'ABCD-EFGH' } }]);
  });

  it('turns broker rpc errors into rpc_error with the code only', async () => {
    const { b } = fakeBroker(() => Promise.reject(Object.assign(new Error('detail'), { code: 'job_expired' })));
    const h = harness(b);
    h.send({ type: 'rpc', id: '1', method: 'claimSecret', params: {} });
    await h.settle();
    expect(h.out).toEqual([{ type: 'rpc_error', id: '1', error: { code: 'job_expired', message: 'rpc failed' } }]);
  });

  it('maps a dropped connection to broker_unavailable', async () => {
    const { b } = fakeBroker(() => Promise.reject(Object.assign(new Error('x'), { code: 'connection_closed' })));
    const h = harness(b);
    h.send({ type: 'rpc', id: '2', method: 'fillResult', params: {} });
    await h.settle();
    expect(h.out[0].error.code).toBe('broker_unavailable');
  });

  it('forwards fill_job pushes to the extension, only from the current connection', async () => {
    const old = fakeBroker(async () => null);
    const fresh = fakeBroker(async () => null);
    const h = harness(old.b);
    h.r.attach(fresh.b);
    old.push({ type: 'fill_job', jobId: 'stale', origin: 'https://a.test', expiresAt: 1 });
    fresh.push({ type: 'fill_job', jobId: 'j1', origin: 'https://a.test', expiresAt: 1 });
    await h.settle();
    expect(h.out).toEqual([{ type: 'fill_job', jobId: 'j1', origin: 'https://a.test', expiresAt: 1 }]);
  });

  it('ignores non-rpc and malformed messages without writing anything', async () => {
    const h = harness(fakeBroker(async () => 1).b);
    h.send({ type: 'hello' });
    h.send({ type: 'rpc', id: 5, method: 'pair' });
    await h.settle();
    expect(h.out).toEqual([]);
  });

  it('writes only valid native frames to the output stream', async () => {
    const extIn = new PassThrough();
    const extOut = new PassThrough();
    const chunks: Buffer[] = [];
    extOut.on('data', (c: Buffer) => chunks.push(c));
    relay(extIn, extOut, null);
    extIn.write(encodeNativeMessage({ type: 'rpc', id: 'q', method: 'pair', params: {} }));
    await new Promise((r) => setTimeout(r, 10));
    const all = Buffer.concat(chunks);
    expect(all.readUInt32LE(0)).toBe(all.length - 4);
  });
});
