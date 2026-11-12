// Service worker: owns the native-messaging port, the pairing key and the fill-job flow.
// Logging rule: only job ids and error codes are ever logged, never values, origins or messages.
import { NATIVE_HOST_NAME, exportPublicKey, normalizeOrigin, openSecret, pairingCode, secretAad } from '@acb/core';
import type {
  BrokerMessage,
  ClaimSecretResult,
  FillErrorCode,
  FillJobMessage,
  FillResult,
  PairResult,
  RpcRequest,
} from '@acb/core';
import { fillAndSubmit } from './fill.js';
import { loadOrCreateKeyPair } from './keystore.js';
import { selectTab } from './select.js';

const RPC_TIMEOUT_MS = 30_000;
const PAIR_POLL_MS = 5_000;

const KNOWN_ERRORS: ReadonlySet<string> = new Set<FillErrorCode>([
  'no_filler', 'not_paired', 'no_tab', 'ambiguous_tab', 'origin_mismatch', 'not_top_frame', 'no_form',
  'cross_origin_action', 'submit_failed', 'injection_failed', 'decrypt_failed', 'job_expired', 'timeout',
]);

class RpcError extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

// ---------- state shown in the popup ----------
const state: { connected: boolean; pairing: 'unknown' | 'pending' | 'paired'; pairingCode: string | null } = {
  connected: false,
  pairing: 'unknown',
  pairingCode: null,
};

// ---------- native port ----------
let port: chrome.runtime.Port | null = null;
let backoffMs = 1_000;
const inflight = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: number }>();

function connect(): void {
  let p: chrome.runtime.Port;
  try {
    p = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  } catch {
    scheduleReconnect();
    return;
  }
  port = p;
  state.connected = true;
  p.onMessage.addListener((m: BrokerMessage) => {
    backoffMs = 1_000;
    onBrokerMessage(m);
  });
  p.onDisconnect.addListener(() => {
    // Chrome's own reason (e.g. "Specified native messaging host not found."); it never carries page or secret data.
    const reason = chrome.runtime.lastError?.message;
    if (reason) console.warn('native host disconnected:', reason);
    if (port === p) port = null;
    state.connected = false;
    state.pairing = 'unknown';
    state.pairingCode = null;
    for (const [id, f] of inflight) {
      clearTimeout(f.timer);
      f.reject(new RpcError('disconnected'));
      inflight.delete(id);
    }
    scheduleReconnect();
  });
  void ensurePaired();
}

function scheduleReconnect(): void {
  setTimeout(connect, backoffMs);
  backoffMs = Math.min(backoffMs * 2, 30_000);
}

function call<R>(method: string, params: unknown): Promise<R> {
  return new Promise<R>((resolve, reject) => {
    if (!port) return reject(new RpcError('disconnected'));
    const id = crypto.randomUUID();
    const timer = setTimeout(() => {
      inflight.delete(id);
      reject(new RpcError('timeout'));
    }, RPC_TIMEOUT_MS) as unknown as number;
    inflight.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
    const req: RpcRequest = { type: 'rpc', id, method, params };
    port.postMessage(req);
  });
}

function onBrokerMessage(m: BrokerMessage): void {
  if (m.type === 'rpc_result' || m.type === 'rpc_error') {
    const f = inflight.get(m.id);
    if (!f) return;
    inflight.delete(m.id);
    clearTimeout(f.timer);
    if (m.type === 'rpc_result') f.resolve(m.result);
    else f.reject(new RpcError(m.error.code));
  } else if (m.type === 'fill_job') {
    void handleFillJob(m);
  }
}

// ---------- pairing ----------
let pairTimer: number | undefined;

/** Registers our public key. Safe to repeat: the broker answers pending/paired with the same code. */
async function ensurePaired(): Promise<void> {
  clearTimeout(pairTimer);
  try {
    const keys = await loadOrCreateKeyPair();
    const publicKey = await exportPublicKey(keys.publicKey);
    const res = await call<PairResult>('pair', { publicKey });
    state.pairing = res.status;
    // Computed from our own key, never taken from the broker, so the popup cannot be told what to show.
    state.pairingCode = await pairingCode(publicKey);
    if (res.status === 'paired') return;
  } catch (e) {
    console.warn('pair failed', e instanceof RpcError ? e.code : 'error');
    if (!port) return; // the reconnect path will call us again
  }
  // Broker down or waiting for the human to confirm: poll until paired.
  pairTimer = setTimeout(() => void ensurePaired(), PAIR_POLL_MS) as unknown as number;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own popup may ask.
  if (sender.id === chrome.runtime.id && msg?.type === 'status') sendResponse(state);
});

// ---------- fill jobs ----------
async function report(jobId: string, result: FillResult): Promise<void> {
  try {
    await call('fillResult', {
      jobId,
      status: result.status,
      ...(result.status === 'error' ? { code: result.code } : {}),
    });
  } catch {
    console.warn('fillResult not delivered', jobId);
  }
}

async function runFill(job: FillJobMessage): Promise<FillResult> {
  const err = (code: FillErrorCode): FillResult => ({ status: 'error', code });
  if (Date.now() >= job.expiresAt) return err('job_expired');

  const keys = await loadOrCreateKeyPair();
  const [tabs, win] = await Promise.all([chrome.tabs.query({}), chrome.windows.getLastFocused()]);
  const sel = selectTab(job.origin, tabs, win.id);
  if (!sel.ok) return err(sel.code);

  // Pin the exact document: documentId goes into the AAD and the injection target (closes the TOCTOU gap).
  const frame = await chrome.webNavigation.getFrame({ tabId: sel.tabId, frameId: 0 });
  if (!frame?.documentId) return err('no_tab');
  const tabOrigin = normalizeOrigin(frame.url);
  if (tabOrigin !== job.origin) return err('origin_mismatch');
  const documentId = frame.documentId;

  let claim: ClaimSecretResult;
  try {
    claim = await call<ClaimSecretResult>('claimSecret', { jobId: job.jobId, tabOrigin, documentId });
  } catch (e) {
    const code = e instanceof RpcError ? e.code : '';
    return err(KNOWN_ERRORS.has(code) ? (code as FillErrorCode) : 'timeout');
  }

  // Decrypted creds live only in these locals and are dropped right after injection.
  let creds: { username: string; password: string } | null = null;
  try {
    creds = await openSecret(keys.privateKey, claim.sealed, secretAad(job.jobId, job.origin, documentId));
  } catch {
    return err('decrypt_failed');
  }
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: sel.tabId, documentIds: [documentId] },
      world: 'ISOLATED',
      func: fillAndSubmit,
      args: [job.origin, creds, claim.fillConfig],
    });
    return res?.result ?? err('injection_failed');
  } catch {
    return err('injection_failed');
  } finally {
    creds = null;
  }
}

async function handleFillJob(job: FillJobMessage): Promise<void> {
  let result: FillResult;
  try {
    result = await runFill(job);
  } catch {
    result = { status: 'error', code: 'injection_failed' };
  }
  console.info('fill_job', job.jobId, result.status === 'error' ? result.code : 'submitted');
  await report(job.jobId, result);
}

connect();
