// Wire protocol between broker <-> MCP server (role 'agent') and broker <-> native host (role 'filler').
// Transport: named pipe (Windows) / unix socket, newline-delimited JSON, one message per line.
// The native host relays filler messages to/from the extension unchanged using Chrome's
// native-messaging framing (uint32 LE length + UTF-8 JSON).
//
// INVARIANT: no plaintext secret ever crosses this protocol. Secrets travel only as SealedSecret
// (encrypted to the paired extension's public key).

import type { BrokerAgentApi, FillConfig, FillErrorCode, Origin } from './types.js';

export const PROTOCOL_VERSION = 1;
export const NATIVE_HOST_NAME = 'com.acb.broker';

/** First message on every connection, client -> broker. */
export interface HelloMessage {
  type: 'hello';
  role: 'agent' | 'filler';
  protocolVersion: number;
  /** role 'agent' only. */
  agentId?: string;
}
export interface HelloOk {
  type: 'hello_ok';
  protocolVersion: number;
}

/** Request/response envelope (client -> broker). `id` is chosen by the client. */
export interface RpcRequest<M extends string = string, P = unknown> {
  type: 'rpc';
  id: string;
  method: M;
  params: P;
}
export interface RpcResponseOk<R = unknown> {
  type: 'rpc_result';
  id: string;
  result: R;
}
export interface RpcResponseErr {
  type: 'rpc_error';
  id: string;
  error: { code: string; message: string };
}
export type RpcResponse<R = unknown> = RpcResponseOk<R> | RpcResponseErr;

// ---- role 'agent' methods: names match BrokerAgentApi ----
export type AgentMethod = keyof BrokerAgentApi; // 'requestLogin' | 'grantStatus' | 'listGrants'

// ---- role 'filler' ----

/** Broker -> filler push. */
export interface FillJobMessage {
  type: 'fill_job';
  jobId: string;
  origin: Origin;
  expiresAt: number;
}

/** AES-GCM ciphertext of JSON {"username","password"}; see crypto.ts for the scheme. */
export interface SealedSecret {
  /** Broker's ephemeral ECDH P-256 public key, raw uncompressed, base64url. */
  epk: string;
  /** 12-byte IV, base64url. */
  iv: string;
  /** Ciphertext incl. GCM tag, base64url. */
  ct: string;
}

export interface ClaimSecretParams {
  jobId: string;
  /** Origin of the tab's committed top-frame document as observed by the extension. */
  tabOrigin: Origin;
  /** documentId from chrome.webNavigation.getFrame({tabId, frameId: 0}). */
  documentId: string;
}
export interface ClaimSecretResult {
  jobId: string;
  sealed: SealedSecret;
  fillConfig: FillConfig;
}

export interface FillResultParams {
  jobId: string;
  status: 'submitted' | 'error';
  code?: FillErrorCode;
  message?: string;
}

export interface PairParams {
  /** Extension's static ECDH P-256 public key, raw uncompressed, base64url. */
  publicKey: string;
}
export interface PairResult {
  status: 'pending' | 'paired';
  /** Short code shown in both the extension and the dashboard for human comparison. */
  pairingCode: string;
}

export type FillerMethod = 'claimSecret' | 'fillResult' | 'pair';

export type ClientMessage = HelloMessage | RpcRequest;
export type BrokerMessage = HelloOk | RpcResponse | FillJobMessage;

/** AAD binding for the sealed secret. Both sides must build it identically. */
export function secretAad(jobId: string, origin: Origin, documentId: string): string {
  return `acb-v1|${jobId}|${origin}|${documentId}`;
}
