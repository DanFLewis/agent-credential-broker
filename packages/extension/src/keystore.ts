// Persists the extension's ECDH key pair in IndexedDB. CryptoKey objects are structured-cloneable,
// so the non-extractable private key is stored directly and its bytes never become readable JS.
import { generateRecipientKeyPair } from '@acb/core';

const DB_NAME = 'acb';
const STORE = 'keys';
const KEY_ID = 'recipient';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(db: IDBDatabase, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = fn(db.transaction(STORE, mode).objectStore(STORE));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

let pending: Promise<CryptoKeyPair> | null = null;

/** Loads the key pair, creating and storing it on first run. Memoised so concurrent callers share one. */
export function loadOrCreateKeyPair(): Promise<CryptoKeyPair> {
  pending ??= (async () => {
    const db = await openDb();
    const existing = await tx<CryptoKeyPair | undefined>(db, 'readonly', (s) => s.get(KEY_ID));
    if (existing) return existing;
    const pair = await generateRecipientKeyPair();
    await tx(db, 'readwrite', (s) => s.put(pair, KEY_ID));
    return pair;
  })().catch((e) => {
    pending = null; // allow a retry after a transient failure
    throw e;
  });
  return pending;
}
