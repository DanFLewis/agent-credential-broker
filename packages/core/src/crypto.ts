// Sealed-secret scheme (ECDH P-256 -> HKDF-SHA256 -> AES-256-GCM), see CONTRACT.md.
// Only globalThis.crypto.subtle is used, so this runs in Node 24 and in the extension service worker.

import type { SealedSecret } from './protocol.js';

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const HKDF_INFO = enc.encode('acb-v1-seal');
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ECDH = { name: 'ECDH', namedCurve: 'P-256' } as const;

export function b64uEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** The private key is non-extractable: it can be used but never read back out. */
export function generateRecipientKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey(ECDH, false, ['deriveBits']);
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return b64uEncode(new Uint8Array(await subtle.exportKey('raw', key)));
}

/**
 * 80 bits of SHA-256(raw public key) as Crockford base32, "XXXX-XXXX-XXXX-XXXX"; humans compare it
 * on both screens. 80 bits so a same-user attacker cannot grind a key whose code collides with the
 * real extension's (the pending key is readable in broker.db).
 */
export async function pairingCode(publicKeyB64u: string): Promise<string> {
  const digest = new Uint8Array(await subtle.digest('SHA-256', b64uDecode(publicKeyB64u) as BufferSource));
  let bits = 0n;
  for (const b of digest.subarray(0, 10)) bits = (bits << 8n) | BigInt(b);
  let out = '';
  for (let i = 15; i >= 0; i--) out += CROCKFORD[Number((bits >> BigInt(i * 5)) & 31n)];
  return out.match(/.{4}/g)!.join('-');
}

/** Shared by seal and open: ECDH shared bits -> HKDF (salt = ephemeral public key) -> AES-GCM key. */
async function deriveAesKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  epkRaw: Uint8Array,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  const shared = await subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: epkRaw as BufferSource, info: HKDF_INFO },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

export async function sealSecret(
  recipientPublicKeyB64u: string,
  secret: { username: string; password: string },
  aad: string,
): Promise<SealedSecret> {
  const recipient = await subtle.importKey('raw', b64uDecode(recipientPublicKeyB64u) as BufferSource, ECDH, false, []);
  const eph = await subtle.generateKey(ECDH, false, ['deriveBits']);
  const epkRaw = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const key = await deriveAesKey(eph.privateKey, recipient, epkRaw, 'encrypt');
  // Fresh random IV per message (the key is also fresh per message).
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = enc.encode(JSON.stringify({ username: secret.username, password: secret.password }));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, plaintext);
  return { epk: b64uEncode(epkRaw), iv: b64uEncode(iv), ct: b64uEncode(new Uint8Array(ct)) };
}

/** Throws (GCM authentication failure) on a wrong key, wrong AAD or tampered ciphertext. */
export async function openSecret(
  privateKey: CryptoKey,
  sealed: SealedSecret,
  aad: string,
): Promise<{ username: string; password: string }> {
  const epkRaw = b64uDecode(sealed.epk);
  const epk = await subtle.importKey('raw', epkRaw as BufferSource, ECDH, false, []);
  const key = await deriveAesKey(privateKey, epk, epkRaw, 'decrypt');
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64uDecode(sealed.iv) as BufferSource, additionalData: enc.encode(aad) },
    key,
    b64uDecode(sealed.ct) as BufferSource,
  );
  const { username, password } = JSON.parse(new TextDecoder().decode(pt)) as { username: string; password: string };
  return { username, password };
}
