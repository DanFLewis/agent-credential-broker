import { describe, expect, it } from 'vitest';
import {
  b64uDecode,
  b64uEncode,
  exportPublicKey,
  generateRecipientKeyPair,
  openSecret,
  pairingCode,
  sealSecret,
} from '../src/crypto.js';
import { secretAad } from '../src/protocol.js';

const SECRET = { username: 'test-user', password: 'correct-horse-test-only' };
const AAD = secretAad('job-1', 'https://example.com', 'doc-1');

describe('base64url', () => {
  it('round-trips arbitrary bytes without padding or url-unsafe chars', () => {
    for (let len = 0; len < 40; len++) {
      const bytes = crypto.getRandomValues(new Uint8Array(len));
      const s = b64uEncode(bytes);
      expect(s).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(Array.from(b64uDecode(s))).toEqual(Array.from(bytes));
    }
  });
});

describe('key pair', () => {
  it('has a non-extractable private key and a raw 65-byte public key', async () => {
    const kp = await generateRecipientKeyPair();
    expect(kp.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', kp.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('jwk', kp.privateKey)).rejects.toThrow();
    const raw = b64uDecode(await exportPublicKey(kp.publicKey));
    expect(raw.length).toBe(65);
    expect(raw[0]).toBe(0x04);
  });
});

describe('seal / open', () => {
  it('round-trips', async () => {
    const kp = await generateRecipientKeyPair();
    const sealed = await sealSecret(await exportPublicKey(kp.publicKey), SECRET, AAD);
    expect(await openSecret(kp.privateKey, sealed, AAD)).toEqual(SECRET);
  });

  it('does not contain the plaintext and uses a fresh epk/iv each time', async () => {
    const kp = await generateRecipientKeyPair();
    const pub = await exportPublicKey(kp.publicKey);
    const a = await sealSecret(pub, SECRET, AAD);
    const b = await sealSecret(pub, SECRET, AAD);
    expect(JSON.stringify(a)).not.toContain(SECRET.password);
    expect(a.epk).not.toBe(b.epk);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
    expect(b64uDecode(a.iv).length).toBe(12);
  });

  it('handles unicode and quotes', async () => {
    const kp = await generateRecipientKeyPair();
    const s = { username: 'üser"\\', password: 'pä$$ "wörd" 🔑' };
    const sealed = await sealSecret(await exportPublicKey(kp.publicKey), s, AAD);
    expect(await openSecret(kp.privateKey, sealed, AAD)).toEqual(s);
  });

  it('fails with the wrong AAD', async () => {
    const kp = await generateRecipientKeyPair();
    const sealed = await sealSecret(await exportPublicKey(kp.publicKey), SECRET, AAD);
    await expect(
      openSecret(kp.privateKey, sealed, secretAad('job-1', 'https://evil.example', 'doc-1')),
    ).rejects.toThrow();
    await expect(openSecret(kp.privateKey, sealed, secretAad('job-1', 'https://example.com', 'doc-2'))).rejects.toThrow();
  });

  it('fails with the wrong key', async () => {
    const kp = await generateRecipientKeyPair();
    const other = await generateRecipientKeyPair();
    const sealed = await sealSecret(await exportPublicKey(kp.publicKey), SECRET, AAD);
    await expect(openSecret(other.privateKey, sealed, AAD)).rejects.toThrow();
  });

  it('fails when ct, iv or epk are tampered with', async () => {
    const kp = await generateRecipientKeyPair();
    const pub = await exportPublicKey(kp.publicKey);
    const sealed = await sealSecret(pub, SECRET, AAD);

    const ct = b64uDecode(sealed.ct);
    ct[0] = ct[0]! ^ 0x01;
    await expect(openSecret(kp.privateKey, { ...sealed, ct: b64uEncode(ct) }, AAD)).rejects.toThrow();

    const iv = b64uDecode(sealed.iv);
    iv[0] = iv[0]! ^ 0x01;
    await expect(openSecret(kp.privateKey, { ...sealed, iv: b64uEncode(iv) }, AAD)).rejects.toThrow();

    const other = await sealSecret(pub, SECRET, AAD);
    await expect(openSecret(kp.privateKey, { ...sealed, epk: other.epk }, AAD)).rejects.toThrow();
  });
});

describe('pairingCode', () => {
  it('has the XXXX-XXXX Crockford format', async () => {
    const kp = await generateRecipientKeyPair();
    expect(await pairingCode(await exportPublicKey(kp.publicKey))).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  });

  it('is stable for the same key and differs between keys', async () => {
    const a = await exportPublicKey((await generateRecipientKeyPair()).publicKey);
    const b = await exportPublicKey((await generateRecipientKeyPair()).publicKey);
    expect(await pairingCode(a)).toBe(await pairingCode(a));
    expect(await pairingCode(a)).not.toBe(await pairingCode(b));
  });

  it('matches a known vector (SHA-256 of 65 zero bytes, first 40 bits)', async () => {
    const key = b64uEncode(new Uint8Array(65));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(65)));
    const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    let bits = '';
    for (const b of digest.subarray(0, 5)) bits += b.toString(2).padStart(8, '0');
    let expected = '';
    for (let i = 0; i < 40; i += 5) expected += alphabet[parseInt(bits.slice(i, i + 5), 2)];
    expect(await pairingCode(key)).toBe(`${expected.slice(0, 4)}-${expected.slice(4)}`);
  });
});
