// Origin normalisation and LAN classification.
// SECURITY: every origin comparison in the system goes through normalizeOrigin() and then uses
// exact string equality. Never compare raw URLs, never use endsWith/includes on hosts.

import type { Origin } from './types.js';

/**
 * Returns the canonical "scheme://host[:port]" or null if the input is not an acceptable origin.
 * The WHATWG URL parser does the heavy lifting: it lowercases scheme/host, drops default ports,
 * converts IDN to punycode and canonicalises IPv4 (hex/decimal/octal) and IPv6 forms.
 */
export function normalizeOrigin(input: string): Origin | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  // Userinfo is the classic spoofing trick (https://192.168.50.1@evil.com); refuse it outright.
  if (url.username !== '' || url.password !== '') return null;
  // "example.com." is a distinct string from "example.com" even though DNS treats them alike.
  if (url.hostname === '' || url.hostname.endsWith('.')) return null;
  if (url.origin === 'null') return null;
  return url.origin;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** True for private, loopback and link-local hosts. Accepts a URL hostname (IPv6 may be bracketed). */
export function isLanHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;

  const m = IPV4.exec(h);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254)
    );
  }

  if (h.includes(':')) {
    const v6 = h.replace(/^\[|\]$/g, '');
    if (v6 === '::1') return true;
    const first = Number.parseInt(v6.split(':')[0] || '0', 16);
    if (Number.isNaN(first)) return false;
    return (first & 0xffc0) === 0xfe80 /* fe80::/10 */ || (first & 0xfe00) === 0xfc00 /* fc00::/7 */;
  }
  return false;
}

/** Callers must reject 'http-public' (cleartext over the internet) with `insecure_site`. */
export function classifyOrigin(origin: Origin): 'https' | 'http-lan' | 'http-public' {
  const url = new URL(origin);
  if (url.protocol === 'https:') return 'https';
  return isLanHost(url.hostname) ? 'http-lan' : 'http-public';
}

export function originsEqual(a: string, b: string): boolean {
  const na = normalizeOrigin(a);
  const nb = normalizeOrigin(b);
  return na !== null && nb !== null && na === nb;
}
