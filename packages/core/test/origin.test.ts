import { describe, expect, it } from 'vitest';
import { classifyOrigin, isLanHost, normalizeOrigin, originsEqual } from '../src/origin.js';

describe('normalizeOrigin', () => {
  it.each([
    ['https://example.com', 'https://example.com'],
    ['HTTPS://Example.COM', 'https://example.com'],
    ['https://example.com:443', 'https://example.com'],
    ['http://example.com:80', 'http://example.com'],
    ['https://example.com:8443', 'https://example.com:8443'],
    ['http://example.com:443', 'http://example.com:443'],
    ['https://example.com:80', 'https://example.com:80'],
    ['https://example.com/path/x?q=1#frag', 'https://example.com'],
    ['https://example.com/', 'https://example.com'],
    ['http://192.168.50.1', 'http://192.168.50.1'],
    ['http://192.168.50.1:8080/login', 'http://192.168.50.1:8080'],
    // IPv4 alternative encodings are canonicalised by the URL parser
    ['http://0xC0A83201', 'http://192.168.50.1'],
    ['http://3232248321', 'http://192.168.50.1'],
    ['http://0300.0250.0062.0001', 'http://192.168.50.1'],
    ['http://192.168.12801', 'http://192.168.50.1'],
    // IPv6
    ['http://[::1]:8080/x', 'http://[::1]:8080'],
    ['http://[0:0:0:0:0:0:0:1]', 'http://[::1]'],
    ['https://[2001:DB8::1]', 'https://[2001:db8::1]'],
    // IDN -> punycode
    ['https://bücher.example', 'https://xn--bcher-kva.example'],
    ['https://BÜCHER.example/x', 'https://xn--bcher-kva.example'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeOrigin(input)).toBe(expected);
  });

  it.each([
    'https://192.168.50.1@evil.com',
    'https://user:pw@x.com',
    'https://user@x.com',
    'https://:pw@x.com',
    'https://example.com.',
    'https://example.com.:8443',
    'javascript:alert(1)',
    'data:text/html,hi',
    'file:///etc/passwd',
    'chrome-extension://abcdefghijklmnop/page.html',
    'ftp://example.com',
    'ws://example.com',
    'about:blank',
    'blob:https://example.com/uuid',
    '192.168.50.1',
    'example.com',
    '//example.com',
    '',
    'https://',
    'http://exa mple.com',
  ])('rejects %j', (input) => {
    expect(normalizeOrigin(input)).toBeNull();
  });

  it('is idempotent', () => {
    const once = normalizeOrigin('HTTPS://Example.com:443/a?b#c')!;
    expect(normalizeOrigin(once)).toBe(once);
  });
});

describe('originsEqual', () => {
  it('treats equivalent spellings as equal', () => {
    expect(originsEqual('HTTPS://Example.com:443/a', 'https://example.com/b?c')).toBe(true);
    expect(originsEqual('http://0xC0A83201/', 'http://192.168.50.1')).toBe(true);
  });

  it('never equates http with https', () => {
    expect(originsEqual('http://example.com', 'https://example.com')).toBe(false);
    expect(originsEqual('http://192.168.50.1', 'https://192.168.50.1')).toBe(false);
  });

  it('distinguishes ports', () => {
    expect(originsEqual('https://example.com:8443', 'https://example.com')).toBe(false);
  });

  it('rejects look-alikes', () => {
    expect(originsEqual('http://192.168.50.1.evil.com', 'http://192.168.50.1')).toBe(false);
    expect(originsEqual('https://router.asus.com', 'https://asus.com')).toBe(false);
    expect(originsEqual('https://asus.com', 'https://www.asus.com')).toBe(false);
    expect(originsEqual('https://example.com.evil.net', 'https://example.com')).toBe(false);
  });

  it('is false when either side is invalid', () => {
    expect(originsEqual('https://a@example.com', 'https://a@example.com')).toBe(false);
    expect(originsEqual('example.com', 'example.com')).toBe(false);
    expect(originsEqual('https://example.com', 'javascript:1')).toBe(false);
  });
});

describe('isLanHost', () => {
  it.each([
    '192.168.50.1',
    '192.168.1.254',
    '192.168.0.0',
    '10.0.0.1',
    '10.255.255.255',
    '172.16.0.1',
    '172.31.255.255',
    '169.254.1.1',
    '127.0.0.1',
    '127.1.2.3',
    'localhost',
    'LOCALHOST',
    'app.localhost',
    'foo.local',
    'printer.office.local',
    '[::1]',
    '::1',
    '[fe80::1]',
    '[febf::1]',
    '[fc00::1]',
    '[fd12:3456::1]',
  ])('%s is LAN', (h) => {
    expect(isLanHost(h)).toBe(true);
  });

  it.each([
    '172.15.255.255',
    '172.32.0.1',
    '192.169.0.1',
    '192.167.0.1',
    '11.0.0.1',
    '9.255.255.255',
    '169.253.0.1',
    '8.8.8.8',
    'example.com',
    'locally.com',
    'notlocalhost',
    'foo.local.evil.com',
    'localhost.evil.com',
    '192.168.50.1.evil.com',
    '[2001:db8::1]',
    '[fec0::1]',
    '[fe00::1]',
    '[fb00::1]',
    '[fe::1]',
  ])('%s is public', (h) => {
    expect(isLanHost(h)).toBe(false);
  });
});

describe('classifyOrigin', () => {
  it.each([
    ['https://example.com', 'https'],
    ['https://192.168.50.1', 'https'],
    ['http://192.168.50.1', 'http-lan'],
    ['http://192.168.1.254:8080', 'http-lan'],
    ['http://10.1.2.3', 'http-lan'],
    ['http://172.16.0.1', 'http-lan'],
    ['http://172.31.0.1', 'http-lan'],
    ['http://172.15.0.1', 'http-public'],
    ['http://172.32.0.1', 'http-public'],
    ['http://127.0.0.1:7414', 'http-lan'],
    ['http://localhost:3000', 'http-lan'],
    ['http://foo.local', 'http-lan'],
    ['http://[::1]:8080', 'http-lan'],
    ['http://example.com', 'http-public'],
    ['http://8.8.8.8', 'http-public'],
    ['http://192.168.50.1.evil.com', 'http-public'],
  ] as const)('%s -> %s', (origin, expected) => {
    expect(classifyOrigin(origin)).toBe(expected);
  });

  it('classifies a canonicalised hex IP as LAN', () => {
    expect(classifyOrigin(normalizeOrigin('http://0xC0A83201')!)).toBe('http-lan');
  });
});
