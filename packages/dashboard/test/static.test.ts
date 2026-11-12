import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { publicDir } from '../src/index.js';

const read = (f: string) => readFileSync(join(publicDir, f), 'utf8');

describe('dashboard static files', () => {
  it('publicDir exists and holds the three files', () => {
    expect(existsSync(publicDir)).toBe(true);
    for (const f of ['index.html', 'app.js', 'app.css']) expect(existsSync(join(publicDir, f))).toBe(true);
  });

  it('index.html is CSP-clean: no inline script bodies, on* handlers or style attributes', () => {
    const html = read('index.html');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) expect(m[2].trim()).toBe('');
    expect(html).not.toMatch(/<style\b/i);
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/\sstyle\s*=/i);
    expect(html).not.toMatch(/(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i);
  });

  it('app.js avoids HTML-injection and eval sinks', () => {
    const js = read('app.js');
    for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function'])
      expect(js).not.toContain(bad);
  });
});
