import { describe, expect, it } from 'vitest';
import { selectTab } from '../src/select.js';

const O = 'https://example.test';

describe('selectTab', () => {
  it('no_tab when nothing matches', () => {
    expect(selectTab(O, [{ id: 1, url: 'https://other.test/' }, { id: 2 }], 1)).toEqual({ ok: false, code: 'no_tab' });
  });

  it('uses the single matching tab regardless of focus', () => {
    const tabs = [{ id: 1, url: 'https://other.test/' }, { id: 2, url: `${O}/login?x=1` }];
    expect(selectTab(O, tabs, 9)).toEqual({ ok: true, tabId: 2 });
  });

  it('compares origins exactly: scheme, port and subdomain all matter', () => {
    const tabs = [
      { id: 1, url: 'http://example.test/' },
      { id: 2, url: 'https://example.test:8443/' },
      { id: 3, url: 'https://sub.example.test/' },
      { id: 4, url: 'https://example.test.evil.test/' },
    ];
    expect(selectTab(O, tabs, 1)).toEqual({ ok: false, code: 'no_tab' });
  });

  it('prefers the active tab of the last-focused window among several', () => {
    const tabs = [
      { id: 1, url: `${O}/a`, active: false, windowId: 1 },
      { id: 2, url: `${O}/b`, active: true, windowId: 1 },
      { id: 3, url: `${O}/c`, active: true, windowId: 2 },
    ];
    expect(selectTab(O, tabs, 1)).toEqual({ ok: true, tabId: 2 });
  });

  it('ambiguous_tab when several match and none is active in the focused window', () => {
    const tabs = [
      { id: 1, url: `${O}/a`, active: false, windowId: 1 },
      { id: 3, url: `${O}/c`, active: true, windowId: 2 },
    ];
    expect(selectTab(O, tabs, 1)).toEqual({ ok: false, code: 'ambiguous_tab' });
    expect(selectTab(O, tabs, undefined)).toEqual({ ok: false, code: 'ambiguous_tab' });
  });
});
