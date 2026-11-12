// Pure tab selection for a fill job. No chrome.* calls so it can be unit tested with plain objects.
import { normalizeOrigin } from '@acb/core';
import type { Origin } from '@acb/core';

/** The subset of chrome.tabs.Tab that selection needs. */
export interface TabLike {
  id?: number;
  url?: string;
  active?: boolean;
  windowId?: number;
}

export type TabSelection = { ok: true; tabId: number } | { ok: false; code: 'no_tab' | 'ambiguous_tab' };

/**
 * Picks the tab to fill. Only tabs whose normalised URL origin equals `origin` (exact match) count.
 * One match: use it. Several: use the active tab of the last-focused window if it is one of them,
 * otherwise refuse (`ambiguous_tab`) rather than guess. None: `no_tab`.
 */
export function selectTab(origin: Origin, tabs: TabLike[], lastFocusedWindowId: number | undefined): TabSelection {
  const matches = tabs.filter((t) => t.id !== undefined && t.url !== undefined && normalizeOrigin(t.url) === origin);
  if (matches.length === 0) return { ok: false, code: 'no_tab' };
  if (matches.length === 1) return { ok: true, tabId: matches[0]!.id! };
  const focused = matches.filter((t) => t.active === true && t.windowId === lastFocusedWindowId);
  if (focused.length === 1) return { ok: true, tabId: focused[0]!.id! };
  return { ok: false, code: 'ambiguous_tab' };
}
