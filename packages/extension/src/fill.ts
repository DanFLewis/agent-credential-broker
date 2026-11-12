// Injected into the page by chrome.scripting.executeScript, which serialises the function source.
// It must therefore be fully self-contained: no imports (type-only imports are erased), no closures
// over module scope, every helper declared inside. Never echo, log or return the credential values.
import type { FillConfig, FillResult } from '@acb/core';

export function fillAndSubmit(
  expectedOrigin: string,
  creds: { username: string; password: string },
  cfg: FillConfig,
): FillResult {
  const fail = (code: Extract<FillResult, { status: 'error' }>['code']): FillResult => ({ status: 'error', code });

  // Layer 3 of the origin defence: re-check inside the page, and only ever fill the top frame.
  if (window.top !== window) return fail('not_top_frame');
  if (location.origin !== expectedOrigin) return fail('origin_mismatch');

  const visible = (el: Element): boolean => {
    if (el.getClientRects().length === 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== 'hidden' && s.display !== 'none';
  };
  const inputs = Array.from(document.querySelectorAll('input'));

  let pw: HTMLInputElement | null = null;
  if (cfg.passwordSelector) {
    const el = document.querySelector(cfg.passwordSelector);
    // Never type the password into a visible text box, whatever the fill config says.
    pw = el instanceof HTMLInputElement && el.type === 'password' ? el : null;
  } else {
    pw = inputs.find((i) => i.type === 'password' && visible(i)) ?? null;
  }
  if (!pw || !visible(pw)) return fail('no_form');

  let user: HTMLInputElement | null = null;
  if (cfg.usernameSelector) {
    const el = document.querySelector(cfg.usernameSelector);
    user = el instanceof HTMLInputElement ? el : null;
  } else {
    // Nearest visible text-like input preceding the password field in document order.
    const before = inputs.slice(0, inputs.indexOf(pw));
    user = before.reverse().find((i) => ['text', 'email', 'tel', ''].includes(i.type) && visible(i)) ?? null;
  }

  // The post target must stay on this origin (a same-origin page can still post elsewhere).
  // getAttribute, not form.action: an <input name="action"> would shadow the property.
  const sameOriginTarget = (attr: string | null): boolean => {
    if (attr === null || attr === '') return true;
    try {
      return new URL(attr, document.baseURI).origin === location.origin;
    } catch {
      return false;
    }
  };
  const form = pw.form;
  if (form && !sameOriginTarget(form.getAttribute('action'))) return fail('cross_origin_action');

  let clickTarget: HTMLElement | null = null;
  if (cfg.submit.kind === 'click') {
    const el = document.querySelector(cfg.submit.selector);
    if (!(el instanceof HTMLElement) || !visible(el)) return fail('no_form');
    if (!sameOriginTarget(el.getAttribute('formaction'))) return fail('cross_origin_action');
    clickTarget = el;
  } else if (!form) {
    return fail('no_form');
  }

  // Native setter + events so frameworks that track input state see the change.
  const setValue = (el: HTMLInputElement, v: string): void => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter) setter.call(el, v);
    else el.value = v;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  try {
    if (user) setValue(user, creds.username);
    setValue(pw, creds.password);

    if (clickTarget) {
      clickTarget.click();
    } else if (form) {
      if (!form.checkValidity()) throw new Error('invalid form');
      if (cfg.submit.kind === 'enter') {
        // Synthetic Enter does not trigger implicit submission, so submit if the page did not handle it.
        const key = { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true, cancelable: true };
        const handled = !pw.dispatchEvent(new KeyboardEvent('keydown', key));
        if (!handled) form.requestSubmit();
        pw.dispatchEvent(new KeyboardEvent('keyup', key));
      } else {
        form.requestSubmit();
      }
    }
    return { status: 'submitted' };
  } catch {
    // Never leave a password sitting in the DOM after a failed submit.
    try {
      if (user) setValue(user, '');
      setValue(pw, '');
    } catch {
      /* best effort */
    }
    return fail('submit_failed');
  }
}
