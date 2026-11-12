// fillAndSubmit runs in a page, and vitest's jsdom is not installed, so this uses a minimal
// hand-rolled fake DOM (just the members fill.ts touches). The values are obviously fake.
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FillConfig } from '@acb/core';
import { fillAndSubmit } from '../src/fill.js';

const O = 'https://login.test';
const CREDS = { username: 'test-user', password: 'correct-horse-test-only' };

class FakeEvent {
  defaultPrevented = false;
  constructor(
    readonly type: string,
    readonly init: Record<string, unknown> = {},
  ) {}
}
class FakeEl {
  hidden = false;
  listeners: Record<string, Array<(e: FakeEvent) => void>> = {};
  clicked = 0;
  constructor(
    public attrs: Record<string, string> = {},
    public form: FakeForm | null = null,
  ) {}
  getAttribute(n: string) {
    return this.attrs[n] ?? null;
  }
  getClientRects() {
    return this.hidden ? [] : [{}];
  }
  dispatchEvent(e: FakeEvent) {
    (this.listeners[e.type] ?? []).forEach((l) => l(e));
    return !e.defaultPrevented;
  }
  click() {
    this.clicked++;
  }
}
class FakeInput extends FakeEl {
  v = '';
  get type() {
    return this.attrs.type ?? 'text';
  }
}
class FakeForm extends FakeEl {
  submits = 0;
  valid = true;
  throwOnSubmit = false;
  checkValidity() {
    return this.valid;
  }
  requestSubmit() {
    if (this.throwOnSubmit) throw new Error('boom');
    this.submits++;
  }
}

interface Page {
  user: FakeInput;
  pw: FakeInput;
  form: FakeForm;
  button: FakeEl;
}

function setup(opts: { action?: string; origin?: string; top?: boolean } = {}): Page {
  const form = new FakeForm(opts.action === undefined ? {} : { action: opts.action });
  const user = new FakeInput({ type: 'text' }, form);
  const pw = new FakeInput({ type: 'password' }, form);
  (pw as unknown as { form: FakeForm }).form = form;
  const button = new FakeEl({ id: 'login-btn' });
  const inputs = [new FakeInput({ type: 'hidden' }), user, pw];
  const g = globalThis as Record<string, unknown>;
  const win: Record<string, unknown> = {};
  win.top = opts.top === false ? {} : win;
  g.window = win;
  g.location = { origin: opts.origin ?? O };
  g.Event = FakeEvent;
  g.KeyboardEvent = FakeEvent;
  g.getComputedStyle = () => ({ visibility: 'visible', display: 'block' });
  g.HTMLElement = FakeEl;
  g.HTMLInputElement = FakeInput;
  // The native setter lives on the prototype, as in a browser; fill.ts must call it.
  Object.defineProperty(FakeInput.prototype, 'value', {
    configurable: true,
    get(this: FakeInput) {
      return this.v;
    },
    set(this: FakeInput, x: string) {
      this.v = x;
    },
  });
  g.document = {
    baseURI: `${O}/login`,
    querySelectorAll: () => inputs,
    querySelector: (s: string) => (s === '#login-btn' ? button : null),
  };
  return { user, pw, form, button };
}

const CFG: FillConfig = { submit: { kind: 'requestSubmit' } };
const GLOBALS = ['window', 'location', 'document', 'Event', 'KeyboardEvent', 'getComputedStyle', 'HTMLElement', 'HTMLInputElement'];

beforeEach(() => {
  setup();
});
afterEach(() => {
  for (const k of GLOBALS) delete (globalThis as Record<string, unknown>)[k];
});

describe('fillAndSubmit', () => {
  it('fills username and password and calls requestSubmit', () => {
    const p = setup();
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'submitted' });
    expect(p.user.v).toBe('test-user');
    expect(p.pw.v).toBe('correct-horse-test-only');
    expect(p.form.submits).toBe(1);
  });

  it('never echoes values in its result', () => {
    setup();
    expect(JSON.stringify(fillAndSubmit(O, CREDS, CFG))).not.toContain('correct-horse');
  });

  it('refuses frames', () => {
    const p = setup({ top: false });
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'error', code: 'not_top_frame' });
    expect(p.pw.v).toBe('');
  });

  it('refuses a different origin', () => {
    const p = setup({ origin: 'https://evil.test' });
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'error', code: 'origin_mismatch' });
    expect(p.pw.v).toBe('');
  });

  it('no_form when the password field is hidden', () => {
    const p = setup();
    p.pw.hidden = true;
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'error', code: 'no_form' });
  });

  it('cross_origin_action when the form posts elsewhere, and fills nothing', () => {
    const p = setup({ action: 'https://evil.test/steal' });
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'error', code: 'cross_origin_action' });
    expect(p.pw.v).toBe('');
    expect(p.form.submits).toBe(0);
  });

  it('accepts a relative same-origin action', () => {
    setup({ action: '/login' });
    expect(fillAndSubmit(O, CREDS, CFG).status).toBe('submitted');
  });

  it('blanks both fields when submission throws', () => {
    const p = setup();
    p.form.throwOnSubmit = true;
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'error', code: 'submit_failed' });
    expect(p.user.v).toBe('');
    expect(p.pw.v).toBe('');
  });

  it('treats an invalid form as submit_failed and blanks the fields', () => {
    const p = setup();
    p.form.valid = false;
    expect(fillAndSubmit(O, CREDS, CFG)).toEqual({ status: 'error', code: 'submit_failed' });
    expect(p.pw.v).toBe('');
  });

  it('click strategy clicks the selector instead of submitting', () => {
    const p = setup();
    expect(fillAndSubmit(O, CREDS, { submit: { kind: 'click', selector: '#login-btn' } })).toEqual({ status: 'submitted' });
    expect(p.button.clicked).toBe(1);
    expect(p.form.submits).toBe(0);
  });

  it('click strategy rejects a button with a cross-origin formaction', () => {
    const p = setup();
    p.button.attrs.formaction = 'https://evil.test/x';
    expect(fillAndSubmit(O, CREDS, { submit: { kind: 'click', selector: '#login-btn' } })).toEqual({
      status: 'error',
      code: 'cross_origin_action',
    });
    expect(p.pw.v).toBe('');
  });

  it('click strategy with a missing selector is no_form', () => {
    expect(fillAndSubmit(O, CREDS, { submit: { kind: 'click', selector: '#nope' } })).toEqual({
      status: 'error',
      code: 'no_form',
    });
  });

  it('enter strategy falls back to requestSubmit when the page does not handle the key', () => {
    const p = setup();
    expect(fillAndSubmit(O, CREDS, { submit: { kind: 'enter' } }).status).toBe('submitted');
    expect(p.form.submits).toBe(1);
  });
});
