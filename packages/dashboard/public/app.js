// Dashboard UI. Everything from the broker (and especially agent-supplied text) is rendered
// with textContent / createElement only. The CSP forbids inline script, so no HTML strings either.
const $ = (id) => document.getElementById(id);
const DURATIONS = { once: 'once', '1h': '1 hour', '1d': '1 day', '7d': '7 days', '30d': '30 days' };
const POLICIES = ['normal', 'never-long-grant', 'blocked'];
let csrf = null;
let timer = null;
const lastSig = {};

/** Tiny element builder. Children that are strings become text nodes. */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (v !== undefined && v !== false) el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

function flash(msg) {
  const el = $('flash');
  el.textContent = msg || '';
  el.hidden = !msg;
}

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['x-acb-csrf'] = csrf;
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) {
    const err = new Error((data && (data.message || data.error)) || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function rel(ts) {
  const s = Math.round((ts - Date.now()) / 1000);
  const a = Math.abs(s);
  const [n, unit] = a < 60 ? [a, 'second']
    : a < 3600 ? [Math.round(a / 60), 'minute']
    : a < 86400 ? [Math.round(a / 3600), 'hour']
    : [Math.round(a / 86400), 'day'];
  const txt = `${n} ${unit}${n === 1 ? '' : 's'}`;
  return s >= 0 ? `in ${txt}` : `${txt} ago`;
}
const when = (ts) => `${rel(ts)} (${new Date(ts).toLocaleString()})`;

/**
 * Replace a container's children, but only if the data changed and the user isn't mid-typing
 * (a poll must never wipe a half-typed password).
 */
function render(id, data, build) {
  const box = $(id);
  const sig = JSON.stringify(data);
  if (lastSig[id] === sig) return;
  const typing = [...box.querySelectorAll('input, select')]
    .some((i) => i === document.activeElement || (i.type === 'password' && i.value));
  if (typing) return;
  lastSig[id] = sig;
  box.replaceChildren(...build(data));
}

// ---------- actions ----------
async function act(fn) {
  try {
    flash('');
    await fn();
  } catch (e) {
    flash(e.message);
  }
  await refresh();
}

/** Read a password field and clear it at once, so the value only lives for the fetch call. */
function takePassword(input) {
  const v = input.value;
  input.value = '';
  input.dispatchEvent(new Event('input'));
  return v;
}

// ---------- views ----------
function statusView(s) {
  const pill = (text, ok) => h('span', { class: `pill ${ok ? 'ok' : 'bad'}`, text });
  return [
    pill(`Vault: ${s.vault}`, s.vault === 'unlocked'),
    pill(s.fillerConnected ? 'Extension connected' : 'Extension not connected', s.fillerConnected),
    pill(`Pairing: ${s.pairing}`, s.pairing === 'paired'),
  ];
}

function requestCard(req) {
  let selected = req.candidates[0];
  const durBox = h('div', { class: 'durations' });
  const pw = h('input', { type: 'password', autocomplete: 'off', id: `pw-${req.id}` });
  const buttons = [];

  const approve = (duration) => act(async () => {
    const password = takePassword(pw);
    await api('POST', `/api/requests/${encodeURIComponent(req.id)}/approve`,
      { itemId: selected.itemId, duration, password });
  });
  // Approval stays disabled until a password has been typed.
  const sync = () => { for (const b of buttons) b.disabled = pw.value.length === 0; };
  const drawDurations = () => {
    buttons.length = 0;
    for (const d of selected ? selected.allowedDurations || [] : []) {
      const b = h('button', { type: 'button', text: d === 'once' ? 'Approve once' : `Approve ${DURATIONS[d]}`, disabled: true });
      b.addEventListener('click', () => approve(d));
      buttons.push(b);
    }
    durBox.replaceChildren(...(buttons.length
      ? buttons
      : [h('p', { class: 'muted', text: 'This item is blocked by policy and cannot be approved.' })]));
    sync();
  };
  pw.addEventListener('input', sync);

  let chooser;
  if (req.candidates.length > 1) {
    chooser = h('fieldset', {}, h('legend', { text: 'Which login should be used?' }),
      req.candidates.map((c, i) => {
        const r = h('input', { type: 'radio', name: `cand-${req.id}`, checked: i === 0 });
        r.addEventListener('change', () => { selected = c; drawDurations(); });
        return h('label', { class: 'choice' }, r, h('span', { text: `${c.name} (policy: ${c.policy})` }));
      }));
  } else {
    chooser = h('p', {}, 'Login item: ', h('strong', { text: selected ? selected.name : '(none)' }));
  }

  const deny = h('button', { type: 'button', class: 'deny', text: 'Deny' });
  deny.addEventListener('click', () => act(() => api('POST', `/api/requests/${encodeURIComponent(req.id)}/deny`, {})));
  drawDurations();

  return h('div', { class: 'card' },
    req.insecureHttp && h('div', { class: 'banner', role: 'alert', text: 'Unencrypted HTTP — anyone on your network can see this login' }),
    h('div', { class: 'muted', text: 'Login requested for' }),
    h('div', { class: 'origin', text: req.origin }),
    h('div', { class: 'muted' }, 'Agent: ', h('span', { class: 'mono', text: req.agentId }), ` · requested ${when(req.createdAt)}`),
    h('div', { class: 'hint', text: `Agent says (untrusted): ${req.hint ?? '(no hint)'}` }),
    chooser,
    h('label', { for: `pw-${req.id}`, text: 'Dashboard password (required to approve)' }), pw,
    durBox,
    h('div', { class: 'deny-row' }, deny));
}

function grantsView(grants) {
  if (!grants.length) return [h('p', { class: 'muted', text: 'No grants.' })];
  const now = Date.now();
  return grants.map((g) => {
    const active = !g.revokedAt && g.expiresAt > now && (g.maxUses === null || g.uses < g.maxUses);
    const btn = h('button', { type: 'button', class: 'quiet', text: 'Revoke' });
    btn.addEventListener('click', () => act(() => api('POST', `/api/grants/${encodeURIComponent(g.id)}/revoke`, {})));
    const state = g.revokedAt ? `Revoked ${when(g.revokedAt)}` : `${active ? 'Expires' : 'Expired'} ${when(g.expiresAt)}`;
    return h('div', { class: 'card' },
      h('div', { class: 'origin', text: g.origin }),
      h('div', { class: 'muted', text: `${g.itemName} · agent ${g.agentId}` }),
      h('div', { class: 'muted', text: `${state} · uses ${g.uses}${g.maxUses === null ? '' : '/' + g.maxUses}` }),
      active && btn);
  });
}

function itemRow(it) {
  const option = (v, current) => h('option', { value: v, text: v, selected: v === current });
  const pw = h('input', { type: 'password', autocomplete: 'off', 'aria-label': 'Dashboard password' });
  const policy = h('select', { 'aria-label': 'Policy' }, POLICIES.map((p) => option(p, it.policy)));
  const cfg = it.fillConfig || { submit: { kind: 'requestSubmit' } };
  const kind = h('select', { 'aria-label': 'Submit strategy' },
    ['requestSubmit', 'enter', 'click'].map((k) => option(k, cfg.submit.kind)));
  const text = (label, value) => h('input', { type: 'text', placeholder: label, value: value || '', 'aria-label': label });
  const sel = text('Submit button CSS selector (for click)', cfg.submit.selector);
  const uSel = text('Username selector (optional)', cfg.usernameSelector);
  const pSel = text('Password selector (optional)', cfg.passwordSelector);

  const save = (path, body) => act(async () => {
    const password = takePassword(pw);
    await api('PUT', `/api/items/${encodeURIComponent(it.itemId)}/${path}`, { ...body, password });
  });
  const savePolicy = h('button', { type: 'button', text: 'Save policy' });
  savePolicy.addEventListener('click', () => save('policy', { policy: policy.value }));
  const saveCfg = h('button', { type: 'button', text: 'Save fill config' });
  saveCfg.addEventListener('click', () => {
    const fillConfig = { submit: kind.value === 'click' ? { kind: 'click', selector: sel.value.trim() } : { kind: kind.value } };
    if (uSel.value.trim()) fillConfig.usernameSelector = uSel.value.trim();
    if (pSel.value.trim()) fillConfig.passwordSelector = pSel.value.trim();
    save('fill-config', { fillConfig });
  });
  const sync = () => { savePolicy.disabled = saveCfg.disabled = !pw.value; };
  pw.addEventListener('input', sync);
  sync();

  return h('div', { class: 'card' },
    h('strong', { text: it.name }),
    h('label', { text: 'Policy' }), policy,
    h('label', { text: 'Submit strategy' }), kind, sel, uSel, pSel,
    h('label', { text: 'Dashboard password (required to save)' }), pw,
    h('div', { class: 'durations' }, savePolicy, saveCfg));
}

function pairingView(p) {
  const kids = [];
  const pwField = (label) => h('input', { type: 'password', autocomplete: 'off', 'aria-label': label });
  if (p.status === 'none') return [h('p', { class: 'muted', text: 'No extension paired yet.' })];
  if (p.status === 'pending') {
    const pw = pwField('Dashboard password');
    const ok = h('button', { type: 'button', text: 'Codes match: confirm pairing', disabled: true });
    pw.addEventListener('input', () => { ok.disabled = !pw.value; });
    ok.addEventListener('click', () => act(async () => {
      await api('POST', '/api/pairing/confirm', { password: takePassword(pw), pairingCode: p.pairingCode });
    }));
    kids.push(
      h('p', { text: 'Compare this code with the one shown in the browser extension. Confirm only if they are identical.' }),
      h('div', { class: 'origin', text: p.pairingCode || '' }), pw, ok);
  } else {
    kids.push(h('p', { text: 'An extension is paired.' }));
  }
  const pw2 = pwField('Dashboard password for reset');
  const reset = h('button', { type: 'button', class: 'danger-outline', text: 'Reset pairing', disabled: true });
  pw2.addEventListener('input', () => { reset.disabled = !pw2.value; });
  reset.addEventListener('click', () => act(async () => {
    await api('POST', '/api/pairing/reset', { password: takePassword(pw2) });
  }));
  kids.push(h('div', { class: 'deny-row' }, pw2, reset));
  return kids;
}

function auditView(rows) {
  const head = h('tr', {}, ['Time', 'Event', 'Agent', 'Origin'].map((t) => h('th', { text: t })));
  const body = rows.map((a) => h('tr', {},
    h('td', { text: when(a.ts) }), h('td', { text: a.event }),
    h('td', { text: a.agentId ?? '' }), h('td', { class: 'mono', text: a.origin ?? '' })));
  return [h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, head), h('tbody', {}, body)))];
}

// ---------- lifecycle ----------
function showLogin(on) {
  $('login').hidden = !on;
  $('app').hidden = on;
  $('logout').hidden = on;
  if (on) {
    clearInterval(timer);
    timer = null;
    for (const k of Object.keys(lastSig)) delete lastSig[k];
  }
}

async function refresh() {
  try {
    const [status, reqs, grants, items, audit, pairing] = await Promise.all([
      api('GET', '/api/status'), api('GET', '/api/requests'), api('GET', '/api/grants'),
      api('GET', '/api/items'), api('GET', '/api/audit?limit=200'), api('GET', '/api/pairing'),
    ]);
    render('status', status, statusView);
    render('requests', reqs, (r) => (r.length ? r.map(requestCard) : [h('p', { class: 'muted', text: 'No pending requests.' })]));
    render('pairing', pairing, pairingView);
    render('grants', grants, grantsView);
    render('items', items, (i) => (i.length ? i.map(itemRow) : [h('p', { class: 'muted', text: 'No items seen yet.' })]));
    render('audit', audit, auditView);
  } catch (e) {
    if (e.status === 401) { csrf = null; showLogin(true); } else flash(e.message);
  }
}

function start() {
  showLogin(false);
  refresh();
  timer = setInterval(refresh, 5000);
}

async function init() {
  const s = await api('GET', '/api/session').catch(() => ({ authenticated: false }));
  if (s.authenticated) { csrf = s.csrf; start(); } else showLogin(true);
}

$('login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const password = takePassword($('login-password'));
  try {
    flash('');
    ({ csrf } = await api('POST', '/api/login', { password }));
    start();
  } catch (e) {
    flash(e.status === 401 ? 'Wrong password.' : e.message);
  }
});
$('logout').addEventListener('click', async () => {
  await api('POST', '/api/logout', {}).catch(() => {});
  csrf = null;
  showLogin(true);
});
$('revoke-all').addEventListener('click', () => {
  if (!confirm('Revoke ALL grants? Agents will need new approval for every site.')) return;
  act(async () => {
    const r = await api('POST', '/api/grants/revoke-all', {});
    flash(`Revoked ${r.revoked} grant(s).`);
  });
});

init();
