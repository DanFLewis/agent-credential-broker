// Local test login page for exercising the broker end to end. Plain node, no dependencies.
//   /          native form POST to /login        (submit strategy: requestSubmit / enter)
//   /js-login  inputs + #login-btn, fetch() POST  (submit strategy: click, selector #login-btn)
//   /frame     embeds / in an iframe              (fill must refuse: not_top_frame)
// Credentials come from the fake vault fixture (obviously fake values only). Request bodies are
// never logged.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const HOST = '127.0.0.1';
const PORT = Number(process.env.ACB_TEST_PAGE_PORT ?? 8765);
const ORIGIN_PREFIX = `http://${HOST}:8765`;
const FIXTURE = fileURLToPath(new URL('../../packages/vault-fake/test/fixtures/fake-vault.json', import.meta.url));
const MAX_BODY = 10_000;

const accounts = JSON.parse(readFileSync(FIXTURE, 'utf8')).items.filter((i) =>
  (i.uris ?? []).some((u) => u.startsWith(ORIGIN_PREFIX)),
);
const checkLogin = (u, p) => accounts.some((a) => a.username === u && a.password === p);

const page = (title, body) =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font:16px system-ui;margin:2em">${body}</body>`;

const FORM = page(
  'Test login',
  `<h1>Test login</h1>
<form id="login-form" method="post" action="/login">
  <p><label>Username <input name="username" type="text" autocomplete="username"></label></p>
  <p><label>Password <input name="password" type="password" autocomplete="current-password"></label></p>
  <p><button type="submit">Sign in</button></p>
</form>`,
);

const JS_LOGIN = page(
  'Test login (JS button)',
  `<h1>Test login (JS button)</h1>
<div id="box">
  <p><label>Username <input id="u" type="text"></label></p>
  <p><label>Password <input id="p" type="password"></label></p>
  <p><button id="login-btn" type="button">Sign in</button></p>
</div>
<p id="result"></p>
<script>
  document.getElementById('login-btn').addEventListener('click', async () => {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: document.getElementById('u').value, password: document.getElementById('p').value }),
    });
    document.getElementById('result').textContent = await res.text();
  });
</script>`,
);

const FRAME = page('Framed login', `<h1>Framed login</h1><iframe src="/" width="500" height="300"></iframe>`);

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const send = (res, status, type, body) => {
  res.writeHead(status, { 'content-type': `${type}; charset=utf-8`, 'cache-control': 'no-store' });
  res.end(body);
};

const server = createServer(async (req, res) => {
  const path = (req.url ?? '/').split('?')[0];
  console.log(`${req.method} ${path}`); // method and path only, never bodies or queries
  try {
    if (req.method === 'GET') {
      if (path === '/') return send(res, 200, 'text/html', FORM);
      if (path === '/js-login') return send(res, 200, 'text/html', JS_LOGIN);
      if (path === '/frame') return send(res, 200, 'text/html', FRAME);
    } else if (req.method === 'POST' && path === '/login') {
      const f = new URLSearchParams(await readBody(req));
      const user = f.get('username') ?? '';
      return checkLogin(user, f.get('password') ?? '')
        ? send(res, 200, 'text/html', page('Welcome', `<h1>Welcome, ${user.replace(/[<>&"]/g, '')}</h1>`))
        : send(res, 401, 'text/html', page('Denied', '<h1>Login failed</h1>'));
    } else if (req.method === 'POST' && path === '/api/login') {
      const { username, password } = JSON.parse(await readBody(req));
      return checkLogin(String(username), String(password))
        ? send(res, 200, 'text/plain', `Welcome, ${String(username).replace(/[<>&"]/g, '')}`)
        : send(res, 401, 'text/plain', 'Login failed');
    }
    send(res, 404, 'text/plain', 'Not found');
  } catch {
    send(res, 400, 'text/plain', 'Bad request');
  }
});

server.listen(PORT, HOST, () => console.log(`Test login page on http://${HOST}:${PORT}/`));
