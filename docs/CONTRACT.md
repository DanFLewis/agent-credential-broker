# v1 build contract

This is the build contract each package was written against. The types are defined in
`packages/core/src/types.ts` and `packages/core/src/protocol.ts`, and those two files are authoritative.
Don't change them without the orchestrator. Every package is TypeScript, ESM and strict mode, runs on Node 24, and is tested with vitest
(the root `vitest.config.ts` aliases `@acb/*` to `src/index.ts`). Tests go in `packages/<pkg>/test/*.test.ts`.
Relative imports use the `.js` extension (NodeNext). There are no runtime dependencies beyond those listed here.

## Global invariants
1. No plaintext secret appears in an MCP response, an IPC message, a log line, the audit log, an error message or the native-host stdio.
2. Origins are compared only after `normalizeOrigin()`, using exact string equality. `http` never matches `https`.
3. The agent never learns item names or ids. It sees only status, request ids, origins, expiries and use counts.
4. Human-only actions are approving, changing policy, changing the fill config and confirming pairing. Each one requires the dashboard password on that request.

## @acb/core (pure; no Node imports except in `src/node.ts`)
`src/origin.ts`
- `normalizeOrigin(input: string): Origin | null`. It parses with `new URL()` and returns `url.origin`. It returns null for a scheme other than http or https, an opaque `"null"` origin, any username or password in the URL, an empty host, or a host ending in `.`. A bare host such as `192.168.50.1` is not accepted, so callers must include the scheme. WHATWG canonicalises IPv4 forms (hex, decimal, octal) and IPv6.
- `isLanHost(hostname: string): boolean` is true for 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, `localhost`, `*.localhost`, `*.local`, `[::1]`, `fe80::/10` and `fc00::/7`.
- `classifyOrigin(origin: Origin): 'https' | 'http-lan' | 'http-public'`. Callers reject `http-public` with `insecure_site`.
- `originsEqual(a: string, b: string): boolean` normalises both sides and returns false if either is null.

`src/grants.ts`
- `computeExpiry(duration: GrantDuration, now: number): { expiresAt: number; maxUses: number | null }`. `once` gives `now + ONCE_GRANT_MS` and 1 use. `1h`, `1d`, `7d` and `30d` give unlimited uses. The result is always capped at `now + MAX_GRANT_MS`.
- `allowedDurations(policy: ItemPolicy): GrantDuration[]`. `normal` allows all of them, `never-long-grant` allows `['once']` and `blocked` allows `[]`.
- `isGrantUsable(g: Grant, now: number): boolean` requires that the grant is not revoked, `now < expiresAt`, and `maxUses === null || uses < maxUses`.
- `findUsableGrant(grants: Grant[], q: { origin: Origin; agentId: AgentId; itemIds?: string[] }, now: number): Grant | null`. The origin must match exactly. The agentId must be equal. When `itemIds` is given, the grant's itemId must be one of them. If several grants qualify, it picks the one that expires soonest.
- `usesLeft(g: Grant): number | null`.
- `toGrantSummary(g: Grant): GrantSummary`.

`src/crypto.ts` uses `globalThis.crypto.subtle`, which works in both Node 24 and the extension service worker.
- `generateRecipientKeyPair(): Promise<CryptoKeyPair>` generates ECDH P-256 with a non-extractable private key (`extractable: false` applies to the private key; the public key is always exportable).
- `exportPublicKey(key: CryptoKey): Promise<string>` returns the raw uncompressed key as base64url.
- `pairingCode(publicKeyB64u: string): Promise<string>` takes the SHA-256 of the raw key bytes and returns its first 40 bits as Crockford base32, formatted `XXXX-XXXX`.
- `sealSecret(recipientPublicKeyB64u: string, secret: { username: string; password: string }, aad: string): Promise<SealedSecret>` creates an ephemeral ECDH P-256 key and derives bits (256) from it. It then runs HKDF-SHA256 with salt = epk raw bytes and info = `"acb-v1-seal"` to get an AES-256-GCM key. It uses a random 12-byte IV, encrypts the plaintext `JSON.stringify({username,password})`, and uses utf8(aad) as the additional data.
- `openSecret(privateKey: CryptoKey, sealed: SealedSecret, aad: string): Promise<{ username: string; password: string }>` reverses `sealSecret`. It throws on a GCM failure.
- `b64uEncode(bytes: Uint8Array): string` and `b64uDecode(s: string): Uint8Array`.

`src/redact.ts`
- `class Secret implements SecretMaterial` overrides `toJSON()`, `toString()` and `[Symbol.for('nodejs.util.inspect.custom')]` so they return `"[REDACTED]"`. The username and password are readable only through the properties.
- `assertNoSecret(value: unknown, secrets: string[]): void` deep-scans the JSON serialisation and throws if any non-empty secret string appears. Tests and the MCP server's response guard use it.

`src/node.ts` (Node only, exported as `@acb/core/node`)
- `acbHome(): string` returns `process.env.ACB_HOME`, or `%LOCALAPPDATA%\acb` on Windows, or `~/.acb` elsewhere.
- `pipePath(): string` returns `process.env.ACB_PIPE`, or `\\.\pipe\acb-broker-<os.userInfo().username>` on Windows, or `<acbHome>/broker.sock` elsewhere.
- `class LineSplitter` turns a stream of chunks into complete lines. It drops any line over 1 MiB and calls an error callback.
- `encodeNativeMessage(obj): Buffer` and `class NativeMessageReader` handle Chrome's uint32 little-endian length prefix. Messages are limited to 1 MiB in both directions.
- `connectBroker(opts: { role: 'agent' | 'filler'; agentId?: string; path?: string }): Promise<BrokerConnection>` is the client used by the MCP server and the native host. It sends the hello message and waits for `hello_ok`. It exposes `call(method, params, timeoutMs): Promise<result>`, which rejects on `rpc_error` with an Error carrying `.code`, `onPush(cb)` for messages that are not RPC (fill_job), `send(raw)` (for the native-host relay), `onClose(cb)` and `close()`.

`src/index.ts` re-exports types, protocol, origin, grants, crypto and redact, but not node.

## @acb/broker
- SQLite comes from the built-in `node:sqlite` (`DatabaseSync`) and the database file is `<acbHome>/broker.db`. The tables are grants, requests (with the candidates JSON), audit, item_policy (itemId → policy), item_fill_config, pairing (one row: publicKey, status, createdAt) and the dashboard password hash in `settings`.
- `class GrantStore` holds the SQLite data access, and it can be constructed with `':memory:'` for tests.
- `class BrokerService implements BrokerAgentApi` takes `{ store, vault: VaultAdapter, filler: Filler, notifier: Notifier, clock?: () => number }`.
  - `requestLogin({site, hint, waitMs = 20000 capped at 60000}, agentId)` runs in this order.
    1. It normalises the site, returning `invalid_site` if that fails, then classifies it, returning `insecure_site` for `http-public`.
    2. It checks the vault status, returning `vault_locked` if the vault isn't unlocked.
    3. It calls `vault.find`. No candidates gives `no_match`.
    4. Candidates that are all blocked give `blocked`. Blocked items are dropped from the candidates.
    5. It calls `findUsableGrant` with the candidate itemIds.
    6. With a grant: if no filler is available it returns `no_filler`. Otherwise it creates a job (random 128-bit jobId, expiresAt = now + 60s) in memory with {grantId, itemId, origin, agentId}, audits `fill_job` and awaits `filler.fill(...)`. On `submitted` it audits and notifies use, then returns submitted with the grant's expiry and usesLeft. On an error it returns the error code.
    7. Without a grant: if a pending request for (agentId, origin) already exists, it returns that one's requestId (audit `request_deduped`). If the agent already has 3 pending requests it returns `too_many_pending`. Otherwise it creates the request, audits `request`, calls `notifier.requestApproval` and returns pending.
  - `claimSecret(params, pairedPublicKey)` is called by the extension filler. It looks up the job and checks that it isn't used or expired (`job_expired`). It requires `normalizeOrigin(params.tabOrigin) === job.origin` (`origin_mismatch`) and that the grant is still usable. It marks the job claimed, increments the grant's uses, calls `vault.getSecret`, seals the secret with the AAD `secretAad(jobId, job.origin, documentId)` and audits `secret_released`. A job can be claimed only once.
  - Dashboard-side methods: approve(requestId, itemId ∈ candidates, duration ∈ allowedDurations(policy)), deny, revoke, revokeAll, setPolicy, setFillConfig, listing methods, pairing (requestPairing(publicKey) → stored as pending with its code; confirmPairing; resetPairing). A request expires after 24h.
- `class ExtensionFiller implements Filler` tracks the single connected filler connection (role filler). `fill()` pushes `fill_job`, then resolves when that jobId's `fillResult` arrives or on timeout. When no filler is connected, `isAvailable()` is false.
- `class DashboardNotifier implements Notifier` writes to stdout ("Approval needed: <origin> from <agentId>, open http://127.0.0.1:7414"). Toasts come later.
- `IpcServer` listens on `pipePath()`. The first line must be a hello message or the socket is destroyed. Role agent may call only `requestLogin`, `grantStatus` and `listGrants`. Role filler may call only `claimSecret`, `fillResult` and `pair`. Only one filler connection is allowed at a time; a newer one replaces the older. Messages are limited to 1 MiB. RPC errors carry only a code and a generic message, never a stack.
- `DashboardServer` uses `node:http` on 127.0.0.1:7414 (the `ACB_DASHBOARD_PORT` environment variable can change this). It serves the static files from the `@acb/dashboard` package's `public/` directory and the API below.
- The CLI is `packages/broker/src/cli.ts`, built to `dist/cli.js`:
  - `acb-broker set-password` prompts for the dashboard password with hidden input and stores an scrypt hash.
  - `acb-broker start [--vault bitwarden|fake] [--fake-fixture <path>]`. For Bitwarden it uses `BW_SESSION` from the environment if set, otherwise it prompts for the master password with hidden input in the console and unlocks through the adapter. The master password is never accepted over HTTP.

### Dashboard HTTP API (the broker implements it; the dashboard UI consumes it)
Every response is JSON. Every request must have a `Host` header of exactly `127.0.0.1:<port>` or `localhost:<port>`, otherwise the server returns 421. Mutating methods (POST and PUT) also need an `Origin` header equal to `http://127.0.0.1:<port>` or `http://localhost:<port>` and an `X-ACB-CSRF` header that matches the session, otherwise they get 403. The session is a random 256-bit cookie, `acb_session`, set with HttpOnly, SameSite=Strict and Path=/. It is kept in memory and lasts 8 hours with a 30-minute idle timeout. Sending a "password" field means the body must include the dashboard password, checked with scrypt and `timingSafeEqual`. A wrong password returns 401 and an audit entry `dashboard_auth_fail`, and more than 5 failures a minute return 429. Static responses carry `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`, along with `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | /api/session | – | `{authenticated: boolean, csrf?: string}` |
| POST | /api/login | `{password}` (no CSRF needed; the Origin check still applies) | `{csrf}` + Set-Cookie |
| POST | /api/logout | – | `{ok:true}` |
| GET | /api/status | – | `{vault: VaultStatus, fillerConnected: boolean, pairing: 'none'\|'pending'\|'paired'}` |
| GET | /api/requests | – | `ApprovalRequest[]` with status pending, each candidate extended with `policy: ItemPolicy` and `allowedDurations: GrantDuration[]` |
| POST | /api/requests/:id/approve | `{itemId, duration, password}` | `{grant: Grant}` |
| POST | /api/requests/:id/deny | `{}` | `{ok:true}` |
| GET | /api/grants | – | `Grant[]` (active and recently expired from the last 7 days) |
| POST | /api/grants/:id/revoke | `{}` | `{ok:true}` |
| POST | /api/grants/revoke-all | `{}` | `{revoked: number}` |
| GET | /api/audit?limit=200 | – | `AuditEntry[]`, newest first |
| GET | /api/items | – | `[{itemId, name, policy, fillConfig}]` for the items seen in requests or grants |
| PUT | /api/items/:itemId/policy | `{policy, password}` | `{ok:true}`. Setting `blocked` or `never-long-grant` also revokes that item's grants when they are no longer allowed. |
| PUT | /api/items/:itemId/fill-config | `{fillConfig, password}` | `{ok:true}` |
| GET | /api/pairing | – | `{status, pairingCode?}` |
| POST | /api/pairing/confirm | `{password}` | `{ok:true}` |
| POST | /api/pairing/reset | `{password}` | `{ok:true}` |

Deny, revoke and revoke-all deliberately don't need the password, because they move in the safe direction and a panic button should take one click.

## @acb/dashboard
These are static files in `packages/dashboard/public/`: index.html, app.js and app.css, written in vanilla JS with no build step, no inline script or style, and no external resources. All agent-supplied text (hint, agentId, origin) goes in through `textContent` only, never `innerHTML`. The views are:
- a login form
- status bar
- pending requests, each with an item choice when there are several candidates, a duration button for each allowed duration, a password field and a Deny button, plus a red "unencrypted HTTP" warning when `insecureHttp` is set and the hint shown as "Agent says (untrusted): …"
- grants (Revoke, plus Revoke all)
- items (policy select and fill config, saved with the password)
- pairing (shows the code and asks you to compare it with the extension, then Confirm)
- the audit log
It polls every 5s. The package also has `package.json` (name `@acb/dashboard`), and `src/index.ts` exports `publicDir: string` (an absolute path).

## @acb/vault-fake
`class FakeVault implements VaultAdapter` is built with `{ items: Array<{itemId,name,uris:string[],username,password}>, locked?: boolean }`. `FakeVault.fromFixture(path)` loads JSON. URIs are normalised with `normalizeOrigin` and invalid ones are dropped. `getSecret` returns a core `Secret`. It also has `test/fixtures/fake-vault.json`, which holds obviously fake credentials for the test login page (`http://127.0.0.1:8765`).

## @acb/vault-bitwarden
`class BitwardenVault implements VaultAdapter` is built with `{ bwPath?: string = 'bw', session?: string, run?: Runner }`, where `Runner = (args: string[], env: Record<string,string>, stdin?: string) => Promise<{code, stdout, stderr}>`. The default runner is `child_process.spawn` with `shell: false` and windowsHide.
- `status()` runs `bw status` and parses JSON. Unlocked needs both `status==='unlocked'` and a session.
- `unlock(masterPassword: string): Promise<void>` runs `bw unlock --raw --passwordenv ACB_BW_PASSWORD` with the password only in the child env. It keeps the session in memory.
- `find()` runs `bw list items --session` once. It caches metadata (id, name, login.uris, but never passwords) for 60s and does not use `--url`, because Bitwarden's matching is base-domain. It normalises each uri with `normalizeOrigin` and exact-matches in TS. `hint` ranks by a case-insensitive substring match on the name.
- `getSecret(id)` runs `bw get item <id> --session` and parses `login.username` and `login.password` into a `Secret`. The password is never cached, and stdout/stderr are never logged. Errors are rethrown with generic messages.
- The session is passed to the child as the `BW_SESSION` environment variable, not on argv (argv is visible to other processes).

## @acb/mcp-server
It uses `@modelcontextprotocol/sdk` over the stdio transport, and the binary is `dist/index.js` (bin `acb-mcp`). The agent id comes from `ACB_AGENT_ID`, default `claude-code`. It connects lazily with `connectBroker({role:'agent'})` and reconnects on close.
- `request_login {site: string, hint?: string}`
- `grant_status {request_id: string}`
- `list_grants {}`

Every tool result goes through `toToolResult(value)`, which passes it through an allow-list projection (`projectLoginResult` and the others pick only the known fields from the types), then returns `{content:[{type:'text', text: JSON.stringify(projected)}], structuredContent: projected}`. Tool descriptions tell the agent that it never receives credentials and should ask the human to approve on the dashboard when the status is pending. It exports `createServer(api: BrokerAgentApi)` so tests can inject a fake API, and `class McpFrontend implements AgentFrontend`.

## @acb/native-host
`src/index.ts` reads Chrome native messages from stdin with `NativeMessageReader` and connects with `connectBroker({role:'filler'})`. It relays extension messages (rpc requests) to the broker and broker messages (rpc responses and fill_job) back to stdout as native messages. It never logs message bodies. Diagnostics go to stderr, one line each with the type and method only. When the broker isn't running, it answers each rpc with `rpc_error {code:'broker_unavailable'}` and retries the connection every 2s.
- `scripts/install-native-host.ps1` (owned by this package) writes the host manifest to `%LOCALAPPDATA%\acb\native-host\com.acb.broker.json`. The manifest's path points to the `acb-native-host.cmd` wrapper (`@node "%~dp0\..\..\..\packages\native-host\dist\index.js" %*`, or an absolute path computed by the script), and `allowed_origins` is `["chrome-extension://<ID>/"]`. The script sets the default value of the registry keys `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.acb.broker` and `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.acb.broker` to the manifest path. `-ExtensionId` defaults to the ID derived from the manifest `key`.

## @acb/extension (MV3, Chrome and Edge)
`manifest.json` declares the permissions nativeMessaging, scripting, tabs and webNavigation, with `host_permissions: ["<all_urls>"]`. It includes a fixed `key` so the extension ID is stable, and the matching ID is documented in the README. It is built with esbuild from `src/` to `build/`, through `npm run build -w @acb/extension`.
- `src/background.ts` (service worker):
  - On startup it loads or creates the ECDH key pair in IndexedDB, with a non-extractable private key. It runs `connectNative(NATIVE_HOST_NAME)`, reconnects with backoff, and sends `pair {publicKey}` when the broker says it isn't paired. It keeps the port open.
  - On a `fill_job`, it runs `selectTab(job.origin)`. That looks at all tabs and keeps the ones whose `normalizeOrigin(tab.url) === job.origin`. Exactly one match uses that tab. Several matches use the active tab in the last-focused window if it is one of them, otherwise the result is `ambiguous_tab`. No match gives `no_tab`.
  - Next it calls `chrome.webNavigation.getFrame({tabId, frameId:0})` to get `{url, documentId}`. It re-normalises the url and requires it to equal job.origin, otherwise `origin_mismatch`.
  - Then it calls `claimSecret {jobId, tabOrigin, documentId}` → sealed, decrypts with `openSecret` using `secretAad(jobId, job.origin, documentId)`, and runs `chrome.scripting.executeScript({target:{tabId, documentIds:[documentId]}, world:'ISOLATED', func: fillAndSubmit, args:[expectedOrigin, creds, fillConfig]})`.
  - It sends `fillResult`. Afterwards it drops its references to the creds.
- `src/fill.ts` holds `fillAndSubmit(expectedOrigin, creds, cfg)`. It must be self-contained, because it is serialised for injection.
  - It requires `window.top === window` (`not_top_frame`) and `location.origin === expectedOrigin` (`origin_mismatch`). It needs a visible `input[type=password]` (`no_form`).
  - When there is a form, the form action's origin must be `location.origin` (`cross_origin_action`).
  - It sets values with the native value setter plus `input` and `change` events, then submits according to the strategy, all synchronously. If submission throws, it blanks both fields and returns `submit_failed`.
  - It returns a `FillResult` and never echoes the values.
- `src/select.ts` contains the pure tab-selection logic, which is unit tested with plain objects.
- The popup or options page shows the pairing code and connection status.

## test/login-page
`server.mjs` is a node:http server on 127.0.0.1:8765. It serves a login form (username and password, with a native form POST to `/login`) and returns "Welcome, <user>" on correct fake credentials, matched against `packages/vault-fake/test/fixtures/fake-vault.json`, or 401 otherwise. It never logs the request body.
