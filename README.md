# Agent Credential Broker

Lets an AI agent (Claude Code first) sign in to websites without ever seeing the password.

The agent calls an MCP tool such as `request_login({ site: "https://example.com" })`. You approve the request on a local dashboard: you pick the vault item and how long the grant lasts (one use, 1 hour, 1 day, 7 days or 30 days). A browser extension then fills and submits the login form in a tab you already have open. The agent only gets a status back: `submitted`, `pending`, `denied` or an error code. Credentials come from Bitwarden or Vaultwarden through the `bw` CLI.

The guarantee is narrower than "the agent cannot get the password". Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before you rely on it. In short: the password never enters the agent's tool results, logs or IPC channel, and it is only ever typed into a page whose top-frame origin exactly equals the origin you approved. An agent that runs as your Windows user and sets out to attack the system can still get around this. v1 aims to make leaks by accident impossible, and to make deliberate theft harder. Another process running as your user can still edit the broker's database directly, so the audit log is not tamper-evident.

```
agent ─MCP stdio─► acb-mcp ─named pipe─► acb-broker ─named pipe─► acb-native-host ─native messaging─► extension ─► page
                                           │  SQLite: grants, policies, audit log
                                           ├─ bw CLI (vault)
                                           └─ dashboard http://127.0.0.1:7414
```

## Packages

| Package | What it does |
|---|---|
| `packages/core` | Types, wire protocol, origin normalisation, grant matching, sealing crypto, redaction |
| `packages/broker` | Policy engine, SQLite grant store and audit log, named-pipe IPC, dashboard HTTP server, `acb-broker` CLI |
| `packages/dashboard` | Static approval UI (approve, deny, revoke, revoke all, item policies, fill settings, pairing, audit log) |
| `packages/vault-bitwarden` | `VaultAdapter` over the `bw` CLI (see [its README](packages/vault-bitwarden/README.md)) |
| `packages/vault-fake` | In-memory vault with obviously fake credentials, for tests and demos |
| `packages/mcp-server` | `acb-mcp`: the MCP tools `request_login`, `grant_status` and `list_grants` (metadata only) |
| `packages/native-host` | `acb-native-host`: relays between Chrome native messaging and the broker pipe |
| `packages/extension` | Chrome/Edge MV3 extension that checks the tab origin itself, then fills and submits |

Plug-in points are the `VaultAdapter`, `Filler`, `Notifier` and `AgentFrontend` interfaces in [packages/core/src/types.ts](packages/core/src/types.ts).

## Setup on Windows 11

You need Node.js 24 or later, Chrome or Edge, and for real use the Bitwarden CLI.

### 1. Build

```powershell
git clone <this repo> agent-credential-broker
cd agent-credential-broker
npm install
npm run build
npm test
```

`npm run build` compiles every package and bundles the extension into `packages\extension\build`.

### 2. Set the dashboard password

```powershell
node packages\broker\dist\cli.js set-password
```

The prompt hides your typing. The broker stores a scrypt hash in `%LOCALAPPDATA%\acb\broker.db`. You will type this password for each approval, policy change, fill-config change and pairing confirmation, so make it different from your vault master password.

### 3. Install the Bitwarden CLI and start the broker

Install `bw.exe`, for example with `winget install Bitwarden.CLI`. Then log in once (`bw login`, or `bw config server https://your-vaultwarden` first for Vaultwarden).

```powershell
node packages\broker\dist\cli.js start --vault bitwarden
```

The broker asks for the master password at a hidden console prompt. Alternatively, it uses `BW_SESSION` from the environment if that is set.

The broker reads your vault through `bw`, which works from a local copy that only changes when you run `bw sync`. After you add or edit an item in the Bitwarden app or web vault, run `bw sync`. The broker also caches the list of items (not the passwords) for 60 seconds, so a new item can take up to a minute to appear. If `bw.exe` is not on `PATH` (an npm install gives you `bw.cmd`, which cannot be run without a shell), set `ACB_BW_PATH` to the full path of `bw.exe`.

To try everything without a real vault, use the fake one:

```powershell
node packages\broker\dist\cli.js start --vault fake --fake-fixture packages\vault-fake\test\fixtures\fake-vault.json
```

The dashboard is at http://127.0.0.1:7414. Change the port with `ACB_DASHBOARD_PORT`.

### 4. Load the extension

1. Open `chrome://extensions` (or `edge://extensions`) and turn on Developer mode.
2. Click **Load unpacked** and pick `packages\extension\build`.
3. Check that the ID is `kfjfmplclkcjdebkflnaffmagjakdkec`. The manifest pins its key, so the ID is the same on every machine.

Recent branded Chrome builds ignore the `--load-extension` command-line flag, so loading it through the extensions page is the supported route.

### 5. Register the native messaging host

```powershell
powershell -ExecutionPolicy Bypass -File packages\native-host\scripts\install-native-host.ps1
```

This writes `%LOCALAPPDATA%\acb\native-host\com.acb.broker.json` and sets the per-user registry keys for Chrome and Edge. It needs no admin rights. `uninstall-native-host.ps1` reverses it. Restart the browser afterwards.

Run it from an ordinary PowerShell window, not from a terminal inside the Claude desktop app. The desktop app is packaged with MSIX, which redirects writes to `HKCU` and `%LOCALAPPDATA%` into its own private copy that Chrome can't see. If the extension's service worker logs "Specified native messaging host not found.", this is the usual cause. Start the broker outside the app for the same reason, so that its database lands in the real `%LOCALAPPDATA%\acb`.

### 6. Pair the extension

The extension's popup shows a pairing code such as `K7QM-3XRA-9TFE-2BWN`. Open the dashboard, check that it shows the same code, and confirm with your dashboard password. If the code changes before you click, the broker refuses the confirmation and you compare again. From then on, the broker encrypts every credential to that extension's key. If you reinstall the extension, reset pairing on the dashboard and pair again.

### 7. Add the MCP server to Claude Code

```powershell
claude mcp add acb --env ACB_AGENT_ID=claude-code -- node C:\path\to\agent-credential-broker\packages\mcp-server\dist\index.js
```

`ACB_AGENT_ID` is the label the dashboard and audit log show for this agent. It is self-asserted, not an authenticated identity (see the threat model).

## Using it

1. Open the login page of the site in Chrome yourself.
2. The agent calls `request_login` with the site's origin, for example `http://192.168.50.1`. The first time, the result is `pending`.
3. Approve on the dashboard. Choose the vault item and the duration. Plain-`http` sites get an "unencrypted" warning and are only allowed on LAN, loopback and `.local` hosts.
4. The agent calls `request_login` again. The extension finds the tab whose origin matches exactly, fills the form and submits it in one step, and the agent gets `submitted`.

Per item you can set:

- **never long-grant**: only single-use, 15-minute grants.
- **blocked**: never fillable.
- A submit strategy (`requestSubmit`, `enter`, or `click` on a CSS selector) and optional username and password field selectors, for router pages that log in through a JavaScript button.

Revoke one grant or all of them at any time. Neither needs the password.

The dashboard lists an item only after an agent has asked for it. For a site that needs a submit strategy, set it on the item's card while the first request is waiting, and approve after that. If you approve first, the first fill uses `requestSubmit`, which for those sites sends a wrong password.

## Setting up a site

A sign-in only goes through when every part matches exactly. These are the things that went wrong when the tool was first tested against home routers.

**Use the origin the browser ends up at.** The vault item's URI must equal the tab's origin, including the scheme and port, and the broker matches it before anything is filled. Some pages redirect in the browser by script, so open the login page, let it settle, and copy the origin from the address bar. A request for an origin with no open tab returns `no_tab`.

**Chrome must trust the site's certificate, or the page must be plain `http`.** If Chrome stops at a certificate warning, the login page never loads and nothing can be filled. Routers usually ship with a self-signed or expired certificate. You have three choices:
- If the device serves the same page over plain `http`, use that. The broker allows `http` on the local network only, and flags it as unencrypted.
- If the device can import a certificate, give it one your machine trusts.
- If the device has its own certificate authority, trust that authority's root in your user's certificate store. This lets the device sign a certificate for any site, so do this only for a device you control.

**Password-only logins still need a username in the vault.** Bitwarden returns an empty username as null, and the broker refuses an item without one. Put any placeholder in the username. If the page has no username field, the placeholder is never typed.

**Check the stored password for spaces.** The broker sends the password exactly as stored. A leading or trailing space from a paste makes the site reject it, with nothing to say why.

**Pick the submit strategy from the login button.** If the button runs a script that changes the form before it's sent, for example by hashing or encoding the password into a hidden field, use `click` on the button. `requestSubmit` sends the form without running that script.

### Devices tested so far

| Device | Origin in the vault | Submit strategy | Notes |
|---|---|---|---|
| ASUS router (Asuswrt firmware) | `https://www.asusrouter.com:8443` | `click`, `div.button` | The page at the router's IP redirects to this hostname. The firmware tested has no certificate import, so the router's own root CA was trusted. Its Sign In button base64-encodes the credentials into a hidden field. Three failed sign-ins turn on a captcha. |
| AT&T BGW320-505 | `http://192.168.1.254` | `click`, `input[name="Continue"]` | The HTTPS certificate is self-signed and expired, and plain `http` doesn't redirect. There is no username field. The access-code page only appears when you open a protected page such as `/cgi-bin/home.ha`, and it needs that page's cookie. Continue hashes the code with a one-time nonce, so reload the page if it has been open a while. |

## Local test login page

```powershell
npm run e2e:login-page
```

This serves http://127.0.0.1:8765 with three pages: a native form at `/`, a JavaScript-button login at `/js-login` (set the submit strategy to `click` with selector `#login-btn`), and the form inside an iframe at `/frame`, which the extension must refuse to fill. It accepts only the fake credentials from the fake-vault fixture.

## Tests

`npm test` runs the vitest suite. It covers:

- grant matching and expiry
- origin normalisation and look-alike vectors
- sealing and pairing crypto
- the guarantee that no secret appears in MCP responses
- the dashboard's Host, Origin, CSRF and password checks
- the native-messaging relay
- the `bw` adapter against a fake runner
- the in-page fill logic

`test/e2e/flow.test.ts` drives the whole path. It connects an MCP client to the real MCP server, which talks to a real broker with the fake vault. A simulated extension then pairs, claims the sealed secret, decrypts it and logs in to the local test page. The test checks that nothing the agent saw contains a credential, an item name or an item id.

## Docs

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): what is protected, against whom, and what is out of scope
- [docs/DECISIONS.md](docs/DECISIONS.md): design decisions, including the changes made after the security reviews
- [docs/CONTRACT.md](docs/CONTRACT.md): the internal build contract between packages
- [DESIGN.md](DESIGN.md): the original design notes

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The Bitwarden CLI is GPL-3.0. The broker runs it as a separate program and does not link to it.
