# Agent Credential Broker: design draft

Working name. This is an open-source, extensible tool that lets an AI agent sign in to sites without ever seeing the password. A person approves each login once, and the approval lasts up to 30 days.

## Goals
- **The agent never sees a secret.** The agent asks for a login. The secret goes straight from the vault into the site's login form.
- **A person approves each item**, on a screen the broker controls, not one the agent controls. One approval can last up to 30 days.
- **Approve ahead of time.** You approve the logins you expect to need before you leave, so the agent isn't stuck while you're away.
- **It works with any vault and any agent.** Vaults, form fillers, notification channels and agent protocols are all plug-ins.
- **It runs locally on Windows first, and is open source.** No cloud service is needed.

## Not goals for v1
- It doesn't replace a password manager. Bitwarden or Vaultwarden keeps storing the passwords.
- It won't be multi-user or for teams.
- It won't defend against a compromised operating system.

## Parts

```
 Agent (Claude Code, etc.)
   │  MCP: request_login(site, hint) → returns status only, never a secret
   ▼
 Broker (local background service)
   ├─ Grant store: item + exact site + agent + expiry (≤30 days) + use count
   ├─ Policy: some items can never get long grants (banking, government, mortgage)
   ├─ Audit log: every request, approval, use and revoke
   ├─ Vault plug-ins ──► Bitwarden/Vaultwarden (via the `bw` CLI), then KeePassXC
   ├─ Notifier plug-ins ─► local dashboard, ntfy push, email
   └─ Filler plug-ins
        ├─ Browser extension (Chrome/Edge/Firefox), via the browser's native messaging
        ├─ SSH agent (lets the agent use a key without reading it), later
        └─ Command runner that adds secrets to the environment (like passwd's exec --inject), later
 Approval dashboard (local web page; a phone-friendly version later)
```

## How a login works
1. The agent calls `request_login("https://192.168.50.1", "router")`.
2. The broker looks for a grant that is still valid for that item, that site and that agent.
   - **If there is no grant**, the broker notifies you and returns `pending`. You approve on the dashboard, choosing 1 hour, 1 day, 7 days or 30 days, or Deny.
3. **If there is a grant**, the broker tells the browser extension to fill the form.
4. The extension checks the **real address of the tab** itself. It doesn't trust the address the agent supplied. If it matches the grant, the extension gets the secret from the broker over native messaging, fills the form, submits it, and clears the secret from memory.
5. The agent gets back `filled` or `submitted`, or an error. It never gets a value.
6. The broker logs the use and can send a short notice that needs no tap, such as "Router login used at 2:14 AM".

## Security
- **The broker checks the site, not the agent.** A malicious page that tricks the agent can't reuse the router grant on a look-alike site.
- **Grants are narrow.** Each covers one item, one exact site and one agent. A grant can also have a use limit, and you can revoke one or all of them with one tap.
- **Some items never get long grants.** Items tagged that way need approval on each use, or are blocked outright.
- **Open problem:** after the extension fills the form, an agent with browser-scripting tools could read the password field before the page submits. Ways to reduce this:
  - Fill and submit in one step.
  - Prefer logins that submit without the page's own scripts.
  - Report this honestly in the threat model.
  - Long term: support passkeys and WebAuthn, where there is no reusable secret for anyone to take.
- **Approvals must happen outside the agent.** The dashboard and phone must be somewhere the agent can't click. On the same PC this means a separate login to the dashboard, or approving only from the phone.

## Extension points
Each plug-in type is a small interface, and each plug-in is a separate package:
- `VaultAdapter`: `find(hint, site)` and `getSecret(itemId)`. It runs only inside the broker.
- `Filler`: `fill(target, secretHandle)`.
- `Notifier`: `requestApproval(req)` and `notifyUse(event)`.
- `AgentFrontend`: MCP first. A plain HTTP or command-line front end can come later for agents that don't use MCP.

## v1 scope (the smallest useful version)
- The broker, written in TypeScript on Node, with grants and the audit log in SQLite.
- A Bitwarden/Vaultwarden plug-in that calls the `bw` CLI. That avoids the Bitwarden SDK's licence terms; check them before deciding.
- A Chrome/Edge extension for filling forms.
- An MCP server exposing `request_login`, `grant_status` and `list_grants`, all of which return metadata only.
- A local dashboard for approving, denying, revoking and reading the log.
- First real test: signing in to the ASUS router and the AT&T gateway on a home network.

## Later
- ntfy push with Approve buttons for phone approval.
- A KeePassXC plug-in.
- A Firefox extension.
- The SSH-agent filler.
- The command runner that adds secrets to the environment.
- Passkeys.
- An outside security review before promoting it.

## Licence
Apache-2.0 so others can adopt it easily. GPL-family vault tools are only ever called as separate programs.

## Open questions
- Should a grant cover a specific agent identity, a session, or both? How does the broker tell two Claude sessions apart?
- What does "agent" mean when several sessions share one PC?
- Should the broker also guard the browser profile, so the agent can't simply open the vault's own browser extension?
