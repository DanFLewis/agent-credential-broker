# Design decisions

This file records decisions made while building v1, including the ones the architecture advisor review changed.

## D1. Bitwarden integration is through the `bw` CLI, not the SDK
The Bitwarden SDK (`sdk-sm` and `sdk-internal`) is published under the proprietary *Bitwarden SDK License Agreement v1*. That licence forbids redistribution and derivative works. It also forbids use "to develop applications for use with software other than Bitwarden", which rules out Vaultwarden. Neither of those terms fits an Apache-2.0 project. The `bw` CLI is GPL-3.0, and the broker runs it as a separate program with `spawn` and `shell: false`. The broker never links against it.

## D2. `node:sqlite` instead of better-sqlite3
The built-in module needs no native compile step on Windows, which makes setup easier.

## Changed by the advisor review
| # | Before | After | Why |
|---|---|---|---|
| A1 | "Fill and submit in one step" was presented as a defence against an agent that has browser-scripting access | It is stated as a narrower guarantee: the secret never enters the agent's transcript by accident and never reaches a look-alike origin. It is **not** a defence against an agent that deliberately attacks the page. | A pre-planted MAIN-world listener or a patched `HTMLFormElement.prototype.submit` reads the value synchronously. |
| A2 | `claimSecret` returned plaintext over the pipe | The secret is sealed to the paired extension's static ECDH P-256 key, using an ephemeral broker key, HKDF-SHA256 and AES-256-GCM. The AAD is `jobId\|origin\|documentId`. Pairing needs a human to compare a code on the dashboard. | Any same-user process can connect to the pipe as a "filler" and report a fake origin. Sealing means it gets only ciphertext. |
| A3 | The dashboard session cookie authorised approvals | The dashboard password is required on **each** approve, policy change, fill-config change and pairing confirm. The session cookie only allows reading. | An agent driving a browser profile where Dan is logged in could otherwise just click Approve. |
| A4 | The agent could see item names when a match was ambiguous | The agent never sees item names or ids. An ambiguous match becomes `pending`, and the human picks the item on the dashboard. | Item names leak information, and showing them invites the agent to steer the choice. |
| A5 | `hint` could influence matching | `hint` only ranks results and is displayed as escaped, untrusted text. | It is a prompt-injection channel aimed at the approver. |
| A6 | No limit on pending requests | Pending requests are deduplicated on (agentId, origin), with at most 3 per agent. | Prevents approval fatigue and spam. |
| A7 | Origin check only in the extension | Three layers: the extension observes the tab's origin, the broker decides, and the injected script re-checks `location.origin` and `window.top === window`. Only the top frame is filled. | Defence in depth. Frames are the classic way to defeat autofill. |
| A8 | Tab URL checked, then a separate fill | `documentId` comes from `webNavigation.getFrame`. The extension injects with `documentIds:[id]`, and the documentId is part of the AAD. | Closes the time-of-check/time-of-use gap: if the tab navigates in between, the injection fails. |
| A9 | `bw list items --url` for matching | The adapter fetches metadata, normalises each URI to an origin and exact-matches in core. | Bitwarden's default URI matching uses the base domain. |
| A10 | Plain `http:` allowed everywhere | `http:` is allowed only for LAN, loopback and `.local` hosts, and the approval screen shows an "unencrypted" warning. | Routers often serve plain `http:`. Public sites over `http:` should never be filled. |
| A11 | A `filled` status existed for "filled but not submitted" | Removed. If submission fails, the fields are blanked and the result is `error/submit_failed`. A per-item submit strategy (`requestSubmit`, `enter` or `click` a selector) is configured by the human. | A password should never be left sitting in the DOM. Some routers log in through a JS button. |
| A12 | The form's action origin was not checked | The form's action origin must equal the page origin. | A same-origin page can still post the form somewhere else. |
| A13 | Vault master password entered on the dashboard | The master password is entered only at a hidden console prompt when the broker starts, or the broker reads `BW_SESSION` from the environment. | Keeps it off the HTTP surface and out of any DOM the agent can see. |
| A14 | The docs said the secret is "cleared from memory" | The wording now says the code "drops references". | JS strings can't be zeroed. |

Advisor points I didn't take, or changed:
- **Remove the `Notifier` and `AgentFrontend` abstractions.** I kept them. The v1 brief asks for those plug-in interfaces explicitly. Each has exactly one implementation, and the interfaces are small.
- **Leave Edge out.** I kept Edge. Supporting it costs one extra registry key in the install script.
- **Require the password for revoke-all.** It doesn't need one. Deny, revoke and revoke-all move in the safe direction, and a panic button should take one click. The worst a rogue caller can do with them is deny service.
- **Approve with Windows Hello (WebAuthn, user verification required).** Recorded as the top "later" item. It is the only approval factor that a same-user agent can't replay.

## Changed by the security review

A second Fable review read the finished v1 statically, concentrating on the secret path and the origin check. It found the origin normalisation, the documentId pinning, single-use claiming and the seal sound. The changes below came out of it.

| # | Finding | Change | Test |
|---|---|---|---|
| S1 (high) | Pairing confirm took no argument and paired whatever key was pending. A process on the pipe could swap in its own key while the human typed the password, and the click paired the attacker. The 40-bit code could also be ground offline from `broker.db`. | `confirmPairing(expectedCode)` compares the code the dashboard displayed with the pending key's code and refuses on mismatch (`pairing_changed`, audited). The code is now 80 bits (`XXXX-XXXX-XXXX-XXXX`). The extension computes its displayed code from its own key instead of trusting the broker's answer. | service, dashboard, e2e |
| S2 (med) | All authorisation state is in a user-writable SQLite file, so "forensics on the profile" and "visible in the audit log" overstated the bar. | Docs corrected (threat model and the limits below). The real fix is the separate Windows account, already planned. | n/a |
| S3 (low) | A filler could send a 200-character free-text `message` that reached the agent, and the MCP projection passed broker text through. | The broker drops `message` from fill results. The MCP server builds every agent-visible message from a fixed table keyed by error code, and request ids must match `[A-Za-z0-9-]{1,64}`. | mcp no-secret |
| S4 (low) | The pending-request caps keyed on the self-asserted agent id. | A global cap of 10 pending requests on top of 3 per agent. | service |
| S5 (low) | One global password limiter: five bad `/api/login` posts a minute from a local process kept the human from approving. | Separate buckets for login and for in-session password checks. In-session checks need the cookie and CSRF token (but see the cookie limit below). | dashboard |
| S6 (hardening) | A configured `passwordSelector` accepted any visible input. | It must be an `<input type="password">`, or the fill is refused. | fill |
| S7 (hardening) | A relative `ACB_BW_PATH` with an extension was spawned as given. | It must be absolute. | bitwarden |

Review advice I took only in part:
- **S2: caching the paired key and the password hash in memory and MAC-ing rows.** Not done. A same-user process that can write `broker.db` can also restart the broker, which reloads the database, or read and patch broker memory. A cache would mainly stop the one-statement attack while the broker keeps running. The separate Windows account fixes all of this at once, so v1 documents the limit instead of half-fixing it.
- **S4: dedupe on origin alone.** Not taken, because approvals are per agent and merging requests from different agents would hide who asked. The global cap has a trade-off: a process that rotates agent ids can fill all 10 slots and block the real agent until the human denies those requests.
- **S5: exponential backoff.** Not done; the limit is still 5 failures a minute per bucket. Splitting the buckets helps only against callers without a session. A caller holding a harvested cookie (see the next list) can read the CSRF token from `GET /api/session`, fill the in-session bucket to block approvals, and guess against two buckets instead of one.

Documented rather than fixed in v1:
- **The session cookie is shared across localhost ports**, because cookies ignore ports. A dev server the agent runs and the human visits gets the cookie. With it, a caller can read pending requests, item names and the audit log, and can deny or revoke, but can't approve without the password. It can also fill the in-session password limiter and so block approvals for a minute at a time (S5). HTTPS on a dedicated hostname would fix this and is out of scope for v1.
- **The extension does not authenticate the broker.** Signing fill jobs with a broker key pinned at pairing is the fix. Without it the worst case is a login CSRF, not disclosure.
- **HKDF doesn't bind the recipient public key**, and **Bitwarden "Never" URI match types are ignored**. No attack was found for either; both are small follow-ups.
- **`no_match`, `blocked` and `pending` tell the agent whether a vault item exists for an origin.** Accepted: the agent needs to know whether asking makes sense.

## Remaining honest limits (also in the threat model)
- The agent runs as the same Windows user. It can read broker memory (including `BW_SESSION`) and parse the Chrome profile to extract the extension's key. Sealing stops a process that only connects to the pipe. It doesn't stop one that writes to `broker.db`, which can replace the paired key, add a grant or delete audit rows (S2). Running the broker as a separate Windows user is a later step.
- The agent ID is a self-asserted label. In practice a grant covers (item, origin) for any process running as the same user.
- If the Bitwarden browser extension is unlocked in the browser profile the agent drives, the broker can be bypassed entirely.
- A rogue filler can use up a grant's remaining uses (denial of service), but it can't read the secret.
- An IP-literal grant is bound to an address, not to a device.
