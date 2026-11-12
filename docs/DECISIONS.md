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

## Remaining honest limits (also in the threat model)
- The agent runs as the same Windows user. It can read broker memory (including `BW_SESSION`) and parse the Chrome profile to extract the extension's key. Sealing raises the bar from "connect to a pipe" to "do forensics on the profile". It doesn't remove the risk. Running the broker as a separate Windows user is a later step.
- The agent ID is a self-asserted label. In practice a grant covers (item, origin) for any process running as the same user.
- If the Bitwarden browser extension is unlocked in the browser profile the agent drives, the broker can be bypassed entirely.
- A rogue filler can use up a grant's remaining uses (denial of service), but it can't read the secret.
- An IP-literal grant is bound to an address, not to a device.
