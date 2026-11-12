# Threat model (v1)

## What we protect
1. **Credential values** (username and password) stored in the vault.
2. **The approval decision.** Only the human decides which agent may use which login on which site, and for how long.

## The guarantee, stated precisely
> In normal use, the plaintext credential never enters the agent's context: not its tool results, not its
> logs, not the IPC channel it can talk to. It is only ever typed into a page whose committed top-frame
> origin exactly equals the origin the human approved.

This is narrower than "the agent cannot get the password". An agent that runs as the same Windows user
and deliberately attacks the system can still get it (see *Out of scope*). v1 makes accidental exposure
impossible and deliberate theft harder. The audit log records what a well-behaved system did. It is
not tamper-evident against a same-user attacker, who can edit `broker.db` directly (see *Out of scope*).

## Actors
| Actor | Trust | Capabilities assumed |
|---|---|---|
| Human (Dan) | trusted | Approves on the dashboard and knows the dashboard password |
| Broker process | trusted | Holds the vault session in memory |
| Browser extension | trusted | Holds the non-extractable ECDH private key in IndexedDB |
| AI agent (Claude Code) | **untrusted but not assumed malicious** | Calls MCP tools. Has a shell as the same Windows user. May have browser-automation tools. May be prompt-injected by web content. |
| Web pages | untrusted | May imitate login pages, may frame other sites, may post forms cross-origin |
| LAN | untrusted | Can sniff `http:` router logins |

## Data flow and checks
```
agent ──MCP(stdio)──► mcp-server ──pipe(NDJSON, role=agent)──► broker
                                                          │ grant? (item, exact origin, agent, expiry, uses)
                                                          ▼
extension ◄─native msg─ native-host ◄─pipe(role=filler)── fill_job{jobId, origin}
   │ 1. select tab whose real URL origin == job.origin (exactly one, or the active one)
   │ 2. webNavigation.getFrame(frameId 0) → {url, documentId}; re-check origin
   ├──claimSecret{jobId, tabOrigin, documentId}──► broker re-checks origin, job single-use, grant usable
   │◄── SealedSecret (ECDH P-256 → HKDF → AES-GCM, AAD = jobId|origin|documentId)
   │ 3. decrypt in service worker
   │ 4. executeScript(documentIds:[documentId]) → script checks top frame, location.origin,
   │    form action origin, visible password field → fill + submit synchronously
   └──fillResult{submitted|error code}──► broker → audit → agent gets status only
```

## Threats and mitigations
| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | A look-alike site (`192.168.50.1.evil.com`, `http` vs `https`, userinfo tricks) triggers a fill | WHATWG origin normalisation and exact string equality, with explicit rejects (userinfo, trailing dot, non-http(s)). Checked in three places: extension, broker, injected script. | None known; covered by test vectors |
| T2 | A page frames the real login page, or a frame navigates mid-fill | Only the top frame is filled (`frameId 0` plus `window.top === window`). Injection is pinned to `documentId`, so it fails if the tab navigates. The documentId is bound into the AAD. | |
| T3 | A same-origin form posts elsewhere | The form's action origin must equal the page origin | A page's own JS could still exfiltrate. If you trust the origin, you trust its JS. |
| T4 | The agent connects to the broker pipe and impersonates the filler | The secret is sealed to the paired extension key. Pairing needs a human to compare an 80-bit code and enter the dashboard password. The confirm call carries the code the human saw, so a key swapped in while they type is refused. The extension computes its own code from its own key. A paired key can't be replaced without a password-protected reset. | A rogue filler can use up grant uses (denial of service). Fill results carry only an error code, never free text. |
| T5 | The agent approves its own request through the dashboard | Each approval needs the dashboard password. Host/Origin/CSRF checks, SameSite=Strict, a localhost-only bind and a strict CSP. Failed logins and failed in-session password checks are rate-limited in separate buckets, so spamming `/api/login` can't lock the human out of approvals. | If the agent can read keystrokes or screen, it can capture the password. Windows Hello approval is planned. Cookies ignore ports, so a dev server the agent runs on `localhost` and the human visits receives the session cookie. That gives read access to pending requests, item names and the audit log, plus deny and revoke, but never approve, which needs the password. |
| T6 | The agent's hint text manipulates the approver | The hint is displayed escaped and labelled untrusted, and is never used for matching. The human picks the item. | |
| T7 | Approval fatigue or spam | Requests are deduplicated per (agent, origin), with at most 3 pending per agent and 10 in total (agent ids are self-asserted). Items can be tagged never-long-grant (single-use only) or blocked. | |
| T8 | Secrets leak into logs, errors or MCP output | An allow-list projection on every MCP result. A redacting `Secret` type. The audit log stores metadata only. The native host never logs message bodies. `bw` output is never logged. Tests assert all of this. | |
| T9 | `bw` session or master password exposed on argv | Passed through the child-process environment only. The master password goes in at a console prompt, never over HTTP. | Readable from broker process memory by the same user |
| T10 | Router login over `http:` is sniffed on the LAN | `http:` is allowed only for LAN/loopback/.local hosts, and the approval screen warns | Inherent to the device |
| T11 | An IP-literal grant reused on a different network or a different device at the same address | Documented. Expiry is bounded at 30 days. | Certificate pinning is later |

## Out of scope for v1 (stated honestly)
- **A deliberately malicious agent with browser-scripting access to the same profile.** It can plant a MAIN-world listener before the fill and read the value. Mitigation: don't attach automation tools to the browser profile you use for brokered logins.
- **A deliberately malicious agent with a shell as the same user.** It can read broker process memory (`BW_SESSION`), parse Chrome's profile to recover the extension key, or install a keylogger. It can also write `%LOCALAPPDATA%\acb\broker.db` directly: replace the paired key, insert a grant, overwrite the dashboard password hash, or delete audit rows. None of that needs forensics. Mitigation later: run the broker as a separate Windows account or service, so the database and process are out of the agent's reach.
- **The extension does not authenticate the broker.** Whoever holds the pipe name while the broker is down can send a fill job with credentials of its own choosing (a login CSRF into a tab the human has open). No secret is disclosed. Fix later: pin a broker signing key at pairing and sign fill jobs.
- **An unlocked Bitwarden browser extension in the agent's browser profile** bypasses the broker entirely.
- **Agent identity** is a self-asserted label (`ACB_AGENT_ID`). Grants effectively cover (item, origin) for any same-user process. Per-session tokens are later.
- A compromised OS, browser or extension supply chain.
- Passkeys/WebAuthn, the long-term fix where no reusable secret exists, are future work.
