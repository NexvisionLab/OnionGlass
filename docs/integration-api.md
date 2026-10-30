# Integration API

Status: draft, no stable version. The shapes below will change before version 1.0. A machine-readable OpenAPI description will live in this directory once the first hook is implemented.

## Principles

1. **Everything is optional.** Each hook has a built-in default, so the gateway works with no integration at all.
2. **HTTP, not plugins.** An integration is a separate service the gateway calls. Outside code is never loaded into the gateway process. This keeps the licence boundary and the security boundary clear.
3. **Signed.** Requests from the gateway carry a signature and a key identifier, so a receiver can verify them. Tickets sent to the gateway are signed the same way.
4. **Versioned.** Every request carries a protocol version.
5. **Fail closed.** If the policy hook or the audit hook cannot be reached in time, the gateway refuses the request. Other hooks degrade as documented below.
6. **Short timeouts and caching.** Policy answers may be cached for a short, configured period.

## Hooks

| Hook | Direction | Purpose | Built-in default | If unreachable |
|---|---|---|---|---|
| Ticket issuer | Into the gateway | Says who the visitor is and which profile applies | Local accounts, optional OpenID Connect | Sign-in fails |
| Policy | Gateway calls out | Allow, deny or restrict an onion for an account | Configuration lists, blocklist files, built-in checks | Refuse the request |
| Audit sink | Gateway calls out | Receives audit events | JSON lines file and syslog | Refuse the request |
| Evidence sink | Gateway calls out | Receives captures, manifests and hashes | Local folder or S3-compatible store | Capture fails, browsing continues |
| Quota | Gateway calls out | Check and consume allowance | Local counters | Refuse the request in a quota-limited profile |
| Intel | Gateway calls out | Data for the panel beside a page | What this instance itself knows | Panel shows local data only |
| Entity extraction | Gateway calls out | Wallets, emails, handles and keys found in a page | Built-in pattern matching | Built-in extraction only |
| Translation | Gateway calls out | Translate page text | Any LibreTranslate-compatible URL | Translation unavailable |
| Discovery event | Gateway calls out | An unknown onion was opened | Off | Event is dropped |
| Watch event | Gateway calls out | A visitor asked to watch an onion | Off | Event is dropped |

## Policy and audit in the code today

The policy and audit hooks exist as Python interfaces, `Policy` and `AuditSink`, and the gateway takes them in its settings. The HTTP form described above is not built yet. The built-in `StaticPolicy` (blocklist and allowlist), `JsonLinesAudit` (a file) and the kill file work now.

The quota hook exists the same way, as the `QuotaMeter` interface with the built-in `LocalQuota`. It is asked how much an account has used today and told what to add. If it cannot answer in time, the request is refused in a profile that has an allowance.

A policy receives who is asking (profile, group, subject), the onion origin and whether this is an `open` or a `fetch`, and returns a decision with the name of the rule that made it. It is never told the visitor's network address. Before every request the gateway checks, in this order, the kill switch, the policy, and then writes the audit record. If the policy raises, takes longer than the hook timeout (2 seconds by default) or answers with anything but a decision, the request is refused. If the audit record cannot be written, the request is refused. After the reply arrives its outcome is recorded, and if that fails the reply is dropped.

## Ticket

A ticket is a signed, short-lived, single-use token. Planned claims: subject, group, profile, issued-at, expiry, a unique identifier, and the onion to open. The gateway holds only public keys, so a stolen gateway cannot issue tickets. Keys carry identifiers so they can be rotated without downtime.

## What is deliberately not in the API

- A way to run code inside the gateway.
- A way to fetch a page for a script. The gateway is for people looking at pages, not for bulk retrieval.
- Share links that give access without sign-in.
