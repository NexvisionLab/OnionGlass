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
| Entity sink | Gateway calls out | The entities on the page a visitor is looking at, when they press a button | Off | The visitor is told it could not be sent |
| Entity extraction | Gateway calls out | Wallets, emails, handles and keys found in a page | Built-in pattern matching | Built-in extraction only |
| Translation | Gateway calls out | Translate page text | Any LibreTranslate-compatible URL | Translation unavailable |
| Discovery event | Gateway calls out | An unknown onion was opened | Off | Event is dropped |
| Watch event | Gateway calls out | A visitor asked to watch an onion | Off | Event is dropped |

## Policy, audit and quota in the code today

Three hooks are built, each as a Python interface the gateway takes in its settings, with a built-in version and a signed HTTP version that asks another service.

| Hook | Interface | Built-in | HTTP form |
|---|---|---|---|
| Policy | `Policy` | `StaticPolicy`: blocklist, allowlist, rated list | `HttpPolicy` |
| Audit | `AuditSink` | `JsonLinesAudit`, a file | `HttpAudit` |
| Quota | `QuotaMeter` | `LocalQuota`, with an optional journal file | `HttpQuota` |

A policy receives who is asking (profile, group, subject), the onion origin and whether this is an `open` or a `fetch`, and returns a decision with the name of the rule that made it, and whether the site is to be shown as text only. It is never told the visitor's network address. Before every request the gateway checks, in this order, the kill switch, the held list, the policy, the allowance, and then writes the audit record. If the policy raises, takes longer than the hook timeout (2 seconds by default) or answers with anything but a decision, the request is refused. If the audit record cannot be written, the request is refused. After the reply arrives its outcome is recorded, and if that fails the reply is dropped. The quota meter is asked how much an account has used today and told what to add, and if it cannot answer the request is refused in a profile that has an allowance.

## The signed HTTP hooks

The gateway calls your service with `POST` and a JSON body, to `<base>/policy`, `<base>/audit`, `<base>/quota/used`, `<base>/quota/charge`, `<base>/quota/reserve` and `<base>/entities`. The base address must be `https`, except for this machine, or when the operator says plain `http` is acceptable on a private network. The gateway checks the service's certificate and name, does not follow redirects, uses a new connection for each call, and reads at most 64 KiB of reply. Your service does not have to know anything about onionglass beyond this page, and nothing of it is loaded into the gateway.

### Signing

Both directions use Ed25519. The gateway holds a signing key and a key id, and a ring of public keys it trusts for replies, each with its own key id. Keys can be added and removed without downtime, so rotation is: add the new public key on both sides, switch the signing key, remove the old one.

A request carries these headers:

| Header | Value |
|---|---|
| `X-Onionglass-Version` | `1` |
| `X-Onionglass-Key` | the gateway's key id |
| `X-Onionglass-Timestamp` | whole seconds since the epoch |
| `X-Onionglass-Nonce` | 32 lower-case hex characters, new for every request |
| `X-Onionglass-Signature` | the signature, base64url without padding |

The signature is made over these bytes: the text `onionglass hook request v1`, a zero byte, then six lines joined by a line feed with no final line feed: the key id, `POST`, the full request path, the timestamp, the nonce, and the SHA-256 of the body as lower-case hex. Your service should reject a timestamp more than a minute from its own clock and a nonce it has already seen.

Your reply must be status `200` with a JSON object, and carry `X-Onionglass-Key` (your key id) and `X-Onionglass-Signature`. That signature is made over the text `onionglass hook response v1`, a zero byte, then four lines joined the same way: your key id, the **request's nonce**, the status as a number, and the SHA-256 of the reply body as hex. Because the request's nonce is signed, a recorded "allow" cannot be played back for a different question. A reply that is unsigned, signed by a key the gateway does not trust, signed over anything else, or not valid JSON is treated as a failure, and a failure makes the gateway refuse the request.

### Bodies

Every request body has `"v": 1`. Fields you do not know must be ignored, so that later versions can add some.

**`/policy`** receives `origin` (`scheme`, `address`, `host`, `port`), `profile`, `group`, `subject` and `action` (`open` or `fetch`). Reply `{"allow": true}` or `{"allow": false}`, and optionally `"rule"` (1 to 64 characters from letters, digits and `._:-`, recorded in the audit log and never shown to the visitor) and `"text_only": true` to allow a site but show it without images, fonts, forms, logins or uploads.

**`/audit`** receives `{"event": {...}}` with `kind`, `action`, `rule`, `profile`, `group`, `subject`, `origin`, `path`, `status` and `time`. The site is named in the form the operator chose, the same as in the local log: `full` sends origin and path, `origin` (the default) sends the origin and an empty path, `hash` sends `h:` and a keyed hash with an empty path, and `none` sends an empty origin and path. Reply `{"ok": true}`. Anything else makes the gateway refuse the request that the event describes, because nothing may happen that is not on record.

**`/quota/used`** receives `subject` and `profile` and replies `{"used": <whole number>}`. **`/quota/charge`** receives `subject`, `profile` and `units`, adds them to today's count, and replies with the new total in the same form. **`/quota/reserve`** receives `subject`, `profile`, `units` and `limit`. It must, as one step that no other request can come between, check that today's count plus `units` is not over `limit`, and if so add `units` and reply `{"ok": true, "used": <new total>}`, otherwise change nothing and reply `{"ok": false}`. The gateway uses it for opens, so that requests arriving together cannot overspend an allowance.

**`/entities`** receives `{"batch": {...}}` with `subject`, `group`, `profile`, `origin`, `path`, `entities` and `time`. `entities` is a list of `{"kind": ..., "value": ...}` where kind is `bitcoin`, `ethereum`, `monero`, `email` or `onion`, each already checked by the gateway. `time` is whole seconds since the epoch. The site is named in the audit form the operator chose, as for `/audit`. The page's own text and title are never sent. A batch is sent only when a visitor presses the button, it holds only what the gateway itself found on the page they are looking at, and the send is on the audit record first (`kind` `entities`, `action` `send`, `rule` the number of entities). Reply `{"ok": true}`. Anything else tells the visitor it could not be sent, and does not use up their allowance (`max_entity_sends_per_session`, 20 by default, counted per session and cleared after 24 hours without a send). To turn it on, add `"entities"` to `[hooks].use` and set `send_entities = true` on the profiles that may use it. That setting needs `show_entities` too, because a visitor sends what the panel shows.

### Keeping answers

`HttpPolicy` can keep answers for a short, configured time (`cache_seconds`, off by default), per question: address, profile, group, subject and action. Refusals are kept as well as allows, failures never are, and nothing is served after the time is up or when your service is down. A kill file or the held list still acts at once, because they are checked before the policy.

### Using them

In a config file, the `[hooks]` section sets the address, the two keys and which of the three hooks to use (see `docs/examples/team.toml`). In code, the same thing looks like this:

```python
client = HookClient(
    "https://hooks.internal.example/onionglass",
    signing_key=gateway_private_key,  # Ed25519PrivateKey
    key_id="gw-2026-10",
    response_keys=trusted_service_keys,  # a KeyRing of public keys by key id
)
settings = Settings(
    ...,
    policy=HttpPolicy(client, cache_seconds=5),
    audit=HttpAudit(client),
    quota=HttpQuota(client),
)
```

## Ticket

A ticket is how your sign-in service tells the gateway who is arriving. It is signed, short-lived and single-use. The gateway holds only public keys, so a stolen gateway cannot sign anyone in. Visitors arrive by opening `https://<gateway>/enter?t=<ticket>`. The gateway shows a page with a Continue button, and pressing it signs them in and sends them on, to the entry page or straight to one onion site if the ticket names one. Looking at the page does not use the ticket up, only pressing the button does, and the button works only from the gateway's own page. This stops a page elsewhere from sending a visitor's browser to a sign-in link and signing them in as someone else. Your sign-in service cannot press the button for the visitor: it should send them to the link and let them continue. An operator who must have no extra click can set `confirm_sign_in = false` under `[tickets]`, and then the link signs in at once and that protection is gone.

### Format

```
og1.<key id>.<payload>.<signature>
```

- **`og1`** is the format name and version.
- **Key id** is 1 to 32 characters from letters, digits, `-` and `_`. It names which public key checks the signature, so keys can be rotated without downtime.
- **Payload** is a JSON object in UTF-8, encoded as base64url without padding.
- **Signature** is an Ed25519 signature, encoded the same way. It covers, in order: the text `onionglass ticket v1`, a zero byte, the key id as ASCII, a zero byte, and the payload bytes exactly as they were encoded, not re-written.
- Both encoded parts must be canonical: no padding, no characters outside the base64url set, and nothing that decodes and encodes back to something different. The whole ticket is ASCII and at most 4096 characters.

### Claims

All of these are required except `onion`. Any other claim, a missing one, or a repeated name makes the ticket invalid. Text claims are printable ASCII with no spaces.

| Claim | Meaning | Rule |
|---|---|---|
| `sub` | who the visitor is, as your service knows them | text, 1 to 256 characters |
| `grp` | the group they belong to | text, 1 to 128 characters |
| `prf` | the profile they get | text, 1 to 128 characters, and the gateway must have a profile of that name or the ticket is refused |
| `jti` | a unique id for this ticket | text, 16 to 64 characters, never reused |
| `iat` | when it was issued | whole seconds since the epoch, from 0 to 4102444800, not a fraction and not true or false |
| `exp` | when it stops working | the same, later than `iat` by at most 300 seconds |
| `aud` | which gateway it is for | text, equal to the audience in that gateway's settings |
| `onion` | open this site on arrival | optional, the 56-character address without `.onion` |

The gateway accepts a ticket from 30 seconds before `iat` until 30 seconds after `exp` (not including that last moment), to allow for clocks that differ a little. It remembers each `jti` until the ticket has expired, so a second use fails. The record is kept in the gateway's memory, so with more than one gateway process behind one address a ticket could be used once on each, and the sign-in service should keep tickets as short as it can.

`sub` is what the audit log and the daily allowance use to tell visitors apart. Make it a stable, opaque id for the account, not an address or a name you would not want in a log.

### Keys

The sign-in service keeps the private key. The gateway's settings list the public keys it trusts, each with its key id. `onionglass keys generate` makes a pair, and `onionglass ticket` makes one ticket for testing a deployment. To rotate, add the new public key beside the old one, switch the service to the new private key, wait for the old tickets to expire, then remove the old public key.

## What is deliberately not in the API

- A way to run code inside the gateway.
- A way to fetch a page for a script. The gateway is for people looking at pages, not for bulk retrieval.
- Share links that give access without sign-in.
