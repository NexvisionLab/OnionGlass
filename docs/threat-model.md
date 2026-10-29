# Threat model

Status: draft for the pre-alpha. This document is the project's contract. Every property below must have an automated test before a release.

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| The visitor's browser and device | Onion pages are hostile by default and may try to run code, track, or exploit the browser. |
| The visitor's network identity | The onion site and third parties must not learn the visitor's address. |
| The operator's systems and secrets | The gateway fetches content from strangers and must not become a way into the host. |
| Evidence integrity | A capture is only useful if nobody can alter it undetected. |
| Policy integrity | Blocklists, profiles and limits must not be bypassable. |
| The operator's reputation and legal position | The gateway can be used to reach harmful content. |

## 2. Who the adversaries are

| Adversary | Capability |
|---|---|
| Malicious onion site | Serves crafted HTML, CSS, SVG, headers, redirects and files. Can be slow, huge or hostile on purpose. |
| Third-party content inside a page | Tracking pixels, remote fonts, framed pages, anything a page references. |
| Network observer near the visitor | Sees connections, DNS lookups and the TLS server name. |
| Network observer near the gateway | Sees traffic to and from Tor and hooks. |
| Malicious visitor | Tries to reach non-onion destinations, internal addresses, other visitors' sessions, or to overload the service. |
| Abusive visitor | Uses the gateway to reach illegal material. |
| Compromised gateway host | Full control of one box. |
| Malicious contributor or dependency | Ships harmful code through a pull request or a package. |

The operator of the gateway is trusted by visitors only in the sense that they chose to use it. The operator can read everything that passes through. This is stated plainly in the README and is not a vulnerability.

## 3. Trust boundaries

1. Visitor's browser to gateway, over TLS.
2. Gateway to rewriter worker, a separate process with limited resources.
3. Gateway to Tor, then Tor to the onion site. Everything from the onion site is untrusted.
4. Gateway to session store.
5. Gateway to hooks, which are optional external services.
6. Gateway to evidence sinks.
7. Gateway to the full-session browser container, when that module is used.

## 4. Security properties

These are the properties tests must prove.

| # | Property |
|---|---|
| P1 | No script executes in a rewritten page, even if the rewriter has a bug. |
| P2 | A rewritten page never causes the visitor's browser to contact any host other than the gateway. |
| P3 | Each onion has its own browser origin. One onion cannot read another's cookies, storage or pages. |
| P4 | Upstream cookies and identifying headers never reach the visitor. Cookies live on the server. |
| P5 | The gateway only connects to valid v3 onion addresses and configured hook URLs. |
| P6 | A withheld image is never requested from the onion site. |
| P7 | If a policy, audit or evidence dependency is unavailable, the gateway stops serving. |
| P8 | Page bodies, form bodies and passwords are never logged or stored, except in an explicit evidence capture. |
| P9 | Sign-in tickets cannot be forged, replayed after use, or used after expiry. |
| P10 | Visitor addresses are not written to logs unless the operator opted in, and then only in the form they chose. |
| P11 | The onion address a visitor opens does not appear in DNS lookups, TLS server names or URLs, because hostnames are opaque per-session labels. |

## 5. Threats and mitigations

| Threat | Mitigation | Properties |
|---|---|---|
| Crafted HTML that survives rewriting and runs script | Parse-based rewriting, removal of script and event attributes, sandbox policy in headers, separate origin per onion, fuzzing of the rewriter | P1, P3 |
| Mutation-based bypass of a sanitiser | The rewriter output is also covered by the sandbox policy, so a bypass still cannot execute | P1 |
| Page loads remote images, fonts or frames and reveals the visitor's address | All references are rewritten to the gateway or removed. Policy forbids any other origin | P2 |
| Redirect or link to a non-onion or internal address | Destination validation on every request and every redirect. The service unit allows only the addresses it needs | P5 |
| Malformed or lookalike onion addresses | Strict v3 parsing with checksum verification, lower-casing and trailing-dot handling | P5 |
| Resource exhaustion by a huge, slow or compressed page | Size caps, time limits, bounded decompression, limits per session and per group | P7 |
| Rewriter crash or exploit | Rewriter runs in a separate, memory-limited process. A failure ends the request | P1, P7 |
| Cross-site request forgery between onions | Separate origins, server-side cookies, no ambient cookies reach the visitor | P3, P4 |
| Session theft | Short-lived, single-use tickets, signed with rotating keys, `HttpOnly` and `Secure` session cookies | P9 |
| Network observer learns which onion is opened | Opaque host labels, Encrypted Client Hello where supported, TLS 1.3 | P11 |
| Logs reveal what visitors opened | No bodies, optional address truncation or salted hashing, retention limits | P8, P10 |
| Credentials typed into an onion login form leak | Never logged, masked in captures, warning shown on password fields, blocked in restricted profiles | P8 |
| Policy outage turns the gateway into an open proxy | Fail closed on every dependency | P7 |
| Abuse to reach illegal material | Blocklists, name checks on address and page title, text-only for unrated sites, abuse procedure, images never fetched by default | P6 |
| Tampered evidence | WARC capture, hashes, signed manifest, optional trusted timestamp, encryption at rest | none yet |
| Malicious dependency or contributor | Pinned and hashed dependencies, dependency review, signed releases, code ownership on sensitive modules, CodeQL and fuzzing | none yet |

## 6. Known limits

- **Operator visibility.** The operator, and anyone who compromises the host, sees all traffic. The mitigation is organisational, not technical. Personal mode keeps traffic on the visitor's own machine.
- **Traffic analysis.** A global observer who watches both the visitor and the gateway may correlate them. Tor does not defend against this and neither does this project.
- **Tor protocol and client bugs** are outside this project. We track the Tor package in our images.
- **The visitor's endpoint.** A compromised browser or device is out of scope.
- **Lookalike sites.** The gateway can warn about lookalike addresses but cannot tell a visitor which site is the real one.
- **Evidence timestamps** depend on an external authority the operator chooses.

## 7. Out of scope

Anonymity of the visitor against the operator, circumventing law enforcement or legal obligations, hosting onion services, and protecting content that a visitor chooses to reveal or download.

## 8. Which tests prove which property

| Property | Status | Tests |
|---|---|---|
| P5 only valid v3 onion destinations | Partly covered: address, host and URL validation | `tests/test_onion.py` |
| P9 tickets cannot be forged or replayed | Covered | `tests/test_tickets.py` |
| P11 onion address absent from host names | Covered for label generation and mapping | `tests/test_labels.py`, `tests/test_hosts.py` |
| P1 to P4, P6 to P8, P10 | Not yet implemented | none |

## 9. How this is kept honest

- Each property has a named test in the `tests` directory. A property without a test is a bug.
- A hostile-input corpus grows with every report.
- The rewriter is fuzzed continuously.
- An independent penetration test is required before version 1.0.
