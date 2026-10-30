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

- **Entering through a link.** Opening the gateway's entry address with a ticket signs the visitor in, so a hostile page could make a visitor's browser sign in as someone else (login CSRF). The ticket is single-use and the attacker would need one of their own, which gives them nothing beyond the ability to put a visitor in their own session. A confirmation step is planned.
- **Replay protection is per process.** Ticket replay (P9) is tracked in the gateway's own memory. Running several gateway processes behind one address needs a shared store before the property holds across them.
- **Viewer record.** The viewer page remembers the current address, frame and title for each session so it can show them. That record is per session and is deleted with it, but it exists.
- **One Tor circuit group per session.** All onions a visitor opens in one session share an isolation key, derived from the session so the identifier itself never reaches Tor. Two onions the same visitor opens can therefore be linked by an operator of both. Per-onion isolation is planned.
- **Same-site is read from the browser's own headers.** Cookie `SameSite` rules depend on `Sec-Fetch-Site`. A browser that sends no such header is treated as cross-origin, so cookies are withheld rather than leaked, which can break login on very old browsers.

## 7. Out of scope

Anonymity of the visitor against the operator, circumventing law enforcement or legal obligations, hosting onion services, and protecting content that a visitor chooses to reveal or download.

## 8. Which tests prove which property

| Property | Status | Tests |
|---|---|---|
| P1 no script executes | Covered end to end, and checked by hand in a real browser (section 9) | `tests/test_rewrite_html.py`, `tests/test_rewrite_css.py`, `tests/test_rewrite_review.py`, `tests/test_grammar_fuzz.py`, `tests/test_browser_fuzz.py`, `tests/test_headers.py`, `tests/test_gateway.py` |
| P2 no third-party contact | Covered end to end, and checked by hand in a real browser. Verification of finished CSS is separate from the rewriter | `tests/test_rewrite_urls.py`, `tests/test_rewrite_html.py`, `tests/test_rewrite_css.py`, `tests/test_rewrite_review.py`, `tests/test_gateway.py` |
| P3 one onion cannot read another's data | Covered for cookies (including `SameSite` and the `Origin` a cross-origin post carries), labels and sessions. Browser origin separation is by design and not yet tested in a browser | `tests/test_cookies.py`, `tests/test_gateway.py`, `tests/test_labels.py` |
| P4 nothing identifying reaches the onion site | Covered for requests, for cookies kept on the server, for the multipart boundary and for the session identifier never reaching Tor | `tests/test_review_fixes.py`, `tests/test_headers.py`, `tests/test_upstream.py`, `tests/test_cookies.py`, `tests/test_gateway.py` |
| P5 only valid v3 onion destinations | Covered for parsing, requests and the Tor fetcher | `tests/test_onion.py`, `tests/test_upstream.py`, `tests/test_gateway.py` |
| P6 withheld images never requested | Covered end to end, and checked by hand in a real browser | `tests/test_rewrite_html.py`, `tests/test_rewrite_css.py`, `tests/test_gateway.py` |
| P7 fail closed | Partly: rewrite and decode failures refuse. Policy and audit dependencies do not exist yet | `tests/test_rewrite_review.py`, `tests/test_gateway.py` |
| P8 no bodies or passwords in logs | Partly: nothing identifying is logged on failures. Audit logging does not exist yet | `tests/test_gateway.py` |
| P9 tickets cannot be forged or replayed | Covered | `tests/test_tickets.py` |
| P10 visitor addresses not logged | Partly: the gateway logs no addresses and access logging is off in personal mode | `tests/test_gateway.py` |
| P11 onion address absent from host names | Covered for label generation and mapping, and checked in a real browser | `tests/test_labels.py`, `tests/test_hosts.py`, `tests/test_gateway.py` |

## 9. Checked by hand in a real browser

On 2026-10-30 the gateway was run in personal mode against a fake onion site serving a deliberately hostile page, with a second local web server acting as a leak detector. Chrome opened the page. The page tried inline script, an `onload` and an `onerror` handler, a script that requests an outside address, remote and relative images, `srcset` and `picture`, an `image-set()` in a style attribute and in stylesheets (including through a variable), `@import`, a linked stylesheet, `url()` in many properties, a hostile `base`, a meta refresh, frames, objects, video and audio, an SVG with `onload`, table backgrounds, a form posting to the outside, and a `javascript:` link.

| Result | Images off | Images on |
|---|---|---|
| Script, `onload`, `onerror` ran | No | No |
| Script elements, image, frame, object elements present | None | Only the images the gateway allowed |
| Requests made by the page | One, its own stylesheet | Its own stylesheet and two of its own images, all on the gateway |
| Requests that reached the leak detector | None | None |
| Own stylesheet and inline colour applied | Yes | Yes |

This found one real bug that the automated tests had missed: with a `no-referrer` policy Chrome sends `Origin: null` on a same-origin form post, and the gateway wrongly refused it. It is fixed and has a regression test.

Not covered by this check: the entry form's redirect to a label host could not be completed in the test browser, which aborted the redirect to a different host name (the gateway's reply was confirmed correct with curl, and opening the label address directly worked); the browser's behaviour with the viewer page and a sandboxed frame, which does not exist yet; and anything involving a real Tor connection. An automated browser test for the properties above is planned.

## 10. Independent reviews

Two reviews were run by reviewers who had not seen the code being written, each told to attack it.

The first found that an unquoted `url()` inside `image-set()` survived the stylesheet rewrite (a real break of P2 and P6), that malformed IPv6 references and charset names raised the wrong exceptions, and that very large pages parsed in quadratic time. All were fixed, an independent verification pass over finished CSS was added, and each has a test in `tests/test_rewrite_review.py`.

The second review looked at the gateway around the rewriter. It found, and the fixes are in with tests in `tests/test_review_fixes.py`:

- Cookies were sent to an onion whatever page asked. `SameSite` is now applied from the browser's request headers.
- A cross-origin form post carried the target's own `Origin`. It now carries `null`, and label pages send a referrer only to their own origin.
- The session identifier was used as the Tor isolation key. A key derived with a secret is used instead.
- A visitor could exhaust the label allowance, the store, the number of new sessions or the number of concurrent fetches. Each now has a limit and a clear refusal.
- A site could send endless interim replies, a body with a 204 or 304, or a second `Host` header. These are now refused or ignored.
- A multipart body gave the site a boundary that identifies the visitor's browser. It is rewritten to a fresh one.

Each fix was checked by undoing it and confirming a test fails. The remaining items are the limits listed in section 6.

The two attack classes the reviews had not covered were then tested directly, in `tests/test_grammar_fuzz.py` and `tests/test_browser_fuzz.py`:

- **Character sets.** Multi-byte sets where a lead byte can swallow the next quote, bracket or backslash were tried in every set Python knows, declared in the header and in the page. The rewriter decodes the page itself and sends UTF-8, so what a browser would make of the original bytes does not matter, and no page got through. Pages cannot choose a codec that is not a browser text encoding, such as UTF-7.
- **Generated pages.** Pages and stylesheets built from a grammar of tags, attributes, addresses, style rules and known mutation-XSS shapes must be refused or come out clean under two other parsers. The same pages were then opened in Chrome with the Content-Security-Policy removed, so that only the rewriter stood in the way. Nothing ran and nothing reached the leak detector. With the stylesheet checks switched off the same test fails, which shows it can see a leak.

This found one real flaw. A stylesheet with an unterminated string or address was passed on with the broken token left in, so the closing brackets the rewriter added could end up inside the string. No address leaked, but browsers recover from such input in ways that differ from one parser to the next. Any declaration containing a tokenizer error is now dropped, and finished CSS must tokenise without errors.

The default run uses a few hundred generated pages. Set `ONIONGLASS_FUZZ_SCALE=10` for a long hunt. One run at eight times the default found nothing more. Still not covered: fuzzing of the form-handling and cookie paths, and any real Tor connection.

## 11. How this is kept honest

- Each property has a named test in the `tests` directory. A property without a test is a bug.
- A hostile-input corpus grows with every report.
- The rewriter is fuzzed continuously.
- An independent penetration test is required before version 1.0.
