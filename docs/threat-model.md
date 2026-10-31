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
| A visitor sends a request no page of ours would have produced, such as a post or a file, under a profile that forbids it | The profile is enforced on the request as well as on the page. Unknown profiles are refused, never replaced by the default | P7 |
| One signed-in account floods the gateway | Per-profile request limit for each session, on top of the global limits | P7 |
| Stopping or releasing a site in a hurry goes wrong, or an admin web interface becomes the way in | Operator commands on the files the gateway already watches, with no web interface at all. Files are replaced in one step, bad input is refused before anything is written, and a kill file that is wrong stops everything | P7 |
| The deployment exposes the gateway or lets it reach the internet by mistake | The bundle publishes only the proxy on the web ports, puts the gateway on a network with no route out, lets only the Tor containers out, makes every container read-only with no capabilities, and keeps secrets out of the files. Tests pin each of these. The bundle itself has not been run | P2, P5 |
| A mistake in the configuration weakens the gateway without anyone noticing: a misspelt setting ignored, a secret left readable, a missing list treated as an empty one, a zero turned into a default | The loader refuses unknown settings, keeps secrets out of the file and refuses secret files others can read, treats every list and key that cannot be read as an error at start-up, refuses zero and empty values, and will not listen beyond the machine unless told to | P7 |
| An attacker on the network forges the outside policy's "allow", replays a recorded one, or tampers with an audit event | Requests and replies are signed with Ed25519, a reply is tied to the request it answers by the signed nonce, replies must be signed by a trusted key id, the connection is HTTPS with the certificate and name checked, and any failure refuses the request with no fallback to the built-in policy | P7, P9 |
| Metrics or health data reveal what visitors opened | Every label has a small fixed set of values, nothing is labelled by address, account, session or path, operator rule names are folded into a fixed set, and the endpoint is off unless a token is set and then needs it | P8, P10 |
| A site names what it holds in its page title or headings | A name gate on the title and first headings of every page, with a held list that refuses the site for everyone until a person releases it. The word list is the operator's own | P6, P7 |
| Abuse goes unnoticed because visitors have no way to say so, or the report channel is itself abused | A report button with a fixed list of reasons and no free text, one report per visitor per site, a limit per session, reports that name the site the server says is shown, and an optional threshold that holds a site | P6 |
| An unreviewed site serves a form, a login, a file or an image to a visitor who cannot judge it | Sites not on the rated list are shown as text only, enforced on the request as well as the page | P6, P7 |
| An account uses the free tier without limit, by opening many sessions or lying about what it requests | Daily allowance per account and profile, charged by the type of reply and not by the request's own claims, kept in a journal that survives restarts. A meter that fails stops the request | P7 |
| One visitor fills the shared store, or makes the gateway slow, with endless addresses, a very large hostile post, or a crafted file-upload check | Typed addresses count against the profile's request limit and have a cap of their own per session, a full store is a polite "busy" and never an internal error, the file check reads each part once, and every limit in the settings must be above zero | P7 |
| A site is held because a page repeated what a visitor typed, or because one account asked for it | A page that only echoes the request is refused but does not hold the site, and on a team gateway a site is held only after several different accounts have met it (`hold_after`, default 2). Personal mode holds on the first hit | P6, P7 |
| The outside audit service learns more than the operator chose to record | The audit hook receives the site in the same form as the local log: `full`, `origin`, `hash` or `none`. The default is the origin without the path | P10 |
| Requests that arrive together overspend an allowance, or a link to a new site is a free open | The allowance is checked and taken in one step by the meter, and the first request to a site in a session is an open however it was reached | P7 |
| Something that gets hold of Tor's port uses it to leave through an exit | The SOCKS port is set to `OnionTrafficOnly`, checked against a real Tor, and the bundle's network has no other way out | P2, P5 |
| A visitor types a copycat of a well-known onion site, made by searching for an address with the same start | A warning page before anything is fetched, for an address that shares its first six characters with a site on the operator's list. The end of an address is a checksum and cannot be imitated, so the start is what is checked. Typed and pasted addresses only, not links inside pages | P6 |
| The list of entities a page names is used to attack the analyst's browser or to reach out to a site | Entities are limited to strings that pass their own checksum or have a fixed shape, are shown as plain text through the page's text properties and never as markup or links, are read from shown text only, and are never fetched | P2, P6 |
| A page, or a visitor's browser, makes the gateway send invented entities or page content to a case system | The send is a same-origin POST from a signed-in visitor whose profile allows it, and it carries nothing: the gateway sends only the entities it kept itself for that session's current page, never the page text or title, and writes the audit record first. The site is named in the audit's address form, and the number of sends per session is limited | P6, P9 |
| A hostile page signs a visitor in as someone else by sending their browser to a sign-in link | A Continue page that does not use the ticket up, and a confirmation that works only when it comes from the gateway's own page | P9 |
| The reader view is used to get around a rule, or lets something through that the normal view blocks | The reader view is a second, narrower rendering of the same fetched page: the same admission, audit, quota and name checks run first, the allowed tags and attributes are a strict subset of the normal list, and the setting is kept per session and changed only by a same-origin request from a signed-in visitor | P1, P6 |
| Nobody knows where to report a site, or a complaint has nowhere to go | A public abuse page, reachable without signing in, that names the operator's contact and tells people to send the address and never the material. The contact must be an email address or an https link, and the check-config command warns when it is missing | P6 |
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

- **Entering through a link.** Without the confirmation step, opening the gateway's entry address with a ticket would sign the visitor in, so a hostile page could make a visitor's browser sign in as someone else (login CSRF). The gateway now shows a Continue page first and only the gateway's own page can press it. The setting `confirm_sign_in = false` turns this off, and then the weakness is back: an attacker with an account of their own could put a visitor into that account, so the visitor's opens would count against it and be recorded under its name.
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
| P4 nothing identifying reaches the onion site | Covered for requests, for cookies kept on the server, for the multipart boundary and for the session identifier never reaching Tor, and under generated requests | `tests/test_request_fuzz.py`, `tests/test_review_fixes.py`, `tests/test_headers.py`, `tests/test_upstream.py`, `tests/test_cookies.py`, `tests/test_gateway.py` |
| P5 only valid v3 onion destinations | Covered for parsing, requests and the Tor fetcher | `tests/test_onion.py`, `tests/test_upstream.py`, `tests/test_gateway.py` |
| P6 withheld images never requested | Covered end to end, and checked by hand in a real browser | `tests/test_rewrite_html.py`, `tests/test_rewrite_css.py`, `tests/test_gateway.py` |
| P7 fail closed | Covered for rewrite and decode failures, for the policy, the audit log and the kill file (each is failed, hung and given nonsense in turn and the gateway refuses), for profiles (unknown profiles, forms, uploads and request limits are enforced per session), and for daily allowances, which are counted per account, charged by the reply and refused when the meter cannot be trusted. Evidence capture does not exist yet. The name gate, the held list and text-only display for unrated sites are covered, including a held list that cannot be read | `tests/test_admin.py`, `tests/test_deploy.py`, `tests/test_config.py`, `tests/test_hooks.py`, `tests/test_metrics.py`, `tests/test_reports.py`, `tests/test_namegate.py`, `tests/test_quota.py`, `tests/test_profiles.py`, `tests/test_policy_ops.py`, `tests/test_rewrite_review.py`, `tests/test_gateway.py` |
| P8 no bodies or passwords in logs | Covered for the audit log, which holds no bodies, headers or cookies and keeps a hostile subject on one line | `tests/test_policy_ops.py`, `tests/test_gateway.py` |
| P9 tickets cannot be forged or replayed | Covered | `tests/test_tickets.py` |
| P10 visitor addresses not logged | Covered: the gateway keeps no visitor addresses, and the audit log names the onion site only in the form the operator chose (`origin`, `full`, `hash` or `none`) | `tests/test_policy_ops.py`, `tests/test_gateway.py` |
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

Not covered by this check: the entry form's redirect to a label host could not be completed in the test browser, which aborted the redirect to a different host name (the gateway's reply was confirmed correct with curl, and opening the label address directly worked); the browser's behaviour with the viewer page and a sandboxed frame, which does not exist yet; and anything involving a real Tor connection, which is covered below. An automated browser test for the properties above is planned.

### Real Tor, real sites

On 2026-10-30 the gateway was run against the real Tor network, with Chrome, on the Tor Project's and DuckDuckGo's public onion sites, with the leak detector watching.

| Result | Tor Project, images off | Tor Project, images on | DuckDuckGo |
|---|---|---|---|
| Script elements in the page | 0 | 0 | 0 |
| Requests to anything but the gateway | 0 | 0 | 0 |
| Requests that reached the leak detector | 0 | 0 | 0 |
| Images shown | 0 of 10 withheld | 10 of 10 | none on the page |
| Looks right to a visitor | yes | yes, fully styled | blank at first, see below |

It also showed that an address with a valid key and no site behind it gives "site not found", that the redirect from DuckDuckGo's http onion to its https onion is followed through the gateway, and that the Tor Project's page arrives complete with its fonts and styles.

One real problem came out of it. DuckDuckGo's page tells a browser without scripts to go to a lighter page, and hides its own body in the same place. The gateway turned the redirect into a notice with a link, which is the intended behaviour, but the notice was inside the page that hides itself, so a visitor saw nothing. The request is now shown in the viewer's toolbar, which no page can style, with a "Follow it" button that only accepts an address on the gateway. A test builds a page that hides itself and checks it in Chrome. The opt-in tests in `tests/test_live_tor.py` repeat the real-Tor checks for anyone who has a Tor.

Sites that need scripts to show anything at all will show little or nothing, as they would in any browser with scripts off. That is the cost of never running a site's code, and the full remote session planned for milestone 5 is the answer for those.

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

The request side was then fuzzed the same way, in `tests/test_request_fuzz.py`, through the whole gateway with a fake onion site. Generated visitor requests (odd methods, paths, queries, forwarding and identity headers, every browser fetch-metadata combination, multipart bodies with many boundary styles) must never put a visitor header, the session identifier, the label or the gateway's own address in front of the onion site, and every header name the site receives must be on a short list. Generated onion replies (any status, content type, encoding, redirect target and a long list of response headers) must reach the visitor only through the gateway's own headers, with the policy always present, an allowed content type, and a redirect that points only at the gateway. Generated `Set-Cookie` lines must come back as a well-formed cookie header or not at all and never reach the visitor. This found one small flaw: the multipart boundary swap replaced every occurrence of the boundary text, which would damage a body for a very short boundary. Only the delimiter lines are swapped now.

The default run uses a few hundred generated pages. Set `ONIONGLASS_FUZZ_SCALE=10` for a long hunt. One run at eight times the default found nothing more. Still not covered: the entry form and ticket paths under generated input.

## 11. How this is kept honest

- Each property has a named test in the `tests` directory. A property without a test is a bug.
- A hostile-input corpus grows with every report.
- The rewriter is fuzzed continuously.
- An independent penetration test is required before version 1.0.
