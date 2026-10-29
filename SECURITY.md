# Security policy

onionglass sits between people and untrusted content, so security reports are taken seriously.

## Reporting a vulnerability

Please report privately. Do not open a public issue.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Include what you found, how to reproduce it, and what you think the impact is.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | Within 7 days |
| First assessment | Within 14 days |
| Fix or mitigation plan for confirmed issues | Within 30 days |
| Public disclosure | After a fix is released, or after 90 days, whichever is first, unless we agree otherwise |

We will credit you in the advisory unless you ask us not to.

## What counts as a vulnerability

Anything that breaks one of the security properties in the [threat model](docs/threat-model.md). The most serious are:

- script executing in a rewritten page
- a rewritten page making the visitor's browser contact any host other than the gateway
- one onion reading another onion's cookies or data
- the gateway reaching a destination that is not an onion address or a configured hook
- upstream cookies or headers reaching the visitor
- a withheld image being requested from the onion site
- the gateway continuing to serve when a policy, audit or evidence dependency is down
- page or POST bodies, or passwords, written to logs
- forged or replayed sign-in tickets
- weaknesses in evidence capture, hashing, signing or timestamping

## Out of scope

- Attacks on the Tor network itself. Report those to the Tor Project.
- A malicious operator of the gateway. The operator can see everything that passes through it. This is documented, not a vulnerability.
- Compromise of the visitor's own device.
- Findings that need physical access to the server.
- Reports from automated scanners with no demonstrated impact.

## Supported versions

The project is pre-alpha. Only the latest commit on `main` is supported until a first release.

## Please do not

- Test against a gateway you do not own or have permission to test.
- Access, store or share illegal content while testing. If you find a way to reach such content through the gateway, report the method, not the content.
