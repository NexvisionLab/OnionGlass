# onionglass

A self-hostable gateway that lets you open `.onion` sites in an ordinary browser, safely, and capture what you see as evidence.

> **Status: pre-alpha.** Personal mode works: you can open onion sites in your own browser, on your own machine, through your own Tor, and it has been run against the real Tor network on public sites. A team mode, driven by one config file, adds sign-in links, profiles, allowances, an audit log, a kill file, a name gate with a held list, visitor reports, metrics and signed HTTP hooks. A deployment bundle with a Tor pool and a wildcard-certificate proxy is written but has not been run yet. Evidence capture, passkeys and client certificates, and the full remote browser are not built yet, and the project has not had an independent security test. Do not run it as a service for other people before you have read [Running it for other people](#running-it-for-other-people).

## Contents

- [What it is for](#what-it-is-for)
- [How it works](#how-it-works)
- [What it can do today](#what-it-can-do-today)
- [Requirements and dependencies](#requirements-and-dependencies)
- [Install](#install)
- [Quick start: personal mode](#quick-start-personal-mode)
- [Running it for other people](#running-it-for-other-people)
- [Configuration](#configuration)
- [Operating it](#operating-it)
- [Integrating it](#integrating-it)
- [Technical details](#technical-details)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [What the gateway does not do](#what-the-gateway-does-not-do)
- [Responsible use](#responsible-use)
- [Documentation](#documentation)

## What it is for

onionglass is built for researchers, journalists, threat-intelligence teams and security operations centres who need to look at onion sites and keep a record of what they found. It is not a tool for general anonymous browsing.

## How it works

A visitor's browser talks only to the gateway. The gateway fetches the onion page over Tor, rewrites it so every link, form and resource stays inside the gateway, removes all script, and serves the result. The browser never contacts the onion site or any third party directly.

```
Browser -> reverse proxy (TLS) -> onionglass gateway -> Tor (SOCKS) -> onion site
                                         |
                                         +-> hooks (signed HTTP) -> optional policy, audit, quota or case service
```

In personal mode there is no proxy and no TLS: the gateway listens on `127.0.0.1` and your browser talks to it directly.

1. **Parse-based rewriting.** Pages are parsed and rewritten through an allowlist of tags and attributes, not patched with regular expressions. All script is removed, and a second, independent pass checks the result.
2. **Isolation.** Each onion gets its own browser origin, a random label under the gateway's domain, so one site cannot read another's cookies or storage. Cookies stay on the server. Every visitor session uses its own Tor circuit.
3. **A second line of defence.** Every page is served with a browser sandbox policy that has no `allow-scripts`, so even a rewriting bug cannot run script.
4. **Policy built in.** Profiles, blocklists, allowlists, rate limits, allowances, kill switches. If a safety dependency is unreachable, the gateway stops serving instead of carrying on.
5. **Everything on the record.** Each request is written to the audit log before it is made, and its outcome after. If the log cannot be written, the request is refused.

## What it can do today

| Area | What works |
|---|---|
| Viewing | Onion sites in an ordinary browser, with the real address shown above the page. Images and fonts are withheld unless a profile allows them, and links to the normal internet go through a warning page. |
| Reader view | A toolbar button that shows a page as plain readable text, with no pictures, forms or styles. |
| Entity panel | Lists the wallets (Bitcoin, Ethereum, Monero), email addresses and onion addresses a page names, each checked against its own checksum. Optionally sends them on to a case system when the visitor presses a button. |
| Safety | Blocklist, allowlist, rated list (unrated sites are shown as text only), kill file, page-title name gate with a held list, look-alike warning for copycat addresses, visitor reports with a review queue. |
| Accounts | Signed one-time sign-in links (Ed25519) that name a profile, a group and a subject. Per-session profiles with request limits and daily allowances. |
| Operations | Audit log with a choice of how sites are named in it, Prometheus metrics, operator commands for stopping, holding and reading reports, a public abuse page, a config checker. |
| Integration | Signed HTTP hooks for policy, audit, quota and entity sending. See [docs/integration-api.md](docs/integration-api.md). |
| Deployment | A container bundle with a Tor pool and a proxy that gets a wildcard certificate by itself (written, not yet run). |

Not built yet: evidence capture as WARC files with a signed manifest, passkeys and client certificates, the full remote browser, Encrypted Client Hello, and running the gateway itself as an onion service.

## Requirements and dependencies

### What you need installed

| Need | Version | Why |
|---|---|---|
| Python | 3.11, 3.12 or 3.13 (all three run in continuous integration) | Runs the gateway. |
| Tor | 0.4.8 or newer | Reaches onion sites. Some onion sites need the newer version to accept your connection. The gateway talks to Tor's SOCKS port and does not start Tor itself. |
| A current browser | Chrome, Edge or Firefox | The viewer uses a host name under `localhost` for each site, and these browsers send those names to your own machine without setup. |
| Docker with the Compose plugin | Optional | Only for the container setups. |
| A domain, a wildcard certificate and a sign-in service | Only for team mode | See [Running it for other people](#running-it-for-other-people). |

It runs on Linux, macOS and Windows. Nothing in it is specific to one system.

### Python packages

`pip` installs these for you. They are all open source, and the gateway writes its own SOCKS client, so there is no Tor library to trust.

| Package | Version range | Licence | What it is used for |
|---|---|---|---|
| `starlette` | 1.10 up to 2 | BSD-3-Clause | The web application. |
| `uvicorn` | 0.54 up to 1 | BSD-3-Clause | The web server that runs it. |
| `selectolax` | 1.0.2 up to 2 | MIT | Fast HTML parser. Pages are parsed, never matched with regular expressions. |
| `nh3` | 0.3.7 up to 0.4 | MIT | The second, independent HTML allowlist pass over the rewritten page. |
| `tinycss2` | 1.5 up to 2 | BSD-3-Clause | CSS parser, so style sheets are rewritten as CSS and not as text. |
| `cryptography` | 50 up to 51 | Apache-2.0 or BSD-3-Clause | Ed25519 signatures for sign-in tickets and hook requests, and TLS for hook calls. |
| `h11` | 0.16 up to 1 | MIT | The HTTP client side of the signed hooks. |

The gateway's own code is licensed AGPL-3.0-only. The packages above are all under permissive licences that can be combined with it.

## Install

### 1. Install Tor and start it

The gateway needs a Tor SOCKS port, on 9050 by default. Tor's own packages are the best source.

| System | How |
|---|---|
| Debian, Ubuntu | Add the Tor Project's package repository (see [the Tor Project's instructions](https://support.torproject.org/apt/tor-deb-repo/)), then `sudo apt install tor`. The version in a distribution's own repository can be older than 0.4.8. Then `sudo systemctl enable --now tor`. |
| Fedora and similar | `sudo dnf install tor`, then `sudo systemctl enable --now tor`. |
| macOS | `brew install tor`, then `brew services start tor`. |
| Windows | Download the Tor Expert Bundle from [torproject.org/download/tor](https://www.torproject.org/download/tor/), unpack it, and run `tor.exe`. With no config file it opens port 9050. |
| Any, if Tor Browser is running | Tor Browser's own Tor listens on port 9150. Start the gateway with `--tor-port 9150`. Error pages are less specific, because Tor Browser does not turn on Tor's detailed failure reasons. |

Check that the port is open before going on. On Linux or macOS, `ss -ltn | grep 9050` or `lsof -i :9050`. On Windows, `netstat -ano | findstr 9050`.

### 2. Install onionglass

The package is not on PyPI yet, so install it from a clone of the repository. A virtual environment keeps it, and its dependencies, away from the rest of your Python.

On Linux or macOS:

```bash
git clone https://github.com/NexvisionLab/OnionGlass.git
cd OnionGlass
python3 -m venv .venv
. .venv/bin/activate
pip install .
```

On Windows, in PowerShell:

```powershell
git clone https://github.com/NexvisionLab/OnionGlass.git
cd OnionGlass
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

This installs the gateway and the seven packages above, and puts an `onionglass` command on your path while the environment is active. Check it:

```bash
onionglass --help
```

If `pip` stops with "No such file or directory" for a very long path on Windows, the folder you are installing from or into is nested too deeply for Windows' default path limit. Use a shorter folder such as `C:\dev`, or turn on long paths ([how](https://pip.pypa.io/warnings/enable-long-paths)).

### 3. Or use containers

```bash
docker compose up --build
```

Then open `http://localhost:8080/`. The compose file starts three containers: Tor (from the Tor Project's own package repository), the gateway on a private network with no route to the internet, and a small proxy that is the only thing published, and only on your machine's loopback address. The container files have not been run by the project's maintainers yet. Continuous integration builds both images and checks the compose file, but nobody has watched them start Tor and open a site, so read them first and treat them as a starting point.

## Quick start: personal mode

Personal mode is for one person on their own machine. The gateway listens on `127.0.0.1` only and needs no sign-in, so it refuses to listen anywhere else.

```bash
onionglass
```

Open `http://localhost:8080/` in your browser, type an onion address, and press Open. The page appears in a frame, with its real address above it and a toolbar for copying the address, reloading, switching to the reader view and reporting the site.

Every option is off unless you give it:

| Option | Meaning |
|---|---|
| `--port 9000` | Listen on another port. |
| `--tor-port 9150` | Use another Tor SOCKS port. Repeat the option to spread visitors over several Tor processes. |
| `--tor-host 127.0.0.1` | Where Tor listens. |
| `--allow-images` | Load images from onion sites. When it is off, no image is ever requested. |
| `--blocklist FILE` | Onion addresses that are never opened. One per line, `#` starts a comment. |
| `--allowlist FILE` | The only addresses that may be opened. The blocklist still wins. |
| `--rated-list FILE` | Sites on the list are served normally. Every other site is shown as text only. |
| `--kill-file FILE` | Stops serving while the file lists a scope. |
| `--name-list FILE` and `--held-file FILE` | Phrases that hold a site when they appear in a page title or heading, and where held sites are kept. |
| `--known-sites FILE` | Well-known sites. A typed address that starts like one of them gets a look-alike warning. |
| `--report-file FILE` and `--hold-after N` | Adds a report button, keeps the reports, and holds a site once N visitors have reported it. |
| `--metrics-token-file FILE` | Turns on Prometheus metrics at `/_og/metrics` for a scraper that sends the token in the file. |
| `--audit-log FILE` and `--audit-address FORM` | An audit line for every request, and how it names the site: `origin` (the default), `full`, `hash` or `none`. |

A list that cannot be read, or that has a line that is not an onion address, stops the program from starting. A typo never means "no list". The full description of each option is in [docs/running.md](docs/running.md).

## Running it for other people

Team mode serves several people from one gateway behind a proxy that ends TLS. It is for a security team or research group, and it brings duties: read [docs/operator-responsibilities.md](docs/operator-responsibilities.md) and [docs/abuse-procedure.md](docs/abuse-procedure.md) first.

What you need that the software does not give you:

- **A server you control**, hardened before anything else is installed. About 2 vCPU and 4 GB is enough to start.
- **A domain with a wildcard certificate.** Each session gets random sub-domains, so the certificate must cover `*.your-domain`. A wildcard certificate can only be proved through DNS. The bundle in `deploy/team` is built for domains whose DNS is hosted at Cloudflare.
- **A sign-in service.** It makes a short-lived, single-use ticket for each visit and signs it with a private key. The gateway holds only the public key, so a stolen gateway cannot sign anyone in. This repository gives you the key tools and a test command, not a sign-in service.
- **A contact for abuse reports**, and a decision on what you will do when one arrives.

The steps, in short. [docs/deploying.md](docs/deploying.md) has the whole job, including the server, DNS, proxy and certificate.

```bash
onionglass keys generate --id signin-2026-10 --out keys     # a signing key pair for sign-in links
onionglass check-config --config team.toml                  # read the file and say what it would do
onionglass serve --config team.toml                         # run it
onionglass ticket --key-file keys/signin-2026-10.private.pem --key-id signin-2026-10 \
    --subject alice --group team --profile standard --url https://gateway.example.org
```

The last command prints a one-time sign-in link, to test a deployment. In real use your own sign-in service makes the tickets. By default, following a link shows a Continue button first, so a hostile page cannot send a visitor's browser to a sign-in link and sign them in as someone else.

With containers, the bundle is `deploy/team`: a gateway, two Tor processes and a Caddy proxy that obtains the wildcard certificate itself. It has been checked for structure by the tests and has not been started, so bring it up on a test machine and a test domain first.

The project has had three reviews and a lot of testing. None of that replaces a test by someone outside it before you open a service to the public.

## Configuration

Team mode is described in one TOML file. [docs/examples/team.toml](docs/examples/team.toml) lists every setting with its meaning, and the tests load that file exactly as written, so it stays correct.

What the loader promises:

- **Typos fail.** A section or setting it does not know is an error.
- **No secrets in the file.** A key, salt or token is a path to a file. On systems with file modes, one that other users can read is refused.
- **Paths are relative to the config file**, not to where you start the program.
- **Problems show at start-up.** A list that cannot be read, a profile with a quota but no meter, a name list without a held list, a hook address that is not https: each stops the start with a message that names the place. A setting of zero or an empty string is an error, never a silent default.
- **It does not listen beyond this machine** unless you say `allow_non_loopback = true`, or it is in the container image. The gateway has no TLS of its own, so the proxy must be the only way in.
- **`check-config` shows what is on and what is missing**, and warns when there is no audit log, no kill file, no held list, no policy or no abuse contact. It never prints a secret.

The sections:

| Section | What it sets |
|---|---|
| `[server]` | Domain, scheme, where the proxy reaches the gateway, port. |
| `[tor]` | The Tor host and one SOCKS port for each Tor process. |
| `[tickets]` | Audience, whether a sign-in link asks for a click, and the public keys that may sign visitors in. |
| `[limits]` | Session lifetime, labels per session and per page, new sessions per minute, concurrent fetches, opens per session, reports per session, entity sends per session, request body size, hook timeout. |
| `[profile]`, `[profiles.NAME]` | What a visitor may do. A ticket names its profile, and an unknown name is refused. |
| `[policy]` | Blocklist, allowlist and rated list. |
| `[kill]`, `[held]`, `[names]`, `[known_sites]`, `[reports]` | The stop file, held sites, the name gate, the look-alike list and the report queue. |
| `[audit]`, `[quota]`, `[metrics]`, `[abuse]` | The audit log, the allowance journal, the metrics token, and the abuse contact. |
| `[hooks]` | A signed HTTP service that takes over policy, audit, quota or entity sending. |

A profile has these settings. The defaults are the cautious ones:

| Setting | Default | Meaning |
|---|---|---|
| `allow_images`, `allow_fonts` | `false`, `true` | Whether images and fonts are loaded. |
| `allow_post_forms`, `allow_password_fields`, `allow_uploads` | `true`, `true`, `false` | Forms, logins and file uploads, enforced on the request as well as on the page. |
| `max_page_bytes`, `max_asset_bytes` | 5,000,000, 10,000,000 | Size limits. |
| `rewrite_timeout` | 15 seconds | Time allowed to make one page safe. |
| `max_requests_per_minute` | none | A limit per session. Typing in an address counts. |
| `daily_quota`, `open_cost`, `page_cost` | none, 1, 0 | A daily allowance per account, counted in opens or pages or any mix. |
| `show_entities`, `send_entities` | `false`, `false` | The entity panel, and the button that sends its list to the case system. |

`preset = "restricted"` gives a ready-made text-only profile with no forms, logins, uploads, images or fonts and 60 requests a minute.

## Operating it

The things an operator does in a hurry are commands, and they work on the same files the gateway watches. There is no web admin interface on purpose: it would be one more thing to defend, on a gateway whose job is to be hard to attack. A change takes effect when the gateway next looks at the file, within a couple of seconds, with no restart.

```bash
onionglass admin --config team.toml kill status
onionglass admin --config team.toml kill on --all                  # stop everything
onionglass admin --config team.toml kill on --profile free         # stop one profile
onionglass admin --config team.toml kill on --onion ADDRESS        # stop one site
onionglass admin --config team.toml kill off                       # resume everything

onionglass admin --config team.toml held list
onionglass admin --config team.toml held add ADDRESS --reason "why"
onionglass admin --config team.toml held release ADDRESS

onionglass admin --config team.toml reports summary --at-least 3
```

The health check at `/_og/health` stays up when the gateway is stopped on purpose, so a supervisor does not restart it. Metrics are at `/_og/metrics` when a token is set. The deployment bundle's proxy answers `404` for that path from outside, so scrape the gateway from inside the same network. The metrics never name an onion address, an account or a session. The public abuse page is at `/abuse`.

## Integrating it

An integration is a separate service the gateway calls over HTTP. Outside code is never loaded into the gateway process, which keeps the licence boundary and the security boundary clear.

| Hook | What it does | If it cannot be reached |
|---|---|---|
| Ticket | Says who the visitor is and which profile applies. A signed, short-lived, single-use link. | Sign-in fails. |
| Policy | Allow, deny or restrict an onion for an account. | The request is refused. |
| Audit | Receives every audit event. | The request is refused. |
| Quota | Checks and takes allowance. | The request is refused in a profile that has an allowance. |
| Entity sink | Receives the entities on a page when a visitor presses a button. | The visitor is told it could not be sent. |

Requests carry an Ed25519 signature, a key id, a timestamp and a one-time nonce, and replies must be signed too, with the request's nonce inside the signature so a recorded "allow" cannot be played back. Everything is optional, and each hook has a built-in version, so the gateway works with no integration at all. The formats are in [docs/integration-api.md](docs/integration-api.md).

## Technical details

### Request flow

1. A visitor arrives with a signed ticket, or in personal mode with nothing. The ticket names a profile, and the gateway creates a session.
2. The gateway shows the viewer page. It frames the onion content at a host name made of an opaque, random label under the gateway's domain.
3. For each request the gateway maps the label back to the onion and checks, in this order: the kill switch, the held list, the policy, the allowance. Then it writes the audit record. Then it takes the allowance in one atomic step. Any of these failing refuses the request.
4. It builds a clean request from scratch, copying nothing from the visitor's own headers, and sends it through Tor. The session is the SOCKS credential, so each session has its own circuit.
5. The reply is decoded, size-limited and rewritten. The gateway adds its own headers. Nothing from the onion site's own headers reaches the visitor except the media type.
6. The outcome is recorded. If that fails, the reply is dropped, cookies included.

### Safety properties

The properties, the threats against them and the tests that prove each one are listed in [docs/threat-model.md](docs/threat-model.md). In short:

- No script ever runs, because it is removed and because the sandbox policy forbids it.
- The visitor's browser makes no request to any address outside the gateway. Every URL a page can load is rewritten or dropped.
- Nothing identifying the visitor reaches an onion site. The Referer is only sent for a page on the same site, and the user agent is a fixed recent Tor Browser string.
- Cookies live on the server, one jar for each session and site. The onion address never appears in DNS or in the TLS server name.
- The Tor SOCKS port is set to `OnionTrafficOnly`, so anything that gets hold of it cannot use it to leave through an exit relay.
- Every limit is checked to be above zero, so a typo cannot switch a protection off.
- A page the gateway cannot make safe is refused, never passed on in part.

### Modules

| Module | Job |
|---|---|
| `gateway` | The web application: routing, admission order, the viewer, sessions. |
| `rewrite/html`, `rewrite/css`, `rewrite/urls` | The parse-based rewriter for pages, style sheets and URLs. |
| `upstream`, `socks` | Fetching over Tor, with a SOCKS client written for this project. |
| `headers`, `cookies`, `decode` | Headers in both directions, the server-side cookie jar, safe decoding of replies. |
| `labels`, `hosts`, `mapper`, `onion` | Per-session host labels, host names, URL placeholders, onion address checks. |
| `policy`, `killswitch`, `held`, `namegate`, `lookalike` | Allow and deny decisions, the stop file, held sites, the page-title gate, copycat detection. |
| `quota`, `audit`, `reports`, `metrics` | Allowances, the audit log, visitor reports, Prometheus metrics. |
| `tickets`, `hooks` | Sign-in tickets and key rings, the signed HTTP hooks. |
| `entities` | Wallet, email and onion address extraction with checksums, and the entity batch. |
| `settings`, `config`, `cli`, `teamcli`, `admin` | Profiles and settings, the config loader, the commands. |
| `pages`, `store`, `files` | The gateway's own pages, the session store, safe file appends. |

The code is about 9,000 lines of typed Python, and the tests are more than 1,500.

## Development

```bash
git clone https://github.com/NexvisionLab/OnionGlass.git
cd OnionGlass
python3 -m venv .venv
. .venv/bin/activate              # on Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

The `dev` extra adds the linter and formatter (`ruff`), the type checker (`mypy`, strict), `pytest` with `hypothesis` for generated hostile input, `playwright` for tests in a real browser, and `pip-audit`. The browser tests use an installed Chrome or Edge, or Playwright's own Chromium (`playwright install chromium`), and are skipped when none can start.

```bash
ruff check .
ruff format --check .
mypy
pytest
```

The full suite takes about five minutes. Tests against the real Tor network use only the Tor Project's and DuckDuckGo's public onion sites, and are skipped unless you name a Tor you have started:

```bash
ONIONGLASS_TEST_TOR=127.0.0.1:9050 pytest tests/test_live_tor.py
```

Everything above also runs in continuous integration on Python 3.11, 3.12 and 3.13, with secret scanning, CodeQL and a dependency review. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request: it lists the rules that are not negotiable, such as never putting illegal material or a real deployment's secrets in the repository.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| "Tor is not available" | Tor is not running, or the port is wrong. Check `--tor-port`. |
| "Site not found" | The onion site is offline or the address is wrong. |
| "Could not reach the site" | The site is busy. Try again in a minute. |
| "The page could not be shown safely" | The page was too large or complex to make safe. |
| Nothing opens after pressing Open | Your browser may not resolve `*.localhost`. Try Chrome, Edge or Firefox. |
| `pip install` fails on Windows with a very long path | The folder is nested too deeply. Install from a shorter path, or turn on Windows long paths. |
| `onionglass` is not found after installing | The virtual environment is not active. Activate it again, or run `python -m onionglass`. |
| The gateway refuses to start with a message naming a file or a setting | By design. A list or setting it cannot read or understand stops the start. Fix what the message names. |

## What the gateway does not do

- **It does not make the person using it anonymous.** The onion site and third parties never see the visitor's IP address. The person running the gateway always does, and so does the visitor's own network. If you need anonymity, use Tor Browser.
- It is not a way to browse the normal internet, and it does not cache or mirror onion content.
- It does not make dangerous content safe to look at. Images are withheld by default and never fetched unless revealed, but the operator remains responsible for what the gateway is used to view.

## Responsible use

Onion sites can host illegal and harmful material. The project includes blocklist support, a name gate, a report button and an abuse procedure, and the repository will never contain illicit content. If you operate an instance, read [docs/operator-responsibilities.md](docs/operator-responsibilities.md) first.

## Documentation

- [Running onionglass](docs/running.md): every option, profile, allowance and operator command.
- [Deploying for other people](docs/deploying.md): the step-by-step for the server bundle.
- [Threat model](docs/threat-model.md): what is protected, who the adversaries are, and which test proves which property.
- [Architecture](docs/architecture.md)
- [Integration API](docs/integration-api.md): the signed hooks and the ticket format.
- [Operator responsibilities](docs/operator-responsibilities.md)
- [Abuse procedure](docs/abuse-procedure.md)

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

GNU Affero General Public License version 3. See [LICENSE](LICENSE). If you run a modified version as a network service, you must offer its source code to the people using it.

onionglass is an independent project. It is not affiliated with or endorsed by the Tor Project.
