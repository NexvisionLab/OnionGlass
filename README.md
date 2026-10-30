# onionglass

A self-hostable gateway that lets you open `.onion` sites in an ordinary browser, safely, and capture what you see as evidence.

> **Status: pre-alpha.** Personal mode works: you can open onion sites in your own browser, on your own machine, through your own Tor. Blocklists and allowlists, a kill file, an audit log and per-session profiles with request limits and daily allowances, a page-title name gate with a held list, text-only display of unrated sites, a report button with a review queue, and Prometheus metrics work. Evidence capture, the admin interface, team and public modes, and the full remote browser are not built yet, and it has not had an independent security test. Do not run it as a service for other people. See [Running onionglass](docs/running.md).

## What it is for

onionglass is built for researchers, journalists, threat-intelligence teams and security operations centres who need to look at onion sites and keep a record of what they found. It is not a tool for general anonymous browsing.

## How it will work

A visitor's browser talks only to the gateway. The gateway fetches the onion page over Tor, rewrites it so every link, form and resource stays inside the gateway, removes all script, and serves the result. The browser never contacts the onion site or any third party directly.

Planned design goals:

1. **Parse-based rewriting.** Pages are parsed and rewritten, not patched with regular expressions. All script is removed.
2. **Isolation.** Each onion gets its own browser origin. Cookies stay on the server. Each visitor session gets its own Tor circuit.
3. **A second line of defence.** A browser sandbox policy means that even a rewriting bug cannot run script.
4. **Policy built in.** Profiles, blocklists, rate limits, kill switches. If a safety dependency is unreachable, the gateway stops serving.
5. **Evidence built in.** Captures are stored as WARC files with a signed manifest and an optional trusted timestamp.
6. **Optional full session.** A remote browser for sites that need JavaScript, streamed to the visitor as pixels only.

## Ways to run it

| Mode | For | Notes |
|---|---|---|
| Personal | One person on their own machine | One command, no domain or certificate needed. Bound to the local machine. |
| Team | A security team or research group | Behind a domain with a wildcard certificate, accounts and shared audit log. |
| Public | An operator serving many people | Off by default. Needs an explicit acknowledgement and brings legal duties. |

## What the gateway does not do

- **It does not make the person using it anonymous.** The onion site and third parties never see the visitor's IP address. The person running the gateway always does, and so does the visitor's own network. If you need anonymity, use Tor Browser.
- It is not a way to browse the normal internet, and it does not cache or mirror onion content.
- It does not make dangerous content safe to look at. Images are withheld by default and never fetched unless revealed, but the operator remains responsible for what the gateway is used to view.

## Responsible use

Onion sites can host illegal and harmful material. The project includes blocklist support and an abuse procedure, and the repository will never contain illicit content. If you operate an instance, read [docs/operator-responsibilities.md](docs/operator-responsibilities.md) first.

## Documentation

- [Running onionglass](docs/running.md)
- [Threat model](docs/threat-model.md)
- [Architecture](docs/architecture.md)
- [Integration API](docs/integration-api.md)
- [Operator responsibilities](docs/operator-responsibilities.md)
- [Abuse procedure](docs/abuse-procedure.md)

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

GNU Affero General Public License version 3. See [LICENSE](LICENSE). If you run a modified version as a network service, you must offer its source code to the people using it.

onionglass is an independent project. It is not affiliated with or endorsed by the Tor Project.
