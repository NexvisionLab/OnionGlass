# Architecture

Status: draft. Components marked "planned" do not exist yet.

```
Browser -> reverse proxy (TLS) -> Gateway -> Tor pool -> onion site
                                     |  \-> rewriter worker (separate process)
                                     |  \-> evidence module (WARC)
                                     \-> hooks (HTTP) -> optional integration service
```

## Components

| Component | Role | Notes |
|---|---|---|
| Reverse proxy | Terminates TLS, forwards to the gateway | Needs a wildcard certificate in team and public modes. Not needed in personal mode. |
| Gateway | Accepts requests, checks sign-in and policy, fetches over Tor, builds the response | Python, asynchronous, stateless apart from the session store. |
| Session store | Sessions, cookie jars, rate limits | In memory for one node, Redis-compatible for several. |
| Tor pool | One or more Tor processes | Tor 0.4.8 or newer with proof-of-work support. Per-visitor stream isolation through SOCKS credentials. |
| Rewriter worker | Parses and rewrites HTML and CSS | Separate process, limited memory and processor time, restricted system calls. Planned. |
| Evidence module | Writes WARC files, manifests, timestamps | Pluggable sink: local folder, S3-compatible store, or webhook. Planned. |
| Admin | Kill switches, blocklists, review queue, audit view, usage | Planned. |
| Full-session module | Remote browser streamed as pixels | Separate container image, off by default. Planned. |
| Browser extension | Adds "open in onionglass" to onion links | Planned. |

## Request flow

1. A visitor signs in or arrives with a signed ticket. The ticket names a profile.
2. The gateway verifies the ticket, creates a session, and shows the viewer page.
3. The viewer frames the onion content at a hostname made of an opaque per-session label under the gateway's domain.
4. For each request the gateway maps the label back to the onion, checks policy and limits, builds a clean upstream request, and sends it through Tor with the session as the SOCKS credential.
5. The response goes through the rewriter worker. The gateway adds its own headers and returns it.
6. Every request is recorded in the audit log, without bodies.

## Hostnames

Each session gets random labels, one per onion it opens, under the gateway's domain. The browser treats each label as a separate origin. The onion address never appears in DNS, in the TLS server name or in the URL. In personal mode the labels live under `localhost`, which browsers resolve to the local machine without any DNS setup.

## Profiles

A profile is a named set of capabilities in a configuration file. Examples: `restricted`, `standard`, `analyst`. Capabilities include which onions may open, whether images may be revealed, whether forms may post, whether uploads and downloads are allowed, whether evidence capture and full sessions are allowed, rate limits and quota cost. The sign-in ticket selects the profile.

## Hooks

Optional HTTP services the gateway calls for policy, intel, evidence, quota and events. See [integration-api.md](integration-api.md). Every hook has a built-in default so the gateway works alone. Hooks are separate programs that talk to the gateway over a documented protocol. The gateway never loads outside code into its own process.

## Network rules for a deployment

The gateway should be able to reach only Tor, its session store, and the hook URLs it is configured for. Enforce that with the host firewall or the service unit, not only in code.
