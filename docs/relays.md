# Entry relays: many addresses in front of one hidden gateway

Status: pre-alpha. The whole path, a visitor, the relay and the real gateway behind a real web server, is tested on one machine over a plain connection. The encrypted hop and the fingerprint check are tested against a small stand-in for the gateway, and the relay's own start-up was tried by hand and under test with its web server replaced. It has not been run on a real relay host, behind a real firewall or against a real censor. The proxy, firewall and service snippets on this page have not been tried either, and each says so where it appears.

This page is for someone who runs a gateway for people in a country that blocks it. Read [censorship.md](censorship.md) first, because it says what a gateway cannot do whatever you add to it.

## What a relay is for

A censor can block a gateway in two ways. It can block the **domain**, by poisoning the name lookup or reading the server name in the connection. Or it can block the **address**, the one server address the domain points to. [Changing domains](censorship.md#fast-change-of-domains) answers the first. A relay answers the second.

```
visitor  --HTTPS to your domain-->  relay  --signed, encrypted, pinned-->  gateway  -->  Tor
                                    (many, cheap, replaceable)           (one, kept out of sight)
```

The domain points at relays. Only the relays know where the gateway is. The gateway answers only requests that a relay has signed, and shows every other visitor the plain cover page. When a relay's address is blocked, you take it out of DNS, cut off its key and destroy the host. The gateway, its sessions and its users are not touched, because the relay keeps nothing.

## Read this before you build it

- **A relay reads every page.** It ends the visitor's TLS, and the pages are plain HTTPS inside, so it sees every address a visitor opens, every page, every form and every sign-in link. That is why relays must be servers that **you** run, on hosts you control and would trust with the gateway itself. Never ask volunteers to run them. Tor's Snowflake and WebTunnel can use volunteers because what passes through is encrypted from end to end. A gateway cannot do that without running script in the visitor's browser, and it runs none.
- **A stolen relay is a serious loss.** Someone who gets into a relay host can read what passes through it, take sign-in links and session cookies, and change the pages a visitor sees, including their security headers. Treat a relay host like the gateway host. What a stolen relay does not give away is below.
- **Relays can still be blocked.** A relay's address can be found and blocked like any other. What changes is the cost of recovery: you replace one cheap host, and the gateway, its sessions and its users are not touched. Relays make blocking slower and cheaper to survive. They do not prevent it.
- **It does not stop the domain being blocked.** Many relays hide behind one domain. If the censor blocks the domain, every relay is blocked with it. Use [one domain for each group](censorship.md#one-domain-for-each-group-of-users) as well.
- **It does not make anyone anonymous.** You and your relay hosts can still see what visitors do.
- **The gateway never learns a visitor's address.** The relay sends on a short list of ordinary browser headers and nothing that names the visitor, and it writes no log of requests. That protects visitors. It also means the gateway's records show the relay and not the person, so a visitor who must be found can only be found through the relay host's own network records, if you keep them.
- **The relay is not a hardened edge server.** It limits slow bodies, slow readers and the total time of a request, and how many it will serve. Its web server has no limit on how long a visitor may take to send a request head. For a relay on a public address, put a proxy in front that has one, or a firewall that limits connections.
- **More servers is more to look after.** Each relay needs a host, an address, a certificate and a key, and watching.
- **A relay knows where the gateway is.** Anyone who controls one can find it. Keep the gateway's address out of public view, and treat a relay's file as a secret.

## How a request travels

1. A visitor's browser asks for your domain, or a name under it. DNS answers with the address of a relay.
2. The relay ends TLS with the certificate for your domain. If the name is not one of the relay's own domains, it answers as a missing page and goes no further. A request it cannot forward as asked, such as a malformed address or a body over its limit, gets the same missing page, so that one probe cannot tell a relay from the gateway behind it.
3. The relay signs the request with its own key. The signature covers the method, the host, the path and query, the time and a number used once. It leaves out the visitor's address and everything about the visitor's connection, and it sends on only a short list of ordinary browser headers, such as `Cookie`, `User-Agent`, `Referer`, `Origin` and `Sec-Fetch-*`.
4. The relay sends it to the gateway over TLS. It checks the gateway's certificate against a fingerprint it was given, and sends nothing if it does not match.
5. The gateway checks the signature. If it is good, it serves the request as it would any other. If it is missing, wrong, old or used already, the gateway treats the visit as a stranger's: the cover page at `/`, a missing page everywhere else, and no sign-in.
6. The relay passes the answer back a piece at a time. If the answer cannot be finished, the relay drops the visitor's connection and does not end the answer as if it were whole.

The signature is Ed25519. Each relay has its own key and the gateway holds only the public keys, so a gateway that is broken into gives away no way to speak as a relay. The one exception is a key that was made on the gateway's own machine and left there, which step 2 tells you to delete.

## Setting it up

### 1. On the gateway server: a way in for relays only

The gateway speaks plain HTTP on a private address. A relay must reach it over an encrypted connection from outside, so put a TLS endpoint in front of it, on its own port, and let only your relays' addresses reach that port.

Make a certificate for the purpose. It is checked by fingerprint, so it does not need to come from a certificate authority:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj "/CN=gateway-origin" -keyout origin.key -out origin.crt
openssl x509 -in origin.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
```

The second command prints the fingerprint as 64 lower-case hexadecimal digits. That is the `pin_sha256` the relays need. It was checked against the value the relay computes.

**Renewing the certificate without a gap.** A relay accepts the gateway if its certificate matches any one of the fingerprints it was given. Make the new certificate first and put both fingerprints in every relay's file, as a list, then restart the relays. Then switch the gateway to the new certificate. Take the old fingerprint out when you next touch the relays. Changing the certificate first stops every relay at once.

A proxy block for the gateway's own proxy, not tried here:

```
https://:8443 {
    tls /etc/caddy/origin.crt /etc/caddy/origin.key
    header -Server
    reverse_proxy gateway:8080 {
        header_up -X-Forwarded-For
        header_up -X-Forwarded-Host
        header_up -X-Forwarded-Proto
        header_up -X-Real-IP
    }
}
```

The proxy must pass the request's address on exactly as it received it, because the signature covers it. It must not rewrite the path or the query. A proxy that does will fail every request that it changes, and the visitor will see the cover page. `onionglass relay check` only tries one address, so it would not show this.

Publish port 8443 on the gateway server and allow it only from the relays' addresses, for example `ufw allow from 203.0.113.10 to any port 8443 proto tcp` for each. The firewall is the first wall and the signature is the second. Either one alone would be too little.

If the gateway has [several entry domains](running.md#entry-domains), each one is its own gateway on its own port (`onionglass domains list` shows them). Give each its own TLS port. A relay has one gateway address, so a relay for a domain points at that domain's port, and a relay for two of your domains needs a file for each. The relay keys are shared by all of them.

### 2. Add a relay

```
onionglass relays add --config team.toml --name r1 --out relay-r1 \
  --origin-url https://203.0.113.5:8443 --pin-sha256 <the fingerprint>
```

Use the gateway server's own address and the fingerprint from step 1. The command:

- makes a key pair for the relay and keeps the private key in `relay-r1/relay-r1.key`, readable only by you;
- writes the public key to `keys/relay-r1.public.pem` and lists it in `team.toml` under `[relays]`;
- writes `relay-r1/relay-r1.toml`, the file the relay starts from, also readable only by you, because it holds the gateway's address.

It never overwrites a file. It checks that the gateway's file still works with the new relay, and leaves it as it was if anything fails. It keeps the file's own line endings and every comment in it. It refuses a config that writes its relay keys as an inline list, because it edits lines, and says so. Without `--origin-url` and `--pin-sha256` it writes the file with those two lines marked `EDIT`, and the relay will not start until you fill them in. A value with a quote, a space or a line break in it is refused. For a gateway with several domains, name the domain the relay serves with `--domain`.

**Once the key is on the relay host, delete the copy on the gateway server.** The key was made there, and whoever holds a copy can speak to the gateway as that relay.

At first `[relays]` has `require = false`. The gateway then knows its relays but still answers anyone who reaches it directly. That lets you build and test the relays before anything is cut off.

### 3. Restart the gateway

It reads its keys when it starts, so it does not know the new relay until it is restarted. A restart also ends the sessions it holds, so choose the time. A key id used twice in the file is refused at start.

### 4. On the relay host

Install onionglass on a new server, and harden it as you would the gateway server. Copy `relay-r1.toml` and `relay-r1.key` to it. Then:

```
onionglass relay run --config relay-r1.toml --check-config
onionglass relay check --config relay-r1.toml
```

The first says what the relay would do. The second asks the gateway whether it knows this relay, and says what the answer means:

- `ok` means the gateway knows the key and the relay can reach it.
- A reply that says the gateway answered as it does to a stranger means it does not know this relay. Check the key id, that the gateway was restarted after the key was added, and that this machine's clock is right, to within `max_skew_seconds` of the gateway's.
- A reply that says the relay could not reach the gateway means a firewall, a wrong address, or a certificate that is not the one pinned.

The check asks a question that only the operator's own command can ask. A visitor who requests the same address through the relay gets the missing page, because the relay passes on no header a visitor made up.

Then give the relay a certificate for your domain. There are two ways.

**The relay ends TLS itself.** Obtain one certificate for the domain and `*.domain` on a machine that is not a relay, and copy the certificate and its key to each relay. Let's Encrypt limits how many certificates it will issue for the same names, so one certificate shared by every relay is easier than one for each. In the relay file:

```
[relay]
domains = ["gateway.example.org"]
listen = "0.0.0.0"
port = 443
tls_cert_file = "tls/fullchain.pem"
tls_key_file = "tls/privkey.pem"
```

You must renew the certificate and copy it again before it runs out. The relay reads it when it starts.

**A proxy on the same machine ends TLS,** with `listen = "127.0.0.1"` and `trust_forwarded = true`, which is what the generated file has. The relay then takes the visitor's address for its limits from the proxy, only when the proxy is on this machine, and uses it for nothing else. The proxy has three jobs, and none of this has been tried here:

- It must write the visitor's address in `X-Forwarded-For`. Without it every visitor looks like the proxy, and all of them share one allowance of `max_per_client`.
- It must keep no access log. Caddy writes none unless asked. nginx writes one by default, and needs `access_log off`. A log there would undo the relay's own promise to write none.
- It should set a time limit for a visitor to send a request head, which the relay's own server does not have.

Run it as a service. A unit file, not tried here:

```
[Unit]
Description=onionglass entry relay
After=network-online.target

[Service]
User=onionglass
ExecStart=/opt/onionglass/.venv/bin/onionglass relay run --config /etc/onionglass/relay.toml
Restart=always
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 5. Point the domain at the relays

Give the domain and `*.domain` an address record for each relay. Visitors will be sent to one of them. When a relay's address is blocked, remove its records. A short lifetime on the records makes that quicker.

Check from outside with `onionglass domains check --domain gateway.example.org`, and from a trusted machine in the country for the real answer. How the domain and the links to it are handed out matters as much as where it points. See [distribution.md](distribution.md).

### 6. Require relays

When every visitor comes through a relay, and the gateway's own address has been taken out of DNS, set `require = true` under `[relays]` and restart the gateway. After that, anyone who reaches the gateway directly sees only the cover page, with two exceptions that the machine itself needs: the health check, when it comes from the gateway's own machine and not through a relay, and a metrics scrape that carries the token. This needs [cover mode](running.md#cover-mode) to be on, and the gateway will not start otherwise.

The cover page is the same for every method and every kind of address a stranger can send, including ones a web framework would normally answer for itself.

Before you require relays, make sure a relay works: `onionglass relay check` must say `ok`. A gateway that requires relays and has none that work serves nobody.

### 7. Replace a relay that is blocked

1. Remove the blocked relay's address from DNS.
2. `onionglass relays revoke --config team.toml --name r1`, then restart the gateway. From then on its key is worth nothing.
3. Stop the relay and destroy the host, so that no copy of its key is left.
4. Add a new relay with a new name, as in steps 2 to 5.

`revoke` removes every entry with that name, and checks that the gateway's file still works without it before it writes. It does not delete the relay's public key file, and says where it is. Revoking the last relay while relays are required is refused, because the gateway would not start. Add another first. If it is the last relay and they are not required, the whole `[relays]` section goes, relay mode is off, and anything else in that section, such as `max_skew_seconds`, goes with it.

## The settings

In the gateway's `team.toml`:

| Setting | What it does |
|---|---|
| `[relays].require` | `true` serves only requests a relay signed. Default `false`. Needs cover mode. |
| `[relays].max_skew_seconds` | How far a relay's clock may differ from the gateway's, in either direction. 5 to 600, default 60. A signature is good for one request within that time. |
| `[[relays.keys]]` `id`, `public_key_file` | One entry for each relay. The id is the relay's name, and two entries may not share one. |

In a relay's own file, as in [`docs/examples/relay.toml`](examples/relay.toml):

| Setting | What it does |
|---|---|
| `[relay].domains` | The entry domains this relay serves, and the names under them. Anything else is a missing page. |
| `[relay].listen`, `port` | Where it listens. Default `127.0.0.1` and 8081. |
| `[relay].tls_cert_file`, `tls_key_file` | Let the relay end TLS itself. Both or neither. A relay that listens on a public address must have them. |
| `[relay].trust_forwarded` | Take the visitor's address for the limits from a proxy on this machine. Default `false`. |
| `[origin].url` | The gateway's address, `https://host:port`, with no path. The host must be a name or an address. |
| `[origin].pin_sha256` | The gateway certificate's SHA-256 fingerprint, 64 lower-case hexadecimal digits, or a list of them of which any one will do. Required for `https`. |
| `[origin].allow_plain` | Allow an unencrypted `http` hop to an address that is not on this machine. Only for a network you trust completely. Default `false`. |
| `[origin].connect_timeout`, `idle_timeout` | Seconds. Defaults 10 and 60. The idle time applies to a visitor who stops sending a body and to a visitor who does not take the answer, who are cut off so that they cannot hold a place for ever, and to a gateway that goes quiet once the whole request has been sent. |
| `[sign].key_id`, `key_file` | This relay's name and its private key. |
| `[limits].max_concurrent`, `max_per_client` | Requests in flight in all, and for one visitor. Defaults 200 and 20. Over the limit, the relay answers 503 or 429 and asks the visitor to wait. One visitor is one IPv4 address, or one IPv6 network of 2 to the power 64 addresses. Past twice `max_concurrent` open connections, silent ones included, the relay's web server answers with a plain 503 of its own, which no relay setting changes. |
| `[limits].max_request_body`, `max_response_body` | Bytes. Defaults 1,000,000 and 200,000,000. Keep the first the same as the gateway's. A body over the first gets the missing page. |
| `[limits].max_request_seconds` | Seconds for one whole request and its answer, however slowly the visitor sends or reads. Default 300. A long download needs more. |

Every mistake in either file stops the start with a message that names it.

## What a relay holds, and what a stolen one gives away

| | A relay holds it | A stolen relay gives away |
|---|---|---|
| Its own signing key | yes | The ability to send requests to the gateway as that relay, until you revoke it. It still cannot sign anyone in without a valid sign-in link. |
| The certificate and key for your domain | yes, if it ends TLS | The ability to pass as your domain to visitors, until the certificate is replaced. |
| The gateway's address and fingerprint | yes | Where the gateway is. Change the firewall and the address if this happens. |
| The sign-in keys, the audit log, the policy, the held list, Tor | no | Nothing. |
| What visitors did before | no, it keeps nothing | Nothing from the past. From now until you notice, everything that passes through. |

## What the relay does not do

- It writes no log of requests or addresses. Its server runs with access logging off. It prints a short warning, with nothing about any visitor in it, when the gateway cannot be reached, goes quiet, answers in a way that is not a web server's, or shows a certificate that is not the pinned one. A visitor who is slow, who stops sending or reading, or whose request takes longer than the total time, is not the gateway's fault and is not written down. The server's own error line for an answer the relay cut off on purpose is left out, because it comes with a traceback that a visitor could make as often as they liked. Its web server still says that it received an invalid request for traffic that is not HTTP at all, which names nothing.
- It passes on only a short list of ordinary browser headers, so a header nobody thought of is not passed on. That leaves out anything a CDN or a proxy adds about the visitor, any header with an underscore in its name, and any header whose name starts with `x-og-`, which the relay and the gateway keep for themselves.
- It will not forward a request for any name that is not one of its own domains.
- It will not talk to the gateway over an unencrypted connection unless you say so, and it will not send a request to a gateway whose certificate is not one of the pinned ones.
- It keeps no session, cookie or cache. Restarting it loses nothing.
- It does not go on pulling an answer for a visitor who has left, and it does not hold a place for a visitor who stops sending or stops reading.
- It reads the gateway's answer while it is still sending the visitor's upload, so a gateway that answers early, with a refusal for instance, is heard. It does not run an idle clock on the gateway's silence while the visitor is still sending, because a gateway says nothing until it has the whole body. A slow upload that keeps coming is not cut off, and only the total time limits it.
- It sends the first piece of an upload in the same write as the request's head. In cover mode the gateway also reads and throws away what a stranger uploads, up to its body limit and a few seconds, before it answers. Without both, a gateway that answers at once and closes can reset the connection and the answer is lost on the way, so the visitor sees a cut-off page or the relay's own error where the gateway would have said "not found". That would tell a probe what is in front of the gateway.
- Each request is a new connection to the gateway. That costs a little time on every request. A relay far from the gateway will feel slower than the gateway alone.
