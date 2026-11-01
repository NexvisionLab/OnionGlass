# Deploying onionglass for other people

This is the step-by-step for the bundle in `deploy/team`. It sets up a gateway on its own server, with two Tor processes, a proxy that gets a wildcard certificate by itself, and the safety settings from [running.md](running.md).

Read [operator-responsibilities.md](operator-responsibilities.md) and [abuse-procedure.md](abuse-procedure.md) before you open this to anyone. Running a gateway for other people is a legal and operational responsibility, and the software cannot take it from you.

**Status.** The bundle has been checked for structure by the tests and has not been started, because Docker was not available where it was written. Bring it up on a test machine and a test domain first, and expect to find things.

## What you need

- A server you control, with Docker and the Compose plugin. About 2 vCPU and 4 GB is enough to start, and more if you add Tor processes or many visitors.
- A domain whose DNS is hosted at Cloudflare. A wildcard certificate can only be proved by DNS, and Cloudflare is the provider the proxy image is built for. The domain can stay registered anywhere. Only its nameservers move.
- Whatever signs your visitors in. It makes a short-lived ticket for each visit and signs it with a private key. This repository gives you the key tools and a test command, not a sign-in service.
- A decision on the free allowance, if you have a free profile (see "Daily allowances" in running.md).

## 1. Harden the server first

Do this before anything else is installed, and never skip it for a quick test on a machine that has a public address.

- Log in with keys only. Turn off password logins and root login over SSH.
- Allow only SSH, 80 and 443 through the firewall. Limit SSH to your own addresses if you can. Docker publishes ports around some firewalls, so check from outside with a port scanner after you start.
- Turn on automatic security updates, and a tool that blocks repeated failed logins.
- Put nothing else on the machine. The gateway shows pages from the dark web to its visitors, and a neighbour on the same box is a neighbour at risk.
- Install Docker from Docker's own package repository, and run the stack as a normal user in the `docker` group.

## 2. DNS

In Cloudflare, add the domain and change the nameservers at the registrar as it tells you. Then add:

| Type | Name | Value | Proxy |
|---|---|---|---|
| A | `@` (the domain itself) | the server's address | **DNS only** |
| A | `*` | the server's address | **DNS only** |
| CAA | `@` | `0 issue "letsencrypt.org"` | |
| CAA | `@` | `0 issuewild "letsencrypt.org"` | |

Leave the orange cloud off. If Cloudflare proxies the traffic it sees every page, and the gateway's whole point is that only you do.

Add the same records for IPv6 (`AAAA`) if the server has an IPv6 address, and make sure it is reachable, or leave IPv6 out.

Make an API token for the proxy: in Cloudflare, My Profile, API Tokens, create a custom token with the single permission "Zone, DNS, Edit", limited to this one zone. It cannot do anything else.

## 3. The files

```
git clone https://github.com/NexvisionLab/OnionGlass.git
cd OnionGlass/deploy/team
cp env.example .env              # set DOMAIN and ACME_EMAIL
mkdir -p secrets state config/keys config/secrets
```

Put the DNS token in `secrets/proxy.env` as one line, `CLOUDFLARE_API_TOKEN=` followed by the token, and run `chmod 600 secrets/proxy.env`. Do not paste the token into a chat, a ticket or a shell history that is kept.

Make the sign-in key pair on a machine that has the package installed (the server is fine), then keep the private key with your sign-in service and nowhere else:

```
onionglass keys generate --id signin-1 --out config/keys
```

Move `config/keys/signin-1.private.pem` away to wherever your sign-in service keeps its key. Only the public key stays in `config/keys`.

Make the metrics token and keep it out of the repository too:

```
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > config/secrets/metrics.token
chmod 600 config/secrets/metrics.token
```

Edit `config/team.toml`: set the domain, then decide which profiles you will have. The gateway runs as user 10001 inside the container, so give it what it needs to read and write:

```
sudo chown -R 10001:10001 state config/secrets
sudo chmod 700 config/secrets
```

Check the file before starting anything. Copy it to a machine that has onionglass installed and run:

```
onionglass check-config --config config/team.toml
```

It says what is on and warns about what is missing: no audit log, no kill file, no held list, no policy. Take every warning seriously, or know exactly why you are ignoring it.

## 4. Start it

```
docker compose up --build -d
docker compose logs -f proxy
```

The proxy asks Let's Encrypt for the wildcard certificate by creating a short-lived record in your DNS zone. The first time can take a minute or two. When the log shows the certificate was obtained, open `https://your-domain/`. You should see the entry page, and it should say the address is not yours to open without signing in.

If the certificate fails, the likeliest causes are a token with too little permission, the domain not yet on Cloudflare's nameservers, or a CAA record that does not allow Let's Encrypt. If it complains that the record never appeared, the server's own resolver may be caching an old answer. Add a `resolvers` line with a public resolver inside the `tls` block of `proxy/Caddyfile`. Let's Encrypt limits repeated failures, so fix the cause before retrying many times.

## 5. Try it before anyone else does

Make a sign-in link with the private key, from wherever you keep it:

```
onionglass ticket --key-file signin-1.private.pem --key-id signin-1 \
    --subject test --group staff --profile free --url https://your-domain
```

Open the link in a browser. You should land on the entry page signed in, be able to open an onion address, and see it in a frame with its address above it. Check these before you open the doors:

- A profile that does not exist is refused, and a link works only once.
- A blocked address is refused, and a held one too.
- The audit log in `state/audit.log` records what you did, with no page content.
- `admin kill on --all` stops the gateway within a couple of seconds, and `admin kill off` resumes it.
- The report button works, and a report appears in `state/reports.log`.
- From outside, only ports 80 and 443 answer.
- Stopping both Tor containers makes pages fail with a clear message instead of hanging.

## 6. Running it

**Stopping.** `docker compose exec gateway onionglass admin --config /etc/onionglass/team.toml kill on --all` stops everything, and `kill off` resumes. `--profile NAME` and `--onion ADDRESS` stop one profile or one site. The health check stays up. Writing `all` into `state/kill` by hand does the same thing if the container is not running.

**Reviewing.** `admin held list` shows the queue of sites held by the name gate or by enough reports, with the time and the reason, and `admin held release ADDRESS` serves one again. `admin reports summary` shows which sites visitors have reported, how many of them and why, without saying who. Look at what is behind a site as the abuse procedure says, which is as little as you can.

**Logs.** The audit log is opened for every line, so moving it away to rotate it just works. Keep it on a disk with room, because a full disk stops the gateway. Decide how long you keep it and write it down.

**Metrics.** The proxy answers `404` for `/_og/metrics` from outside, so the endpoint is never public. Run Prometheus on the same compose network and point it at `gateway:8080/_og/metrics` with the token, as shown in running.md. Alert on fetch failures rising, on the kill gauge going to 1, and on any `unavailable` refusal. Monitor the certificate's expiry separately.

**What a compromised gateway can change.** The gateway writes to `state/`: the audit log, the held list, the report queue and the quota journal. If someone takes over the gateway process, they can edit those files, and a kill file kept in the same folder as well. The kill file and the lists the gateway only reads are mounted read-only already. For the kill file, the stronger setup is to keep it in a folder of its own, mount that folder read-only into the gateway, and switch it on and off from the host by writing `all` into it or removing it. Then a takeover of the gateway cannot lift a stop you put in place. Send the audit log to a place the gateway cannot rewrite as well, such as a log collector, if you need to rely on it later.

**Hooks need a route.** The gateway sits on a network with no way out. If you use `[hooks]` for policy, audit or quota, the service they call must be reachable from the gateway, so put that service on the `private` network or on a second internal network that holds only it. Do not give the gateway general internet access to make a hook work. A hook that cannot be reached makes the gateway refuse requests, which is the safe failure.

**The proxy's own log.** The proxy keeps no request log, but Caddy still writes operational messages to its output, and some of them, such as a failed TLS handshake, name the address that connected. Treat the proxy's container logs as sensitive, keep them short, and do not ship them anywhere that keeps them for long. This could not be checked here because Docker was not available, so look at what your own proxy writes on a test machine.

**Backups.** Back up `config/` (without the private key, which lives elsewhere), `state/` and the `caddy-data` volume. Losing the volume only costs you a new certificate.

**Updating.** `git pull`, then `docker compose up --build -d`. Read the release notes first. Sessions end when the gateway restarts, which also moves every visitor to new Tor circuits.

**Rotating the sign-in key.** Make a new pair, add its public key to `[tickets]` beside the old one, switch your sign-in service to the new private key, wait for the old links to expire (five minutes at most), then remove the old public key and restart.

## If your visitors are in a country that blocks the internet

Read [censorship.md](censorship.md) first. It says what a gateway can and cannot do there, and it starts with the fact that nothing is unblockable. What the bundle gives you:

- **Cover mode** (`[cover] enabled = true`), so that the domain shows a stranger a plain page.
- **A domain for each group** (`onionglass domains add`), each its own gateway service. `compose.yaml` has a commented example, and `onionglass domains caddy` prints the proxy block for every domain. Each domain needs its own DNS records and wildcard certificate, and the DNS token must cover every zone.
- **`onionglass domains check`** to see where a domain fails, from the server and from a trusted machine inside the country.

Tor bridges and Snowflake proxies do not go in this bundle and must not share the gateway's server. [bridges.md](bridges.md) says how to run them on another one.

Points about the proxy:

- **HTTP/3 (QUIC).** The Great Firewall reads the server name inside QUIC and blocks by it, so a domain blocked over HTTPS is blocked over HTTP/3 as well. Leaving HTTP/3 on does no harm, but it is not a defence.
- **Encrypted Client Hello** hides the server name in the TLS hello, but a client needs the encrypted DNS lookup that carries its key, and China and Iran block those lookups. In those countries it usually cannot start. Caddy can serve it from version 2.10, and it needs a DNS plugin built in to publish the key, which this bundle's proxy image already has. The bundle follows the `caddy:2` tag, so a fresh build gets 2.10 or later. The setting is the `ech` option in the Caddyfile's global block, next to the `dns` line, naming a public outer domain. The setting is not tried here, and the Caddy documentation is the place to confirm its exact form, so the bundle does not switch it on. Turn it on if you want it for visitors elsewhere, but do not count on it.
- **A content network in front of the gateway** gives a censor shared addresses to worry about, which helps. But the network then sees every page a visitor reads, which breaks the promise that only you do. The bundle does not do it, and I do not recommend it.
- **Certificates are public.** Each new domain's certificate appears in certificate transparency logs, so assume a new domain can be found by anyone watching them.

## What this does not give you

- **Anonymity from you.** You, and anyone who breaks into the server, can see every address visitors open. The entry page says so. Do not describe the service as anonymous.
- **Encrypted client hello.** The name of the site a visitor reaches is a random-looking sub-domain, so nothing about the onion address leaks in a certificate or in a name lookup, but the domain itself is visible to anyone watching the network. Encrypted Client Hello would hide it from some watchers, and the proxy notes above say what it needs and where it does not work.
- **A sign-in service**, the legal review, the abuse contact and the reporting route. Those are yours.
- **An independent penetration test.** The project has had three reviews and a lot of testing, and none of it replaces a test by someone outside it before you open the service to the public.
