# Running onionglass

Status: pre-alpha. Personal mode works. Team and public modes are not built yet.

## Personal mode

Personal mode is for one person on their own machine. The gateway listens on `127.0.0.1` only and needs no sign-in, so it refuses to listen anywhere else.

### What you need

- Python 3.11 or newer.
- Tor running on your machine with its SOCKS port open. The default is port 9050.

Tor's own packages are the best source: the Tor Project's repository for Linux, `brew install tor` on macOS, and the Tor Expert Bundle on Windows. Use version 0.4.8 or newer, which some onion sites need to accept your connection.

### Start it

```bash
pip install .
onionglass
```

Then open `http://localhost:8080/` in your browser, type an onion address, and press Open.

Useful options:

| Option | Meaning |
|---|---|
| `--port 9000` | Listen on another port. |
| `--tor-port 9150` | Use another Tor SOCKS port. Repeat the option to spread visitors over several Tor processes. |
| `--tor-host 127.0.0.1` | Where Tor listens. |
| `--allow-images` | Load images from onion sites. Off by default, and when it is off no image is ever requested. |

### Checking Tor

```
onionglass check-tor
onionglass check-tor --tor-port 9150
onionglass check-tor --config team.toml        # every Tor the config file names
```

For each Tor it prints `ok` or `FAIL`, and for a failure one of these words with a sentence of advice:

- `not_listening`: nothing is on that port. Start Tor, or give the right port.
- `not_socks`: something answers but does not speak SOCKS5, so it is not Tor's SOCKS port.
- `no_login`: it speaks SOCKS5 but will not take the user name and password that onionglass uses to keep visitors apart, so it may not be Tor.
- `starting`: Tor answers but cannot reach the Tor network yet. Wait a minute and try again.
- `slow`: Tor took longer than `--wait` seconds (30 by default) to finish a lookup.
- `refused`: Tor answered the lookup with a refusal, named in the message.

To know whether Tor is connected, it asks Tor to find an onion address that it has just made up, which cannot exist. That is a question only an onion lookup can answer, and Tor never sends it through an exit, so it cannot reach a site on the ordinary internet. The answer tells it whether Tor looked. A Tor without detailed error reasons, such as Tor Browser's, is reported as working with a note that error pages will be less specific. The command exits 1 if any Tor fails.

Personal mode also does a quick check when it starts, and prints a warning if nothing is listening on a Tor port. It still starts, because Tor may be started a moment later, but pages cannot load until it is.

### Using Tor Browser's Tor

If Tor Browser is running, its Tor listens on port 9150. `onionglass --tor-port 9150` works with it. Tor Browser does not turn on Tor's detailed failure reasons, so error pages will be less specific.

### Your browser and `*.localhost`

Each site you open is shown from its own host name under `localhost`, such as `abcd...wxyz.localhost`. Current Chrome, Edge and Firefox send those names to your own machine without any setup. If your browser does not, use a browser that does.

## Testing against a real Tor

The ordinary tests use a pretend Tor. A second set talks to the real Tor network, using only the Tor Project's and DuckDuckGo's public onion sites. They are skipped unless you name a Tor you have started:

```
ONIONGLASS_TEST_TOR=127.0.0.1:9050 pytest tests/test_live_tor.py
```

They check that a real page comes through safely, that an address with nothing behind it gives "site not found", and that a redirect between https onions is followed. They need the internet and take a few minutes.

## Containers

```bash
docker compose up --build
```

Then open `http://localhost:8080/`. The compose file starts three containers:

- **tor**: Tor from the Tor Project's own package repository.
- **gateway**: onionglass, on a private network with no route to the internet.
- **proxy**: a small web proxy, the only thing published, and only on your machine's loopback address.

The container files have not been run by the project's maintainers yet. The continuous-integration job builds both images and checks the compose file, but nobody has watched them start Tor and open a site. Treat them as a starting point and read them first.

## Operating it

The things an operator does in a hurry are commands, and they work on the same files the gateway watches. There is no web admin interface on purpose: it would be one more thing to defend, on a gateway whose job is to be hard to attack. A change takes effect when the gateway next looks at the file, within a couple of seconds, with no restart.

```
onionglass admin --config team.toml kill status
onionglass admin --config team.toml kill on --all                  # stop everything
onionglass admin --config team.toml kill on --profile free         # stop one profile
onionglass admin --config team.toml kill on --onion ADDRESS        # stop one site
onionglass admin --config team.toml kill off                       # resume everything
onionglass admin --config team.toml kill off --profile free        # resume one scope

onionglass admin --config team.toml held list
onionglass admin --config team.toml held add ADDRESS --reason "why"
onionglass admin --config team.toml held release ADDRESS

onionglass admin --config team.toml reports summary --at-least 3
```

- The commands read only the kill, held and report file paths from the config, so they work even when the rest of it would not load.
- Files are replaced in one step, so the gateway never reads half of one. Comments and other lines are kept. A site that the gateway held in the very moment you released another can be lost, so run `held list` again afterwards if the gateway is busy.
- `held release` finds the site however its address was written, with or without `.onion` or a sub-domain.
- The report summary shows how many different visitors reported each site, and why. It never shows who they were.
- A mistake is one line on the error output and exit code 2, and nothing is changed.

On a deployment from `deploy/team`, run them inside the gateway container:

```
docker compose exec gateway onionglass admin --config /etc/onionglass/team.toml kill status
```

## Blocking, stopping and logging

These options work in personal mode and are the same ones a team deployment uses. All of them are off unless you give them.

| Option | What it does |
|---|---|
| `--blocklist FILE` | Onion addresses that are never opened. One per line, `#` starts a comment. A sub-domain counts as its whole address. |
| `--allowlist FILE` | The only addresses that may be opened. The blocklist still wins. |
| `--kill-file FILE` | Stops serving while the file lists a scope. See below. |
| `--audit-log FILE` | Appends one JSON line for every request that reaches an onion site. |
| `--audit-address FORM` | How the audit log names the site: `origin` (default, no path), `full`, `hash` or `none`. |

A list that cannot be read, or that has a line that is not an onion address, stops the program from starting. A typo never means "no list".

### Profiles

A profile says what a visitor may do: images, fonts, forms and logins, file uploads, page and file size limits, and a limit on requests per minute (typing in an address counts as a request, and one session can only type in so many addresses, `max_opens_per_session`). A signed-in visitor's ticket names a profile, and the gateway gives that session exactly that profile. A ticket that names a profile this gateway does not have is refused, and so is a session whose profile has since been removed. Nobody is ever given the default profile by mistake.

The profile is enforced on the request as well as on the page that comes back. A profile without forms refuses a post even if the visitor sends one by hand, and a profile without uploads refuses a body that carries a file. Profiles are set in the gateway's settings (`Settings.profiles`). `Profile.restricted()` is a ready-made text-only profile: no images, fonts, forms, logins or uploads, and 60 requests a minute. Personal mode has one profile and the command line does not change it.

### Daily allowances

A profile can carry a daily allowance per account (`daily_quota`). What it counts is your choice, through two costs: `open_cost` is taken when an address is opened, and `page_cost` for every web page that comes back. Opens per day is `open_cost=1, page_cost=0`. Pages per day is `open_cost=0, page_cost=1`. Any mix works, and the two must not both be zero.

- Counts belong to the account (the subject on the ticket), not the session, and are kept per profile. Opening a second session does not give a second allowance.
- The day is a UTC day. Counts start again at midnight UTC.
- A page is charged by what comes back, not by what the browser says it asked for. Images, style sheets and fonts are never charged as pages.
- When the allowance is spent, opening is refused. Fetching is only refused when pages are what is counted, so a visitor who has used their opens can still read the sites they already opened.
- With a journal file (`LocalQuota(path)`) the counts survive a restart. Without one they live in memory and a restart starts everyone afresh.
- If the meter cannot be read or written, the request is refused, and a page whose charge cannot be recorded is withheld. A profile without an allowance is not affected.

Opens are taken in one step: the meter checks that the allowance is not passed and takes the units together, so requests that arrive at the same moment cannot overspend it. The first request to a site in a session counts as an open, whether the address was typed in or reached by following a link, and the same site again in that session does not. Pages are charged after they come back, so a burst of simultaneous page requests can still overshoot a pages allowance by about as many pages as are in flight.

### Unrated sites

With `--rated-list FILE` (one onion address per line), the sites on the list are served normally and every other site is unrated. An unrated site can still be opened, but it is shown as text only: no images, fonts, forms, logins or uploads, and a post to it is refused even if sent by hand. Everything else about the visitor's profile still applies. The audit log marks these requests with the rule `unrated`. A blocklist entry always wins over the rated list.

### The name gate and the held list

`--name-list FILE` lists phrases, one per line. When the title or one of the first headings of a page contains a listed phrase, the page is refused and the site is added to the held list. Every later request to that site is refused, for everyone, until a person removes its line from the file given with `--held-file`. The two options go together, because a gate with nowhere to remember its hits could only refuse once. A listed title is always refused. The site is only held when the page did not merely repeat what the visitor sent (a search page that prints back the search is refused but proves nothing about the site), and on a gateway for other people, when at least `hold_after` different accounts have met it (setting `hold_after` in `[names]`, 2 by default). Without this, one visitor could hold any site by searching it for a listed phrase. In personal mode there is one visitor and the first hit holds.

- A phrase matches whole words, so a word inside a longer, innocent word is not a hit. A single word can end in `*` to match every word that starts with it.
- Accents, full-width letters, zero-width characters and common look-alike digits and symbols (`4` for `a`, `3` for `e`, and so on) do not hide a word.
- Only the title and the first few headings are read. The body of a page, images, and a page written in a script or spelling your list does not cover are not checked. The gate is one layer next to the address blocklist and a review, not a substitute for either.
- Each line in the held file has the address, the time and the reason, so the file is also the queue of sites waiting for review. If the file cannot be read or understood, every site is held, as with the kill file.
- The project ships no list and the repository never holds one. What belongs on it is a legal and operational decision for you to take.

### Reports from visitors

With `--report-file FILE`, the viewer shows a "Report this site" button next to a short list of reasons: illegal content, harmful content, scam or fraud, or something else. There is no free text, so the queue never holds other people's personal details or anything harmful to read.

- The report names the site the server says the visitor is looking at, never an address the browser supplies.
- Each line in the file holds the time, the onion address, the reason and the reporter's subject from their ticket. No page content is stored.
- A visitor can report a site once, and a session can send ten reports (`max_reports_per_session`). A repeated report does not use up the limit.
- With `--hold-after N` (and `--held-file`), a site that N different visitors have reported is held, so nobody can open it until a person has looked and removed its line from the held file.
- If the file cannot be written, the visitor is told the report was not recorded.

### The entity panel

A profile with `show_entities = true` gets an "Entities" button in the viewer's toolbar. It lists the wallets, email addresses and onion addresses that the page names, as plain text, so an analyst can note them without reading the page closely. It is off by default and off in the restricted preset.

- **Wallets are checked.** Bitcoin (legacy, script and segwit, including taproot), Ethereum (a mixed-case address must pass its capital-letter checksum) and Monero addresses are only listed if their own checksum holds. A transaction hash, a token or a made-up address is not listed.
- **Onion addresses** are listed with their checksum checked, and the sub-domain is dropped.
- **Only what the page shows is read.** Text inside scripts, style sheets and attributes is not. Up to 500,000 characters of a page are read, and at most 100 entities are listed, 40 of any one kind.
- **Nothing is fetched.** Looking for an entity never contacts it. The list is kept with the current page for the session and is gone when the session ends.
- **It is a lead, not proof.** A wallet on a page may be copied from somewhere else.
- **Sending them on is optional.** A profile with `send_entities = true` (it needs `show_entities`) gets a "Send these on" button in the panel. It hands the list to the service named in `[hooks]` when `"entities"` is in `use`, in the signed form described in `docs/integration-api.md`. Nothing is sent unless the visitor presses it. Only what the gateway itself found is sent, never the page's text or title, and the site is named in the form chosen for the audit log. Each send is on the audit record before it is made, so the config file must have an audit log (or `"audit"` in `[hooks].use`) or it is refused at start-up. A session can send 20 times (`max_entity_sends_per_session`, cleared after 24 hours without a send). A send that fails does not use up that allowance, but every try counts toward a cap of four times it, so a broken service cannot be hammered for ever. Sends are one at a time for a session, so presses that arrive together cannot pass the limit, and they count against the profile's request limit. The site is checked again when the button is pressed: if the kill switch, the held list or the policy now stops it, nothing is sent.

### The reader view

Every visitor has a "Reader view" button in the viewer's toolbar. It shows pages as plain, readable text and turns the page back with "Normal view". It needs no setting, because it only ever shows less than the normal view does.

- **What stays:** headings, paragraphs, lists, tables, quotes, code and links. Links still go through the gateway, and a link that leaves Tor still shows the warning page.
- **What goes:** pictures (a bracketed note names each one, even when the profile allows images), forms, buttons, styles, menus, side bars and footers. The only attribute left on anything is a link's address.
- **Per visitor, per session.** The choice covers every site that visitor opens until they switch it off or the session ends. Another visitor's view is not changed.
- **Same rules otherwise.** The page is fetched, counted, audited and checked against the policy exactly as in the normal view, and goes through the same safety pass with a shorter list of allowed tags. Cost, quota and the entity panel behave as before.

### Translation

A profile with `allow_translate = true` gets a "Translate" button in the viewer's toolbar, when the config file has a `[translate]` section. Pressing it shows every page the visitor opens in the reader view, with its text translated into the language the operator chose. "Original language" turns it back. It is off by default and off in the restricted preset.

```
[translate]
url = "https://translate.internal.example.net"   # a LibreTranslate-compatible service
target = "en"                                     # the language pages are translated into
api_key_file = "secrets/translate.key"            # only if the service needs a key
timeout = 20                                      # seconds the service has for one page
```

- **The service is yours.** Page text goes to it, so run it yourself, for example a self-hosted LibreTranslate, and not a service you do not control. The address must be https, unless it is on this machine or `allow_plain_http = true`. The gateway needs a route to it, as for any hook.
- **Only the words go.** The service is sent the visible text of the page and the target language. It is never sent the onion address, the page title, links, the account, the session or anything about the visitor. Code blocks and text with no letters in it are left out.
- **Each page is on the audit record first** (kind `translate`, with the number of characters as the rule). If that cannot be written, nothing is sent and the page is shown in its own language. A config file with a `[translate]` section and no audit log is refused at start-up.
- **What comes back is text, never markup.** A translation that contains tags is shown as the characters it is. The page keeps the safety rules of the reader view.
- **Translation never stops a page.** If the service is down, slow, answers with the wrong number of texts, answers with text that cannot be used, would make a page larger than the profile's page limit, or is already busy with `max_concurrent_translations` other pages (8 by default, in `[limits]`), the visitor gets the original text and a note saying translation was not available. A page with more than 1,000 pieces of text, or more than 100,000 characters, is translated up to that point and says so.
- **It is a machine translation.** Every translated page says so at the top. Do not rely on one for evidence: keep the original.
- **Entities are found in the original text**, so the panel is not affected by what a translation says.

### Cover mode

Where the internet is censored, a censor may visit a gateway's domain to see what it is. With cover mode on, a visitor who has not signed in sees an ordinary plain page, and every other address answers as a missing page on a small web server would. Only a valid sign-in link opens the gateway.

```
[cover]
enabled = true
page_file = "lists/cover.html"   # optional: your own front page, one file with its styles inline
```

- **A stranger sees a plain page at `/`** (a neutral "under construction" page unless you give your own), and a missing page everywhere else: the same status, the same body and the same headers for every address and every method, including the ones a web framework would normally refuse with its own message.
- **A valid sign-in link still works.** One that is wrong, used already or forged gets the missing page and not a refusal. Looking at the Continue page still needs a valid link.
- **Hidden from a stranger:** the entry page, the abuse page, the health check, the metrics, the robots file and every session host name. The health check still answers a supervisor on this machine, and the metrics still answer a scraper that has the token. `check-config` warns that the public abuse page is hidden, so publish your abuse contact somewhere else.
- **Errors give nothing away.** If something fails while a stranger is asking, they get the missing page and not the gateway's own error page.
- **Your own page** is served under a policy that lets it load nothing and run nothing, apart from its own inline styles and small pictures given as `data:` links. It must be UTF-8 text of up to 200,000 bytes, and a file that cannot be used stops the start.
- **It does not hide that the domain exists,** who connects to it, or how the server behaves under load. It is one layer, and [censorship.md](censorship.md) says what the others are. It is for gateways that need a sign-in, so it cannot be used in personal mode.

### Entry domains

A censor blocks a domain. If everyone shares one, that is everyone. Give each group of users its own domain, and a block costs one group and tells you which. Each domain runs as its own gateway, with its own port, sign-in audience, sessions and state files, and all of them are described in the one config file:

```
[entries.alpha]
domain = "a.example.net"
port = 8081
# public_port = 8443      # only if visitors do not use the usual port
# audience = "group-one"  # the default is the main audience and the entry name
```

```
onionglass domains add --config team.toml --name alpha --domain a.example.net
onionglass domains list --config team.toml
onionglass serve --config team.toml --entry alpha
onionglass ticket --config team.toml --entry alpha --key-file ... --key-id ... --subject ... --group ... --profile ...
onionglass domains caddy --config team.toml          # the proxy blocks for every domain
onionglass domains retire --config team.toml --name alpha
```

- **What an entry changes.** Its domain, its port, its sign-in audience (so a link made for one group does not work on another), and a folder of its own for every file the gateway writes: `state/audit.log` becomes `state/alpha/audit.log`. The folder must exist before it starts, and `domains add` makes it. The keys and the lists the gateway only reads are shared.
- **Nothing links the groups.** Sessions, labels, quotas and logs are separate, because they are separate processes.
- **Checked as a set.** Every entry is checked when any gateway starts, so a mistake stops them all and not only one: a name that is not lower-case letters, digits and dashes, a domain used twice or the same as the main one, a domain inside another (it would be taken for one of that gateway's session hosts), a port used twice, a missing port.
- **Retiring.** `domains retire` puts `all` in that entry's kill file, so it stops within a couple of seconds and the others carry on. Then remove its DNS records, its proxy block and its process. A retired entry stays in the file as a record, and its name cannot be used again by accident.
- **You still arrange** the DNS records, the wildcard certificate for each domain (the proxy blocks use one DNS token, so it must be able to edit every zone) and a service for each entry in the deployment bundle. `deploy/team/compose.yaml` has a commented example.
- **Why not one gateway for many domains.** The domain is built into the security headers, the host parsing, the rewritten links and the cookies. Changing all of that would put the most sensitive code at risk to save starting a few more processes.

### Checking that a domain is reachable

```
onionglass domains check --config team.toml
onionglass domains check --domain a.example.net --expect-address 203.0.113.7
```

For each domain it says where a connection stops: the name lookup (`dns_failed`, or `dns_unexpected` if the answer is not an address you expect, as with DNS poisoning, or `wildcard_dns_failed` if a session host name does not resolve), the connection (`tcp_failed`: a timeout suggests dropped packets, a reset or refusal suggests a block or nothing listening), the TLS handshake (`tls_failed`: a reset right after the hello suggests blocking by server name, silence suggests dropped packets, and a certificate that does not match suggests interception), or the page (`http_failed`, or `content_changed` if you gave the hash of the front page with `--expect-sha256` and a different page came back). It exits 1 if any domain fails.

It asks for the front page once, as a browser would, and sends no cookie, account or identifier, follows no redirect and reads at most a megabyte. Run it from a trusted machine inside the country to see what the censor does, and from outside for a baseline. Connecting to the domain is itself a risk to whoever runs it in a country that watches for it.

### Look-alike warning

Copycat onion sites are made by searching for an address that starts like a popular one: a few characters are cheap to match, and the end of an address is a checksum that cannot be chosen. With `--known-sites FILE` (or `[known_sites]` in the config file), you list the sites people are likely to mean, one per line, the address and then a name:

```
2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid   The Tor Project
```

When a visitor types an address that starts with the same six characters as a listed one, and is not it, they see a page that names the listed site, shows both addresses as plain text, and offers "Open it anyway". Nothing has been fetched, counted, charged or recorded by then. Six characters are 30 bits, so an unrelated site shares them with a given listed one about once in a billion times. The warning covers addresses people type or paste. It does not look at links on pages, and it knows only the sites on your list. An address on the list is never warned about.

### The abuse page

With `[abuse] contact = "..."` in the config file, the gateway serves `/abuse` to anyone, signed in or not. It names the contact (an email address or an https link, nothing else is accepted), tells people to send the address and never the material, lists the reasons the report button offers, and says what happens next. The entry page links to it. Without a contact the page says the operator has not published one, the entry page does not link to it, and `check-config` warns. Write the contact once and read what arrives there: the [abuse procedure](abuse-procedure.md) is what to do with it.

### Metrics

With `--metrics-token-file FILE`, the gateway serves Prometheus metrics at `/_og/metrics` on its main address, to a scraper that sends the token from that file as `Authorization: Bearer <token>`. The token must be 16 or more printable characters with no spaces. Without the option the endpoint does not exist. Keep the token in a file and not on the command line. The deployment bundle's proxy answers `404` for this path from outside, so scrape the gateway directly, from inside the same network.

```
scrape_configs:
  - job_name: onionglass
    metrics_path: /_og/metrics
    authorization:
      credentials_file: /etc/prometheus/onionglass.token
    static_configs:
      - targets: ["gateway.example:443"]
```

What you get: requests allowed and refused, refusals by reason, replies by status class, Tor fetch failures by kind, how long fetches take, sessions created, reports, pages that could not be rewritten, fetches in progress against the most allowed, and whether a kill file is stopping the whole gateway. Useful alerts are a rising rate of fetch failures, the kill gauge going to 1, fetches in progress close to the limit, and any sign of `policy-unavailable`, `audit-unavailable` or `quota-unavailable` refusals, which mean a dependency is down.

Every label has a small fixed set of values. No metric is labelled with an onion address, an account, a session, a path or a rule name you wrote, so the endpoint cannot say what anyone opened. Certificate expiry is not reported here. Watch it with whatever monitors your certificates.

### The kill file

Create the file to stop serving, delete it or empty it to start again. The gateway looks at it about once a second and does not need a restart. One scope per line:

```
all
profile restricted
onion <56 character address>
```

A file that exists but cannot be read, or that has a line the gateway does not understand, stops everything. The health check at `/_og/health` stays up, so a supervisor does not restart a gateway you stopped on purpose.

### The audit log

Each request is written down before it goes out, and its outcome when it comes back. If the log cannot be written, the request is refused. The log holds the time, what happened, which rule decided it, the profile, group and subject, the site in the form you chose, and the status. It never holds page or form bodies, headers or cookies, and the gateway does not keep visitors' network addresses at all. The file is opened for every line and is private to its owner, so moving it away for rotation works. Keep it on a disk with room, because a full disk stops the gateway.

## Running it for other people

This section explains the config file. For the whole job on a server, including the proxy, the certificate and the checks to make before opening it, follow [deploying.md](deploying.md).

Personal mode, above, is for one person on one machine. To serve other people, run the gateway behind a proxy that ends TLS, give it a domain with a wildcard certificate, and describe it in one TOML file. [docs/examples/team.toml](examples/team.toml) lists every setting with its meaning, and the tests load that file exactly as written, so it stays correct.

```
onionglass keys generate --id signin-2026-10 --out keys     # a signing key pair for sign-in links
onionglass check-config --config team.toml                 # read the file and say what it would do
onionglass serve --config team.toml                        # run it
onionglass ticket --key-file keys/signin-2026-10.private.pem --key-id signin-2026-10 \
    --subject alice --group team --profile standard --url https://gateway.example.org
```

The last command prints a one-time sign-in link, to test a deployment. In real use your own sign-in service makes the tickets, signs them with the private key, and the gateway holds only the public key, so a stolen gateway cannot sign anyone in.

What the loader promises:

- **Typos fail.** A section or setting it does not know is an error.
- **No secrets in the file.** A key, salt or token is a path to a file. On systems with file modes, one that other users can read is refused.
- **Paths are relative to the config file**, not to where you start the program.
- **Problems show at start-up.** A list that cannot be read, a profile with a quota but no meter, a name list without a held list, a file whose folder does not exist, a hook address that is not https: each stops the start with a message that names the place. A setting of zero or an empty string is an error, never a silent default.
- **It does not listen beyond this machine** unless you say `allow_non_loopback = true`, or it is in the container image. The gateway has no TLS of its own, so the proxy must be the only way in.
- **`check-config` shows what is on and what is missing**, and warns when there is no audit log, no kill file, no held list or no policy. It never prints a secret.

To rotate the sign-in key, make a new pair, add its public key under `[tickets]`, switch your sign-in service to the new private key, wait for the old links to expire, then remove the old public key. The gateway checks tickets against every key it holds.

## What the gateway does and does not do for you

- Pages are shown without scripts.
- Images are not loaded unless you allow them.
- Links to the normal internet go through a warning page.
- The person running the gateway can see every address you open and everything you view. In personal mode that person is you.
- It does not make you anonymous. Use Tor Browser for that.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| "Tor is not available" | Tor is not running, or the port is wrong. Run `onionglass check-tor`, which says which, and use `--tor-port` for another port. |
| "Site not found" | The onion site is offline or the address is wrong. |
| "Could not reach the site" | The site is busy. Try again in a minute. |
| "The page could not be shown safely" | The page was too large or complex to make safe. |
| Nothing opens after pressing Open | Your browser may not resolve `*.localhost`. Try another browser. |
