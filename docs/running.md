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

### Using Tor Browser's Tor

If Tor Browser is running, its Tor listens on port 9150. `onionglass --tor-port 9150` works with it. Tor Browser does not turn on Tor's detailed failure reasons, so error pages will be less specific.

### Your browser and `*.localhost`

Each site you open is shown from its own host name under `localhost`, such as `abcd...wxyz.localhost`. Current Chrome, Edge and Firefox send those names to your own machine without any setup. If your browser does not, use a browser that does.

## Containers

```bash
docker compose up --build
```

Then open `http://localhost:8080/`. The compose file starts three containers:

- **tor**: Tor from the Tor Project's own package repository.
- **gateway**: onionglass, on a private network with no route to the internet.
- **proxy**: a small web proxy, the only thing published, and only on your machine's loopback address.

The container files have not been run by the project's maintainers yet. The continuous-integration job builds both images and checks the compose file, but nobody has watched them start Tor and open a site. Treat them as a starting point and read them first.

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

A profile says what a visitor may do: images, fonts, forms and logins, file uploads, page and file size limits, and a limit on requests per minute. A signed-in visitor's ticket names a profile, and the gateway gives that session exactly that profile. A ticket that names a profile this gateway does not have is refused, and so is a session whose profile has since been removed. Nobody is ever given the default profile by mistake.

The profile is enforced on the request as well as on the page that comes back. A profile without forms refuses a post even if the visitor sends one by hand, and a profile without uploads refuses a body that carries a file. Profiles are set in the gateway's settings (`Settings.profiles`). `Profile.restricted()` is a ready-made text-only profile: no images, fonts, forms, logins or uploads, and 60 requests a minute. Personal mode has one profile and the command line does not change it.

### Daily allowances

A profile can carry a daily allowance per account (`daily_quota`). What it counts is your choice, through two costs: `open_cost` is taken when an address is opened, and `page_cost` for every web page that comes back. Opens per day is `open_cost=1, page_cost=0`. Pages per day is `open_cost=0, page_cost=1`. Any mix works, and the two must not both be zero.

- Counts belong to the account (the subject on the ticket), not the session, and are kept per profile. Opening a second session does not give a second allowance.
- The day is a UTC day. Counts start again at midnight UTC.
- A page is charged by what comes back, not by what the browser says it asked for. Images, style sheets and fonts are never charged as pages.
- When the allowance is spent, opening is refused. Fetching is only refused when pages are what is counted, so a visitor who has used their opens can still read the sites they already opened.
- With a journal file (`LocalQuota(path)`) the counts survive a restart. Without one they live in memory and a restart starts everyone afresh.
- If the meter cannot be read or written, the request is refused, and a page whose charge cannot be recorded is withheld. A profile without an allowance is not affected.

The check happens just before a request goes out and the charge just after, so a burst of simultaneous requests can overshoot the allowance by about as many requests as are in flight.

### Unrated sites

With `--rated-list FILE` (one onion address per line), the sites on the list are served normally and every other site is unrated. An unrated site can still be opened, but it is shown as text only: no images, fonts, forms, logins or uploads, and a post to it is refused even if sent by hand. Everything else about the visitor's profile still applies. The audit log marks these requests with the rule `unrated`. A blocklist entry always wins over the rated list.

### The name gate and the held list

`--name-list FILE` lists phrases, one per line. When the title or one of the first headings of a page contains a listed phrase, the page is refused and the site is added to the held list. Every later request to that site is refused, for everyone, until a person removes its line from the file given with `--held-file`. The two options go together, because a gate with nowhere to remember its hits could only refuse once.

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

### Metrics

With `--metrics-token-file FILE`, the gateway serves Prometheus metrics at `/_og/metrics` on its main address, to a scraper that sends the token from that file as `Authorization: Bearer <token>`. The token must be 16 or more printable characters with no spaces. Without the option the endpoint does not exist. Keep the token in a file and not on the command line.

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

## What the gateway does and does not do for you

- Pages are shown without scripts.
- Images are not loaded unless you allow them.
- Links to the normal internet go through a warning page.
- The person running the gateway can see every address you open and everything you view. In personal mode that person is you.
- It does not make you anonymous. Use Tor Browser for that.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| "Tor is not available" | Tor is not running, or the port is wrong. Check `--tor-port`. |
| "Site not found" | The onion site is offline or the address is wrong. |
| "Could not reach the site" | The site is busy. Try again in a minute. |
| "The page could not be shown safely" | The page was too large or complex to make safe. |
| Nothing opens after pressing Open | Your browser may not resolve `*.localhost`. Try another browser. |
