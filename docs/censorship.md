# Censorship: using and running onionglass where the internet is blocked

Status: pre-alpha. This page says what onionglass can and cannot do against a censor. It is written to be read by two people: someone who wants to look at a site from a country that blocks the internet, and someone who runs a gateway that such people might use.

## The short version

- **Nothing is unblockable.** Every circumvention tool has been blocked somewhere, sooner or later. In Iran in January 2026 the state went further and let only an approved list of services through, and during that time no tool that relies on ordinary internet connectivity worked. onionglass cannot do better than that, and it does not claim to.
- **The operator sees everything.** A gateway is run by someone, and that someone can see every address you open and every page you read. It does not make you anonymous.
- **Using it may put you at risk.** In some countries, using or sharing circumvention tools is a crime or draws attention. That is your decision to make, knowing it.
- **For most people, Tor Browser with a bridge is the safer choice.** It does not put a gateway operator between you and what you read.

## If you are in a country that blocks the internet

If you can reach this page, you may already be reaching a gateway. Before you rely on it, know what it is.

A gateway is a website. It fetches onion sites for you and shows you a safe copy. The people watching your connection can see that you connect to the gateway's domain, even if they cannot see which onion site you open. The person running it can see both.

If you need to read onion sites and your safety matters, these are the Tor Project's own routes, which do not need a gateway:

- **Tor Browser, with a bridge.** A bridge is a Tor entry point that is not listed publicly, so it is harder to block. Get one from [bridges.torproject.org](https://bridges.torproject.org/). The Tor Project has a page on [using Tor where it is censored](https://support.torproject.org/censorship/).
- **If you cannot download Tor Browser,** [GetTor](https://gettor.torproject.org/) sends you the download by other routes, such as email, when the Tor Project's website is blocked.
- **Snowflake**, built into Tor Browser, uses volunteers' browsers as short-lived entry points, and was the most used tool in Iran in 2025 according to the [Tor Project](https://blog.torproject.org/staying-ahead-of-censors-2025/). See [snowflake.torproject.org](https://snowflake.torproject.org/).

Take care with where you read this advice, and with who you tell. A message that points to a circumvention tool can itself be monitored.

## What censors do, and what that means for a gateway

These are the methods that matter for a gateway, from published research. They change quickly, so check the sources, and a measurement project such as [OONI](https://ooni.org/install/), before you rely on any of this. The newest source used here covers events up to early 2026.

| What the censor does | Why it matters here |
|---|---|
| Blocks traffic that looks fully encrypted, in real time ([USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi)) | A gateway speaks ordinary HTTPS to an ordinary web server, which is the right shape. onionglass must never add a custom encrypted protocol of its own. |
| Reads the server name inside QUIC connections and blocks by it, since April 2024 ([USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib)) | A blocked domain is blocked over HTTP/3 as well. |
| Poisons DNS and filters the server name in TLS | A blocked domain stops working. This is the main way a gateway is blocked. |
| Blocks server addresses in bulk, and collects the addresses of tools that are handed out ([Tor Project, 2025](https://blog.torproject.org/staying-ahead-of-censors-2025/)) | One address is not enough, and how you hand out addresses matters as much as the address. |
| Blocks the encrypted DNS lookup that Encrypted Client Hello needs ([FOCI 2025](https://petsymposium.org/foci/2025/foci-2025-0016.php)) | ECH usually cannot start in China or Iran, so it is not a defence there. |
| Visits an address to see what it is | A gateway that answers every visitor with its own pages confirms what it is. See cover mode below. |
| Shuts down general access and allows only approved services (Iran, January 2026) | Nothing here can work through that. |

## What onionglass does about it

None of these makes a gateway unblockable. Each one makes blocking slower, narrower or more expensive.

### Cover mode: look like a boring website

With cover mode on, a visitor who has not signed in sees an ordinary, plain web page, and every other address on the site gives the same answer a normal small website would give for a page that does not exist. A censor who visits the domain to see what it is learns nothing. See [Cover mode](running.md#cover-mode) for how to turn it on.

Limits: it hides what the gateway is from a visitor who has no ticket. It does not hide that the domain exists, who connects to it, or the timing of what it does. It also hides the public abuse page, so the operator's contact must be published somewhere else.

### One domain for each group of users

A group of users is given one domain of its own. If a domain is blocked, or its address leaks, only that group is affected, and you know which group it was. Each domain runs as a separate gateway with its own sessions, its own sign-in audience and its own state files, so nothing is shared between groups that could be used to link them. See [Entry domains](running.md#entry-domains).

### Fast change of domains

Adding a domain, issuing a link for it and retiring one that has been blocked are commands, so a response to blocking takes minutes and not a day. The domain still needs DNS and a certificate, which are yours to arrange.

### Knowing that you have been blocked

`onionglass domains check` reports, for each domain, where a connection fails: the name lookup, the connection, the TLS handshake or the page. Run from a trusted machine inside the country, it tells you which domains are blocked and how. Run from outside, it gives you a baseline to compare with. Running it from inside the country is a risk to whoever does it, because it connects to the domain.

## What to do as an operator

1. **Decide who the gateway is for.** For analysts and journalists with an operator they trust, a gateway is reasonable. For the general public in a censoring country, it is not the right tool, and the better use of your effort is running Tor bridges (below) and pointing people to the Tor Project's routes.
2. **Choose boring domain names.** Do not put "tor", "onion", "proxy" or "gateway" in a name. Remember that each session also gets random sub-domains under your domain.
3. **Plan for domains being found.** Every certificate is public in certificate transparency logs, so a new domain can be found by anyone watching them. I did not verify that a particular censor does so, but assume it can. Do not rely on a domain staying unknown.
4. **Hand out domains carefully.** A domain given freely is found by the censor. Give each group its own, give it through a channel the censor cannot easily read, and expect to rotate. The Tor Project found that bridges handed out through a channel that was easy to collect were blocked within months, while handing them out through a Telegram bot was harder for the censor to collect ([Tor Project, 2025](https://blog.torproject.org/staying-ahead-of-censors-2025/)). The sign-in service decides this, and it is yours. onionglass only checks the ticket it is given.
5. **Run Tor bridges as well.** The Tor Project asks anyone with a website to [run a WebTunnel bridge](https://community.torproject.org/relay/setup/webtunnel/), and anyone to run a Snowflake proxy. That helps the people who most need it, and it does not put your gateway between them and what they read. Use a separate server. The deployment guide says the gateway should share its machine with nothing else. [bridges.md](bridges.md) says how.
6. **Watch for blocking from the inside.** Use `onionglass domains check` from a trusted vantage point, or OONI Probe, and rotate when a domain stops working.
7. **Think about a CDN before using one.** Putting a large content network in front of the gateway means a censor must block a shared address that many other sites use, which is a real cost to it. But the network then sees every page a visitor reads. That breaks the promise that only the operator sees them. It is your decision, and it should be a conscious one. onionglass does not do it for you and does not recommend it.
8. **Take legal advice.** Serving users in sanctioned countries has rules that differ by country, and neither this page nor the project can advise on them.

## What this cannot do

- Make a gateway unblockable.
- Work when a country allows only an approved list of services.
- Protect a user from the operator, from someone watching their device, or from the law.
- Hide that a user connects to a domain, only what they do there.
- Keep a domain secret from someone who can see certificate logs.

## Sources

The state of blocking changes, and the evidence here is uneven. Some points rest on one secondary source: a reported wide block on port 443 in China on 20 August 2025, and whether China blocks ECH directly (the 2025 paper says it blocks the DNS lookups instead). The Tor Project report covers 2025 only.

- [How the Great Firewall of China detects and blocks fully encrypted traffic](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi), USENIX Security 2023
- [Exposing and circumventing SNI-based QUIC censorship of the Great Firewall of China](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib), USENIX Security 2025
- [Encrypted Client Hello in censorship circumvention](https://petsymposium.org/foci/2025/foci-2025-0016.php), FOCI 2025
- [Iran's January 2026 internet shutdown: public data, censorship methods and circumvention techniques](https://arxiv.org/html/2603.28753), arXiv 2603.28753
- [Staying ahead of censors in 2025](https://blog.torproject.org/staying-ahead-of-censors-2025/), Tor Project, December 2025
- [From blackout to whitelist: the anatomy of a tiered internet](https://asl19.org/en/blog/2026-04-30-from-blackout-to-whitelist-the-anatomy-of-a-tiered-internet), ASL19, April 2026
- [Lox: protecting the social graph in bridge distribution](https://petsymposium.org/popets/2023/popets-2023-0029.php), PETS 2023
