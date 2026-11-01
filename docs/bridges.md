# Running Tor bridges and Snowflake proxies beside a gateway

This page is for someone who runs an onionglass gateway and wants to help people in countries that block the internet in a way that does not put the gateway between them and what they read. The Tor Project runs the software and keeps it up to date. This page says what to do, in what order, and where the Tor Project's own instructions are.

## Read this first

- **Use a separate server.** The [deployment guide](deploying.md) says the gateway should share its machine with nothing else. A bridge is the opposite kind of service. It is meant to be found by many people, and a WebTunnel bridge runs a public website. Put bridges and proxies on their own server, with their own address, and never on the gateway's.
- **onionglass does not ship a bridge, an image or a compose file for this.** The Tor Project maintains them and changes them. The commands below were read from the Tor Project's pages on 2026-11-01. They are not tried here, because Docker has not been run on the machine this was written on. Read the pages again before you use them, and read any file you download before you run it.
- **Bridges can still be blocked.** They make blocking slower and costlier. They do not stop it. The Tor Project's own report on 2025 says so ([Staying ahead of censors in 2025](https://blog.torproject.org/staying-ahead-of-censors-2025/)).

## Two ways to help

| | What it is | What you need |
| --- | --- | --- |
| **Snowflake proxy** | You lend some bandwidth. People in a censored country reach Tor through proxies like yours, and their connection looks like an ordinary video call. | A server that is on all the time. No website and no domain. |
| **WebTunnel bridge** | A Tor bridge that hides behind your own website. To a censor it looks like a normal visit to a normal site over HTTPS. | A server, a website on a domain you control, and a certificate. |

Start with a Snowflake proxy if you only want to help. Run a WebTunnel bridge if you already have a website that you can put on the server. The Tor Project has asked for more WebTunnel bridges, including for Russia ([Tor in Russia: a call for more WebTunnel bridges](https://blog.torproject.org/call-for-webtunnel-bridges/)).

## Who can see what

A bridge is the first step of a Tor circuit. It sees that someone connects to it. It does not see which pages that person reads, because those travel inside Tor. A gateway is different, because the operator sees every address. That difference is the reason to run bridges as well. A person who can reach a bridge needs no gateway and no trust in you.

## Run a Snowflake proxy

The Tor Project's guide is [Snowflake standalone proxy, with Docker](https://community.torproject.org/relay/setup/snowflake/standalone/docker/). In short, after you have installed Docker, from a folder of your choice on the new server:

```
curl -fsSL -o docker-compose.yml "https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/raw/main/docker-compose.yml?ref_type=heads"
docker compose up -d snowflake-proxy
docker logs -f snowflake-proxy
```

- Open `docker-compose.yml` and read it before you start anything. It shows the network settings and the image it will run. The Tor Project's page does not list ports to open, so the file is where to look.
- The file also contains a container called Watchtower, which checks for a new version of the proxy once a day and installs it. `docker compose up -d` starts both. Without Watchtower, you pull the new image and restart the proxy yourself from time to time.

## Run a WebTunnel bridge

The Tor Project's guides are [Set up a WebTunnel bridge](https://community.torproject.org/relay/setup/webtunnel/) and [WebTunnel with Docker](https://community.torproject.org/relay/setup/webtunnel/docker/). What the first one asks for:

1. A static IPv4 address, if you can.
2. The ability to open TCP ports to the internet, with no address translation in the way.
3. A website you host yourself, with a web server you can configure, such as nginx or Apache, and a domain you control.
4. A valid TLS certificate for the domain.
5. At least 1 GB of memory, and 4 GB is better.

For the Russia campaign the Tor Project also asked for one WebTunnel bridge for each IPv4 address and at least 1 TB of bandwidth a month. Those rules are from that call and not from the guide, so check them for your case.

The steps, in order:

1. **Get the website and certificate working first.** The Tor Project's page shows one way to get a certificate, and shows nginx as the web server. It does not show Caddy or Apache.
2. **Choose a long random path.** The page shows how to make 24 random letters and digits. This is the secret that tells your web server a request is for the bridge. Anyone who asks for a different path gets the ordinary website.
3. **Pass exactly that path to the bridge.** In the web server, forward that one path to the bridge on the same machine, on port 15000, and keep the WebSocket upgrade headers. The page has the full nginx block. Do not retype it from memory.
4. **Start the bridge with Docker.** You set the address of the website with its secret path, a contact address for the bridge, a nickname, and a random port, in a file called `.env`. Use a contact address for the role, such as one for your security team, and never a person's own. Then download the Tor Project's compose file, which is linked from the Docker guide, and start it:

```
docker compose up -d
docker compose exec webtunnel-bridge get-bridge-line.sh
```

The second command prints the bridge line that people put in Tor Browser. The Tor Project's compose file updates the bridge by itself, using Watchtower. Remove that container if you do not want this.

## Handing out the bridge line

Do not publish the bridge line on the gateway's pages, on your website or anywhere else a censor can read it. A bridge that is easy to find is blocked quickly.

- By default a WebTunnel bridge is given out through the Tor Project's own bridge service, [bridges.torproject.org](https://bridges.torproject.org). For most operators that is the right choice, and it needs nothing more from you.
- If you give lines to your own users, treat them as you treat gateway domains: give each group its own, give them through a channel the censor cannot easily read, and expect to replace them. Step 4 of [what to do as an operator](censorship.md#what-to-do-as-an-operator) says why.
- Your sign-in service decides who is told what. A sign-in ticket from onionglass does not carry a bridge line, and this page does not add one.

## What this does not do

- It does not make the gateway safer or harder to block. It is a separate way for people to reach Tor.
- It does not make a bridge unblockable. It can still be blocked, and you may have to start another.
- It does not replace legal advice. Serving people in some countries has rules, and neither this page nor the project can advise on them. See [censorship.md](censorship.md).

## Sources

- [Set up a WebTunnel bridge](https://community.torproject.org/relay/setup/webtunnel/), Tor Project
- [WebTunnel with Docker](https://community.torproject.org/relay/setup/webtunnel/docker/), Tor Project
- [Snowflake standalone proxy, with Docker](https://community.torproject.org/relay/setup/snowflake/standalone/docker/), Tor Project
- [Tor in Russia: a call for more WebTunnel bridges](https://blog.torproject.org/call-for-webtunnel-bridges/), Tor Project
- [Staying ahead of censors in 2025](https://blog.torproject.org/staying-ahead-of-censors-2025/), Tor Project, December 2025
