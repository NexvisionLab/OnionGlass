# Handing out domains and links without handing them to the censor

Status: pre-alpha. This page is advice, built on what a sign-in ticket carries today. It describes no feature that does not exist, and it says where the work is yours.

## The short version

- **Nothing here stops a censor collecting what you hand out.** A domain, a link or a bridge line that reaches many people will reach the censor too, and a censor that wants them will scrape the places they are given out. What you can do is make that slower, learn which channel leaked, and keep one leak from costing everything.
- **onionglass does not decide who gets a link.** It checks the ticket it is shown. Who is given a ticket, by what route and how many, is decided by your sign-in service, and that part is yours. This page says what to build around.
- **Hand each person the least that works.** A domain that is given to one small group, over a channel that group already uses with you, and rotated when it fails, costs a censor far more than one given to everyone.

## What a censor does to collect

The Tor Project's own report on 2025 found that bridges handed out through a channel that was easy to collect were blocked within months, and that a bot on Telegram was harder to collect and its addresses lasted longer ([Staying ahead of censors in 2025](https://blog.torproject.org/staying-ahead-of-censors-2025/)). That is one project's measurement in a few countries and it will not hold for every censor or for ever. Treat it as a direction.

The research answer to collection is to let new people see little and trust grow with time and vouching, so that an address a stranger can obtain is cheap to lose. The best known design is Lox ([PETS 2023](https://petsymposium.org/popets/2023/popets-2023-0029.php)). onionglass does not have a trust ladder. A sign-in service can build one out of the parts below.

## What onionglass gives you to build with

A sign-in link carries a [ticket](integration-api.md#claims). These are the fields that matter for handing links out:

| Field | What it is | What to use it for |
|---|---|---|
| `grp` | the group the person belongs to | Record which group a link was made for, so that a leak points at a group. |
| `aud` | which gateway the ticket is for | With one domain for each group, a link made for one group does not work on another group's domain. |
| `prf` | the profile the person gets | A newer person can be given a profile with fewer powers: no images, forms or uploads, and a small daily allowance. |
| `exp`, `iat` | when it was made and when it ends | Make a link when it is wanted. It lasts 300 seconds at most, so one that is sent ahead of time is already dead. |
| `jti` | a unique id | The gateway remembers it, so a link works once. |
| `sub` | who the person is | Whatever your service uses to tell people apart. It is recorded in the audit log. |
| `onion` | an address to open on arrival | Optional. |

How a link behaves:

- It works **once**, and for 300 seconds at most, plus 30 seconds either side for clocks that differ. A second use is refused. With cover mode on, which relays need, whoever is shown a used or old link gets the cover page and not a refusal.
- The gateway shows a **Continue** page first, and only the press of its button uses the link up, so a chat program that fetches a link to show a preview does not spend it.
- The link is a web address. It sits in browser history, in a chat and, on the way, in front of every proxy and every [relay](relays.md) that carries the visit. A relay sees every link that passes through it. That is one more reason to keep links short-lived, and one more reason relays must be servers you run.

Domains are the other thing to hand out. [One domain for each group](running.md#entry-domains) is made by command:

```
onionglass domains add --config team.toml --name alpha --domain a.example.net
onionglass domains retire --config team.toml --name alpha
```

A domain that is blocked or leaked is retired, and a new one is added for that group alone.

## What to do around it

These are rules for the service you run. onionglass cannot enforce them.

1. **One domain for each small group, and write down who has which.** If a domain stops working or turns up where it should not, the record tells you which group to move.
2. **Hand out through a channel the person already uses with you.** A message from someone they know is better than a public page, a post or a search result, which a censor can read as well as they can.
3. **Never publish a domain, a link or a bridge line.** Not on your website, not on the cover page, not in a post. A public list is the first thing a censor collects.
4. **Make the link when it is wanted.** Ask for a ticket at the moment the person is about to use it, with a short lifetime, and not before.
5. **Give new people the least.** A first domain can be one that you expect to lose, with a profile that has few powers. More reach, a quieter domain or a bigger allowance can follow time and a vouch from someone who is already trusted. You build that from groups, domains and profiles, since there is no ladder in onionglass.
6. **Limit what one person can ask for.** A person who can request any number of links can be used to collect them all. Allow few, and notice the one who asks for many.
7. **When something is blocked, rotate that group, not everyone.** Retire its domain, add a new one, send the new one over the channel you used before, and treat the old group as known to someone. Do not re-send the old domain to the people who have it.
8. **Keep the record of who asked for what small and private.** It is how you find a leak, and it is also a list that would hurt people if it were taken. Keep it only as long as it helps, and protect it as you would the gateway's audit log.

## Bridge lines

A Tor bridge line, from [the bridge guide](bridges.md#handing-out-the-bridge-line), is handed out by the same rules: never published, over a private channel, rotated when it fails. There is no field for a bridge line in a ticket, and none should be put in a link. A link is a web address that browsers keep and relays see. The Tor Project's own service, [bridges.torproject.org](https://bridges.torproject.org), is the default way to give bridges out, and needs nothing from you.

## What goes wrong anyway

- **A person works for the censor.** One of the people you vouch for gives away what they were given. A group of one limits the harm to that one, and a record of who has what tells you who it was. Neither stops it.
- **A group is large.** The bigger a group, the likelier it has someone who gives the domain away, and the more people move when it is retired.
- **The channel is watched.** If a censor reads the chat where you send links, it has the links. Choose the channel with that in mind, and expect to lose some.
- **The sign-in service is taken.** It can issue a ticket for anyone. Keep its private key where the gateway is not, rotate it as [the ticket guide](integration-api.md#keys) says, and keep tickets short.
- **A country allows only an approved list of services.** Nothing here works then. See [censorship.md](censorship.md#what-this-cannot-do).

See also [what to do as an operator](censorship.md#what-to-do-as-an-operator), which says why distribution matters as much as the address.
