# Operator responsibilities

Status: draft. This is guidance, not legal advice. Laws about handling, viewing and transmitting content differ between countries. Take legal advice for your own situation before you run an instance for other people.

## Read this first

When you run onionglass for other people, **you are the gateway.** You can see every onion address your visitors open and every page they view. Your visitors' network addresses reach your server. Your server fetches content from sites you have never reviewed, and some of it will be illegal or harmful. You are responsible for what your instance is used for.

## Choose the right mode

| Mode | When it is appropriate |
|---|---|
| Personal | You are the only user, on your own machine. You carry the risk of what you look at. |
| Team | Everyone using it is a colleague you can name, under an agreement with you, for a work purpose. |
| Public | Strangers use it. This brings the most legal duty and the most abuse. It is off by default and needs an explicit acknowledgement in the configuration. |

## Before opening to anyone else

1. **Tell visitors the truth.** Show the standing banner, keep the first-run acknowledgement, and publish a privacy notice that says what you log and for how long.
2. **Have a way to report and remove.** Publish a contact for abuse and takedown requests, and read it. See the [abuse procedure](abuse-procedure.md).
3. **Keep logs small.** Do not log page or form bodies. Decide whether to keep visitor addresses at all, and for how long. Delete on schedule.
4. **Keep the blocklists current** and review what the name checks and reports flag.
5. **Limit by default.** Use the restricted profile for people you do not know. Do not allow logins, posting, uploads or downloads for them.
6. **Protect the host.** Harden the server before installing, keep Tor and the gateway updated, restrict outbound connections to Tor, the session store and your configured hooks, and keep secrets out of the repository and the configuration files you share.
7. **Plan for the domain being flagged.** A domain that serves onion content will attract blocklists and browser warnings. Keep it separate from any site you care about.
8. **Understand your jurisdiction.** Some places restrict the viewing or transmission of certain material even for research. Know the rules and keep your visitors informed.

## What the software does and does not do for you

It withholds images by default and never fetches them unless revealed. It supports blocklists and name checks. It stops serving when its safety dependencies fail. It keeps logs free of bodies and passwords. It gives you kill switches.

It cannot decide what is lawful in your country, cannot see the content of every site, and cannot make an unsafe use safe. Those remain yours.

## Evidence

If you capture pages as evidence, store captures encrypted, keep a record of who captured what and when, and limit access. A capture can contain material that is itself regulated. Do not share one without checking the rules that apply.
