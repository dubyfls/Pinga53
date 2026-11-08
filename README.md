# Pinga53

**If Pi-hole is a beast, Pinga53 builds the jungle.**

Pi-hole blocks ads. Pinga53 makes your whole network hostile to scammers.
It runs beside your Pi-hole and adds what one blocklist can't give you:
your own recursive resolver, DNS firewalls, and **ScamWall**, a scam and
phishing engine that blocks a domain only when the evidence holds up.

> **Status: v0.1.0-alpha.** It installs in **shadow mode**: it logs every
> domain it *would* block and blocks nothing until you say so. Run it in
> shadow for a few days, read what it caught, then switch it on.

---

## What you get

| Layer | What it does |
| --- | --- |
| **Pi-hole v6** (yours) | Ads, trackers, your lists, your dashboard. Untouched. |
| **Unbound, recursive** | Pi-hole asks Unbound; Unbound asks the root servers itself and checks DNSSEC. No single DNS company sees all your lookups. |
| **RPZ firewall** | Response Policy Zones inside Unbound. Bad names get NXDOMAIN before any connection opens. |
| **ScamWall** | Pulls live phishing and scam feeds, weighs the evidence, and writes its own RPZ zone. |

### Why ScamWall is different

Most blocklists block anything any feed ever named. ScamWall asks harder
questions first.

- **Two independent voices.** By default a domain is blocked only when two
  *independent* sources agree. Two feeds from the same provider count as
  one voice. A feed that re-publishes other feeds doesn't count as
  independent.
- **Every block is explainable.** Each decision records which sources said
  what, and when. `scamwall decide --json` shows the reasons.
- **Blocks expire.** A domain that drops off every source is released
  after a set lifetime (7 days by default).
- **Caps and a kill switch.** Each run and each day can only add or remove
  so many domains. One file (`STOP-AUTOMATIC`) halts automatic blocking.
- **Rights-aware.** Every source carries its provider's terms, quoted and
  dated. Blocking for your own network uses only the local rights (fetch,
  store, combine). Anything published needs the provider's permission to
  redistribute, and the engine refuses it otherwise.
- **Fails safe.** If a feed goes down, existing blocks hold. Nothing is
  silently dropped and nothing is silently added. A broken zone is never
  loaded, and DNS keeps resolving.
- **Your data stays home.** Fetchers only download. Your queries, clients
  and allow list never leave the box.

### Sources in v0.1

| Source | Key needed | Provider terms |
| --- | --- | --- |
| CERT Polska warning list | no | Any use, including commercial |
| Phishing.Database | no | MIT |
| OpenPhish community feed | no | Personal use only |
| abuse.ch URLhaus | free abuse.ch key | Not-for-profit use; commercial use needs a Spamhaus subscription |
| abuse.ch ThreatFox | same key | same as URLhaus |

URLhaus and ThreatFox count as one voice: same provider.

**Pinga53 does not ship feed data.** Your machine downloads each feed
straight from its provider, under that provider's terms. Using Pinga53
commercially (an MSP, an ISP, a product) means you need your own
agreement with each provider whose terms require one.

---

## Install

You need Debian 12+ or Ubuntu 22.04+, systemd, and Pi-hole v6 already
installed and working.

```bash
git clone https://github.com/dubyfls/Pinga53.git
cd Pinga53
sudo ./install.sh --set-upstream
```

`--set-upstream` points Pi-hole at the new Unbound resolver. Leave it off
to keep your current upstream; ScamWall still logs, but Pi-hole won't use it.

See [INSTALL.md](INSTALL.md) for what the installer does, how to add the
abuse.ch key, how to read the shadow log, and how to uninstall.

### Go live

After a few days in shadow mode:

```bash
journalctl -u unbound | grep 'rpz: applied \[scamwall\]'   # what it would have blocked
sudo ./install.sh --enforce                                  # start blocking
```

Stop automatic changes at any time: `sudo touch /etc/pinga53/scamwall/STOP-AUTOMATIC`

---

## Licensing: free for people, paid for profit

Pinga53 is free to use, study, change and share. If you make money with it,
the owner gets paid.

| What | License | In plain words |
| --- | --- | --- |
| **Code** (this repository's software) | [AGPL-3.0-only](LICENSE) | Use it free. If you change it and run it for other people, including as a hosted service, you must publish your changed source under the AGPL. |
| **Closed-source or proprietary use of the code** | [Commercial license](COMMERCIAL.md) | You don't want to publish your changes, or want to ship it inside a product: buy a commercial license. |
| **Pinga53 Data** (lists, zones, scores and metadata published by the Pinga53 project) | [CC BY-NC-SA 4.0](LICENSE-DATA.md) | Free for non-commercial use with credit. **Any commercial use requires a paid license.** |
| **Third-party feed data** | Each provider's own terms | Not ours, not shipped, not relicensed. |

Contributions require the [CLA](CLA.md), so the project can keep offering
both licenses. Questions about commercial use: [COMMERCIAL.md](COMMERCIAL.md).

---

## Project

- [INSTALL.md](INSTALL.md): install, configure, uninstall
- [SECURITY.md](SECURITY.md): report a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md): how to help
- [NOTICE](NOTICE): copyright and third-party notices

Pinga53 is an independent project. It is not affiliated with or endorsed by
Pi-hole LLC, NLnet Labs (Unbound), abuse.ch, Spamhaus, OpenPhish,
CERT Polska / NASK, or Phishing.Database. Names are used only to say what
Pinga53 works with.

Copyright © 2026 Dee ([@dubyfls](https://github.com/dubyfls)). All rights not
granted by the licenses above are reserved.
