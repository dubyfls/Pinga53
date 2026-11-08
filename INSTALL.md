# Installing Pinga53

## Requirements

- Debian 12+ or Ubuntu 22.04+ (amd64 or arm64; Raspberry Pi OS 64-bit works)
- systemd
- **Pi-hole v6**, installed and working: <https://docs.pi-hole.net>
- About 300 MB of disk and 512 MB of RAM to spare
- Internet access to download Go, Go modules and the feeds

## Install

```bash
git clone https://github.com/dubyfls/Pinga53.git
cd Pinga53
sudo ./install.sh --set-upstream
```

| Option | Effect |
| --- | --- |
| *(none)* | Install engine (shadow mode) and the dashboard. Pi-hole upstream left as-is. |
| `--set-upstream` | Also set Pi-hole's upstream DNS to Unbound (`127.0.0.1#5335`). |
| `--install-pihole` | Install Pi-hole first (upstream installer, interactive), then continue. |
| `--no-dashboard` | Engine only; skip the dashboard install. |
| `--enforce` | Switch an installed Pinga53 from shadow to blocking. |
| `--uninstall` | Remove Pinga53 (engine + dashboard). Keeps Pi-hole, Unbound, keys, history. |

### What the installer does

1. Checks for root, Debian/Ubuntu, systemd and Pi-hole FTL v6.
2. Installs `unbound`, `bind9-dnsutils`, `bind9-utils`, `python3`, `sqlite3`, `curl`.
3. Installs Go from go.dev (checksum-verified) if Go 1.26+ is missing.
4. Builds the ScamWall engine as an unprivileged user into `/usr/local/bin/scamwall`.
5. Creates the `scamwall` system user, `/var/lib/scamwall` (state) and
   `/etc/pinga53/scamwall` (config).
6. Generates a local signing key. It never leaves the machine.
7. Unbound:
   - adds a recursive resolver on `127.0.0.1@5335`, only if none exists on port 5335;
   - adds its own file, `/etc/unbound/unbound.conf.d/pinga53.conf`, with the
     ScamWall RPZ zone in **passthru (shadow)** mode.
8. Installs and starts systemd timers:

   | Timer | Every | Job |
   | --- | --- | --- |
   | `scamwall-fetch` | 30 min | download the feeds |
   | `scamwall-run` | 1 h | weigh evidence, decide, write the zone |
   | `pinga53-scamwall-zone-install` | 1 h | validate and load the zone into Unbound |
   | `pinga53-allowlist-export` | 15 min | read Pi-hole's allow list (read-only) so it is never blocked |
   | `pinga53-baseline` | daily | snapshot other RPZ zones for comparison |
   | `scamwall-metrics` | daily | shadow hits, overlap, lead time |

9. Runs one fetch, decision and zone install, then checks DNS still resolves.

It never edits Pi-hole's own files (except the upstream, with
`--set-upstream`) and never removes another Unbound config.

## Optional: abuse.ch key (URLhaus + ThreatFox)

Get a free Auth-Key at <https://auth.abuse.ch/>, then:

```bash
sudo install -o root -g scamwall -m 0640 /dev/stdin /etc/pinga53/scamwall/secrets/abusech.key <<< 'YOUR-KEY'
```

Without the key, both sources are skipped, not failed. abuse.ch data is
free for not-for-profit use only.

## Reading shadow mode

```bash
journalctl -u scamwall-run -n 30                         # last decision
journalctl -u unbound | grep 'rpz: applied \[scamwall\]' # what would have been blocked
ls /var/lib/scamwall/metrics/                            # daily metrics (JSON)
```

Never block a domain: add it to Pi-hole's allow list, or one per line in
`/etc/pinga53/scamwall/protected.txt`.

## Go live

```bash
sudo ./install.sh --enforce
```

Back to shadow mode:

```bash
sudo cp /etc/unbound/unbound.conf.d/pinga53.conf.shadow-backup /etc/unbound/unbound.conf.d/pinga53.conf
sudo systemctl reload unbound
```

Stop all automatic changes immediately: `sudo touch /etc/pinga53/scamwall/STOP-AUTOMATIC`
(delete the file to resume).

## Tuning

`/etc/pinga53/scamwall/policy.json` is yours to edit; upgrades never
overwrite it.

| Field | Default | Meaning |
| --- | --- | --- |
| `min_independent_sources` | 2 | independent voices needed to block |
| `automatic.max_additions_per_run` | 200 | new blocks per run |
| `automatic.max_additions_per_day` | 1000 | new blocks per day |
| `automatic.block_lifetime` | 168h | how long a block lasts after its sources go quiet |
| `automatic.on_source_outage` | hold_existing_blocks | keep blocks when a feed is down |

## Dashboard (v0.2.0-alpha)

By default `install.sh` also installs the Pinga53 dashboard: a small FastAPI
service that serves a React UI with login, MFA, an audit view, and a
ScamWall control page. It runs on **port 8053 over HTTPS** (Pi-hole v6 owns
80/443). Pi-hole's own admin UI stays at `/admin` and is unaffected.

### Ports and TLS

- `https://<host>:8053` — the dashboard.
- First-start generates a **self-signed certificate** at
  `/etc/pinga53/dashboard/tls/{cert.pem,key.pem}` with a SAN list covering
  the system hostname and each non-loopback IPv4 address. Browsers will
  warn you once; accept it, then bookmark the page.
- To use your own certificate, set `PINGA53_TLS_CERT` / `PINGA53_TLS_KEY`
  in `/etc/pinga53/dashboard.env` to the paths of your cert and key.

### Pi-hole app password

The dashboard calls the Pi-hole v6 REST API (status + today's query counts)
server-side. The browser never handles the password. Set the password on
Pi-hole, then paste it into `/etc/pinga53/dashboard.env` once:

```bash
sudo pihole setpassword
sudo editor /etc/pinga53/dashboard.env    # PINGA53_PIHOLE_APP_PASSWORD=...
sudo systemctl restart pinga53-dashboard
```

The Pi-hole web UI continues to work with that same password — Pinga53
doesn't change anything about how Pi-hole authenticates you.

### First login

At the end of `install.sh` a one-time administrator password is printed. Go
to `https://<host>:8053`, log in as `administrator` with that password,
then **the UI forces a password change and MFA enrollment** (scan the QR
with any TOTP app). After that you have ten recovery codes; save them.

If you missed the password, re-run the bootstrap command (keeping the DB
and the `SECRET_KEY` from `/etc/pinga53/dashboard.env`):

```bash
sudo systemctl stop pinga53-dashboard
sudo -u pinga53 EnvironmentFile=/etc/pinga53/dashboard.env pinga53d bootstrap
sudo systemctl start pinga53-dashboard
```

### Changing your password

From the dashboard's **Account** page: enter current password, new password,
and (if MFA is enrolled) a current TOTP code. The same page lets you
reset your MFA secret and regenerate recovery codes.

### Owner actions on the ScamWall page

Admins can toggle shadow↔enforce, pause and resume automatic blocking, add
or remove protected hosts, and run one fetch+decide+install cycle on
demand. Each action requires re-entering a fresh TOTP code and is
dispatched through a tiny setuid-free root helper
(`/usr/local/sbin/pinga53-helper`) whose subcommand set is fixed. Every
action is audited.

## Upgrade

```bash
cd Pinga53 && git pull && sudo ./install.sh
```

Your keys, policy, protected list and history are kept.

## Uninstall

```bash
sudo ./install.sh --uninstall
```

This removes the timers, engine binary, Pinga53's Unbound file, and the
dashboard unit, helper, and sudoers drop-in. It keeps:

- `/etc/pinga53/scamwall` and `/var/lib/scamwall` (engine state);
- `/etc/pinga53/dashboard`, `/var/lib/pinga53`, `/var/log/pinga53`
  (dashboard config + DB + audit log).

The command prints how to remove those too. If you used `--set-upstream`,
set Pi-hole's upstream back in its web interface under **Settings → DNS**.

## Troubleshooting

### Quick health check

```bash
systemctl status unbound pihole-FTL --no-pager          # both should be active
dig +short @127.0.0.1 -p 5335 example.com               # Unbound answers
dig +short @127.0.0.1 example.com                        # Pi-hole answers
sudo unbound-checkconf                                   # config is valid
systemctl list-timers --no-pager | grep -E 'scamwall|pinga53'   # 6 timers listed
sudo -u scamwall scamwall doctor --offline --no-credential            # engine config + trust material
```

### Logs

```bash
journalctl -u scamwall-fetch -n 50 --no-pager            # feed downloads
journalctl -u scamwall-run -n 50 --no-pager              # decisions, zone written
journalctl -u pinga53-scamwall-zone-install -n 20 --no-pager   # zone loaded into Unbound
journalctl -u unbound -n 50 --no-pager                   # resolver errors
sudo cat /var/log/pinga53/scamwall-install.log           # zone install history
```

### Run a step now (instead of waiting for its timer)

```bash
sudo systemctl start scamwall-fetch.service
sudo systemctl start scamwall-run.service
sudo systemctl start pinga53-scamwall-zone-install.service
```

### What is blocked (or would be, in shadow mode)

```bash
grep -c CNAME /etc/unbound/rpz/scamwall.zone             # entries in the zone
grep CNAME /etc/unbound/rpz/scamwall.zone                # the hosts
journalctl -u unbound | grep 'rpz: applied \[scamwall\]' # lookups that hit it
```

### Common problems

| Symptom | Cause and fix |
| --- | --- |
| `unbound-checkconf failed` | Another file defines a conflicting `rpz:` or `port:`. Run `sudo unbound-checkconf` to see the file and line. |
| The zone stays empty | A domain needs two independent sources. Check `journalctl -u scamwall-fetch` for failing feeds, then `journalctl -u scamwall-run` for the decision. |
| `missing input: .../registry.json` | Wrong owner on the config. Fix: `sudo chown root:scamwall /etc/pinga53/scamwall/*.json && sudo chmod 0640 /etc/pinga53/scamwall/*.json` |
| URLhaus / ThreatFox say "skipped" | No abuse.ch key. See "Optional: abuse.ch key" above. |
| A site you need is blocked | Add it to Pi-hole's allow list, or to `/etc/pinga53/scamwall/protected.txt`, then run the three steps above. |
| DNS stops resolving | `sudo touch /etc/pinga53/scamwall/STOP-AUTOMATIC`, then `sudo ./install.sh --uninstall` if needed. Pi-hole keeps working. |

### Passwords

Pinga53 v0.1 has no web UI and no password of its own. You manage it with
the commands above. The dashboard you log in to is Pi-hole's.

```bash
sudo pihole setpassword          # change the Pi-hole web UI password (prompts)
```

You can also change it in the Pi-hole web UI under **Settings → Web interface / API**.
