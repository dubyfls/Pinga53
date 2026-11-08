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
| *(none)* | Install in shadow mode. Pi-hole's upstream is left as it is. |
| `--set-upstream` | Also set Pi-hole's upstream DNS to Unbound (`127.0.0.1#5335`). |
| `--enforce` | Switch an installed Pinga53 from shadow to blocking. |
| `--uninstall` | Remove Pinga53. Keeps Pi-hole, Unbound, your keys and history. |

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

## Upgrade

```bash
cd Pinga53 && git pull && sudo ./install.sh
```

Your keys, policy, protected list and history are kept.

## Uninstall

```bash
sudo ./install.sh --uninstall
```

This removes the timers, binary and Pinga53's Unbound file. It keeps
`/etc/pinga53/scamwall` and `/var/lib/scamwall`; the command prints how to
remove those too. If you used `--set-upstream`, set Pi-hole's upstream back
in its web interface under **Settings → DNS**.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `unbound-checkconf failed` | `sudo unbound-checkconf`; another file may define a conflicting `rpz:` or `port:` |
| Nothing in the zone after a day | `journalctl -u scamwall-fetch` and `journalctl -u scamwall-run`; a domain needs two independent sources |
| DNS stops resolving | `sudo ./install.sh --uninstall` removes Pinga53's Unbound file and reloads Unbound |
