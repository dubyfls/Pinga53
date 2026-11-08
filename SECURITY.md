# Security policy

Pinga53 sits in your DNS path, so we take security reports seriously.

## Reporting

Please report vulnerabilities **privately** through GitHub:
**Security → Report a vulnerability** on
<https://github.com/dubyfls/Pinga53>. Do not open a public issue.

Include what you found, how to reproduce it, and the version
(`scamwall version`). You should hear back within 7 days.

## Supported versions

Pinga53 is alpha. Only the latest release gets fixes.

## Design notes

- The ScamWall engine runs as an unprivileged `scamwall` user. Only the
  zone installer runs as root, and it validates the zone
  (`named-checkzone`, size and change caps, protected names) before
  Unbound sees it.
- Fetchers only download. They never send your queries, clients or
  allow list anywhere.
- Evidence is signed with a key generated on your machine. The private
  key never leaves it.
- API keys live in `/etc/pinga53/scamwall/secrets/` (root:scamwall, 0640)
  and are redacted from logs and errors.
