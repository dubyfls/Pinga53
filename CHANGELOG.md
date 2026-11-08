<!--
SPDX-License-Identifier: AGPL-3.0-only
-->
# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/) within the
pre-1.0 alpha window (minor bumps may carry breaking changes).

## [v0.2.0-alpha] — unreleased

### Added
- **Pinga53 dashboard.** A small FastAPI + React + TypeScript app that
  runs on `https://<host>:8053` alongside Pi-hole v6. Pi-hole's own web
  UI stays at `/admin`.
- **Auth.** Argon2id password hashing, TOTP MFA (QR enrollment,
  recovery codes), per-IP login rate limit, 8h JWT sessions. Forced
  password change + MFA enrollment on first login.
- **ScamWall view.** Read-only surface over the engine's on-disk state:
  mode (shadow/enforce), STOP-AUTOMATIC flag, standing-hosts list with
  filter, per-source feed health, last decision run, last zone install.
- **Owner actions.** Admin-only, each gated by a fresh TOTP step-up and
  audited: stop-on/off, mode-shadow/enforce, protect-add/remove, run-now.
- **Root helper** (`/usr/local/sbin/pinga53-helper`) with a fixed
  seven-entry subcommand allowlist and strict argument validation, invoked
  by the non-root service user through a `visudo -cf`-validated sudoers
  drop-in. The dashboard itself never runs as root.
- **Audit log.** Append-only, hash-chained; verifiable with
  `pinga53d audit-verify`.
- **Installer flags.** `--install-pihole` (run the official Pi-hole
  installer first), `--no-dashboard` (engine only). `--uninstall` now also
  removes the dashboard unit, helper, and sudoers drop-in.
- **Self-signed TLS bootstrap.** First start generates an ECDSA P-256
  certificate at `/etc/pinga53/dashboard/tls/` with SANs for the box
  hostname and its non-loopback IPv4 addresses.
- **Tests.** 87 Python tests (auth/MFA/account, admin routes, ScamWall
  reader against fixture files, helper argument validation) + 19
  shell-driven helper tests.

### Changed
- Engine Go tests still pass unchanged.

### Security
- `pinga53-helper`'s host validator refuses control characters and
  whitespace up front, so a multi-line argv value cannot bypass the
  per-line anchors of the shape regex.

### Notes
- The committed `dashboard/frontend/dist/` is the exact output of
  `dashboard/frontend/build.sh` against the pinned lockfile. Operators
  therefore do not need Node on the box.

## [v0.1.0-alpha] — 2026-11

Initial public release: ScamWall engine + Unbound RPZ, systemd timers,
`install.sh`, documentation.
