#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# install.sh: install Pinga53 (ScamWall engine + Unbound RPZ) beside an
# existing Pi-hole v6 on Debian or Ubuntu.
#
#   sudo ./install.sh                    # engine in SHADOW mode + dashboard on https://<host>:8053
#   sudo ./install.sh --set-upstream     # also point Pi-hole at Unbound (127.0.0.1#5335)
#   sudo ./install.sh --install-pihole   # install Pi-hole first (upstream installer), then continue
#   sudo ./install.sh --no-dashboard     # engine only (do not install the dashboard)
#   sudo ./install.sh --enforce          # switch an installed Pinga53 from shadow to blocking
#   sudo ./install.sh --uninstall        # remove Pinga53 + dashboard; keep Pi-hole, keep local state
#
# What it does, in order:
#   1. checks: root, Debian/Ubuntu, systemd, Pi-hole v6 (pihole-FTL)
#   2. apt: unbound, bind9-dnsutils, bind9-utils, python3, sqlite3, curl, ca-certificates
#   3. Go >= 1.26 (official go.dev tarball, sha256-verified) if missing
#   4. builds the engine as an unprivileged user -> /usr/local/bin/scamwall
#   5. system user `scamwall`, state in /var/lib/scamwall, config in /etc/pinga53/scamwall
#   6. a local signing key (generated here, never leaves the box) + signers.json
#   7. Unbound: a recursive resolver on 127.0.0.1@5335 (only if you have no
#      Unbound config yet) and its OWN drop-in /etc/unbound/unbound.conf.d/pinga53.conf
#      with the ScamWall RPZ zone in passthru (shadow) mode
#   8. systemd timers: fetch (30 min), decide (hourly), install zone (hourly),
#      allow-list export (15 min), baseline + metrics (daily)
#   9. one fetch + decide + zone install, then verifies DNS still resolves
#
# It never edits Pi-hole's own files, never removes another Unbound config,
# and never blocks anything until you run --enforce.
set -Eeuo pipefail
umask 022
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$HERE/engine"
CONF=/etc/pinga53/scamwall
STATE=/var/lib/scamwall
BIN=/usr/local/bin/scamwall
UNBOUND_DROPIN=/etc/unbound/unbound.conf.d/pinga53.conf
UNBOUND_RECURSIVE=/etc/unbound/unbound.conf.d/pinga53-recursive.conf
RPZ_DIR=/etc/unbound/rpz
ZONE=$RPZ_DIR/scamwall.zone
GO_MIN=1.26
TIMERS="pinga53-allowlist-export.timer scamwall-fetch.timer scamwall-run.timer pinga53-scamwall-zone-install.timer pinga53-baseline.timer scamwall-metrics.timer"

say()  { printf '\033[1;32m[pinga53]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[pinga53]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[pinga53] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

MODE=install SET_UPSTREAM=false INSTALL_PIHOLE=false DASHBOARD=true
for a in "$@"; do
  case "$a" in
    --set-upstream) SET_UPSTREAM=true ;;
    --install-pihole) INSTALL_PIHOLE=true ;;
    --no-dashboard) DASHBOARD=false ;;
    --enforce) MODE=enforce ;;
    --uninstall) MODE=uninstall ;;
    -h|--help) sed -n '4,30p' "$0"; exit 0 ;;
    *) die "unknown option: $a (see --help)" ;;
  esac
done

# Dashboard paths.
DASH_SRC="$HERE/dashboard"
DASH_ROOT=/opt/pinga53/dashboard
DASH_VENV="$DASH_ROOT/venv"
DASH_USER=pinga53
DASH_CONF=/etc/pinga53/dashboard
DASH_ENV=/etc/pinga53/dashboard.env
DASH_STATE=/var/lib/pinga53
DASH_LOG=/var/log/pinga53
DASH_TLS="$DASH_CONF/tls"
DASH_HELPER=/usr/local/sbin/pinga53-helper
DASH_SUDOERS=/etc/sudoers.d/pinga53-dashboard
DASH_UNIT=/etc/systemd/system/pinga53-dashboard.service

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 $*"
command -v systemctl >/dev/null || die "systemd is required"

# ------------------------------------------------------------------ helpers
rpz_stanza() {  # $1 = passthru|block
  local override=""
  [ "$1" = passthru ] && override='    rpz-action-override: passthru'
  cat <<EOF
# Managed by Pinga53 install.sh. Remove with: sudo ./install.sh --uninstall
# ScamWall RPZ zone. passthru = SHADOW (log only); no override = ENFORCE.
server:
    # RPZ needs the respip module in front of the validator.
    module-config: "respip validator iterator"

rpz:
    name: "scamwall.rpz"
    zonefile: "$ZONE"
$override
    rpz-log: yes
    rpz-log-name: "scamwall"
EOF
}

reload_unbound() {
  unbound-checkconf >/dev/null || die "unbound-checkconf failed; nothing reloaded (see: unbound-checkconf)"
  systemctl reload unbound 2>/dev/null || systemctl restart unbound
}

# ------------------------------------------------------------------ uninstall
if [ "$MODE" = uninstall ]; then
  say "stopping timers"
  for t in $TIMERS; do systemctl disable --now "$t" 2>/dev/null || true; done
  for u in $TIMERS; do rm -f "/etc/systemd/system/$u" "/etc/systemd/system/${u%.timer}.service"; done

  if [ -f "$DASH_UNIT" ]; then
    say "stopping and removing the dashboard unit"
    systemctl disable --now pinga53-dashboard.service 2>/dev/null || true
    rm -f "$DASH_UNIT"
  fi
  rm -f "$DASH_SUDOERS" "$DASH_HELPER"
  systemctl daemon-reload

  rm -f "$UNBOUND_DROPIN" "$ZONE" "$ZONE.prev"
  if command -v unbound-checkconf >/dev/null; then reload_unbound; fi
  rm -f "$BIN" /usr/local/sbin/scamwall-run /usr/local/sbin/pinga53-scamwall-zone-install.sh /usr/local/sbin/pinga53-baseline-snapshot.sh
  rm -rf /opt/pinga53/scamwall "$DASH_ROOT"
  say "removed. Kept: $CONF (engine keys/policy), $STATE (history),"
  say "       $DASH_CONF (dashboard config), $DASH_STATE (dashboard DB), Unbound, Pi-hole."
  say "to remove the dashboard DB too: sudo rm -rf $DASH_CONF $DASH_STATE $DASH_LOG && sudo userdel pinga53"
  say "to remove the engine state too:  sudo rm -rf $CONF $STATE && sudo userdel scamwall"
  exit 0
fi

# ------------------------------------------------------------------ enforce
if [ "$MODE" = enforce ]; then
  [ -f "$UNBOUND_DROPIN" ] || die "Pinga53 is not installed (no $UNBOUND_DROPIN)"
  cp -a "$UNBOUND_DROPIN" "$UNBOUND_DROPIN.shadow-backup"
  rpz_stanza block >"$UNBOUND_DROPIN"
  if ! unbound-checkconf >/dev/null; then
    cp -a "$UNBOUND_DROPIN.shadow-backup" "$UNBOUND_DROPIN"; die "unbound-checkconf failed; shadow mode restored"
  fi
  reload_unbound
  say "ENFORCE on: ScamWall entries now resolve to NXDOMAIN."
  say "back to shadow: sudo cp $UNBOUND_DROPIN.shadow-backup $UNBOUND_DROPIN && sudo systemctl reload unbound"
  say "stop all automatic blocking instantly: sudo touch $CONF/STOP-AUTOMATIC"
  exit 0
fi

# ------------------------------------------------------------------ 1. checks
. /etc/os-release 2>/dev/null || true
case "${ID:-}:${ID_LIKE:-}" in
  debian:*|ubuntu:*|*:*debian*) ;;
  *) die "Debian or Ubuntu required (found ${PRETTY_NAME:-unknown})" ;;
esac
if ! command -v pihole-FTL >/dev/null; then
  if $INSTALL_PIHOLE; then
    say "Pi-hole not found. Installing it from the official installer (interactive)."
    curl -sSL https://install.pi-hole.net | bash
    command -v pihole-FTL >/dev/null || die "Pi-hole installer did not produce pihole-FTL"
  else
    die "Pi-hole v6 not found. Install Pi-hole first (https://docs.pi-hole.net), or re-run with --install-pihole."
  fi
fi
ftl_major="$(pihole-FTL --version 2>/dev/null | grep -oE 'v[0-9]+' | head -1 | tr -d v || true)"
[ "${ftl_major:-0}" -ge 6 ] || die "Pi-hole FTL v6 or newer required (found ${ftl_major:-unknown})"
[ -d "$ENGINE/cmd/scamwall" ] || die "run from the repository root (engine/ not found next to install.sh)"
say "Pi-hole FTL v$ftl_major on ${PRETTY_NAME:-Linux}"

# ------------------------------------------------------------------ 2. packages
say "installing packages"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
apt-get update -qq
apt-get install -y -qq unbound bind9-dnsutils bind9-utils python3 python3-venv sqlite3 curl ca-certificates tar openssl rsync >/dev/null

# ------------------------------------------------------------------ 3. Go
go_ok() { command -v go >/dev/null && go version | grep -qE "go(1\.(2[6-9]|[3-9][0-9])|[2-9])\."; }
export PATH=/usr/local/go/bin:$PATH
if ! go_ok; then
  arch="$(dpkg --print-architecture)"; case "$arch" in amd64|arm64) ;; armhf) arch=armv6l ;; *) die "unsupported arch $arch" ;; esac
  say "installing Go (>= $GO_MIN) for linux-$arch from go.dev"
  meta="$(curl -fsSL 'https://go.dev/dl/?mode=json')"
  read -r gofile gosha < <(python3 -I -c '
import json, sys
arch = sys.argv[1]
for rel in json.loads(sys.stdin.read()):
    if not rel.get("stable"): continue
    for f in rel["files"]:
        if f["os"] == "linux" and f["arch"] == arch and f["kind"] == "archive":
            print(f["filename"], f["sha256"]); sys.exit(0)
sys.exit(1)' "$arch" <<<"$meta") || die "could not find a Go release for linux-$arch"
  tmp="$(mktemp -d)"
  curl -fsSL "https://go.dev/dl/$gofile" -o "$tmp/$gofile"
  echo "$gosha  $tmp/$gofile" | sha256sum -c --quiet - || die "Go download checksum mismatch"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "$tmp/$gofile" && rm -rf "$tmp"
  go_ok || die "Go install failed"
fi
say "$(go version)"

# ------------------------------------------------------------------ 4. build (unprivileged)
say "building the ScamWall engine (as an unprivileged user)"
id scamwall >/dev/null 2>&1 || useradd --system --home-dir "$STATE" --shell /usr/sbin/nologin scamwall
build="$(mktemp -d)"; cp -a "$ENGINE/." "$build/"; chown -R nobody:nogroup "$build"
runuser -u nobody -- env -i HOME="$build" PATH="/usr/local/go/bin:/usr/bin:/bin" GOCACHE="$build/.cache" \
  GOPATH="$build/.gopath" GOFLAGS=-mod=readonly CGO_ENABLED=0 \
  sh -c "cd '$build' && go build -trimpath -o '$build/scamwall.bin' ./cmd/scamwall" \
  || die "build failed"
install -m 0755 "$build/scamwall.bin" "$BIN"; rm -rf "$build"
"$BIN" version >/dev/null || die "built binary does not run"

# ------------------------------------------------------------------ 5. dirs, scripts, config
install -d -o scamwall -g scamwall -m 0755 "$STATE" "$STATE/out"
install -d -o scamwall -g scamwall -m 0750 "$STATE/records" "$STATE/cache" "$STATE/baseline" "$STATE/metrics" "$STATE/journal"
install -d -o root -g scamwall -m 0750 "$CONF" "$CONF/secrets"
install -d -m 0755 /var/log/pinga53 /opt/pinga53/scamwall/scripts "$RPZ_DIR"
install -m 0755 "$ENGINE/scripts/scamwall-run.sh" /usr/local/sbin/scamwall-run
install -m 0755 "$ENGINE/scripts/pinga53-scamwall-zone-install.sh" /usr/local/sbin/
install -m 0755 "$ENGINE/scripts/pinga53-baseline-snapshot.sh" /usr/local/sbin/
install -m 0755 "$ENGINE/scripts/pinga53-allowlist-export.py" /opt/pinga53/scamwall/scripts/
for f in registry.json policy.json protected.txt brands.txt; do
  if [ -f "$CONF/$f" ]; then say "  keeping existing $CONF/$f"
  else install -o root -g scamwall -m 0640 "$ENGINE/config/$f" "$CONF/$f"; fi
done
[ -f "$STATE/ledger.json" ] || { printf '{\n  "schema_version": 1,\n  "owned": []\n}\n' >"$STATE/ledger.json"; chown scamwall:scamwall "$STATE/ledger.json"; chmod 0600 "$STATE/ledger.json"; }

# ------------------------------------------------------------------ 6. local signer
KEY_ID=pinga53-local-1
if [ ! -f "$CONF/signer.key" ] || [ ! -f "$CONF/signers.json" ]; then
  say "generating the local signing key (stays on this machine)"
  rm -f "$CONF/signer.key"
  pubd="$(mktemp -d)"
  "$BIN" gen-signer-key --out "$CONF/signer.key" --pub-out "$pubd/pub" >/dev/null
  chown scamwall:scamwall "$CONF/signer.key"; chmod 0600 "$CONF/signer.key"
  pub="$(tr -d '\n' <"$pubd/pub")"; rm -rf "$pubd"
  ids="$(python3 -I -c 'import json,sys; print(" ".join(s["source_id"] for s in json.load(open(sys.argv[1]))["sources"] if s.get("enabled")))' "$CONF/registry.json")"
  python3 -I - "$CONF/signers.json" "$KEY_ID" "$pub" $ids <<'PY'
import json, sys
out, kid, pub, *ids = sys.argv[1:]
doc = {"schema_version": 1,
       "note": "Pinga53 local signer. The fetcher downloads each enabled source directly from its provider, so this key asserts for each of them; independence between sources is decided by registry lineage.",
       "signers": [{"key_id": kid, "public_key": pub,
                    "asserts_source_ids": ["pinga53-local", *ids], "aggregator_for": [],
                    "note": "generated by install.sh; the private seed never leaves this machine"}]}
json.dump(doc, open(out, "w"), indent=2)
PY
  chown root:scamwall "$CONF/signers.json"; chmod 0640 "$CONF/signers.json"
fi
if [ ! -f "$CONF/mac.key" ]; then
  head -c 48 /dev/urandom >"$CONF/mac.key"; chown scamwall:scamwall "$CONF/mac.key"; chmod 0600 "$CONF/mac.key"
fi

# ------------------------------------------------------------------ 7. Unbound
if ! grep -RqsE "^[[:space:]]*port:[[:space:]]*5335" /etc/unbound/unbound.conf /etc/unbound/unbound.conf.d/; then
  say "no Unbound resolver on port 5335 yet: adding one on 127.0.0.1@5335"
  install -m 0644 "$HERE/unbound/pinga53-recursive.conf" "$UNBOUND_RECURSIVE"
else
  say "existing Unbound resolver on 5335 found: left untouched (Pinga53 only adds $UNBOUND_DROPIN)"
fi
[ -f "$UNBOUND_DROPIN" ] || rpz_stanza passthru >"$UNBOUND_DROPIN"
[ -f "$ZONE" ] || printf '$ORIGIN scamwall.rpz.\n$TTL 60\n@ IN SOA localhost. hostmaster.scamwall.rpz. ( 1 3600 600 604800 60 )\n@ IN NS localhost.\n' >"$ZONE"
chown unbound:unbound "$ZONE" 2>/dev/null || true
systemctl enable --now unbound >/dev/null 2>&1 || true
reload_unbound

if $SET_UPSTREAM; then
  say "pointing Pi-hole upstream DNS at Unbound (127.0.0.1#5335)"
  pihole-FTL --config dns.upstreams '["127.0.0.1#5335"]' >/dev/null
fi

# ------------------------------------------------------------------ 8. timers
for f in "$ENGINE"/systemd/*.service "$ENGINE"/systemd/*.timer; do install -m 0644 "$f" /etc/systemd/system/; done
systemctl daemon-reload

# ------------------------------------------------------------------ 9. first run + verify
say "first fetch (CERT Polska, Phishing.Database, OpenPhish; abuse.ch needs a key)"
systemctl start pinga53-allowlist-export.service || warn "allow-list export failed (see: journalctl -u pinga53-allowlist-export)"
systemctl start scamwall-fetch.service || warn "some sources failed to fetch (see: journalctl -u scamwall-fetch)"
systemctl start scamwall-run.service || die "first decision run failed (see: journalctl -u scamwall-run)"
systemctl start pinga53-scamwall-zone-install.service || die "zone install failed (see: journalctl -u pinga53-scamwall-zone-install)"
reload_unbound
for t in $TIMERS; do systemctl enable --now "$t" >/dev/null; done
ans="$(dig +short +time=5 @127.0.0.1 -p 5335 example.com | head -1)"
[ -n "$ans" ] || die "Unbound does not resolve example.com after install; run: sudo ./install.sh --uninstall"

# ------------------------------------------------------------------ 10. dashboard
if $DASHBOARD; then
  [ -d "$DASH_SRC/backend" ] || die "dashboard/ not found next to install.sh; cannot install dashboard"
  say "installing the Pinga53 dashboard"

  id "$DASH_USER" >/dev/null 2>&1 \
    || useradd --system --home-dir "$DASH_STATE" --shell /usr/sbin/nologin "$DASH_USER"
  # read-only access to ScamWall state (zone, records headers, metrics, journal)
  usermod -aG scamwall "$DASH_USER"

  install -d -o root -g root -m 0755 /opt/pinga53 "$DASH_ROOT"
  install -d -o root -g "$DASH_USER" -m 0750 "$DASH_CONF"
  install -d -o "$DASH_USER" -g "$DASH_USER" -m 0750 "$DASH_TLS"
  install -d -o "$DASH_USER" -g "$DASH_USER" -m 0750 "$DASH_STATE" "$DASH_STATE/audit" "$DASH_LOG"

  # application source
  rsync -a --delete --exclude 'node_modules' --exclude 'build.sh' --exclude '__pycache__' \
      --exclude 'tests' --exclude 'pytest.ini' \
      "$DASH_SRC/backend/"  "$DASH_ROOT/backend/"
  rsync -a --delete --exclude 'node_modules' --exclude 'build.sh' --exclude 'src' \
      --exclude 'tsconfig.json' --exclude 'vite.config.ts' --exclude 'package.json' \
      --exclude 'package-lock.json' --exclude '.gitignore' --exclude 'index.html' \
      "$DASH_SRC/frontend/dist/" "$DASH_ROOT/frontend/dist/"
  chown -R root:root "$DASH_ROOT/backend" "$DASH_ROOT/frontend"

  # python venv + pinned deps
  if [ ! -x "$DASH_VENV/bin/python" ]; then
    python3 -m venv "$DASH_VENV"
  fi
  "$DASH_VENV/bin/pip" install -q --upgrade pip
  "$DASH_VENV/bin/pip" install -q --require-hashes -r "$DASH_SRC/backend/requirements.txt" \
    || "$DASH_VENV/bin/pip" install -q -r "$DASH_SRC/backend/requirements.txt"
  cat >"$DASH_VENV/bin/pinga53d" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
exec "$DASH_VENV/bin/python" -m backend.main "\$@"
EOF
  chmod 0755 "$DASH_VENV/bin/pinga53d"
  ln -sf "$DASH_VENV/bin/pinga53d" /usr/local/bin/pinga53d
  (cd "$DASH_ROOT" && ln -sfn "$DASH_SRC/frontend/dist" "$DASH_ROOT/frontend/dist" 2>/dev/null || true)

  # env file (skip if already present)
  if [ ! -f "$DASH_ENV" ]; then
    install -o root -g "$DASH_USER" -m 0640 "$DASH_SRC/deploy/dashboard.env.example" "$DASH_ENV"
    jwt_key="$(openssl rand -hex 32)"
    sed -i "s|^PINGA53_SECRET_KEY=.*|PINGA53_SECRET_KEY=$jwt_key|" "$DASH_ENV"
    unset jwt_key
    say "  wrote $DASH_ENV (fill in PINGA53_PIHOLE_APP_PASSWORD)"
  else
    say "  keeping existing $DASH_ENV"
  fi

  # helper + sudoers
  install -m 0755 "$DASH_SRC/deploy/pinga53-helper" "$DASH_HELPER"
  tmp_sudo="$(mktemp)"
  install -m 0440 "$DASH_SRC/deploy/sudoers.d/pinga53-dashboard" "$tmp_sudo"
  visudo -cf "$tmp_sudo" >/dev/null || die "sudoers drop-in fails visudo check"
  install -m 0440 -o root -g root "$tmp_sudo" "$DASH_SUDOERS"
  rm -f "$tmp_sudo"

  # systemd unit
  install -m 0644 "$DASH_SRC/deploy/systemd/pinga53-dashboard.service" "$DASH_UNIT"
  systemctl daemon-reload

  # TLS cert (self-signed first-run)
  bash "$DASH_SRC/deploy/gen-tls-cert.sh" "$DASH_TLS" "$DASH_USER"
  if ! grep -q '^PINGA53_TLS_CERT=.' "$DASH_ENV"; then
    sed -i "s|^PINGA53_TLS_CERT=.*|PINGA53_TLS_CERT=$DASH_TLS/cert.pem|" "$DASH_ENV"
    sed -i "s|^PINGA53_TLS_KEY=.*|PINGA53_TLS_KEY=$DASH_TLS/key.pem|"   "$DASH_ENV"
  fi

  # bootstrap the first administrator and print the one-time password.
  if ! systemd-run --quiet --wait --uid="$DASH_USER" \
      --property=EnvironmentFile="$DASH_ENV" \
      --property=WorkingDirectory="$DASH_ROOT" \
      /usr/local/bin/pinga53d list-users 2>/dev/null | grep -q .; then
    say "  provisioning the first administrator"
    systemd-run --quiet --wait --uid="$DASH_USER" \
      --property=EnvironmentFile="$DASH_ENV" \
      --property=WorkingDirectory="$DASH_ROOT" \
      /usr/local/bin/pinga53d bootstrap
  fi

  systemctl enable --now pinga53-dashboard.service
  say "  dashboard: https://$(hostname -s):8053"
fi

say "installed in SHADOW mode: ScamWall logs what it would block and blocks nothing."
say "  status:       journalctl -u scamwall-run -n 20"
say "  hits so far:  journalctl -u unbound | grep 'rpz: applied \\[scamwall\\]'"
say "  abuse.ch key: see INSTALL.md (optional, adds URLhaus + ThreatFox)"
say "  go live:      sudo ./install.sh --enforce   (after a few days in shadow)"
if $DASHBOARD; then
  say "  Pi-hole admin stays at http://$(hostname -s)/admin (set its password with 'sudo pihole setpassword')"
fi
$SET_UPSTREAM || say "  Pi-hole still uses its current upstream; add --set-upstream to route it through Unbound."
