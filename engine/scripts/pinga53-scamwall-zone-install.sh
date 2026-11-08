#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# pinga53-scamwall-zone-install.sh — validate a ScamWall-written RPZ zone
# under /var/lib/scamwall/out and, iff every check passes, install it
# atomically at /etc/unbound/rpz/scamwall.zone with the previous copy kept
# beside it as scamwall.zone.prev. Reloads Unbound the same way
# /usr/local/sbin/pinga53-nrd-update.sh does — unbound-control rpz_reload
# preferred, then unbound-control reload, then systemctl reload/restart.
#
# Any failed check keeps the currently-installed zone untouched, appends a
# reason to /var/log/pinga53/scamwall-install.log, and exits non-zero. No
# rollback is needed: nothing has replaced the live zone until every check
# has passed.
#
# Runs as root. Called by pinga53-scamwall-zone-install.service on the
# hourly timer, 20 minutes after scamwall-run.service finishes.
#
# Usage:
#   pinga53-scamwall-zone-install.sh [--dry-run]
#
# Env overrides (defaulted for production; tests set them to stubs):
#   SCAMWALL_OUT ZONE_TARGET PROTECTED_FILE LOG_FILE ZONE_ORIGIN
#   MAX_ZONE_BYTES MAX_ZONE_ENTRIES MAX_ADD_DELTA MAX_REMOVE_DELTA
#   NAMED_CHECKZONE UNBOUND_CONTROL SYSTEMCTL SHA256SUM REQUIRE_ROOT

set -uo pipefail

: "${SCAMWALL_OUT:=/var/lib/scamwall/out}"
: "${ZONE_TARGET:=/etc/unbound/rpz/scamwall.zone}"
: "${PROTECTED_FILE:=/etc/pinga53/scamwall/protected.txt}"
: "${LOG_FILE:=/var/log/pinga53/scamwall-install.log}"
: "${ZONE_ORIGIN:=scamwall.rpz.}"
: "${MAX_ZONE_BYTES:=8388608}"    # 8 MiB — a ScamWall zone larger than this is either wrong or a mistake.
: "${MAX_ZONE_ENTRIES:=200000}"   # 200 000 CNAME records — 2× ORDER-11 writer's own cap.
: "${MAX_ADD_DELTA:=10000}"       # hosts added in a single run.
: "${MAX_REMOVE_DELTA:=10000}"    # hosts removed in a single run.
: "${NAMED_CHECKZONE:=named-checkzone}"
: "${UNBOUND_CONTROL:=unbound-control}"
: "${SYSTEMCTL:=systemctl}"
: "${SHA256SUM:=sha256sum}"
: "${REQUIRE_ROOT:=1}"

DRY_RUN=false

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "pinga53-scamwall-zone-install: unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ------------------------------------------------------------------ helpers
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# log_reject <reason...> — record a REJECT event to the audit log and print
# the same line to stderr so systemd's journal has it too. Uses a lock-less
# append (>>) because bash's single write() of a short line is atomic on
# POSIX regular files up to PIPE_BUF, which is 4 KiB on Linux; a longer
# reason would be truncated by the kernel, not interleaved.
log_reject() {
  local msg="$*"
  local ts line
  ts="$(now_utc)"
  line="$ts REJECT $msg"
  # Ensure the log directory exists; refuse silently if we cannot create
  # it (e.g. tests running without write access to /var/log/pinga53).
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
  printf 'REJECT: %s\n' "$msg" >&2
}

log_ok() {
  local msg="$*"
  local ts line
  ts="$(now_utc)"
  line="$ts INSTALL $msg"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
  printf 'INSTALL: %s\n' "$msg"
}

# extract_soa_serial <zone-file> — echo the SOA serial number of the zone or
# empty if none was found. The writer emits SOA as
#   @ IN SOA localhost. hostmaster.<origin> ( <serial> 3600 600 604800 <ttl> )
# The serial is the 4th "IN SOA … ( <serial>" token. Falls back to a scan
# so a hand-edited but syntactically-valid variant is still recognised.
extract_soa_serial() {
  local f="$1"
  awk '
    /IN[ \t]+SOA/ {
      # tokenise; the serial is the first token after the "("
      for (i=1; i<=NF; i++) {
        if ($i == "(") { print $(i+1); exit }
      }
    }' "$f"
}

# extract_hosts <zone-file> — echo the owner names of every CNAME line.
extract_hosts() {
  local f="$1"
  awk '
    /^[[:space:]]*;/ { next }
    /IN[ \t]+CNAME[ \t]+\.[ \t]*$|IN[ \t]+CNAME[ \t]+\.[ \t]*;/ {
      # owner is the first field; strip a trailing dot for comparison
      name=$1
      sub(/\.$/, "", name)
      if (name != "@") print name
    }' "$f" | sort -u
}

# host_under_protected <host> <protected-list-file>
# Returns 0 (true) if <host> falls under any suffix in the protected file,
# 1 otherwise. A "suffix" is a whole-label match: pinga53.example matches
# pinga53.example and www.pinga53.example, but never notpinga53.example.
# Blank lines and lines starting with '#' in the protected file are ignored.
host_under_protected() {
  local host="$1" protected="$2"
  [ -r "$protected" ] || return 1
  local line
  while IFS= read -r line; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    if [ "$host" = "$line" ]; then
      return 0
    fi
    if grep -q -E "\\.${line//./\\.}\$" <<<"$host"; then
      return 0
    fi
  done < "$protected"
  return 1
}

# --------------------------------------------------------------- root guard
if [ "$REQUIRE_ROOT" = "1" ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "pinga53-scamwall-zone-install: must be run as root" >&2
  exit 1
fi

if $DRY_RUN; then
  echo "DRY RUN — checks will run but nothing installs or reloads"
fi

# ------------------------------------------------------------ preconditions
zone_in="${SCAMWALL_OUT}/scamwall.zone"
sha_in="${SCAMWALL_OUT}/scamwall.zone.sha256"

if [ ! -f "$zone_in" ]; then
  log_reject "no scamwall.zone in ${SCAMWALL_OUT}"
  exit 1
fi
if [ ! -f "$sha_in" ]; then
  log_reject "no scamwall.zone.sha256 next to the zone (${SCAMWALL_OUT})"
  exit 1
fi

# ------------------------------------------------------ check 1: sha256 file
# The sha256 file's canonical shape is "sha256sum -c" output:
#   <hex>  scamwall.zone
# so it can be re-verified with `sha256sum -c` too.
expected_sha="$(awk 'NR==1{print $1}' "$sha_in")"
if ! grep -Eq '^[0-9a-f]{64}$' <<<"$expected_sha"; then
  log_reject "sha256 file first token is not a 64-char lowercase hex"
  exit 1
fi
actual_sha="$("$SHA256SUM" "$zone_in" | awk '{print $1}')"
if [ "$expected_sha" != "$actual_sha" ]; then
  log_reject "sha256 mismatch: expected ${expected_sha} got ${actual_sha}"
  exit 1
fi

# --------------------------------------------------------- check 2: size cap
size="$(wc -c <"$zone_in" | tr -d ' ')"
if [ "$size" -gt "$MAX_ZONE_BYTES" ]; then
  log_reject "zone is ${size} bytes, over the ${MAX_ZONE_BYTES}-byte cap"
  exit 1
fi

# ------------------------------------------------------- check 3: entry cap
mapfile -t new_hosts < <(extract_hosts "$zone_in")
new_count=${#new_hosts[@]}
if [ "$new_count" -gt "$MAX_ZONE_ENTRIES" ]; then
  log_reject "zone has ${new_count} entries, over the ${MAX_ZONE_ENTRIES} cap"
  exit 1
fi

# ------------------------------------------------------ check 4: SOA serial
new_serial="$(extract_soa_serial "$zone_in")"
if [ -z "$new_serial" ]; then
  log_reject "zone has no SOA serial"
  exit 1
fi
old_serial=""
if [ -f "$ZONE_TARGET" ]; then
  old_serial="$(extract_soa_serial "$ZONE_TARGET")"
fi
# The same zone, byte for byte, is not a regression: scamwall-run leaves the
# zone untouched when nothing changed, so the hourly timer sees the installed
# file again. Report it as unchanged and do nothing (no reload). Only a
# DIFFERENT zone must carry a strictly greater serial.
if [ -f "$ZONE_TARGET" ] && cmp -s "$zone_in" "$ZONE_TARGET"; then
  log_ok "zone unchanged (serial ${new_serial}); nothing to install"
  exit 0
fi
if [ -n "$old_serial" ]; then
  if ! [ "$new_serial" -gt "$old_serial" ] 2>/dev/null; then
    log_reject "SOA serial ${new_serial} is not strictly greater than the installed ${old_serial}"
    exit 1
  fi
fi

# --------------------------------------------------------- check 5: deltas
if [ -f "$ZONE_TARGET" ]; then
  mapfile -t old_hosts < <(extract_hosts "$ZONE_TARGET")
  old_set="$(mktemp)"
  new_set="$(mktemp)"
  trap 'rm -f "$old_set" "$new_set"' EXIT
  printf '%s\n' "${old_hosts[@]}" | sort -u >"$old_set"
  printf '%s\n' "${new_hosts[@]}" | sort -u >"$new_set"
  adds="$(comm -13 "$old_set" "$new_set" | wc -l | tr -d ' ')"
  removes="$(comm -23 "$old_set" "$new_set" | wc -l | tr -d ' ')"
  if [ "$adds" -gt "$MAX_ADD_DELTA" ]; then
    log_reject "add delta ${adds} > ${MAX_ADD_DELTA}"
    exit 1
  fi
  if [ "$removes" -gt "$MAX_REMOVE_DELTA" ]; then
    log_reject "remove delta ${removes} > ${MAX_REMOVE_DELTA}"
    exit 1
  fi
else
  adds="$new_count"
  removes="0"
fi

# ------------------------------------------------------ check 6: protected
if [ -f "$PROTECTED_FILE" ]; then
  for host in "${new_hosts[@]}"; do
    if host_under_protected "$host" "$PROTECTED_FILE"; then
      log_reject "host ${host} is under a suffix in ${PROTECTED_FILE}"
      exit 1
    fi
  done
fi

# --------------------------------------------------- check 7: named-checkzone
if ! command -v "$NAMED_CHECKZONE" >/dev/null 2>&1; then
  log_reject "${NAMED_CHECKZONE} not installed — refusing to install an unvalidated zone"
  exit 1
fi
if ! "$NAMED_CHECKZONE" -q "$ZONE_ORIGIN" "$zone_in" >/dev/null 2>&1; then
  # Rerun without -q so the log captures WHY.
  reason="$("$NAMED_CHECKZONE" "$ZONE_ORIGIN" "$zone_in" 2>&1 | tr '\n' ' ')"
  log_reject "named-checkzone rejected the zone: ${reason}"
  exit 1
fi

# --------------------------------------------------- everything passed: install
if $DRY_RUN; then
  log_ok "DRY RUN — all checks passed. Would install ${zone_in} at ${ZONE_TARGET} (serial ${new_serial}, entries ${new_count}, adds ${adds}, removes ${removes})"
  exit 0
fi

# .prev handling: only if a live zone is present. Never overwrite .prev
# with the CANDIDATE — the whole point is a working baseline to fall back
# to, and the candidate has been the live zone for zero seconds so far.
if [ -f "$ZONE_TARGET" ]; then
  if ! cp -p "$ZONE_TARGET" "${ZONE_TARGET}.prev.tmp"; then
    log_reject "could not stage previous zone as ${ZONE_TARGET}.prev.tmp"
    exit 1
  fi
  if ! mv -f "${ZONE_TARGET}.prev.tmp" "${ZONE_TARGET}.prev"; then
    rm -f "${ZONE_TARGET}.prev.tmp"
    log_reject "could not promote ${ZONE_TARGET}.prev.tmp to .prev"
    exit 1
  fi
fi

# Atomic install: cp+rename via a same-directory temp.
target_dir="$(dirname "$ZONE_TARGET")"
mkdir -p "$target_dir"
tmp_new="$(mktemp -p "$target_dir" .scamwall.zone.XXXXXX)" || {
  log_reject "could not create install temp in ${target_dir}"
  exit 1
}
if ! cp "$zone_in" "$tmp_new"; then
  rm -f "$tmp_new"
  log_reject "could not stage the new zone at ${tmp_new}"
  exit 1
fi
chmod 0644 "$tmp_new"
# unbound reads the file back as its own user; matching ownership avoids a
# quiet EACCES on the next reload.
chown unbound:unbound "$tmp_new" 2>/dev/null || true
if ! mv -f "$tmp_new" "$ZONE_TARGET"; then
  rm -f "$tmp_new"
  log_reject "could not install ${tmp_new} at ${ZONE_TARGET}"
  exit 1
fi

log_ok "installed ${zone_in} at ${ZONE_TARGET} (serial ${new_serial}, entries ${new_count}, adds ${adds}, removes ${removes})"

# ------------------------------------------------ reload — same as pinga53-nrd-update.sh
reload_status="none"
if command -v "$UNBOUND_CONTROL" >/dev/null 2>&1 && "$UNBOUND_CONTROL" status >/dev/null 2>&1; then
  # Named per the $ORIGIN we just installed under, without the trailing dot.
  zone_name="${ZONE_ORIGIN%.}"
  if "$UNBOUND_CONTROL" rpz_reload "$zone_name" >/dev/null 2>&1; then
    reload_status="rpz_reload"
  elif "$UNBOUND_CONTROL" reload >/dev/null 2>&1; then
    reload_status="reload"
  else
    reload_status="reload-failed"
  fi
else
  if "$SYSTEMCTL" reload unbound >/dev/null 2>&1; then
    reload_status="systemctl-reload"
  elif "$SYSTEMCTL" restart unbound >/dev/null 2>&1; then
    reload_status="systemctl-restart"
  else
    reload_status="systemctl-failed"
  fi
fi

case "$reload_status" in
  reload-failed|systemctl-failed|none)
    log_reject "reload after install failed (${reload_status}) — the new zone is on disk but Unbound may not have picked it up"
    exit 1
    ;;
esac
log_ok "unbound reload OK via ${reload_status}"
exit 0
