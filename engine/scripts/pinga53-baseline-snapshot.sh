#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# pinga53-baseline-snapshot.sh — daily snapshot of the free RPZ stack.
#
# WHY THIS EXISTS
#
# `scamwall metrics` needs a day-over-day baseline of the free stack to
# compute shadow_hits, false_block_candidates, lead-time and the §4
# fields that go into ORDER 17's gate decision. The baseline is a JSON
# document holding the host entries from the free RPZ zones that were
# live on a given UTC day.
#
# WHAT IS IN SCOPE
#
# Live zones under /etc/unbound/rpz/:
#   urlhaus.zone    — abuse.ch malware URLs projected to hosts
#   nrd.zone        — newly-registered-domain source
#   allowlist.local — household never-block list (NOT snapshotted; see below)
#   canary.local    — resolver test fixture (NOT snapshotted)
#
# This script snapshots urlhaus.zone and nrd.zone ONLY. allowlist.local is
# the household's own list — snapshotting it would leak household-private
# data into the baseline archive, and it is NEVER a block source, so it
# cannot contribute to shadow_hits or any §4 metric. canary.local is a
# test fixture whose contents are not evidence about anything.
#
# WHAT A HOST LOOKS LIKE IN RPZ
#
# The writer in internal/rpz emits one "host CNAME ." line per entry:
#
#     bad.example.com  CNAME  .
#
# The parser reads that shape and nothing else. A line with a different
# RR type (SOA, NS, TXT) is skipped; a line without CNAME . is skipped;
# the origin header and comments are skipped.
#
# OUTPUT
#
# /var/lib/scamwall/baseline/<UTC_DATE>.json, mode 0640, scamwall:scamwall:
#
#     {
#       "schema_version": 1,
#       "generated_at": "2026-11-07T06:12:00Z",
#       "zones": {
#         "urlhaus": ["bad1.example.com", "bad2.example.com"],
#         "nrd":     ["new1.example.com", "new2.example.com"]
#       }
#     }
#
# Written atomically via a temp file + mv; re-running on the same day
# overwrites the file for that date (idempotent — a newer snapshot is a
# strictly more recent reading).
#
# USAGE
#
#     pinga53-baseline-snapshot.sh [--rpz-dir DIR] [--out-dir DIR] [--date YYYY-MM-DD]
#
# All flags are optional. The service unit calls this script with no
# arguments; tests supply synthetic directories via the flags.

set -euo pipefail

: "${RPZ_DIR:=/etc/unbound/rpz}"
: "${OUT_DIR:=/var/lib/scamwall/baseline}"
: "${BASELINE_DATE:=}"

while [ $# -gt 0 ]; do
  case "$1" in
    --rpz-dir) RPZ_DIR="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --date)    BASELINE_DATE="$2"; shift 2 ;;
    -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
    *) echo "pinga53-baseline-snapshot: unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -d "$RPZ_DIR" ] || { echo "pinga53-baseline-snapshot: RPZ_DIR not a dir: $RPZ_DIR" >&2; exit 1; }
mkdir -p "$OUT_DIR"

if [ -z "$BASELINE_DATE" ]; then
  BASELINE_DATE="$(date -u +%F)"
fi
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# A small awk program that extracts the host from every line of shape
#
#     host.example.com[.]  [IN]  CNAME  .
#
# The trailing dot on the host is optional and is stripped. Case is
# normalised to lower. A line that does not match emits nothing.
extract_hosts() {
  awk '
    # Skip comments and SOA / $ORIGIN / $TTL lines.
    /^[[:space:]]*;/ || /^\$/ { next }
    {
      # Normalise whitespace: collapse tabs/spaces so the parse is one shape.
      line = tolower($0)
      n = split(line, f, /[[:space:]]+/)
      if (n < 3) { next }
      # Shape 1:  host  cname  .
      # Shape 2:  host  in     cname  .
      host  = f[1]
      type  = ""
      rdata = ""
      if (n >= 4 && f[2] == "in") {
        type  = f[3]
        rdata = f[4]
      } else {
        type  = f[2]
        rdata = f[3]
      }
      if (type != "cname") { next }
      if (rdata != ".")    { next }
      # Strip a trailing dot from the host.
      if (substr(host, length(host), 1) == ".") {
        host = substr(host, 1, length(host) - 1)
      }
      if (host == "") { next }
      print host
    }
  ' "$1" | sort -u
}

tmp="$(mktemp "$OUT_DIR/.baseline-XXXXXX.json.tmp")"
trap 'rm -f "$tmp"' EXIT

{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "generated_at": "%s",\n' "$generated_at"
  printf '  "zones": {\n'

  first_zone=1
  # ORDER 17B §4: snapshot urlhaus and nrd ONLY. allowlist.local is the
  # household's own list and is never snapshotted.
  for pair in "urlhaus:urlhaus.zone" "nrd:nrd.zone"; do
    label="${pair%%:*}"
    file="${pair#*:}"
    path="$RPZ_DIR/$file"
    if [ "$first_zone" -eq 1 ]; then
      first_zone=0
    else
      printf ',\n'
    fi
    printf '    "%s": [' "$label"
    if [ -f "$path" ]; then
      first_host=1
      while IFS= read -r h; do
        [ -z "$h" ] && continue
        if [ "$first_host" -eq 1 ]; then
          first_host=0
        else
          printf ','
        fi
          printf '"%s"' "$h"
      done < <(extract_hosts "$path")
    fi
    printf ']'
  done

  printf '\n  }\n'
  printf '}\n'
} > "$tmp"

out="$OUT_DIR/${BASELINE_DATE}.json"
mv "$tmp" "$out"
# Best-effort ownership fix when running as root; if we are already the
# scamwall user, chown is a no-op.
if [ "$(id -u)" = "0" ]; then
  chown scamwall:scamwall "$out" 2>/dev/null || true
fi
chmod 0640 "$out" 2>/dev/null || true
trap - EXIT
echo "pinga53-baseline-snapshot: wrote $out" >&2
