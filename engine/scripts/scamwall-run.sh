#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# scamwall-run.sh — the real end-to-end ScamWall run that
# scamwall-run.service.ExecStart invokes on Pinga53.
#
# WHY THIS SHIM EXISTS
#
# The old unit had `ExecStart=/usr/local/bin/scamwall rpz --out … --snapshot …`.
# The `rpz` subcommand requires six paths (--evidence --signers --registry
# --policy --ledger plus either --allowlist OR --source-outage), takes no
# `--snapshot` flag, and freezes when any of them is absent. Running `rpz`
# directly on a freshly-provisioned Pinga53 — where the signed evidence
# document, the signer authority and the pinga53-local-format allowlist are
# all PRODUCED BY THIS SCRIPT, not shipped — exited 2 with the usage text
# (`scamwall-run.service: Main process exited, code=exited, status=2`).
# Every phase of the deploy after it then saw an empty /var/lib/scamwall/out.
#
# WHAT THE PIPELINE PRODUCES, PHASE BY PHASE
#
#   acquire       scamwall acquire               -> $STATE_DIR/evidence.json
#                 (signed EvidenceManifest, schema 2; records: either the
#                  caller-supplied list or the single-record sentinel below)
#
#   translate     this script                    -> $STATE_DIR/allowlist.rpz.json
#                 (pinga53-allowlist-export writes the Pinga53 snapshot format
#                  — snapshot_pinga53.go — but `scamwall rpz --allowlist` reads
#                  the ORDER-11 format — snapshot.go. Two readers of two
#                  shapes; we translate once here rather than carrying the
#                  mismatch through the pipeline.)
#
#   rpz           scamwall rpz                   -> $STATE_DIR/out/scamwall.zone
#                                                    + <same>.record (sealed)
#
#   sha256        this script                    -> $STATE_DIR/out/scamwall.zone.sha256
#
# THE SENTINEL
#
# `feed.LoadEvidenceFile` refuses an evidence doc with zero records
# (`ErrNoRecords`), on the reasonable grounds that an empty manifest is
# indistinguishable from a bug in the fetcher. On a Pinga53 install that
# has no feed fetchers wired yet, the shim therefore passes `scamwall
# acquire` one sentinel record: `pinga53-liveness-sentinel.invalid`,
# source_id `pinga53-local`, classification `benign`. The record IS admitted
# (its signer has authority over `pinga53-local`), does NOT propose a block
# (benign isn't harmful) and keeps the pipeline exercised end-to-end. When
# real fetchers land, SENTINEL_RECORDS is set to a file they write.
#
# EXIT CODES (from scamwall rpz, documented at cmd/scamwall/rpz.go):
#   0 — zone was written / is already correct / was dry-run reported
#   3 — nothing written, a person has to look (review)
#   4 — nothing written, inputs weren't trustworthy (frozen) [tolerated: the
#       existing zone is left alone, as --source-outage asked for]
#   5 — the writer's safety rules refused [tolerated for the first run: an
#       empty standing set with no --allow-empty is a refusal; we always
#       pass --allow-empty here]
#   other — treat as failure, let systemd mark the unit failed.
set -euo pipefail

: "${SCAMWALL_BIN:=/usr/local/bin/scamwall}"
: "${CONFIG_DIR:=/etc/pinga53/scamwall}"
: "${STATE_DIR:=/var/lib/scamwall}"
: "${EVIDENCE_PATH:=${STATE_DIR}/evidence.json}"
: "${SENTINEL_RECORDS:=${STATE_DIR}/sentinel-records.json}"
: "${RECORDS_DIR:=${STATE_DIR}/records}"
: "${SIGNER_KEY:=${CONFIG_DIR}/signer.key}"
: "${SIGNER_KEY_ID:=pinga53-local-1}"
: "${FEED_ID:=pinga53-local}"
: "${MAC_KEY:=${CONFIG_DIR}/mac.key}"
: "${POLICY:=${CONFIG_DIR}/policy.json}"
: "${REGISTRY:=${CONFIG_DIR}/registry.json}"
: "${SIGNERS:=${CONFIG_DIR}/signers.json}"
: "${LEDGER:=${STATE_DIR}/ledger.json}"
: "${ALLOWLIST_SRC:=${STATE_DIR}/allowlist.json}"
: "${ALLOWLIST_RPZ:=${STATE_DIR}/allowlist.rpz.json}"
: "${ZONE_OUT:=${STATE_DIR}/out/scamwall.zone}"
: "${ZONE_ORIGIN:=scamwall.rpz.}"

log() { printf '[%s] scamwall-run: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "FATAL: $*" >&2; exit 1; }

for required in "$SCAMWALL_BIN" "$SIGNER_KEY" "$MAC_KEY" \
                "$POLICY" "$REGISTRY" "$SIGNERS" "$LEDGER" "$ALLOWLIST_SRC"; do
  [ -r "$required" ] || die "missing input: $required (run deploy-scamwall.sh to provision)"
done
mkdir -p "$(dirname "$ZONE_OUT")"

# -------------------------------------------------------- merge fresh records
# scamwall-fetch.service writes per-source records files into $RECORDS_DIR;
# merge any that are newer than 2 × their declared cadence into a single
# JSON array for `scamwall acquire --records`. If nothing is fresh (or the
# directory is missing), fall back to the sentinel below.
#
# `scamwall merge-records` writes the array to stdout and a one-line
# summary to stderr. A non-empty array is fresh; `[]` means no fresh file
# was found.
log "phase: merge fresh records (from ${RECORDS_DIR})"
merged_records=$(mktemp)
merge_cleanup() { rm -f "$merged_records" "${tmp_records:-}" "${merge_err:-}"; }
trap merge_cleanup EXIT

# stdout is the JSON array; stderr is the summary. They must not share the
# file (the summary line made the array invalid JSON).
merge_err=$(mktemp)
if "$SCAMWALL_BIN" merge-records --dir "$RECORDS_DIR" \
     --min-sources "${MERGE_MIN_SOURCES:-2}" --max-records "${MERGE_MAX_RECORDS:-90000}" \
     >"$merged_records" 2>"$merge_err"; then
  while IFS= read -r l; do log "$l"; done <"$merge_err"
else
  while IFS= read -r l; do log "$l"; done <"$merge_err"
  log "warning: merge-records exited non-zero; falling back to sentinel"
  : >"$merged_records"
fi

# -------------------------------------------------------- acquire -> evidence
log "phase: acquire (signing evidence with ${SIGNER_KEY_ID})"
records_arg=""
# merged_records is non-empty and not `[]` means fresh records are present.
if [ -s "$merged_records" ] && [ "$(head -c 2 "$merged_records" | tr -d ' \n')" != "[]" ]; then
  records_arg="--records $merged_records"
  record_count=$(grep -c '"source_id"' "$merged_records" || true)
  log "acquire: using ${record_count} merged record(s) from ${RECORDS_DIR}"
elif [ -s "$SENTINEL_RECORDS" ]; then
  records_arg="--records $SENTINEL_RECORDS"
  log "acquire: using operator-supplied SENTINEL_RECORDS (${SENTINEL_RECORDS})"
else
  # Inline sentinel. Not written to a persistent path on purpose: a sentinel
  # that lingered under $CONFIG_DIR could be read later as a configured
  # record, and the point of the sentinel is that it is NOT configuration.
  tmp_records=$(mktemp)
  cat >"$tmp_records" <<'EOF'
[
  {
    "type": "domain",
    "value": "pinga53-liveness-sentinel.invalid",
    "source_id": "pinga53-local",
    "source_record_id": "sentinel-1",
    "classification": "benign",
    "state": "active"
  }
]
EOF
  records_arg="--records $tmp_records"
  log "acquire: no fresh records and no operator SENTINEL_RECORDS; using inline liveness sentinel"
fi

# shellcheck disable=SC2086  # $records_arg intentionally expands to two tokens.
"$SCAMWALL_BIN" acquire \
  --signer-key "$SIGNER_KEY" \
  --key-id     "$SIGNER_KEY_ID" \
  --feed-id    "$FEED_ID" \
  --out        "$EVIDENCE_PATH" \
  $records_arg

# -------------------------------------------------------- translate allowlist
log "phase: translate pinga53-snapshot -> rpz-snapshot ($ALLOWLIST_RPZ)"
python3 - "$ALLOWLIST_SRC" "$ALLOWLIST_RPZ" <<'PY'
# Translate the pinga53-allowlist-export output into the shape
# scamwall rpz --allowlist reads. The two have the same intent and
# different field names; see snapshot_pinga53.go and snapshot.go.
import json, os, sys, tempfile
src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    doc = json.load(f)
if doc.get("schema") != 1:
    sys.exit(f"allowlist {src} has schema={doc.get('schema')!r}; expected 1")
origin = (
    f"pinga53-allowlist-export schema=1 generated_at={doc.get('generated_at')!r} "
    f"source_sha256={doc.get('source_sha256','')[:12]}…"
)
out = {
    "schema_version":   1,
    "origin":           origin,
    "exact_allow":      doc.get("exact_allow", []),
    "regex_allow":      doc.get("regex_allow", []),
    "subscribed_allow": doc.get("subscribed_allow", []),
    "subscribed_read":  True,
}
dirn = os.path.dirname(dst) or "."
fd, tmp = tempfile.mkstemp(dir=dirn, prefix=".allowlist-rpz-", suffix=".json.tmp")
with os.fdopen(fd, "wb") as f:
    f.write((json.dumps(out, indent=2, sort_keys=False) + "\n").encode("utf-8"))
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, dst)
PY

# -------------------------------------------------------- rpz
log "phase: rpz (writing $ZONE_OUT)"
set +e
"$SCAMWALL_BIN" rpz \
  --evidence  "$EVIDENCE_PATH" \
  --signers   "$SIGNERS" \
  --registry  "$REGISTRY" \
  --policy    "$POLICY" \
  --ledger    "$LEDGER" \
  --allowlist "$ALLOWLIST_RPZ" \
  --out       "$ZONE_OUT" \
  --origin    "$ZONE_ORIGIN" \
  --allow-empty \
  --key       "$MAC_KEY"
rpz_rc=$?
set -e
case "$rpz_rc" in
  0) log "rpz: zone written / already correct" ;;
  3) log "rpz: review required (exit 3) — leaving existing zone alone" ;;
  4) log "rpz: inputs not trustworthy (freeze, exit 4) — leaving existing zone alone" ;;
  5) log "rpz: writer refused (exit 5) — leaving existing zone alone" ;;
  *) die "rpz failed with exit $rpz_rc" ;;
esac

# -------------------------------------------------------- sha256 companion
# Written beside the zone so the installer (pinga53-scamwall-zone-install.sh)
# can verify the file it is about to publish is the one this run produced.
# Only computed when the zone itself is present — a review/freeze exit 3/4/5
# left the previous zone (if any) in place; its sha256 is still valid.
if [ -f "$ZONE_OUT" ]; then
  log "phase: sha256 companion ($ZONE_OUT.sha256)"
  tmp_sha="${ZONE_OUT}.sha256.tmp"
  ( cd "$(dirname "$ZONE_OUT")" && sha256sum "$(basename "$ZONE_OUT")" >"$tmp_sha" )
  mv "$tmp_sha" "${ZONE_OUT}.sha256"
fi

log "done (rpz exit=$rpz_rc)"
exit 0
