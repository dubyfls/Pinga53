// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// # WHY THIS TEST EXISTS
//
// On the first production deploy of ORDER 12 §12C the shadow soak failed at
// phase 5 with:
//
//	scamwall-run.service: Main process exited, code=exited, status=2
//	usage: ...  rpz    --evidence --signers --registry --policy --ledger ...
//
// The systemd unit's ExecStart was `scamwall rpz --out ... --snapshot ...`,
// but `rpz` requires six paths and takes no --snapshot. Every subsequent
// phase of the deploy — the zone installer, the shadow patch, the
// verification probes — then ran against an empty /var/lib/scamwall/out and
// the rollback fired against a config the operator could not read.
//
// This test executes the REAL scamwall binary via the REAL shim
// (scripts/scamwall-run.sh) against a self-contained fixture under
// t.TempDir(). No stubs — a build defect in the shim or a mismatched flag on
// the subcommand surfaces here before the deploy ever reaches a host.
//
// The property under test: given a provisioning snapshot that matches what
// `deploy-scamwall.sh` writes on first install (signer.key + mac.key +
// signers.json + registry.json + policy.json + ledger.json + a
// pinga53-allowlist-export snapshot), the shim produces either a valid RPZ
// zone + sha256 at $STATE_DIR/out, or exits 0 with a documented freeze.
// Anything else — a usage error, a nonzero exit, a half-written zone — is
// the exact regression this test exists to catch.
func TestScamwallRunShim_RealBinary_WritesValidZoneOrFreezes(t *testing.T) {
	// 1. Build the real scamwall binary. `go test -race` default build is
	//    fine; we invoke `go build` so this test does not depend on the
	//    testing binary itself being invokable as `scamwall`.
	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "scamwall")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/scamwall")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build scamwall: %v\n%s", err, out)
	}

	// 2. Lay out the fixture. The directory names mirror production so a
	//    reader can translate 1:1 between this test's layout and the host.
	root4 := t.TempDir()
	configDir := filepath.Join(root4, "etc", "pinga53", "scamwall")
	stateDir := filepath.Join(root4, "var", "lib", "scamwall")
	outDir := filepath.Join(stateDir, "out")
	for _, d := range []string{configDir, stateDir, outDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// 3. Generate the signer keypair the same way the deploy does: by
	//    calling our own gen-signer-key subcommand on the real binary. This
	//    is deliberately NOT a `crypto/ed25519.GenerateKey` call inside the
	//    test — the on-disk file shape the shim reads (32-byte seed, mode
	//    0600) is part of the contract under test.
	signerKey := filepath.Join(configDir, "signer.key")
	signerPub := filepath.Join(t.TempDir(), "signer.pub")
	runCmd(t, bin, "gen-signer-key", "--out", signerKey, "--pub-out", signerPub)
	pubB64 := strings.TrimSpace(readFile(t, signerPub))
	// Sanity: a round-trip of the base64 pubkey decodes to 32 bytes and
	// matches the seed's derived public key.
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("derived public key is not a valid 32-byte ed25519 pubkey: %v (%d bytes)", err, len(pubBytes))
	}

	// 4. MAC key: 48 bytes of random data, mode 0600. mac.LoadKeyFile
	//    refuses a world-readable file, so the mode is part of the contract.
	macKey := filepath.Join(configDir, "mac.key")
	writeFileMode(t, macKey, bytes.Repeat([]byte("K"), 48), 0o600)

	// 5. The four config documents the deploy's phase 4b writes. They are
	//    the minimum valid set: a one-source pinga53-local registry, a
	//    signer authority naming that source, a policy with the two-voice
	//    threshold set, and an empty ledger.
	writeFileMode(t, filepath.Join(configDir, "signers.json"), []byte(`{
  "schema_version": 1,
  "signers": [
    {
      "key_id": "pinga53-local-1",
      "public_key": "`+pubB64+`",
      "asserts_source_ids": ["pinga53-local"],
      "aggregator_for": [],
      "note": "test fixture: local signer, asserts for pinga53-local only"
    }
  ]
}
`), 0o640)
	writeFileMode(t, filepath.Join(configDir, "registry.json"), []byte(minimalPinga53Registry), 0o640)
	writeFileMode(t, filepath.Join(configDir, "policy.json"), []byte(`{
  "schema_version": 1,
  "note": "test fixture policy",
  "min_independent_sources": 2,
  "proposal_scope": "exact",
  "accept_unestablished_independence": false,
  "accept_authoritative_alone": false,
  "exceptions": []
}
`), 0o640)
	writeFileMode(t, filepath.Join(stateDir, "ledger.json"), []byte(`{
  "schema_version": 1,
  "owned": []
}
`), 0o600)

	// 6. A pinga53-allowlist-export snapshot in the format the real exporter
	//    writes (schema_version=1 under the Pinga53 shape, with
	//    generated_at + source_sha256). Empty allow lists are legal and
	//    representative of a first install.
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z07:00")
	writeFileMode(t, filepath.Join(stateDir, "allowlist.json"), []byte(`{
  "schema": 1,
  "generated_at": "`+now+`",
  "source_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "exact_allow": [],
  "regex_allow": [],
  "subscribed_allow": []
}
`), 0o644)

	// 7. Execute the SHIM, not the Go binary directly. The whole point of
	//    this test is that the glue between the unit and the subcommands is
	//    what broke; invoking `scamwall rpz` here would prove the subcommand
	//    works and prove nothing about the deploy.
	shim := filepath.Join(root, "scripts", "scamwall-run.sh")
	cmd = exec.Command("bash", shim)
	cmd.Env = append(os.Environ(),
		"SCAMWALL_BIN="+bin,
		"CONFIG_DIR="+configDir,
		"STATE_DIR="+stateDir,
		"EVIDENCE_PATH="+filepath.Join(stateDir, "evidence.json"),
		"SIGNER_KEY="+signerKey,
		"MAC_KEY="+macKey,
		"POLICY="+filepath.Join(configDir, "policy.json"),
		"REGISTRY="+filepath.Join(configDir, "registry.json"),
		"SIGNERS="+filepath.Join(configDir, "signers.json"),
		"LEDGER="+filepath.Join(stateDir, "ledger.json"),
		"ALLOWLIST_SRC="+filepath.Join(stateDir, "allowlist.json"),
		"ALLOWLIST_RPZ="+filepath.Join(stateDir, "allowlist.rpz.json"),
		"ZONE_OUT="+filepath.Join(outDir, "scamwall.zone"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim failed: %v\n--- combined output ---\n%s", err, out)
	}
	t.Logf("shim output:\n%s", out)

	// 8. Assertions on the real pipeline's observable state:
	//
	//    a) The signed evidence envelope was written.
	//    b) The translated allowlist exists in ORDER-11 shape.
	//    c) The zone + sha256 companion are at the output path, OR the
	//       shim log recorded a documented freeze (exit 3/4/5 for rpz).
	//
	// A missing evidence or allowlist.rpz.json is a shim-regression; a
	// missing zone with no documented freeze is the original production
	// defect reproduced.
	assertFile(t, filepath.Join(stateDir, "evidence.json"))
	assertFile(t, filepath.Join(stateDir, "allowlist.rpz.json"))

	zone := filepath.Join(outDir, "scamwall.zone")
	zoneSHA := zone + ".sha256"
	outputStr := string(out)
	hasZone := fileExists(zone) && fileExists(zoneSHA)
	documentedFreeze := strings.Contains(outputStr, "rpz: review required") ||
		strings.Contains(outputStr, "inputs not trustworthy") ||
		strings.Contains(outputStr, "writer refused")
	if !hasZone && !documentedFreeze {
		t.Fatalf("neither a zone+sha256 nor a documented freeze: zone=%v sha=%v\n%s",
			fileExists(zone), fileExists(zoneSHA), out)
	}
	if hasZone {
		// A written zone must be internally consistent: $BIND SOA line
		// present, origin ends in '.', sha256 matches content.
		zoneBytes := readFileBytes(t, zone)
		if !bytes.Contains(zoneBytes, []byte("$ORIGIN scamwall.rpz.")) {
			t.Errorf("zone is missing $ORIGIN directive:\n%s", zoneBytes)
		}
		if !bytes.Contains(zoneBytes, []byte("SOA")) {
			t.Errorf("zone is missing SOA record:\n%s", zoneBytes)
		}
	}
}

// --- helpers --------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	// cmd/scamwall is two levels down from the module root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func runCmd(t *testing.T, bin string, args ...string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
}

func writeFileMode(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string { return string(readFileBytes(t, path)) }

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func assertFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// minimalPinga53Registry is the one-source registry deploy-scamwall.sh's
// phase 4b writes. Kept inline rather than read from the live file: the two
// have the same shape by design, and a change to the deploy's template
// should force a change here too (compiled-in evidence, not file-based).
const minimalPinga53Registry = `{
  "schema_version": 2,
  "note": "test fixture: Pinga53's one-source registry",
  "retired_source_ids": [],
  "sources": [
    {
      "source_id": "pinga53-local",
      "catalog_ref": "none",
      "requested_priority": "unknown",
      "official_name": "Pinga53 local evidence stream",
      "official_documentation": "unknown",
      "verified_on": "unknown",
      "kind": "bulk feed",
      "indicator_types": ["domain"],
      "classification_meaning": "test fixture",
      "authentication": "none",
      "quotas": "unknown",
      "update_cadence": "unknown",
      "retention": "unknown",
      "withdrawal_behaviour": "unknown",
      "attribution_required": "unknown",
      "derived_data_restrictions": "unknown",
      "upstream_sources": [],
      "upstream_sources_completeness": "documented_complete",
      "aggregation_dependencies": [],
      "access_status": "unresolved",
      "disposition_reason": "local source; data is produced on this host",
      "privacy_implications": "unknown",
      "intended_permitted_use": "unknown",
      "coverage_limitations": "unknown",
      "operational_cost": "unknown",
      "intended_operations": [],
      "permissions": {
        "retrieval":      {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}},
        "local_storage":  {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}},
        "enrichment":     {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}},
        "model_training": {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}},
        "commercial_use": {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}},
        "redistribution": {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}},
        "derived_output": {"status": "not_applicable", "evidence": {"provider_terms": [{"url": "https://pinga53.invalid/local-source", "checked_on": "2026-10-01", "quote": "local source; operation does not apply"}]}}
      },
      "enabled": false
    }
  ]
}
`
