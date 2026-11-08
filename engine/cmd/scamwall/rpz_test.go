// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// # ORDER 11 QUEUE ITEM 9 — `scamwall rpz`
//
// The probe first. internal/rpz is finished and tested, and a rule with no
// caller protects nobody: this is the same measurement item 2 made of C-20
// and C-21, applied to the package item 8 built.
func TestTheCommandCanBeAskedToWriteAZone(t *testing.T) {
	code, stdout, stderr := capture(t, "rpz", "-h")
	if code == exitUsage && strings.Contains(stderr, "unknown command") {
		t.Fatalf("the command cannot be asked to produce an RPZ zone, so internal/rpz has no "+
			"caller and the owned resolver still has no ScamWall output:\nstdout: %s\nstderr: %s",
			stdout, stderr)
	}
}

// rpzEnv is a decide fixture plus the two things only this command needs.
type rpzEnv struct {
	*decideEnv
	zonePath  string
	allowPath string
}

// newRPZEnv builds a run with padding, so that the standing set is large
// enough for the removal fraction to stay under C-20's abnormal threshold and
// the tests below measure the writer rather than the gate above it.
func newRPZEnv(t *testing.T) *rpzEnv {
	t.Helper()
	e := newCapEnv(t, 16, 50, 50)
	return &rpzEnv{
		decideEnv: e,
		zonePath:  filepath.Join(e.dir, "scamwall.zone"),
		allowPath: writeAllowSnapshot(t, e.dir, nil),
	}
}

// writeAllowSnapshot writes an allow-list export the household could plausibly
// have produced. `exact` is what it allows.
func writeAllowSnapshot(t *testing.T, dir string, exact []string) string {
	t.Helper()
	if exact == nil {
		exact = []string{}
	}
	return writeFixture(t, dir, "allowlist.json", mustJSON(t, map[string]any{
		"schema_version":   1,
		"origin":           "synthetic export written for this test suite",
		"exact_allow":      exact,
		"regex_allow":      []string{},
		"subscribed_allow": []string{},
		"subscribed_read":  true,
	}))
}

func (e *rpzEnv) args(extra ...string) []string {
	return append([]string{
		"rpz",
		"-evidence", e.evidencePath,
		"-signers", e.signersPath,
		"-registry", e.registryPath,
		"-policy", e.policyPath,
		"-ledger", e.ledgerPath,
		"-allowlist", e.allowPath,
		"-at", proposeAt,
	}, extra...)
}

func TestTheCommandWritesAZoneAndReportsWhatItWrote(t *testing.T) {
	e := newRPZEnv(t)
	code, stdout, stderr := capture(t, e.args("-out", e.zonePath)...)
	if code != exitOK {
		t.Fatalf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	zone, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatalf("no zone was written: %v", err)
	}
	for _, want := range []string{"$ORIGIN scamwall.rpz.", "IN SOA", "IN NS", "IN CNAME ."} {
		if !strings.Contains(string(zone), want) {
			t.Errorf("the zone has no %q:\n%s", want, zone)
		}
	}
	// The ledger's own hosts are the standing set; they must be in the zone,
	// because a zone holding only today's additions unblocks everything else.
	if !strings.Contains(string(zone), qualifyingName(0)) {
		t.Errorf("a host ScamWall already owns is missing from the zone:\n%s", zone)
	}
	if !strings.Contains(stdout, "rpz: applied") {
		t.Errorf("the command did not report what it did:\n%s", stdout)
	}
	if _, err := os.Stat(e.zonePath + ".record.json"); err != nil {
		t.Errorf("no decision record was written beside the zone: %v", err)
	}
}

func TestOmittingOutIsADryRun(t *testing.T) {
	e := newRPZEnv(t)
	code, stdout, stderr := capture(t, e.args()...)
	if code != exitOK {
		t.Fatalf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "dry-run") {
		t.Errorf("a run with no --out did not say it was a dry run:\n%s", stdout)
	}
	if entries, _ := os.ReadDir(e.dir); len(entries) > 0 {
		for _, f := range entries {
			if strings.HasSuffix(f.Name(), ".zone") {
				t.Errorf("a dry run wrote %s", f.Name())
			}
		}
	}
}

func TestADryRunOverAnExistingZoneChangesNothing(t *testing.T) {
	e := newRPZEnv(t)
	if code, _, se := capture(t, e.args("-out", e.zonePath)...); code != exitOK {
		t.Fatalf("the setup run failed: %s", se)
	}
	before, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, se := capture(t, e.args("-out", e.zonePath, "-dry-run")...); code != exitOK {
		t.Fatalf("exit %d: %s", code, se)
	}
	after, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("--dry-run with --out rewrote the zone")
	}
}

func TestWithoutAnAllowSnapshotTheRunFreezesAndTheZoneSurvives(t *testing.T) {
	e := newRPZEnv(t)
	if code, _, se := capture(t, e.args("-out", e.zonePath)...); code != exitOK {
		t.Fatalf("the setup run failed: %s", se)
	}
	before, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}

	// The same run, with the allow snapshot taken away.
	args := []string{
		"rpz", "-evidence", e.evidencePath, "-signers", e.signersPath,
		"-registry", e.registryPath, "-policy", e.policyPath, "-ledger", e.ledgerPath,
		"-at", proposeAt, "-out", e.zonePath,
	}
	code, stdout, stderr := capture(t, args...)
	if code != exitFrozen {
		t.Fatalf("exit %d, want %d (freeze)\nstdout: %s\nstderr: %s", code, exitFrozen, stdout, stderr)
	}
	if !strings.Contains(stdout, "frozen") {
		t.Errorf("the run did not say it froze:\n%s", stdout)
	}
	after, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a frozen run changed the zone")
	}
}

func TestADeclaredSourceOutageFreezesTheZone(t *testing.T) {
	e := newRPZEnv(t)
	code, stdout, _ := capture(t, e.args("-out", e.zonePath,
		"-source-outage", "the provider is down")...)
	if code != exitFrozen {
		t.Fatalf("exit %d, want %d (freeze)\n%s", code, exitFrozen, stdout)
	}
	if _, err := os.Stat(e.zonePath); err == nil {
		t.Error("a frozen run wrote a zone")
	}
}

func TestAHostTheHouseholdAllowsIsHeldForAPersonAndNotWritten(t *testing.T) {
	e := newRPZEnv(t)
	allowed := qualifyingName(0)
	e.allowPath = writeAllowSnapshot(t, e.dir, []string{allowed})

	code, stdout, stderr := capture(t, e.args("-out", e.zonePath)...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	zone, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(zone), allowed) {
		t.Errorf("a host the household allows was written into the zone:\n%s", zone)
	}
	if !strings.Contains(stdout, allowed) || !strings.Contains(stdout, "allow") {
		t.Errorf("the exclusion was not reported to the operator:\n%s", stdout)
	}
}

func TestTheProtectedBankIsNeverWrittenEvenWhenTheEvidenceSaysBlockIt(t *testing.T) {
	// The fixture policy excepts bank.example.com. This asserts the writer's
	// own refusal from the command side: the decider already excludes it, and
	// this is the second gate, in front of the file.
	e := newRPZEnv(t)
	if code, _, se := capture(t, e.args("-out", e.zonePath)...); code != exitOK {
		t.Fatalf("exit: %s", se)
	}
	zone, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(zone), "bank.example.com") {
		t.Errorf("the household's bank is in the zone:\n%s", zone)
	}
}

func TestASecondIdenticalRunChangesNothingAndStillSucceeds(t *testing.T) {
	e := newRPZEnv(t)
	if code, _, se := capture(t, e.args("-out", e.zonePath)...); code != exitOK {
		t.Fatalf("the first run failed: %s", se)
	}
	before, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := capture(t, e.args("-out", e.zonePath)...)
	if code != exitOK {
		t.Fatalf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "no_change") {
		t.Errorf("the second run did not report no_change:\n%s", stdout)
	}
	after, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a run with nothing to do rewrote the zone and moved its serial")
	}
}

func TestWithoutALedgerTheCommandRefusesToWriteAnything(t *testing.T) {
	e := newRPZEnv(t)
	args := []string{
		"rpz", "-evidence", e.evidencePath, "-signers", e.signersPath,
		"-registry", e.registryPath, "-policy", e.policyPath,
		"-allowlist", e.allowPath, "-at", proposeAt, "-out", e.zonePath,
	}
	code, stdout, _ := capture(t, args...)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d (usage)\n%s", code, exitUsage, stdout)
	}
	if _, err := os.Stat(e.zonePath); err == nil {
		t.Error("a run with no ownership ledger wrote a zone")
	}
}

func TestTheZoneAndItsRecordAgree(t *testing.T) {
	e := newRPZEnv(t)
	code, stdout, stderr := capture(t, append(e.args("-out", e.zonePath), "-json")...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var doc struct {
		Result struct {
			Digest  string `json:"digest"`
			Serial  string `json:"serial"`
			Entries int    `json:"entries"`
		} `json:"result"`
		Standing int `json:"standing"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("the command did not emit JSON: %v\n%s", err, stdout)
	}

	zone, err := os.ReadFile(e.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(zone)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != doc.Result.Digest {
		t.Errorf("the reported digest %s is not the zone's %s", doc.Result.Digest, got)
	}
	if !strings.Contains(string(zone), doc.Result.Serial) {
		t.Errorf("the zone does not carry the serial the run reported (%s)", doc.Result.Serial)
	}
	if doc.Standing < doc.Result.Entries {
		t.Errorf("more entries were written (%d) than the decision holds (%d)",
			doc.Result.Entries, doc.Standing)
	}
}

func TestHelpDocumentsTheExitCodes(t *testing.T) {
	_, stdout, _ := capture(t, "help")
	for _, want := range []string{"rpz", "review", "freeze", "--allow-empty", "--dry-run"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the usage text does not mention %q", want)
		}
	}
}

func TestTheCommandReadsNoConfigurationAndNoCredential(t *testing.T) {
	// The same standard `propose` and `decide` hold themselves to. Measured
	// by pointing the shared -config flag at a path that does not exist: a
	// command that read configuration would fail on it.
	e := newRPZEnv(t)
	args := append(e.args("-out", e.zonePath), "-config", filepath.Join(e.dir, "no-such-config.json"))
	if code, stdout, stderr := capture(t, args...); code != exitUsage {
		// -config is not even a flag on this command, which is the strongest
		// form of the same statement.
		if !strings.Contains(stdout+stderr, "flag provided but not defined") {
			t.Errorf("exit %d: rpz appears to accept configuration\nstdout: %s\nstderr: %s",
				code, stdout, stderr)
		}
	}
}

func TestWritingAZoneDoesNotTouchTheOwnershipLedger(t *testing.T) {
	// `rpz` writes the zone and the record beside it, and nothing else.
	// Persisting the new serial back into the ledger was considered and not
	// done: nothing in this tree writes an ownership ledger at all, and a run
	// that rewrote one field of a document it otherwise never maintains would
	// leave a ledger whose serial is current and whose `owned` set is however
	// stale it already was. The zone's own SOA is the authoritative serial —
	// rpz.nextSerial reads it — so nothing is lost. Recorded as an owner
	// question.
	e := newRPZEnv(t)
	before, err := os.ReadFile(e.ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, se := capture(t, e.args("-out", e.zonePath)...); code != exitOK {
		t.Fatalf("exit: %s", se)
	}
	after, err := os.ReadFile(e.ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("writing a zone modified the ownership ledger")
	}
}

func TestTheZoneSerialStillIncreasesWithNothingPersistingIt(t *testing.T) {
	// The consequence of the test above: with no ledger writer, PrevSerial is
	// always empty and the zone on disk is the only state there is. It has to
	// be enough, so this drives three writes through the command and requires
	// the serial to move every time.
	e := newRPZEnv(t)
	seen := map[string]bool{}
	var last string
	for i, allowed := range [][]string{nil, {qualifyingName(1)}, {qualifyingName(1), qualifyingName(2)}} {
		e.allowPath = writeAllowSnapshot(t, e.dir, allowed)
		code, stdout, stderr := capture(t, append(e.args("-out", e.zonePath), "-json")...)
		if code != exitOK {
			t.Fatalf("run %d: exit %d\nstdout: %s\nstderr: %s", i, code, stdout, stderr)
		}
		var doc struct {
			Result struct{ Serial string } `json:"result"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("run %d: %v\n%s", i, err, stdout)
		}
		if seen[doc.Result.Serial] {
			t.Fatalf("run %d reissued serial %s", i, doc.Result.Serial)
		}
		if doc.Result.Serial <= last {
			t.Fatalf("run %d: serial %s did not increase past %s", i, doc.Result.Serial, last)
		}
		seen[doc.Result.Serial], last = true, doc.Result.Serial
	}
}
