// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// # ORDER 11 QUEUE ITEM 5 — C-22 AND C-23, DRIVEN FROM cmd/
//
// internal/journal was complete, tested, and imported by nothing outside its
// own tests: `REQUIREMENTS_MATRIX.md` §5.9.6 records it as RULE VERIFIED
// (synthetic), NO CALLER. For C-23 that is a particularly hollow state. The
// rule says a run that did not read the appliance may not journal what it
// would have changed there, and no run was journalling anything at all, so
// the refusal had never been asked for.
//
// Every test here drives `shadow` against the e2e fake appliance — the one
// that records every request it receives — and then reads the journal file
// off disk.

type journalDoc struct {
	SchemaVersion int `json:"schema_version"`
	Entries       []struct {
		Canonical         string `json:"canonical"`
		FirstJournalledAt string `json:"first_journalled_at"`
		LastSeenAt        string `json:"last_seen_at"`
		LastBlockAt       string `json:"last_block_at"`
		Revisions         int    `json:"revisions"`
		History           []struct {
			Substance      string `json:"substance"`
			Blocked        bool   `json:"blocked"`
			ObservedDigest string `json:"observed_digest"`
		} `json:"history"`
	} `json:"entries"`
}

func readJournal(t *testing.T, path string) journalDoc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var d journalDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("decode journal: %v\n%s", err, b)
	}
	return d
}

func (d journalDoc) entry(t *testing.T, host string) int {
	t.Helper()
	for i, e := range d.Entries {
		if e.Canonical == host {
			return i
		}
	}
	t.Fatalf("no journal entry for %q", host)
	return -1
}

// TestTheJournalRecordsTheFirstRunAndBindsWhatItSaw — C-22, the base case.
func TestTheJournalRecordsTheFirstRunAndBindsWhatItSaw(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	path := filepath.Join(t.TempDir(), "journal.json")

	code, stdout, stderr := capture(t, e.args("-journal", path)...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "recorded for the first time") {
		t.Errorf("the run does not say what it journalled:\n%s", stdout)
	}

	d := readJournal(t, path)
	if len(d.Entries) == 0 {
		t.Fatal("the journal is empty after a run that compared a real appliance")
	}
	// Every revision names the appliance state it was looking at. A revision
	// that cannot say what it saw is a revision about nothing — C-23's other
	// half, and the reason ObservedDigest is on the revision and not on the
	// file.
	for _, entry := range d.Entries {
		for _, r := range entry.History {
			if r.ObservedDigest == "" {
				t.Errorf("%s has a revision bound to no observed state", entry.Canonical)
			}
		}
	}
}

// TestASecondIdenticalRunAppendsNothing — C-22's first rule.
//
// A run reaching the same conclusion as the last one has nothing new to say.
// A journal that appended a revision every run would be a log file with a
// schema: it grows without bound and the one line that matters is invisible
// in it.
func TestASecondIdenticalRunAppendsNothing(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	path := filepath.Join(t.TempDir(), "journal.json")

	if code, out, _ := capture(t, e.args("-journal", path)...); code != exitOK {
		t.Fatalf("first run exited %d: %s", code, out)
	}
	first := readJournal(t, path)

	code, stdout, _ := capture(t, e.args("-journal", path)...)
	if code != exitOK {
		t.Fatalf("second run exited %d: %s", code, stdout)
	}
	if !strings.Contains(stdout, "0 revision(s) appended") {
		t.Errorf("a repeat of an identical run appended something:\n%s", stdout)
	}

	second := readJournal(t, path)
	if len(second.Entries) != len(first.Entries) {
		t.Errorf("the journal went from %d to %d hosts across two identical runs",
			len(first.Entries), len(second.Entries))
	}
	for i := range second.Entries {
		if second.Entries[i].Revisions != first.Entries[i].Revisions {
			t.Errorf("%s gained a revision without a substantive change",
				second.Entries[i].Canonical)
		}
	}
	// And the host is still there. "Nothing changed" must never become "this
	// host is gone": the whole point is that a host ScamWall has ever acted
	// on can be found afterwards.
	if len(second.Entries) == 0 {
		t.Error("a run that changed nothing emptied the journal")
	}
}

// TestASubstantiveChangeAppendsARevision — C-22's other side.
//
// The pair matters. A journal that appends nothing is as broken as one that
// appends everything, and a test for only the first would pass against a
// journal that never writes at all.
func TestASubstantiveChangeAppendsARevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")

	// First run: the appliance holds nothing, so bad.example.com would be
	// added — or held for review, since gravity is unread. Either way it has
	// a verdict.
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	if code, out, _ := capture(t, e.args("-journal", path)...); code != exitOK {
		t.Fatalf("first run exited %d: %s", code, out)
	}
	before := readJournal(t, path)
	host := before.Entries[before.entry(t, "bad.example.com")].Canonical
	revsBefore := before.Entries[before.entry(t, host)].Revisions

	// Second run against an appliance that now holds an entry for it, placed
	// by somebody else. The verdict changes kind.
	e2 := newShadowEnv(t, withStop(completeContract, stopFile(t)),
		`{"domains":[{"domain":"bad.example.com","type":"deny","kind":"exact",`+
			`"comment":"the household added this","enabled":true,"id":1,"date_added":1000}],"took":0.001}`)
	e2.inputs = e.inputs
	if code, out, _ := capture(t, e2.args("-journal", path)...); code != exitOK {
		t.Fatalf("second run exited %d: %s", code, out)
	}

	after := readJournal(t, path)
	if got := after.Entries[after.entry(t, host)].Revisions; got <= revsBefore {
		t.Errorf("%s still has %d revision(s) after its verdict changed from "+
			"absent-from-the-appliance to present-and-user-managed", host, got)
	}
}

// TestAnUnreachableApplianceWritesNoJournalRowAndTheRunIsIncomplete — C-23.
//
// The control the order names explicitly. A run that did not read the
// appliance may not record what it would have changed there, and the refusal
// is TOTAL: not one row for the hosts whose outcome needed no appliance to
// decide, because a journal half-written under a rule that says it should not
// have been written at all is worse than none.
func TestAnUnreachableApplianceWritesNoJournalRowAndTheRunIsIncomplete(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	// The appliance refuses to authenticate, so the read never happens.
	e.authStatus = 401
	path := filepath.Join(t.TempDir(), "journal.json")

	code, stdout, stderr := capture(t, e.args("-journal", path)...)
	if code == exitOK {
		t.Fatalf("a run that could not read the appliance reported success\n%s", stdout)
	}
	if !strings.Contains(stdout, "THE RUN IS INCOMPLETE") {
		t.Errorf("the run is not reported as incomplete:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
	if !strings.Contains(stdout, "Nothing was recorded, for any host") {
		t.Errorf("the refusal does not say it was total:\n%s", stdout)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a journal file was created by a run that never read the appliance")
	}
}

// TestAnUnreachableApplianceDoesNotDisturbAnExistingJournal.
//
// The stronger half of the same rule. A failed run must not rewrite, truncate
// or empty a journal that already holds the household's history — which is
// what an unconditional save-after-record would do the moment the record
// became a no-op.
func TestAnUnreachableApplianceDoesNotDisturbAnExistingJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")

	good := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	if code, out, _ := capture(t, good.args("-journal", path)...); code != exitOK {
		t.Fatalf("setup run exited %d: %s", code, out)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	bad := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	bad.inputs = good.inputs
	bad.authStatus = 401
	if code, _, _ := capture(t, bad.args("-journal", path)...); code == exitOK {
		t.Fatal("the unreachable run reported success")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("a run that could not read the appliance changed the standing journal")
	}
}

// TestTheJournalIsNotWrittenUnlessAskedFor keeps the flag opt-in.
//
// A command that started writing state to a default path would be a command
// that writes to the operator's filesystem without being told to.
func TestTheJournalIsNotWrittenUnlessAskedFor(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	dir := t.TempDir()
	if code, out, _ := capture(t, e.args()...); code != exitOK {
		t.Fatalf("exit %d: %s", code, out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a run given no -journal wrote %d file(s)", len(entries))
	}
}

// TestJSONOutputStaysJSONWithAJournal.
//
// `shadow --json` emits a document and nothing else — the existing code
// refuses to print the session teardown after the closing brace for exactly
// this reason. A journal note appended there would break every caller that
// pipes the output.
func TestJSONOutputStaysJSONWithAJournal(t *testing.T) {
	e := newShadowEnv(t, withStop(completeContract, stopFile(t)), "")
	path := filepath.Join(t.TempDir(), "journal.json")

	code, stdout, stderr := capture(t, e.args("-json", "-journal", path)...)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	var any map[string]any
	if err := json.Unmarshal([]byte(stdout), &any); err != nil {
		t.Fatalf("the output is not a JSON document: %v\n%s", err, stdout)
	}
	// And the journal was still written.
	if len(readJournal(t, path).Entries) == 0 {
		t.Error("the JSON rendering skipped the journal")
	}
}
