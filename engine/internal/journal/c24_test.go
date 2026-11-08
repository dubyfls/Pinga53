// SPDX-License-Identifier: AGPL-3.0-only

package journal_test

import (
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/journal"
	"github.com/dubyfls/Pinga53/engine/internal/mac"
)

// C-24, the store half. A journal entry is a record that something was
// WRITTEN DOWN; a report is a record that something was DECIDED. The two must
// never be interchangeable, and the purpose label is what keeps them apart.

func c24Key(t *testing.T, b byte) *mac.Key {
	t.Helper()
	raw := make([]byte, mac.MinKeyBytes)
	for i := range raw {
		raw[i] = b
	}
	k, err := mac.NewKey(raw)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func sealed(t *testing.T) (*journal.Journal, *mac.Key, string) {
	t.Helper()
	j := journal.New()
	mustRecord(t, j, observedRun(at(0), item("bad.example.com", "propose/corroborated", true)))
	k := c24Key(t, 0x11)
	return j, k, j.Seal(k)
}

func TestASealedJournalVerifies(t *testing.T) {
	j, k, s := sealed(t)
	if s == "" {
		t.Fatalf("Seal returned nothing")
	}
	if err := j.VerifySeal(s, k); err != nil {
		t.Fatalf("a journal did not verify against its own seal: %v", err)
	}
}

func TestAChangedJournalDoesNotVerify(t *testing.T) {
	j, k, s := sealed(t)
	mustRecord(t, j, observedRun(at(1), item("bad.example.com", "abstain/withdrawn_only", false)))
	if err := j.VerifySeal(s, k); err == nil {
		t.Fatalf("a journal with a new revision verified against the old seal")
	}
}

// TestAReportPurposeTagIsNotAJournalSeal — the mirror of
// proposal.TestASealedRecordIsNeverAcceptedAsAReport. Neither direction may
// pass, or the purpose label is decoration.
func TestAReportPurposeTagIsNotAJournalSeal(t *testing.T) {
	j, k, _ := sealed(t)
	b, err := j.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	forged := k.Tag(mac.PurposeReportBinding, string(b))
	if err := j.VerifySeal(forged, k); err == nil {
		t.Fatalf("a report-purpose tag over the journal's own bytes verified as a store seal")
	}
}

func TestAnotherKeyDoesNotVerifyTheJournal(t *testing.T) {
	j, _, s := sealed(t)
	if err := j.VerifySeal(s, c24Key(t, 0x22)); err == nil {
		t.Fatalf("a journal seal verified under a key that did not make it")
	}
}

func TestNoKeyMeansNoJournalSeal(t *testing.T) {
	j := journal.New()
	if s := j.Seal(nil); s != "" {
		t.Fatalf("a nil key produced a seal: %q", s)
	}
	if err := j.VerifySeal("", c24Key(t, 0x11)); err == nil {
		t.Fatalf("verification of an absent seal succeeded")
	}
	if err := j.VerifySeal(j.Seal(c24Key(t, 0x11)), nil); err == nil {
		t.Fatalf("verification with no key succeeded")
	}
}
