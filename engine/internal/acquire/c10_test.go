// SPDX-License-Identifier: AGPL-3.0-only

package acquire_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/acquire"
	"github.com/dubyfls/Pinga53/engine/internal/domain"
)

// C-10 — a snapshot is applied only if EVERY gate passes; otherwise it is
// quarantined, and a quarantine never withdraws what is already in effect.
//
// The last clause is the one that matters. A gate that refuses a bad snapshot
// by emptying the list has converted "this update looks wrong" into the exact
// harm the gate exists to prevent: mass unblocking. So every failure path is
// asserted twice — once that it refused, once that it refused without taking
// anything away.

func mustHosts(t *testing.T, names ...string) []domain.Domain {
	t.Helper()
	out := make([]domain.Domain, 0, len(names))
	for _, n := range names {
		d, err := domain.Normalize(n)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", n, err)
		}
		out = append(out, d)
	}
	return out
}

// hosts builds n distinct synthetic hosts, h0000.example.com upward.
func hosts(t *testing.T, n int) []domain.Domain {
	t.Helper()
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, strings.ToLower(pad(i))+".example.com")
	}
	return mustHosts(t, names...)
}

func pad(i int) string {
	s := "h"
	for _, d := range []int{1000, 100, 10, 1} {
		s += string(rune('0' + (i/d)%10))
	}
	return s
}

func sensibleLimits() acquire.Limits {
	return acquire.Limits{
		MinEntries:            10,
		MaxShrinkFraction:     0.25,
		MaxGrowthFactor:       4,
		MaxWithdrawalFraction: 0.25,
		MaxAge:                48 * time.Hour,
		ClockSkew:             5 * time.Minute,
	}
}

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func good(t *testing.T, n int) acquire.Snapshot {
	t.Helper()
	return acquire.Snapshot{
		SourceID: "src-0001",
		IssuedAt: now.Add(-1 * time.Hour),
		Entries:  hosts(t, n),
		Verified: true,
	}
}

// TestEverySevenGateRefusesAndNoneOfThemWithdraws is the whole of C-10 in one
// table: each row trips exactly one gate, and each row must quarantine while
// leaving the previous snapshot in effect entry for entry.
func TestEverySevenGateRefusesAndNoneOfThemWithdraws(t *testing.T) {
	prev := good(t, 100)

	cases := []struct {
		name string
		gate acquire.Gate
		next func() acquire.Snapshot
	}{
		{"unverified", acquire.GateIntegrity, func() acquire.Snapshot {
			s := good(t, 100)
			s.Verified = false
			return s
		}},
		{"stale", acquire.GateFreshness, func() acquire.Snapshot {
			s := good(t, 100)
			s.IssuedAt = now.Add(-72 * time.Hour)
			return s
		}},
		{"issued in the future", acquire.GateFreshness, func() acquire.Snapshot {
			s := good(t, 100)
			s.IssuedAt = now.Add(1 * time.Hour)
			return s
		}},
		{"older than the one in effect", acquire.GateNotRegressive, func() acquire.Snapshot {
			s := good(t, 100)
			s.IssuedAt = prev.IssuedAt.Add(-1 * time.Minute)
			return s
		}},
		{"too few entries", acquire.GateMinEntries, func() acquire.Snapshot {
			s := good(t, 100)
			s.Entries = hosts(t, 9)
			return s
		}},
		{"shrank too far", acquire.GateMaxShrink, func() acquire.Snapshot {
			s := good(t, 100)
			s.Entries = hosts(t, 60)
			return s
		}},
		{"grew too far", acquire.GateMaxGrowth, func() acquire.Snapshot {
			s := good(t, 100)
			s.Entries = hosts(t, 401)
			return s
		}},
		{"replaced its contents wholesale", acquire.GateMaxWithdrawal, func() acquire.Snapshot {
			// Same count as the previous snapshot, so the shrink gate has
			// nothing to see; every entry is different, so every previously
			// blocked host would be unblocked at once.
			s := good(t, 100)
			names := make([]string, 0, 100)
			for i := range 100 {
				names = append(names, pad(i)+".other.example.com")
			}
			s.Entries = mustHosts(t, names...)
			return s
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := acquire.Decide(&prev, tc.next(), sensibleLimits(), now)

			if d.Applied {
				t.Fatalf("snapshot was applied; %s should have refused it", tc.gate)
			}
			if !d.Quarantined {
				t.Fatalf("snapshot was neither applied nor quarantined")
			}
			if !d.Failed(tc.gate) {
				t.Errorf("gate %s did not fire; failures were %v", tc.gate, d.FailedGates())
			}
			// The clause that matters.
			if got := len(d.InEffect.Entries); got != len(prev.Entries) {
				t.Errorf("quarantine withdrew entries: %d in effect, %d before", got, len(prev.Entries))
			}
			if d.InEffect.IssuedAt != prev.IssuedAt {
				t.Errorf("quarantine replaced the snapshot in effect")
			}
		})
	}
}

// TestASnapshotThatPassesEveryGateIsApplied is the control on the control: the
// gates must not be so tight that nothing ever lands.
func TestASnapshotThatPassesEveryGateIsApplied(t *testing.T) {
	prev := good(t, 100)
	next := good(t, 110)
	next.IssuedAt = now.Add(-10 * time.Minute)

	d := acquire.Decide(&prev, next, sensibleLimits(), now)
	if !d.Applied {
		t.Fatalf("a sound snapshot was refused by %v", d.FailedGates())
	}
	if d.Quarantined {
		t.Errorf("an applied snapshot is also quarantined")
	}
	if len(d.InEffect.Entries) != 110 {
		t.Errorf("in effect has %d entries, want the 110 that were applied", len(d.InEffect.Entries))
	}
}

// TestOneGateIsEnoughToQuarantine — "applied only if EVERY gate passes".
func TestOneGateIsEnoughToQuarantine(t *testing.T) {
	prev := good(t, 100)
	next := good(t, 110)
	next.Verified = false // everything else about it is fine

	d := acquire.Decide(&prev, next, sensibleLimits(), now)
	if d.Applied {
		t.Fatalf("a snapshot failing one gate out of seven was applied")
	}
}

// TestTheFirstSnapshotHasNoPreviousToShrinkFrom — the relative gates have
// nothing to measure and must pass vacuously rather than refuse forever.
func TestTheFirstSnapshotHasNoPreviousToShrinkFrom(t *testing.T) {
	d := acquire.Decide(nil, good(t, 100), sensibleLimits(), now)
	if !d.Applied {
		t.Fatalf("the first snapshot a source ever delivered was refused by %v", d.FailedGates())
	}

	// ...but the absolute gates still apply to it.
	d = acquire.Decide(nil, good(t, 3), sensibleLimits(), now)
	if d.Applied {
		t.Fatalf("a 3-entry first snapshot was applied under a floor of 10")
	}
	if !d.Failed(acquire.GateMinEntries) {
		t.Errorf("failures were %v, want %s", d.FailedGates(), acquire.GateMinEntries)
	}
	if len(d.InEffect.Entries) != 0 {
		t.Errorf("a quarantine with nothing previously in effect put %d entries in effect", len(d.InEffect.Entries))
	}
}

// TestLimitsMustBeStated — a zero limit is not "unbounded", it is an
// unconfigured gate, and an unconfigured gate must not silently pass.
func TestLimitsMustBeStated(t *testing.T) {
	d := acquire.Decide(nil, good(t, 100), acquire.Limits{}, now)
	if d.Applied {
		t.Fatalf("a snapshot was applied under zero-valued limits; an unset gate passed silently")
	}
	if !d.Failed(acquire.GateLimitsUnset) {
		t.Errorf("failures were %v, want %s", d.FailedGates(), acquire.GateLimitsUnset)
	}
}

// TestAFailureNamesNoHost — a quarantine diagnostic reaches the operator's
// terminal and the gate log. It reports arithmetic, never the feed's contents.
func TestAFailureNamesNoHost(t *testing.T) {
	prev := good(t, 100)
	next := good(t, 10)
	d := acquire.Decide(&prev, next, sensibleLimits(), now)

	for _, f := range d.Failures {
		if strings.Contains(f.Detail, "example.com") || strings.Contains(f.Detail, "h0000") {
			t.Errorf("gate %s reproduced a host from the snapshot: %q", f.Gate, f.Detail)
		}
	}
}
