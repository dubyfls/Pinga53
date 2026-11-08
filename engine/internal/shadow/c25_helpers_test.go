// SPDX-License-Identifier: AGPL-3.0-only

package shadow

import (
	"testing"
	"time"
)

// allowNothing is a read that found no allow entries at all — distinct from
// AllowNotRead, which found nothing because it did not look.
type allowNothing struct{}

func (allowNothing) Allowed(string) bool       { return false }
func (allowNothing) Cover(string) (bool, bool) { return false, false }
func (allowNothing) Unevaluable() int          { return 0 }
func (allowNothing) Counts() (int, int)        { return 0, 0 }
func (allowNothing) Read() bool                { return true }
func (allowNothing) Source() string            { return "synthetic: read, and empty" }

// allowExactly is a read that found one exact allow entry.
type allowExactly struct{ name string }

func (a allowExactly) Allowed(d string) bool { return d == a.name }
func (a allowExactly) Cover(d string) (bool, bool) {
	return d == a.name, false
}
func (allowExactly) Unevaluable() int   { return 0 }
func (allowExactly) Counts() (int, int) { return 1, 0 }
func (allowExactly) Read() bool         { return true }
func (allowExactly) Source() string     { return "synthetic: one exact allow entry" }

// fixedSubscription answers the same thing for every host.
type fixedSubscription struct{ allow, deny Tristate }

func (f fixedSubscription) Membership(string) (Tristate, Tristate) { return f.allow, f.deny }
func (fixedSubscription) Read() bool                               { return true }
func (fixedSubscription) Source() string                           { return "synthetic subscription answer" }

func observationOf(entries ...Entry) Observation {
	return Observation{
		Entries: entries, ReadAt: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		TargetHost: "pi.hole.invalid", Complete: true,
	}
}

func planWith(t *testing.T, in Input) *Plan {
	t.Helper()
	p, err := Compare(in)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	return p
}

func changeFor(t *testing.T, p *Plan, domain string) Change {
	t.Helper()
	for _, c := range p.Changes {
		if c.Domain == domain {
			return c
		}
	}
	t.Fatalf("no change for %s in %+v", domain, p.Changes)
	return Change{}
}

// subscribedNothing is a run that READ the subscribed lists and found the
// host in none of them. Distinct from SubscribedNotRead, which found nothing
// because it could not look.
type subscribedNothing struct{}

func (subscribedNothing) Membership(string) (Tristate, Tristate) { return No, No }
func (subscribedNothing) Read() bool                             { return true }
func (subscribedNothing) Source() string {
	return "synthetic: subscribed lists read, host in none of them"
}
