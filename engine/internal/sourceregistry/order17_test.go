// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestOrder17DeployedRegistryValidates proves the registry shipped under
// scamwall/config/registry.json parses, validates with no
// problems at the ORDER 17 landing date, and that the lineage property
// A4 holds: urlhaus and threatfox count as ONE independent voice (same
// abuse.ch origin), while urlhaus+threatfox+openphish count as TWO.
func TestOrder17DeployedRegistryValidates(t *testing.T) {
	// Package lives under scamwall/internal/sourceregistry; registry.json
	// lives under scamwall/deploy/pinga53/scamwall/. Walk up.
	_, here, _, _ := runtime.Caller(0)
	reg, problems, err := Load(filepath.Join(filepath.Dir(here), "..", "..", "config", "registry.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, p := range problems {
		t.Logf("parse warning: %s", p.String())
	}
	asOf := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	if ps := reg.Validate(asOf); len(ps) > 0 {
		for _, p := range ps {
			t.Errorf("registry: %s", p.String())
		}
		t.Fatal("registry has validation problems")
	}

	// Every ORDER 17 source is present.
	for _, id := range []string{
		"pinga53-local",
		"urlhaus",
		"threatfox",
		"openphish-community",
		"phishing-database",
		"cert-polska-warning-list",
		"ct-brand-watch",
	} {
		if _, ok := reg.Source(id); !ok {
			t.Errorf("missing source %q", id)
		}
	}

	// Lineage: abuse.ch pair is one voice.
	pair := reg.MaxDisjointOrigins([]string{"urlhaus", "threatfox"})
	if pair.Count != 1 {
		t.Fatalf("abuse.ch pair: expected 1 independent voice, got %d (shared=%v)", pair.Count, pair.Shared)
	}
	gotSharedAbusech := false
	for _, s := range pair.Shared {
		if s == "abusech" {
			gotSharedAbusech = true
		}
	}
	if !gotSharedAbusech {
		t.Fatalf("expected shared origin `abusech`, got %v", pair.Shared)
	}

	// Add a non-abuse.ch source: should produce 2 voices.
	triple := reg.MaxDisjointOrigins([]string{"urlhaus", "threatfox", "openphish-community"})
	if triple.Count != 2 {
		t.Fatalf("urlhaus+threatfox+openphish: expected 2 voices, got %d", triple.Count)
	}
}

// TestOrder17BEnablesExactlyTheFiveSourcesTheOwnerCited verifies that
// ORDER 17B enabled exactly the five sources the owner provided verbatim
// terms-page citations for, and nothing else. pinga53-local is the local
// sentinel (deliberately not fetched); ct-brand-watch has no terms
// citation and stays disabled with intended_operations empty.
//
// This replaces TestOrder17RegistryKeepsAllSourcesDisabled from ORDER 17,
// which the owner's ORDER 17B §1 explicitly supersedes by shipping the
// citations.
func TestOrder17BEnablesExactlyTheFiveSourcesTheOwnerCited(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	reg, _, err := Load(filepath.Join(filepath.Dir(here), "..", "..", "config", "registry.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantEnabled := map[string]bool{
		"urlhaus":                  true,
		"threatfox":                true,
		"openphish-community":      true,
		"phishing-database":        true,
		"cert-polska-warning-list": true,
	}
	wantDisabled := map[string]bool{
		"pinga53-local":  true,
		"ct-brand-watch": true,
	}
	for i := range reg.Sources {
		s := &reg.Sources[i]
		switch {
		case wantEnabled[s.SourceID]:
			if !s.Enabled {
				t.Errorf("source %q: expected enabled=true", s.SourceID)
			}
			if len(s.IntendedOperations) != 3 {
				t.Errorf("source %q: expected 3 intended_operations, got %d", s.SourceID, len(s.IntendedOperations))
			}
		case wantDisabled[s.SourceID]:
			if s.Enabled {
				t.Errorf("source %q: expected enabled=false", s.SourceID)
			}
		default:
			t.Errorf("source %q appeared in registry but is not expected", s.SourceID)
		}
	}
}
