// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestPinga53AutomaticTemplateIsComplete proves the owner-approved contract
// shipped for Pinga53 (config/policy.json) is a
// complete automatic block: applied to a two-source policy it makes the
// contract ACTIVE and lets a two-voice adverse claim through.
func TestPinga53AutomaticTemplateIsComplete(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "config", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tmpl struct {
		Automatic map[string]any `json:"automatic"`
	}
	if err := json.Unmarshal(b, &tmpl); err != nil {
		t.Fatal(err)
	}
	if tmpl.Automatic == nil {
		t.Fatal("template has no automatic block")
	}
	p := autoPolicy(t, 2, tmpl.Automatic)
	plan := Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{})
	if plan.State != AutomaticActive {
		t.Fatalf("state = %s, want %s (unresolved: %v)", plan.State, AutomaticActive, plan.Unresolved)
	}
	if len(plan.Blocks) != 1 {
		t.Errorf("blocks = %v, want the one two-voice host", plan.Blocks)
	}
	if plan2 := Qualify(twoAdverse(t, p, "bad.example.com"), p, AutoInputs{EmergencyStopPresent: true}); len(plan2.Blocks) != 0 {
		t.Error("the emergency stop did not stop automatic blocking")
	}
}
