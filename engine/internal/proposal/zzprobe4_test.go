package proposal

import (
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

func TestProbePolicyNoteBinding(t *testing.T) {
	mk := func(note string) *Policy {
		p, err := ParsePolicy([]byte(`{"schema_version":1,"min_independent_sources":1,
			"proposal_scope":"exact","note":"policy note",
			"exceptions":[{"value":"bank.example.com","scope":"exact","note":"` + note + `"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := mk("the household bank"), mk("A COMPLETELY DIFFERENT NOTE")
	t.Logf("digest A = %s", a.Digest())
	t.Logf("digest B = %s", b.Digest())
	if a.Digest() == b.Digest() {
		t.Errorf("two policies whose REPORTED notes differ share a digest")
	}
}

func TestProbeAuthorityDigestScope(t *testing.T) {
	_, pub := testKey(t, 0x31)
	one := authorityOver(t, "k", pub, []string{"src-a"}, nil)
	t.Logf("one-signer document digest  = %s", one.Digest())
	t.Logf("binding authorityDigest uses the SELECTED SIGNER only; see report.go")
}

func TestProbeRegistryMutationDuringRun(t *testing.T) {
	_, in := authedEvidence(t)
	before, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("registry digest as bound = %s", before.Binding.RegistryDigest)
	// Mutate the registry the caller still holds, then rebuild.
	in.Registry.Sources[0].Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
	after, err := Build(in)
	if err != nil {
		t.Fatalf("after mutation: %v", err)
	}
	t.Logf("registry digest after     = %s", after.Binding.RegistryDigest)
	t.Logf("decision before=%s after=%s", before.Outcomes[0].Decision, after.Outcomes[0].Decision)
}
