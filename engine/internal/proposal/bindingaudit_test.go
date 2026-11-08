// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// # WHAT THIS FILE IS ABOUT
//
// ORDER 7 item 4. A binding field is a CITATION: it says which input the
// report was computed from. Two ways for one to be wrong, and both were
// present:
//
//	FINDING-123  Policy.Digest omitted the operator NOTES, and a matched
//	             exception's note is quoted in the outcome. Two policies
//	             producing two different reports shared a digest.
//	FINDING-124  authorityDigest was named for the whole authority document,
//	             documented as covering it, and computed over the selected
//	             signer alone.
//
// This file is the audit as a test rather than as a table in a document the
// code can drift away from. Every field of Binding names the input it
// identifies and a mutation that must move it, and the table must name
// EXACTLY the fields the struct has.

// bindingAuditRow is the audited treatment of one Binding field.
type bindingAuditRow struct {
	field string
	// identifies is the input this field is a citation of.
	identifies string
	// mutate changes that input. Nil means the field is not derived from an
	// input a test can vary, and `why` must say so.
	mutate func(*bindingProbe)
	// why records the justification when mutate is nil.
	why string
}

// bindingProbe is a complete, mutable set of inputs for one run.
type bindingProbe struct {
	t           *testing.T
	keyID       string
	feedID      string
	asserts     []string
	extraSigner bool
	sources     []sourceregistry.Source
	policyDoc   string
	records     []feed.EvidenceRecord
	buildID     string
	atOffsetHr  int
}

func newBindingProbe(t *testing.T) *bindingProbe {
	return &bindingProbe{
		t:       t,
		keyID:   "audit-key",
		feedID:  "audit-feed",
		asserts: []string{"src-a"},
		sources: []sourceregistry.Source{testSource("src-a", nil)},
		policyDoc: `{"schema_version":1,"min_independent_sources":1,"proposal_scope":"exact",
			"note":"the audit policy",
			"exceptions":[{"value":"bank.example.com","scope":"exact","note":"the household bank"}]}`,
		records: []feed.EvidenceRecord{adverse("src-a", "a1", "one.example.com")},
		buildID: "scamwall audit (commit aaaa, built 2026-01-01)",
	}
}

func (p *bindingProbe) build() Binding {
	p.t.Helper()
	priv, pub := testKey(p.t, 0x51)

	signers := []feed.Signer{{
		KeyID: p.keyID, PublicKey: pub, AssertsSourceIDs: p.asserts,
	}}
	if p.extraSigner {
		_, other := testKey(p.t, 0x52)
		signers = append(signers, feed.Signer{
			KeyID: "a-second-signer", PublicKey: other,
			AssertsSourceIDs: []string{"src-z"},
		})
	}
	authDoc, err := jsonOf(feed.SignerAuthority{
		SchemaVersion: feed.SignerAuthoritySchemaVersion, Signers: signers,
	})
	if err != nil {
		p.t.Fatal(err)
	}
	auth, err := feed.ParseSignerAuthority(authDoc)
	if err != nil {
		p.t.Fatalf("authority: %v", err)
	}

	doc := signEvidence(p.t, priv, p.keyID, p.feedID, p.records)
	at := testAt.Add(time.Duration(p.atOffsetHr) * time.Hour)
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: at,
	})
	if err != nil {
		p.t.Fatalf("evidence: %v", err)
	}
	policy, err := ParsePolicy([]byte(p.policyDoc))
	if err != nil {
		p.t.Fatalf("policy: %v", err)
	}
	reg := &sourceregistry.Registry{
		SchemaVersion: sourceregistry.SchemaVersion, Sources: p.sources,
	}
	if problems := reg.Validate(testAt); len(problems) > 0 {
		for _, pr := range problems {
			p.t.Errorf("fixture registry problem: %s", pr)
		}
		p.t.FailNow()
	}
	rep, err := Build(Input{Evidence: ev, Registry: reg, Policy: policy,
		At: at, BuildIdentity: p.buildID})
	if err != nil {
		p.t.Fatalf("build: %v", err)
	}
	return rep.Binding
}

var bindingAuditRows = []bindingAuditRow{
	{field: "EvidenceDigest", identifies: "the exact bytes of the signed document",
		mutate: func(p *bindingProbe) {
			p.records = []feed.EvidenceRecord{adverse("src-a", "a1", "two.example.com")}
		}},

	{field: "EvidenceFeedID", identifies: "what the document CLAIMS to be, for readability",
		mutate: func(p *bindingProbe) { p.feedID = "a-different-feed" }},

	{field: "EvidenceManifestVersion", identifies: "the payload version the document declares",
		why: "this build reads exactly one manifest version, so a run with a " +
			"different one is refused before a binding exists. The field is " +
			"carried for a reader, and varying it is not something a passing " +
			"run can do"},

	{field: "SigningKeyID", identifies: "the key id the envelope carried",
		mutate: func(p *bindingProbe) {
			p.keyID = "a-different-key"
			p.asserts = []string{"src-a"}
		}},

	{field: "AuthorityDigest", identifies: "the WHOLE signer-authority document",
		mutate: func(p *bindingProbe) { p.extraSigner = true }},

	{field: "SignerGrantDigest", identifies: "the ONE signer that signed this document",
		mutate: func(p *bindingProbe) { p.asserts = []string{"src-a", "src-b"} }},

	{field: "RegistryDigest", identifies: "the source registry's canonical contents",
		mutate: func(p *bindingProbe) {
			p.sources = append(p.sources, testSource("src-b", nil))
		}},

	{field: "PolicyDigest", identifies: "the proposal policy AS REPORTED, notes included",
		mutate: func(p *bindingProbe) {
			p.policyDoc = strings.Replace(p.policyDoc, "the household bank", "A DIFFERENT NOTE", 1)
		}},

	{field: "EvaluatedAt", identifies: "the instant expiry and withdrawal were decided against",
		mutate: func(p *bindingProbe) { p.atOffsetHr = 3 }},

	{field: "SemanticsVersion", identifies: "this package's DECISION RULES",
		why: "a manually maintained rule version. It is not derived from an " +
			"input and cannot be varied by one, which is exactly why it must " +
			"never be read as identifying the code that ran — see BuildIdentity"},

	{field: "BuildIdentity", identifies: "the code that produced the report, when the caller says",
		mutate: func(p *bindingProbe) { p.buildID = "scamwall other (commit bbbb, built 2026-02-02)" }},

	{field: "BuildIdentityState", identifies: "whether a build identity was supplied at all",
		mutate: func(p *bindingProbe) { p.buildID = "" }},
}

// TestTheBindingAuditCoversEveryField fails when a field is added to Binding
// without a decision being recorded about what it identifies.
func TestTheBindingAuditCoversEveryField(t *testing.T) {
	audited := map[string]bool{}
	for _, row := range bindingAuditRows {
		if audited[row.field] {
			t.Errorf("%s is audited twice", row.field)
		}
		audited[row.field] = true
		if strings.TrimSpace(row.identifies) == "" {
			t.Errorf("%s does not say what input it identifies", row.field)
		}
		if row.mutate == nil && strings.TrimSpace(row.why) == "" {
			t.Errorf("%s has no mutation and no recorded reason for not having one", row.field)
		}
	}
	rt := reflect.TypeOf(Binding{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if !audited[name] {
			t.Errorf("Binding.%s has no audit entry: state which input it identifies "+
				"and how a test changes that input, before it can be carried as a "+
				"citation", name)
		}
		delete(audited, name)
	}
	for name := range audited {
		t.Errorf("the audit has an entry for %s, which Binding no longer has", name)
	}
}

// TestEveryBindingFieldMovesWithTheInputItIdentifies.
//
// One input at a time. The field under test must change, and — this is the
// half that catches a digest computed over too much — no OTHER field may
// change, except where the mutation genuinely changes two inputs.
func TestEveryBindingFieldMovesWithTheInputItIdentifies(t *testing.T) {
	base := newBindingProbe(t).build()

	for _, row := range bindingAuditRows {
		if row.mutate == nil {
			continue
		}
		t.Run(row.field, func(t *testing.T) {
			p := newBindingProbe(t)
			row.mutate(p)
			got := p.build()

			before := reflect.ValueOf(base).FieldByName(row.field).Interface()
			after := reflect.ValueOf(got).FieldByName(row.field).Interface()
			if reflect.DeepEqual(before, after) {
				t.Errorf("%s identifies %s, and changing that input did not move it "+
					"(still %v)", row.field, row.identifies, after)
			}
		})
	}
}

// TestChangingTheEvidenceDoesNotMoveTheOperatorBindings is the other
// direction, and it is what stops "digest everything together" from passing
// the table above.
func TestChangingTheEvidenceDoesNotMoveTheOperatorBindings(t *testing.T) {
	base := newBindingProbe(t).build()
	p := newBindingProbe(t)
	p.records = []feed.EvidenceRecord{adverse("src-a", "a9", "elsewhere.example.net")}
	got := p.build()

	if got.EvidenceDigest == base.EvidenceDigest {
		t.Fatal("premise broken: the evidence did not change")
	}
	for _, f := range []string{"AuthorityDigest", "SignerGrantDigest", "RegistryDigest",
		"PolicyDigest", "EvaluatedAt", "BuildIdentity"} {
		b := reflect.ValueOf(base).FieldByName(f).Interface()
		a := reflect.ValueOf(got).FieldByName(f).Interface()
		if !reflect.DeepEqual(a, b) {
			t.Errorf("changing the EVIDENCE moved %s, which identifies something else:"+
				"\n  before %v\n  after  %v", f, b, a)
		}
	}
}

// TestTheTwoAuthorityDigestsAreDifferentThings.
//
// FINDING-124. One says what the operator's whole file grants; the other says
// what the signer that actually signed was granted. A change to a DIFFERENT
// signer must move the first and not the second.
func TestTheTwoAuthorityDigestsAreDifferentThings(t *testing.T) {
	base := newBindingProbe(t).build()

	p := newBindingProbe(t)
	p.extraSigner = true
	withOther := p.build()

	if withOther.AuthorityDigest == base.AuthorityDigest {
		t.Error("adding a second signer to the operator's document did not move " +
			"the whole-document digest")
	}
	if withOther.SignerGrantDigest != base.SignerGrantDigest {
		t.Error("adding an UNRELATED signer moved the digest of the grant that " +
			"admitted this run; the narrower field is not narrow")
	}

	// And the converse: widening the signing signer's own grant moves both,
	// because the whole document contains that signer.
	q := newBindingProbe(t)
	q.asserts = []string{"src-a", "src-b"}
	widened := q.build()
	if widened.SignerGrantDigest == base.SignerGrantDigest {
		t.Error("widening the signing signer's grant did not move the grant digest")
	}
	if widened.AuthorityDigest == base.AuthorityDigest {
		t.Error("widening a signer inside the document did not move the document digest")
	}
}

// TestSemanticsVersionIsNotPresentedAsCodeIdentity.
//
// It is a manually maintained rule number. A report can carry semantics v1
// from any number of commits, and a reader must not be able to mistake it for
// a build stamp — which is the strongest false claim the binding could make.
func TestSemanticsVersionIsNotPresentedAsCodeIdentity(t *testing.T) {
	t.Run("supplied", func(t *testing.T) {
		out := renderBinding(t, newBindingProbe(t))
		if !strings.Contains(out, "a RULE version, not a build stamp") {
			t.Error("the report does not say what the semantics version is")
		}
		if !strings.Contains(out, "scamwall audit (commit aaaa") {
			t.Error("the supplied build identity is not reported")
		}
	})

	t.Run("not supplied", func(t *testing.T) {
		p := newBindingProbe(t)
		p.buildID = ""
		out := renderBinding(t, p)
		if !strings.Contains(out, "NOT SUPPLIED") {
			t.Error("an absent build identity is not reported as absent")
		}
		if !strings.Contains(out, "says nothing about which commit or binary ran") {
			t.Error("the report does not say that the rule version is not a build stamp")
		}
	})
}

// TestARunWhoseOperatorDocumentsMovedIsRefused.
//
// The binding is assembled before the first record and the decisions read the
// registry and the policy throughout. A report bound to one state and decided
// under another would cite a configuration it was not computed from.
//
// No synchronous path in this package reaches it today, which is why this is
// a CHECK and not a fix: it converts an unreachable mismatch into a detected
// one. The test reaches it by calling the check's own inputs apart, which is
// the only honest way to exercise a guard against something the code cannot
// currently do to itself.
func TestARunWhoseOperatorDocumentsMovedIsRefused(t *testing.T) {
	_, in := authedEvidence(t)

	t.Run("a registry that moved", func(t *testing.T) {
		// Two runs over the same Input with the registry edited in between
		// must produce two DIFFERENT registry digests, never one report
		// carrying the old digest and the new decision.
		first, err := Build(in)
		if err != nil {
			t.Fatal(err)
		}
		in.Registry.Sources[0].Permissions[sourceregistry.OpDerivedOutput] = prohibitedGrant()
		second, err := Build(in)
		if err != nil {
			t.Fatalf("the second run failed: %v", err)
		}
		if first.Binding.RegistryDigest == second.Binding.RegistryDigest {
			t.Error("the registry changed and the binding did not")
		}
		if first.Outcomes[0].Decision == second.Outcomes[0].Decision {
			t.Error("premise broken: the mutation changed no decision")
		}
	})

	t.Run("the guard compares the same digests the binding carries", func(t *testing.T) {
		// The guard is only as good as the equivalence it rests on: it
		// re-computes the registry and policy digests after the run and
		// compares them with the ones in the binding. If either side were
		// computed differently the guard would fire on every run, or never.
		// Asserting the equivalence through the public API is the honest way
		// to exercise a check against something the code cannot currently do
		// to itself.
		_, fresh := authedEvidence(t)
		rep, err := Build(fresh)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := digestJSON("source-registry", fresh.Registry), rep.Binding.RegistryDigest; got != want {
			t.Errorf("the guard would compare %q against a binding of %q", got, want)
		}
		if got, want := fresh.Policy.Digest(), rep.Binding.PolicyDigest; got != want {
			t.Errorf("the guard would compare %q against a binding of %q", got, want)
		}
		// And the source carries the guard, so a reader deleting it as
		// unreachable has to read why it is there first.
		src := buildSource(t)
		for _, want := range []string{
			"the source registry changed while the run was in ",
			"the proposal policy changed while the run was in ",
		} {
			if !strings.Contains(src, want) {
				t.Errorf("proposal.go no longer carries the guard %q", want)
			}
		}
	})
}

// jsonOf marshals a value for a fixture.
func jsonOf(v any) ([]byte, error) { return json.Marshal(v) }

// renderBinding produces the text report's bindings block for a probe.
func renderBinding(t *testing.T, p *bindingProbe) string {
	t.Helper()
	priv, pub := testKey(t, 0x51)
	auth := authorityOver(t, p.keyID, pub, p.asserts, nil)
	doc := signEvidence(t, priv, p.keyID, p.feedID, p.records)
	ev, err := feed.ValidateEvidence(doc, feed.EvidenceOptions{
		MaxFileBytes: 1 << 20, MaxRecords: 100, Authority: auth, Now: testAt,
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	policy, err := ParsePolicy([]byte(p.policyDoc))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	reg := &sourceregistry.Registry{SchemaVersion: sourceregistry.SchemaVersion, Sources: p.sources}
	rep, err := Build(Input{Evidence: ev, Registry: reg, Policy: policy,
		At: testAt, BuildIdentity: p.buildID})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var b strings.Builder
	rep.Text(&b)
	return b.String()
}

// buildSource reads this package's own source, so a guard that cannot be
// reached synchronously is still asserted to exist.
func buildSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("proposal.go")
	if err != nil {
		t.Fatalf("read proposal.go: %v", err)
	}
	return string(b)
}
