// SPDX-License-Identifier: AGPL-3.0-only

package evaluation

import (
	"reflect"
	"strings"
	"testing"
)

// # WHAT THIS FILE IS ABOUT
//
// FINDING-108 … FINDING-110 were each one field of Binding that was recorded
// but not checked. They were found one at a time, which is how a reader finds
// the NEXT one too — by noticing it, or by not noticing it. A field-by-field
// audit answers the question once, and this file is that audit expressed as a
// test rather than as a table in a document that the code can drift away from.
//
// The audit below states, for every field, whether Reproducible REQUIRES it
// and whether comparableWith COMPARES it. Both halves are then measured, in
// both directions:
//
//   - a field marked required must make Reproducible FALSE when it is zeroed,
//     and a field marked not-required must leave it TRUE. The second half is
//     the positive control: without it "require everything" would pass.
//   - a field marked compared must make comparableWith FALSE when it differs
//     on one side, and a field marked not-compared must leave it TRUE. Again
//     the second half is what stops "refuse every comparison" from passing.
//
// And the table must name EXACTLY the fields the struct has. A field added to
// Binding without an entry here fails this test, which is the property the
// three findings above would have needed to be caught when they were written.

// bindingAudit is the audited treatment of every Binding field.
//
// `alt` is a value that genuinely differs from what boundResult produces —
// checked below, because an `alt` that silently equalled the bound value would
// turn a comparison assertion into a tautology.
type bindingAuditRow struct {
	field string
	// required: Reproducible refuses when this field is zeroed.
	required bool
	// compared: comparableWith refuses when this field differs on one side.
	compared bool
	// alt is a differing value for the compared check.
	alt any
	// why records the justification for an exclusion. Required for every row
	// that is not both required and compared.
	why string
}

var bindingAuditRows = []bindingAuditRow{
	{field: "FixtureDigest", required: true, compared: true,
		alt: "sha256:" + strings.Repeat("11", 32)},

	{field: "FixtureSetID", required: false, compared: true, alt: "other-set",
		why: "the id is INSIDE the fixture document, so FixtureDigest already " +
			"binds it and a run whose digest is present is identified without it. " +
			"It is compared anyway as defence in depth for a Binding assembled by " +
			"hand rather than through ParseSet"},

	{field: "FixtureSetVersion", required: false, compared: true, alt: "v99",
		why: "inside the document; see FixtureSetID"},

	{field: "Partition", required: false, compared: true, alt: Partition("development"),
		why: "inside the document; see FixtureSetID. The comparison is the one " +
			"that stops a development result being held up against a held-out one"},

	{field: "RegistryDigest", required: true, compared: true,
		alt: "sha256:" + strings.Repeat("22", 32)},

	{field: "RegistryState", required: true, compared: true, alt: "absent"},

	{field: "BaselineName", required: false, compared: false, alt: "renamed",
		why: "a name is a label the caller chose. BaselineDigest is what the " +
			"baseline IS and is both required and compared; refusing a pair " +
			"because someone renamed a list would compare two labels rather " +
			"than two measurements"},

	{field: "BaselineDigest", required: true, compared: true,
		alt: "sha256:" + strings.Repeat("33", 32)},

	{field: "CandidateName", required: false, compared: false, alt: "renamed",
		why: "see BaselineName"},

	{field: "CandidateDigest", required: true, compared: false,
		alt: "sha256:" + strings.Repeat("44", 32),
		why: "the candidate is EXPECTED to differ — that is what a before/after " +
			"comparison is. It is still required, because a result that does not " +
			"bind the configuration it measured cannot be reproduced"},

	{field: "SemanticsVersion", required: true, compared: true, alt: 1},

	{field: "EvaluationTime", required: true, compared: true, alt: "2020-01-02T03:04:05Z"},

	{field: "SourceCommit", required: true, compared: false,
		alt: strings.Repeat("c", 40),
		why: "a before/after comparison is normally BETWEEN two commits, so " +
			"requiring equality would refuse the operation this package exists " +
			"for. It is required for reproduction, because a result that does " +
			"not identify the code it measured cannot be reproduced"},
}

// TestTheBindingAuditCoversEveryField fails when a field is added to Binding
// without a decision being recorded about it.
func TestTheBindingAuditCoversEveryField(t *testing.T) {
	audited := make(map[string]bool, len(bindingAuditRows))
	for _, row := range bindingAuditRows {
		if audited[row.field] {
			t.Errorf("%s is audited twice", row.field)
		}
		audited[row.field] = true
	}

	rt := reflect.TypeOf(Binding{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if !audited[name] {
			t.Errorf("Binding.%s has no audit entry: state whether Reproducible "+
				"must require it and whether comparableWith must compare it, and "+
				"why, before it can be carried as a binding", name)
		}
		delete(audited, name)
	}
	for name := range audited {
		t.Errorf("the audit has an entry for %s, which Binding no longer has", name)
	}
}

// TestEveryExclusionIsJustified keeps an exclusion from being made by
// forgetting to write one down.
func TestEveryExclusionIsJustified(t *testing.T) {
	for _, row := range bindingAuditRows {
		if row.required && row.compared {
			continue
		}
		if strings.TrimSpace(row.why) == "" {
			t.Errorf("Binding.%s is excluded from a check with no recorded reason",
				row.field)
		}
	}
}

// TestTheAuditedTreatmentIsWhatTheCodeDoes measures both halves of every row.
func TestTheAuditedTreatmentIsWhatTheCodeDoes(t *testing.T) {
	rt := reflect.TypeOf(Binding{})
	for _, row := range bindingAuditRows {
		f, ok := rt.FieldByName(row.field)
		if !ok {
			t.Errorf("Binding has no field %s", row.field)
			continue
		}
		idx := f.Index[0]

		t.Run(row.field+"/required", func(t *testing.T) {
			r := boundResult(t, canonicalCommit)
			if ok, missing := r.Reproducible(); !ok {
				t.Fatalf("premise broken: the unmutated result is not reproducible: %v", missing)
			}
			reflect.ValueOf(&r.Binding).Elem().Field(idx).Set(reflect.Zero(f.Type))

			ok, missing := r.Reproducible()
			switch {
			case row.required && ok:
				t.Errorf("%s was erased and the result still claims to carry every "+
					"binding needed to reproduce it", row.field)
			case !row.required && !ok:
				t.Errorf("%s is audited as not required, but erasing it made the "+
					"result unreproducible: %v\naudit reason: %s",
					row.field, missing, row.why)
			}
			if row.required && claimsFullReproducibility(t, r) {
				t.Errorf("%s was erased and the TEXT report still claims full "+
					"reproducibility", row.field)
			}
		})

		t.Run(row.field+"/compared", func(t *testing.T) {
			before := boundResult(t, canonicalCommit)
			after := boundResult(t, canonicalCommit)
			if why, ok := comparableWith(before, after); !ok {
				t.Fatalf("premise broken: two identical runs are incomparable: %s", why)
			}
			target := reflect.ValueOf(&after.Binding).Elem().Field(idx)
			alt := reflect.ValueOf(row.alt).Convert(f.Type)
			if target.Interface() == alt.Interface() {
				t.Fatalf("premise broken: the audit's alternate value for %s equals "+
					"the bound value, so this assertion would hold vacuously", row.field)
			}
			target.Set(alt)

			why, ok := comparableWith(before, after)
			switch {
			case row.compared && ok:
				t.Errorf("%s differs between the two runs and they were still "+
					"reported comparable", row.field)
			case !row.compared && !ok:
				t.Errorf("%s is audited as not compared, but changing it made the "+
					"two runs incomparable: %s\naudit reason: %s", row.field, why, row.why)
			}
		})
	}
}
