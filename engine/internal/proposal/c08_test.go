// SPDX-License-Identifier: AGPL-3.0-only

package proposal

import (
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// C-08 — a report has an AUDIENCE, and the export audience withholds hosts
// whose evidence may be used here and not published.
//
// The probe first, per the C-06 lesson. This tree already refuses an indicator
// outright when a contributing source does not authorise `derived_output`, and
// that is the strongest half of this control. What it does not have is the
// split: `redistribution` and `derived_output` are different grants, the
// rights model already asks them separately (Indicator.Exportable), and
// nothing in the report path reads that function. A source that permits a
// household to compute a blocklist and forbids publishing one is a real and
// common position, and today its hosts are named in the only report there is.

// localOnly is a source whose data may be used here and not republished.
func localOnly(id string) sourceregistry.Source {
	s := testSource(id, nil)
	s.Permissions[sourceregistry.OpRedistribution] = prohibitedGrant()
	return s
}

func c08Report(t *testing.T, sources ...sourceregistry.Source) *Report {
	t.Helper()
	ids := make([]string, 0, len(sources))
	for _, s := range sources {
		ids = append(ids, s.SourceID)
	}
	return run{
		asserts: ids,
		sources: sources,
		policy:  testPolicy(t, 1, ScopeExact),
		records: adverseRecords(ids...),
	}.do(t)
}

func render(t *testing.T, r *Report) (text, js string) {
	t.Helper()
	var tb, jb strings.Builder
	r.Text(&tb)
	if err := r.JSON(&jb); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	return tb.String(), jb.String()
}

// TestTheLocalReportNamesWhatTheExportReportWithholds is the whole control.
func TestTheLocalReportNamesWhatTheExportReportWithholds(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))

	local := rep.ForAudience(AudienceLocal)
	lt, lj := render(t, local)
	if !strings.Contains(lt, "bad.example.com") || !strings.Contains(lj, "bad.example.com") {
		t.Fatalf("the LOCAL report does not name a host the household is permitted to act on:\n%s", lt)
	}

	export := rep.ForAudience(AudienceExport)
	et, ej := render(t, export)
	if strings.Contains(et, "bad.example.com") {
		t.Errorf("the EXPORT text report names a host whose source forbids redistribution:\n%s", et)
	}
	if strings.Contains(ej, "bad.example.com") {
		t.Errorf("the EXPORT json report names it:\n%s", ej)
	}
}

// TestExportWithholdingCoversEveryDecision — block, abstain AND refuse. A
// refusal names the host today, and a refusal is exactly where a reader would
// look for one.
func TestExportWithholdingCoversEveryDecision(t *testing.T) {
	for name, build := range map[string]func(t *testing.T) *Report{
		"a proposal": func(t *testing.T) *Report {
			return c08Report(t, localOnly("src-a"))
		},
		"an abstention": func(t *testing.T) *Report {
			return run{
				asserts: []string{"src-a"},
				sources: []sourceregistry.Source{localOnly("src-a")},
				policy:  testPolicy(t, 2, ScopeExact), // one source, two required
				records: adverseRecords("src-a"),
			}.do(t)
		},
		"a refusal by household exception": func(t *testing.T) *Report {
			p := testPolicy(t, 1, ScopeExact, Exception{Value: "bad.example.com", Scope: ScopeExact, Note: "ours"})
			return run{
				asserts: []string{"src-a"},
				sources: []sourceregistry.Source{localOnly("src-a")},
				policy:  p,
				records: adverseRecords("src-a"),
			}.do(t)
		},
	} {
		t.Run(name, func(t *testing.T) {
			rep := build(t)
			et, ej := render(t, rep.ForAudience(AudienceExport))
			if strings.Contains(et, "bad.example.com") || strings.Contains(ej, "bad.example.com") {
				t.Errorf("%s names the host in the export report:\n%s", name, et)
			}
		})
	}
}

// TestAnExportableHostIsStillNamed — the control on the control. A withholding
// that withholds everything is not a rights model, it is an off switch.
func TestAnExportableHostIsStillNamed(t *testing.T) {
	rep := c08Report(t, testSource("src-a", nil))
	et, ej := render(t, rep.ForAudience(AudienceExport))
	if !strings.Contains(et, "bad.example.com") || !strings.Contains(ej, "bad.example.com") {
		t.Fatalf("a host every contributing source permits republishing was withheld from export:\n%s", et)
	}
}

// TestTheExplanationIsTruncatedAtTheFirstColon.
//
// An explanation's leading clause is this build's own vocabulary; everything
// after the colon is detail quoted from the evidence and the registry — source
// ids, counts, origin names. A withheld item that carries the detail has had
// its name removed and its fingerprint left behind.
func TestTheExplanationIsTruncatedAtTheFirstColon(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))
	export := rep.ForAudience(AudienceExport)
	for _, o := range export.Outcomes {
		if !o.IdentityWithheld {
			continue
		}
		if strings.Contains(o.Explanation, ":") {
			t.Errorf("a withheld export outcome carries detail past the first colon: %q", o.Explanation)
		}
		if strings.Contains(o.Explanation, "src-a") {
			t.Errorf("a withheld export outcome names a contributing source: %q", o.Explanation)
		}
	}
}

// TestAWithheldExportOutcomeCarriesNoDerivedField — the name is not the only
// identifier. Source lists, signal lists and an origin-group count are a
// fingerprint that a reader holding the same evidence can match.
func TestAWithheldExportOutcomeCarriesNoDerivedField(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))
	for _, o := range rep.ForAudience(AudienceExport).Outcomes {
		if !o.IdentityWithheld {
			continue
		}
		switch {
		case o.Canonical != "":
			t.Errorf("Canonical survived: %q", o.Canonical)
		case len(o.Sources) > 0, len(o.IndependentSources) > 0, len(o.AdverseSources) > 0,
			len(o.UnestablishedSources) > 0, len(o.AggregatedSources) > 0,
			len(o.AuthoritativeSources) > 0, len(o.RetractedBy) > 0, len(o.SharedOrigins) > 0:
			t.Errorf("a source list survived on a withheld outcome: %+v", o)
		case len(o.Signals) > 0:
			t.Errorf("Signals survived: %v", o.Signals)
		case o.IndependentOriginGroups != 0:
			t.Errorf("IndependentOriginGroups survived: %d", o.IndependentOriginGroups)
		case o.Exception != nil:
			t.Errorf("the household's exception survived: %+v", o.Exception)
		case o.Scope != "":
			t.Errorf("Scope survived: %q", o.Scope)
		}
	}
}

// TestRecordsAreWithheldForExportToo — an indicator withheld at the outcome
// and named in the record list is withheld nowhere.
func TestRecordsAreWithheldForExportToo(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))
	for _, rec := range rep.ForAudience(AudienceExport).Records {
		if rec.Canonical != "" {
			t.Errorf("record %d names %q in an export report", rec.Index, rec.Canonical)
		}
		if !rec.CanonicalWithheld {
			t.Errorf("record %d has no value and does not say it was withheld; an empty field that "+
				"means both 'nothing' and 'not for you' is not a statement", rec.Index)
		}
	}
}

// TestASingleWithheldTotal — one number, said out loud, so a reader cannot
// take the counts for a complete picture.
func TestASingleWithheldTotal(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"), testSource("src-b", nil))
	export := rep.ForAudience(AudienceExport)
	c := export.Counts()
	if c.ExportWithheld != 1 {
		t.Fatalf("ExportWithheld = %d, want 1", c.ExportWithheld)
	}
	et, _ := render(t, export)
	if !strings.Contains(et, "WITHHELD") {
		t.Errorf("the export text report does not say anything was withheld:\n%s", et)
	}
	if local := rep.ForAudience(AudienceLocal).Counts(); local.ExportWithheld != 0 {
		t.Errorf("the local report reports %d withheld; nothing is withheld from the household",
			local.ExportWithheld)
	}
}

// TestForAudienceDoesNotMutateTheReport — the two renderings are taken from
// one report in one run, and a caller writing the export first must not get a
// redacted local report afterwards.
func TestForAudienceDoesNotMutateTheReport(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))
	_ = rep.ForAudience(AudienceExport)
	lt, _ := render(t, rep.ForAudience(AudienceLocal))
	if !strings.Contains(lt, "bad.example.com") {
		t.Fatalf("rendering the export report redacted the original:\n%s", lt)
	}
}

// TestAnUnknownAudienceWithholds — fail closed. A caller that passes a typo
// must not get the local report.
func TestAnUnknownAudienceWithholds(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))
	et, _ := render(t, rep.ForAudience(Audience("locel")))
	if strings.Contains(et, "bad.example.com") {
		t.Fatalf("an unrecognised audience was treated as local:\n%s", et)
	}
}

// TestPlanItemsAndDeferredSamplesAreWithheldToo.
//
// The one place a withheld host reappears as a bare string. An outcome
// carries a decision and a reason around its name; `Blocks` and `Deferred`
// are lists of names and nothing else, so a withholding that stopped at the
// outcome list would publish the same hosts one field down.
func TestPlanItemsAndDeferredSamplesAreWithheldToo(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"))
	plan := Qualify(rep, autoPolicy(t, 1, completeAutomatic(5)), AutoInputs{})

	if len(plan.Blocks) != 1 || plan.Blocks[0] != "bad.example.com" {
		t.Fatalf("the local plan does not carry the block it would make: %v", plan.Blocks)
	}

	export := plan.ForAudience(AudienceExport)
	for _, b := range export.Blocks {
		if b == "bad.example.com" {
			t.Errorf("the export plan names a host whose source forbids republishing it")
		}
	}
	for _, d := range export.Deferred {
		if d.Canonical == "bad.example.com" {
			t.Errorf("a deferred sample names it")
		}
	}
	for _, o := range export.Outcomes {
		if o.Canonical == "bad.example.com" {
			t.Errorf("a plan outcome names it")
		}
	}
	if export.WithheldFromExport != 1 {
		t.Errorf("WithheldFromExport = %d, want 1", export.WithheldFromExport)
	}
	// The local plan is unchanged by having rendered the export one.
	if len(plan.Blocks) != 1 {
		t.Errorf("ForAudience mutated the plan it was given: %v", plan.Blocks)
	}
}

// TestADeferredSampleIsWithheldEvenWhenTheRunWasHeld — the deferral queue is
// populated on the held path too, and it is the path a reader is most likely
// to forget.
func TestADeferredSampleIsWithheldEvenWhenTheRunWasHeld(t *testing.T) {
	rep := c08Report(t, localOnly("src-a"), localOnly("src-b"))
	// A per-run cap of zero holds the whole run and defers everything.
	plan := Qualify(rep, autoPolicy(t, 1, completeAutomatic(0)), AutoInputs{})
	if !plan.Held || len(plan.Deferred) == 0 {
		t.Fatalf("the fixture did not produce a held run with deferrals: held=%v deferred=%v",
			plan.Held, plan.Deferred)
	}
	for _, d := range plan.ForAudience(AudienceExport).Deferred {
		if d.Canonical == "bad.example.com" {
			t.Fatalf("a deferred sample named a withheld host in the export plan")
		}
	}
}
