// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/sourceregistry"
)

// asOfOrder17B is the date ORDER 17B's citations were read. Using an
// instant AFTER that date lets Validate accept the citations without
// pretending the clock said otherwise.
var asOfOrder17B = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

// TestOrder17BShippedRegistryExportableAndCommerciallyExportable proves,
// against the registry that actually ships, the three claims ORDER 17B §1
// "Effect" states:
//
//   - Household shadow blocking (UsableLocally) may use CERT Polska,
//     Phishing.Database, OpenPhish, URLhaus and ThreatFox.
//
//   - The free public list (Exportable = derived_output AND redistribution)
//     may carry entries supported ONLY by CERT Polska. Phishing.Database
//     joins once the MIT notice is emitted; until then the entry is still
//     refused because satisfied = unknown.
//
//   - The paid feed (CommerciallyExportable = Exportable AND commercial_use)
//     may carry entries supported ONLY by CERT Polska.
//
// This is B2 in ORDER 17B §5, and it is the test that gates every grant in
// the shipped registry against the policy helpers that read it.
func TestOrder17BShippedRegistryExportableAndCommerciallyExportable(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	reg, _, err := sourceregistry.Load(filepath.Join(filepath.Dir(here), "..", "..", "config", "registry.json"))
	if err != nil {
		t.Fatalf("Load shipped registry: %v", err)
	}
	if ps := reg.Validate(asOfOrder17B); len(ps) > 0 {
		for _, p := range ps {
			t.Errorf("registry: %s", p.String())
		}
		t.Fatal("registry has validation problems")
	}

	type row struct {
		sourceIDs  []string
		localOK    bool
		exportOK   bool
		paidExport bool
		reason     string
	}
	rows := []row{
		{
			sourceIDs:  []string{"cert-polska-warning-list"},
			localOK:    true,
			exportOK:   true,
			paidExport: true,
			reason:     "CERT Polska is `permitted` for every operation except model_training; it clears Exportable and CommerciallyExportable alone.",
		},
		{
			sourceIDs:  []string{"urlhaus"},
			localOK:    true,
			exportOK:   false,
			paidExport: false,
			reason:     "URLhaus is conditional-satisfied for retrieval/local_storage/enrichment but prohibits derived_output and redistribution; commercial_use is conditional-unsatisfied. Locally usable; not exportable; not paid-exportable.",
		},
		{
			sourceIDs:  []string{"threatfox"},
			localOK:    true,
			exportOK:   false,
			paidExport: false,
			reason:     "ThreatFox shares URLhaus's abuse.ch terms.",
		},
		{
			sourceIDs:  []string{"openphish-community"},
			localOK:    true,
			exportOK:   false,
			paidExport: false,
			reason:     "OpenPhish is personal-use-only; redistribution, derived_output and commercial_use are prohibited.",
		},
		{
			sourceIDs:  []string{"phishing-database"},
			localOK:    true,
			exportOK:   false,
			paidExport: false,
			reason:     "Phishing.Database is MIT-conditional; satisfied for retrieval/local_storage/enrichment, unknown for redistribution/derived_output/commercial_use until the publisher emits the notice.",
		},
		{
			sourceIDs:  []string{"urlhaus", "cert-polska-warning-list"},
			localOK:    true,
			exportOK:   false,
			paidExport: false,
			reason:     "A URLhaus-backed indicator is refused for export because derived_output and redistribution are prohibited at URLhaus. A single refusing contributor blocks the derived aggregate (unanimity rule).",
		},
	}

	for _, r := range rows {
		t.Run(filepath.Join(r.sourceIDs...), func(t *testing.T) {
			ind := indicatorOf(t, r.sourceIDs...)
			if got := ind.UsableLocally(reg, t1); got.Permitted != r.localOK {
				t.Errorf("UsableLocally: got=%v want=%v; %s\n  refusals: %v", got.Permitted, r.localOK, r.reason, got.Refusals)
			}
			if got := ind.Exportable(reg, t1); got.Permitted != r.exportOK {
				t.Errorf("Exportable: got=%v want=%v; %s\n  refusals: %v", got.Permitted, r.exportOK, r.reason, got.Refusals)
			}
			if got := ind.CommerciallyExportable(reg, t1); got.Permitted != r.paidExport {
				t.Errorf("CommerciallyExportable: got=%v want=%v; %s\n  refusals: %v", got.Permitted, r.paidExport, r.reason, got.Refusals)
			}
		})
	}
}
