// SPDX-License-Identifier: AGPL-3.0-only

package feedsources_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/observation"
)

// Every classification and state a fetcher writes must be in the
// observation vocabulary. A value outside it ("harmful") makes every record
// record_invalid at admission, so the shadow zone silently stays empty.
func TestFetchersEmitObservationVocabulary(t *testing.T) {
	classRe := regexp.MustCompile(`(?:(?:^|[\s{,])Classification:\s*|class\s*:?=\s*)"([a-z_]+)"`)
	stateRe := regexp.MustCompile(`State:\s*"([a-z_]+)"`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	okClass := map[string]bool{}
	for _, c := range observation.ValidClassifications {
		okClass[string(c)] = true
	}
	okState := map[string]bool{}
	for _, s := range observation.ValidStates {
		okState[string(s)] = true
	}
	seen := 0
	for _, f := range files {
		if regexp.MustCompile(`_test\.go$`).MatchString(f) {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range classRe.FindAllSubmatch(b, -1) {
			seen++
			if !okClass[string(m[1])] {
				t.Errorf("%s: classification %q is not in observation.ValidClassifications", f, m[1])
			}
		}
		for _, m := range stateRe.FindAllSubmatch(b, -1) {
			if !okState[string(m[1])] {
				t.Errorf("%s: state %q is not in observation.ValidStates", f, m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("found no classification literals; the guard is not looking at the fetchers")
	}
}
