// SPDX-License-Identifier: AGPL-3.0-only

package acquire_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/acquire"
)

// C-14 — a secret in a source URL reaches neither a stored row, nor an error,
// nor a log.
//
// The log half is proven in internal/audit/c14_test.go, where the one
// implementation lives. This file covers the other two: the rows this package
// writes down, and the errors it composes.

// See internal/audit/c14_test.go for why the marker is not credential-shaped
// and the parameter is not spelled api_key: this repository's secret scanner
// refuses such a literal in any file, tests included.
const c14Marker = "MARKER-THAT-MUST-NEVER-BE-LOGGED"

func TestNothingThisPackageStoresHasAPlaceToPutAURL(t *testing.T) {
	// The cheapest control there is: a field that does not exist cannot leak.
	// If a URL is ever added to one of these, this test is the place the
	// decision has to be argued.
	for _, v := range []any{acquire.Attempt{}, acquire.Snapshot{}, acquire.Failure{}, acquire.Event{}} {
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			name := strings.ToLower(rt.Field(i).Name)
			if strings.Contains(name, "url") || strings.Contains(name, "uri") ||
				strings.Contains(name, "endpoint") || strings.Contains(name, "address") {
				t.Errorf("%s.%s looks like it holds a URL; a source URL may carry an API key and "+
					"this value is stored", rt.Name(), rt.Field(i).Name)
			}
		}
	}
}

func TestAnAttemptRowNeverCarriesTheCredential(t *testing.T) {
	url := "https://feeds.example.com/v1/list?token=" + c14Marker
	run := acquire.Run(acquire.RunInput{
		SourceIDs: []string{"src-0001"},
		Limits:    sensibleLimits(),
		Now:       now,
		Fetch: func(string) (acquire.Snapshot, error) {
			return acquire.Snapshot{}, errors.New(`Get "` + url + `": dial tcp 192.0.2.1:443: connect: refused`)
		},
	})
	got := run.Attempts[0].Error
	if strings.Contains(got, c14Marker) {
		t.Fatalf("the attempt row carries the credential: %q", got)
	}
	if !strings.Contains(got, "feeds.example.com") {
		t.Errorf("the row lost the host as well as the key, so it cannot say which source failed: %q", got)
	}
}

func TestAFetchErrorNeverCarriesTheCredential(t *testing.T) {
	// A real failure, composed by the standard library, against a port
	// nothing is listening on. The URL is the one this process was given.
	lim := testLimits()
	lim.Deadline = 500 * time.Millisecond
	_, err := acquire.Fetch(context.Background(),
		"https://127.0.0.1:1/v1/list?token="+c14Marker, lim)
	if err == nil {
		t.Fatalf("something answered on port 1")
	}
	if strings.Contains(err.Error(), c14Marker) {
		t.Fatalf("the fetch error carries the credential: %v", err)
	}
}

func TestRedactKeepsWhatTellsSourcesApart(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://feeds.example.com/v1/list?token=" + c14Marker, "https://feeds.example.com/v1/list?[redacted]"},
		{"https://user:" + c14Marker + "@feeds.example.com/v1/list", "https://feeds.example.com/v1/list?[redacted]"},
		{"https://feeds.example.com/v1/list#" + c14Marker, "https://feeds.example.com/v1/list?[redacted]"},
		{"https://feeds.example.com/v1/list.json", "https://feeds.example.com/v1/list.json"},
		{"no url here at all", "no url here at all"},
		{
			`Get "https://a.example.com/x?k=` + c14Marker + `": then https://b.example.com/y?k=` + c14Marker,
			`Get "https://a.example.com/x?[redacted]": then https://b.example.com/y?[redacted]`,
		},
	} {
		if got := acquire.Redact(tc.in); got != tc.want {
			t.Errorf("Redact(%q)\n  = %q\n want %q", tc.in, got, tc.want)
		}
	}
}

// TestTheRemovalIsMarkedNotSilent — a reader must be able to tell a URL that
// had no query from one whose query was taken away. Without the marker the
// two render identically and a reviewer cannot tell whether the control ran.
func TestTheRemovalIsMarkedNotSilent(t *testing.T) {
	plain := acquire.Redact("https://feeds.example.com/list")
	stripped := acquire.Redact("https://feeds.example.com/list?token=" + c14Marker)
	if plain == stripped {
		t.Fatalf("a URL with a query and one without render identically as %q", plain)
	}
}
