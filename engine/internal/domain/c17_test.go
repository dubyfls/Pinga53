// SPDX-License-Identifier: AGPL-3.0-only

package domain

import (
	"errors"
	"testing"
)

// ORDER 8, control C-17: "Public-suffix apexes and configured shared platforms
// (e.g. godaddysites.com, weeblysite.com, 000webhostapp.com) are refused.
// Their tenants remain blockable."
//
// # WHY A SECOND LIST BESIDE THE PUBLIC SUFFIX LIST
//
// The PSL half already works: `github.io` and `pages.dev` are public suffixes
// and Normalize refuses them, while `user.github.io` normalises fine.
//
// A shared hosting platform is the same shape and NOT in the PSL. Nothing
// stopped `godaddysites.com` from becoming a canonical name, and a single
// block on it takes out every tenant on the platform — the household is then
// cut off from sites it never had anything to do with. That is the first harm
// ORDER 8 §1 names, reached from a feed rather than from a mistake.
//
// The list only ever REFUSES. It can cost a block; it cannot cause one.

func TestSharedPlatformApexIsNotBlockable(t *testing.T) {
	for _, in := range []string{
		"godaddysites.com",
		"weeblysite.com",
		"000webhostapp.com",
		"GoDaddySites.com",
	} {
		_, err := Normalize(in)
		if !errors.Is(err, ErrSharedPlatform) {
			t.Errorf("Normalize(%q) error = %v, want ErrSharedPlatform; a block on "+
				"the apex takes out every tenant on the platform", in, err)
		}
	}
}

func TestSharedPlatformTenantsStayBlockable(t *testing.T) {
	for _, in := range []string{
		"scam-tenant.godaddysites.com",
		"a.b.weeblysite.com",
		"phish.000webhostapp.com",
	} {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q) refused a tenant: %v; refusing the platform "+
				"must not refuse the sites hosted on it", in, err)
			continue
		}
		if got.String() == "" {
			t.Errorf("Normalize(%q) returned an empty canonical form", in)
		}
	}
}

// TestPublicSuffixAndSharedPlatformAreDistinctReasons. Two rules, two codes: a
// reviewer asking why a name was not blocked needs to know which list it was
// on, because one is a compiled snapshot of the PSL and the other is this
// repository's own judgement and is extended by hand.
func TestPublicSuffixAndSharedPlatformAreDistinctReasons(t *testing.T) {
	if _, err := Normalize("github.io"); !errors.Is(err, ErrPublicSuffix) {
		t.Errorf("github.io error = %v, want ErrPublicSuffix", err)
	}
	if _, err := Normalize("godaddysites.com"); errors.Is(err, ErrPublicSuffix) {
		t.Error("godaddysites.com was reported as a public suffix; it is not one, " +
			"and saying so would send a reader to the wrong list")
	}
}
