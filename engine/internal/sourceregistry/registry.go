// SPDX-License-Identifier: AGPL-3.0-only

// Package sourceregistry loads and validates the ScamWall source registry.
//
// # WHY THIS EXISTS
//
// docs/SOURCE_REGISTRY.md defines a schema, a disposition vocabulary, and rules
// that bind every record. Until this package, all three were prose. Prose
// refuses nothing: a record with a licence field left blank, a disposition
// invented on the spot, or a source switched on for a use its terms forbid
// would have been written down and read back as fact by whatever consumed the
// file next.
//
// The registry's purpose is provenance — where a claim came from, when it was
// read, and whether the rights permit the use intended for it. A provenance
// document that accepts unchecked input is worse than none, because it
// launders a guess into a record.
//
// # WHAT THIS PACKAGE ESTABLISHES, AND WHAT IT CANNOT
//
// It establishes that a record is STRUCTURALLY sound and INTERNALLY consistent:
// every field present, every closed vocabulary respected, dates real and not in
// the future, identifiers unique and not reused, lineage acyclic and pointing
// at records that exist, every rights assertion carrying a citation, and no
// operation authorised whose conditions are unknown or unmet.
//
// It establishes NOTHING about the truth of any field. `permitted` is checked
// for membership of a vocabulary; whether the provider's licence says so is a
// human reading a human document, and no validator can do it. The same holds
// for whether a cited URL belongs to the provider, and therefore for
// independence: two feeds are only known to share an upstream if somebody
// recorded that they do — see Source.IndependenceClaimable, which refuses to
// call independence demonstrated when the upstreams are undocumented.
//
// So this package makes a false record harder to write by accident. It does not
// make one impossible to write on purpose, and it is not evidence about any
// provider.
package sourceregistry

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SchemaVersion is the only version this package accepts.
//
// Version 2 replaced version 1's three rights fields and single `enabled`
// boolean with per-operation grants. That change is not backward compatible and
// must not be silently accommodated: a v1 record says nothing about retrieval,
// storage, enrichment or training, and reading one as though it did would
// authorise by silence exactly the operations the new model exists to gate.
const SchemaVersion = 2

// DateLayout is the only accepted form for a read date. No time and no zone is
// deliberate: the field records the day a human read a page, which is the
// precision the claim actually has.
const DateLayout = "2006-01-02"

// Problem is one validation failure, addressed to the thing that caused it.
//
// Validation collects every problem rather than stopping at the first, because
// a person correcting a registry wants the whole list, and because a validator
// that reports one error at a time trains its user to fix errors one at a time
// without reading the rest.
type Problem struct {
	Path    string
	Message string
}

func (p Problem) String() string { return p.Path + ": " + p.Message }

// Source is one record.
type Source struct {
	SourceID                string   `json:"source_id"`
	CatalogRef              string   `json:"catalog_ref"`
	RequestedPriority       string   `json:"requested_priority"`
	OfficialName            string   `json:"official_name"`
	OfficialDocumentation   string   `json:"official_documentation"`
	VerifiedOn              string   `json:"verified_on"`
	Kind                    string   `json:"kind"`
	IndicatorTypes          []string `json:"indicator_types"`
	ClassificationMeaning   string   `json:"classification_meaning"`
	Authentication          string   `json:"authentication"`
	Quotas                  string   `json:"quotas"`
	UpdateCadence           string   `json:"update_cadence"`
	Retention               string   `json:"retention"`
	WithdrawalBehaviour     string   `json:"withdrawal_behaviour"`
	AttributionRequired     string   `json:"attribution_required"`
	DerivedDataRestrictions string   `json:"derived_data_restrictions"`
	UpstreamSources         []string `json:"upstream_sources"`
	// UpstreamLabels is the MACHINE-READABLE lineage list: every entry must
	// resolve to a source_id in this registry, to this record's own id, or to
	// an entry in the registry's external_origins. See validateLabels.
	//
	// It is a second field rather than a rule imposed on UpstreamSources,
	// and that is a compromise recorded rather than hidden. UpstreamSources
	// in THIS tree holds human-readable provider names — "PhishTank",
	// "BitcoinAbuse, merged in — see catalog 56" — across the 86 shipped
	// records. Turning it into a label list means deciding which of six
	// provider names corresponds to which registry id, which is research and
	// is the owner's, not a migration an unattended run may perform.
	//
	// OPTIONAL. Absent means this record states no machine-readable lineage
	// beyond aggregation_dependencies, which is where every shipped record
	// stands today.
	UpstreamLabels []string `json:"upstream_labels,omitempty"`
	// TrustTier is `ordinary` or `authoritative`; absent means ordinary.
	// OPTIONAL. See validateTiers: only primary lineage may hold the
	// authoritative tier, and the household's policy still has to permit
	// acting on one.
	TrustTier                   string              `json:"trust_tier,omitempty"`
	UpstreamSourcesCompleteness string              `json:"upstream_sources_completeness"`
	AggregationDependencies     []string            `json:"aggregation_dependencies"`
	AccessStatus                string              `json:"access_status"`
	DispositionReason           string              `json:"disposition_reason"`
	PrivacyImplications         string              `json:"privacy_implications"`
	IntendedPermittedUse        string              `json:"intended_permitted_use"`
	CoverageLimitations         string              `json:"coverage_limitations"`
	OperationalCost             string              `json:"operational_cost"`
	IntendedOperations          []string            `json:"intended_operations"`
	Permissions                 map[Operation]Grant `json:"permissions"`
	Enabled                     bool                `json:"enabled"`
}

// Registry is the whole file.
type Registry struct {
	SchemaVersion int    `json:"schema_version"`
	Note          string `json:"note"`
	// RetiredSourceIDs holds identifiers used once and never to be used again.
	// See ValidateAgainstBaseline for why the list is necessary and what it
	// still does not prove.
	RetiredSourceIDs []string `json:"retired_source_ids"`
	// ExternalOrigins names origins that this registry does NOT hold a
	// record for — a public corpus, a submission queue, somebody else's
	// aggregate — so that two sources drawing on the same one can be seen
	// to be drawing on the same one.
	//
	// Without it, lineage is only visible between records this file
	// happens to contain, and two feeds that both republish the same
	// external corpus are counted as two independent voices. That is the
	// hole C-01 and C-02 fall into and the only thing this field exists
	// to close.
	//
	// OPTIONAL. An absent list and an empty list say the same thing —
	// this registry declares no external origins — and requiring the key
	// would invalidate every registry written before the field existed,
	// including this repository's own, without anything becoming known.
	ExternalOrigins []string `json:"external_origins"`
	Sources         []Source `json:"sources"`
}

// RequiredSourceFields is every key a record must carry. It is the
// machine-readable half of docs/SOURCE_REGISTRY.md §2, kept in step with it by
// hand; a key in one and not the other is a defect in whichever changed last.
var RequiredSourceFields = []string{
	"source_id", "catalog_ref", "requested_priority", "official_name",
	"official_documentation", "verified_on", "kind", "indicator_types",
	"classification_meaning", "authentication", "quotas", "update_cadence",
	"retention", "withdrawal_behaviour", "attribution_required",
	"derived_data_restrictions", "upstream_sources",
	"upstream_sources_completeness", "aggregation_dependencies",
	"access_status", "disposition_reason", "privacy_implications",
	"intended_permitted_use", "coverage_limitations", "operational_cost",
	"intended_operations", "permissions", "enabled",
}

// The closed vocabularies. A value outside one of these is refused rather than
// carried: a disposition invented at the keyboard is the kind of claim this
// registry exists to prevent.
//
// `kind` and `authentication` accept "unknown" — FINDING-69. They did not, and
// the first real research pass produced records they could not express: a
// provider whose documentation returns 403 has an access model and a product
// shape, and nobody has read either. docs/SOURCE_REGISTRY.md §2 says plainly
// that "`unknown` is a permitted value and is not the same as absent"; the two
// vocabularies contradicted it, and the only ways out were to invent a value or
// to leave the field empty, which §2 refuses separately. Adding the value makes
// the code say what the schema always said.
//
// This is not a licence to shrug. `unknown` in either field forces
// access_status to `unresolved` in practice — a disposition other than
// `unresolved` is a claim about what documentation said — and
// disposition_reason still has to say what was tried and what happened.
var (
	ValidKinds = []string{
		"bulk feed", "lookup API", "enrichment service", "corpus",
		"platform", "advisory source", "commercial partnership", "unknown",
	}
	ValidAuthentication = []string{"none", "key", "account", "contract", "unknown"}
	ValidAttribution    = []string{"yes", "no", "unknown"}
	// ValidAccessStatus is the disposition vocabulary — §3, exactly one per
	// source.
	ValidAccessStatus = []string{
		"verified-available", "credentials-required",
		"commercial-approval-required", "historical", "unavailable", "unresolved",
	}
)

// Load reads and parses a registry file.
func Load(path string) (*Registry, []Problem, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the registry: %w", err)
	}
	return Parse(b)
}

// Parse decodes registry bytes, returning every problem it can see before the
// bytes become a value.
//
// Three classes of problem can only be seen here, and all three are silently
// resolved by an ordinary decode:
//
//   - a duplicate key, which encoding/json resolves to the last occurrence;
//   - an absent key, which is indistinguishable from a present-and-empty one
//     once decoded, and which docs/SOURCE_REGISTRY.md is explicit is a
//     different claim from `unknown`;
//   - a field of the wrong TYPE, which aborts a whole-document decode and
//     takes every other diagnostic with it.
//
// Parsing and validating stay separate results. A caller that conflates them
// cannot tell "this file is not JSON" from "this file is JSON and says
// something impossible".
func Parse(b []byte) (*Registry, []Problem, error) {
	if len(b) > MaxRegistryBytes {
		return nil, nil, fmt.Errorf(
			"the registry is %d bytes, over the %d-byte limit; this file is hand-maintained and a larger one is a mistake or a hostile input, not a bigger registry",
			len(b), MaxRegistryBytes)
	}

	problems := checkNoDuplicateKeys(b)

	// Shape first: top-level keys, and each record as raw fields so that a
	// type error in one field is a problem about that field rather than the end
	// of the document.
	var shape struct {
		SchemaVersion    *json.RawMessage `json:"schema_version"`
		Note             *json.RawMessage `json:"note"`
		RetiredSourceIDs *json.RawMessage `json:"retired_source_ids"`
		// Optional; see Registry.ExternalOrigins. Declared here because
		// decodeStrict refuses an unknown top-level key, so a registry that
		// carries the field would otherwise be refused outright.
		ExternalOrigins *json.RawMessage              `json:"external_origins"`
		Sources         *[]map[string]json.RawMessage `json:"sources"`
	}
	if err := decodeStrict(b, &shape); err != nil {
		return nil, problems, fmt.Errorf("the registry is not valid JSON in the expected shape: %w", err)
	}

	for name, raw := range map[string]*json.RawMessage{
		"schema_version":     shape.SchemaVersion,
		"note":               shape.Note,
		"retired_source_ids": shape.RetiredSourceIDs,
	} {
		if raw == nil {
			problems = append(problems, Problem{name, "required and absent"})
		}
	}
	if shape.Sources == nil {
		problems = append(problems, Problem{"sources", "required and absent; write [] to say the registry is empty"})
	}

	// Top-level types, checked for the same reason as record fields: a
	// schema_version written as a string would otherwise abort the whole
	// document instead of naming itself.
	badTopLevel := map[string]bool{}
	for name, spec := range map[string]struct {
		raw  *json.RawMessage
		want string
	}{
		"schema_version":     {shape.SchemaVersion, "a number"},
		"note":               {shape.Note, "a string"},
		"retired_source_ids": {shape.RetiredSourceIDs, "an array"},
		"external_origins":   {shape.ExternalOrigins, "an array"},
	} {
		if spec.raw == nil {
			continue
		}
		if got := typeName(*spec.raw); got != spec.want {
			problems = append(problems, Problem{name, fmt.Sprintf("is %s; this field must be %s", got, spec.want)})
			badTopLevel[name] = true
		}
	}

	if shape.Sources != nil {
		for i, raw := range *shape.Sources {
			for _, f := range RequiredSourceFields {
				if _, ok := raw[f]; !ok {
					problems = append(problems, Problem{
						fmt.Sprintf("sources[%d].%s", i, f),
						"required and absent — an absent field is not the same claim as `unknown`, so write the value out",
					})
				}
			}
			problems = append(problems, unknownFieldProblems(i, raw)...)
			problems = append(problems, checkFieldTypes(i, raw)...)
		}
	}

	// The value decode.
	//
	// Any field already reported as wrongly typed, or as not in the schema, is
	// REMOVED before decoding rather than left to abort the document. That is
	// the difference between "field X is a number and must be a string" — which
	// names the one thing to fix — and a decoder error that discards every
	// other diagnostic in the file because of it. The removed field takes its
	// zero value and plays no further part; it has already been reported, and
	// nothing downstream may treat the record as usable while problems stand.
	//
	// Unknown SOURCE fields are dropped here for the same reason. Unknown
	// TOP-LEVEL keys are refused outright by decodeStrict above, because a
	// stray top-level key means the file is not the document this package
	// thinks it is.
	doc := map[string]json.RawMessage{}
	if shape.SchemaVersion != nil && !badTopLevel["schema_version"] {
		doc["schema_version"] = *shape.SchemaVersion
	}
	if shape.Note != nil && !badTopLevel["note"] {
		doc["note"] = *shape.Note
	}
	if shape.RetiredSourceIDs != nil && !badTopLevel["retired_source_ids"] {
		doc["retired_source_ids"] = *shape.RetiredSourceIDs
	}
	if shape.ExternalOrigins != nil && !badTopLevel["external_origins"] {
		doc["external_origins"] = *shape.ExternalOrigins
	}
	if shape.Sources != nil {
		cleaned := make([]map[string]json.RawMessage, 0, len(*shape.Sources))
		for i, raw := range *shape.Sources {
			keep := map[string]json.RawMessage{}
			for k, v := range raw {
				want, known := fieldKinds[k]
				if !known || typeName(v) != want {
					continue // already reported, by path
				}
				keep[k] = v
			}
			_ = i
			cleaned = append(cleaned, keep)
		}
		enc, err := json.Marshal(cleaned)
		if err != nil {
			return nil, problems, fmt.Errorf("the registry's records could not be re-read after type checking: %w", err)
		}
		doc["sources"] = enc
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, problems, fmt.Errorf("the registry could not be re-read after type checking: %w", err)
	}

	var reg Registry
	if err := json.Unmarshal(encoded, &reg); err != nil {
		return nil, problems, fmt.Errorf("the registry could not be decoded: %w", err)
	}
	return &reg, problems, nil
}

// fieldKinds says what JSON type each field must be, so a wrong type is a
// located problem instead of a decode abort.
var fieldKinds = map[string]string{
	"source_id": "a string", "catalog_ref": "a string", "requested_priority": "a string",
	"official_name": "a string", "official_documentation": "a string", "verified_on": "a string",
	"kind": "a string", "classification_meaning": "a string", "authentication": "a string",
	"quotas": "a string", "update_cadence": "a string", "retention": "a string",
	"withdrawal_behaviour": "a string", "attribution_required": "a string",
	"derived_data_restrictions": "a string", "upstream_sources_completeness": "a string",
	"access_status": "a string", "disposition_reason": "a string",
	"privacy_implications": "a string", "intended_permitted_use": "a string",
	"coverage_limitations": "a string", "operational_cost": "a string",
	"indicator_types": "an array", "upstream_sources": "an array",
	"upstream_labels":          "an array",
	"aggregation_dependencies": "an array", "intended_operations": "an array",
	"permissions": "an object", "enabled": "a boolean",
}

func checkFieldTypes(idx int, raw map[string]json.RawMessage) []Problem {
	var problems []Problem
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		want, known := fieldKinds[k]
		if !known {
			continue // already reported as not-in-schema
		}
		if got := typeName(raw[k]); got != want {
			problems = append(problems, Problem{
				fmt.Sprintf("sources[%d].%s", idx, k),
				fmt.Sprintf("is %s; this field must be %s", got, want),
			})
		}
	}
	return problems
}

// Validate checks every rule this package can check. asOf is supplied rather
// than read from the clock so the result is a function of its inputs.
func (r *Registry) Validate(asOf time.Time) []Problem {
	var problems []Problem

	if r.SchemaVersion != SchemaVersion {
		problems = append(problems, Problem{
			"schema_version",
			fmt.Sprintf("is %d; this package accepts version %d only. Version 1 carried three rights fields and a single `enabled` flag, which say nothing about retrieval, storage, enrichment or training — reading one as though it did would authorise those by silence", r.SchemaVersion, SchemaVersion),
		})
		// Everything below reads fields whose meaning depends on the version.
		// Continuing would produce confident diagnostics about a document this
		// package does not understand.
		return problems
	}

	retired := map[string]bool{}
	for i, id := range r.RetiredSourceIDs {
		p := fmt.Sprintf("retired_source_ids[%d]", i)
		if strings.TrimSpace(id) == "" {
			problems = append(problems, Problem{p, "is empty"})
			continue
		}
		if retired[id] {
			problems = append(problems, Problem{p, fmt.Sprintf("%q is listed twice", id)})
		}
		retired[id] = true
	}

	seenID := map[string]int{}
	seenCatalogRef := map[string]int{}

	for i := range r.Sources {
		s := &r.Sources[i]
		at := func(f string) string { return fmt.Sprintf("sources[%d].%s", i, f) }

		if strings.TrimSpace(s.SourceID) == "" {
			problems = append(problems, Problem{at("source_id"), "is empty"})
		} else {
			if prev, dup := seenID[s.SourceID]; dup {
				problems = append(problems, Problem{at("source_id"), fmt.Sprintf("%q is already used by sources[%d] — ids are never reused", s.SourceID, prev)})
			}
			seenID[s.SourceID] = i
			if retired[s.SourceID] {
				problems = append(problems, Problem{at("source_id"), fmt.Sprintf("%q is in retired_source_ids — a retired id is never reused, so this record needs a new one", s.SourceID)})
			}
		}

		if s.CatalogRef != "none" {
			n, err := strconv.Atoi(s.CatalogRef)
			if err != nil || n < 1 {
				problems = append(problems, Problem{at("catalog_ref"), fmt.Sprintf("is %q; it must be a positive entry number from the supplied catalog, or the string \"none\" for a source added later", s.CatalogRef)})
			} else if prev, dup := seenCatalogRef[s.CatalogRef]; dup {
				problems = append(problems, Problem{at("catalog_ref"), fmt.Sprintf("catalog entry %s is already claimed by sources[%d]", s.CatalogRef, prev)})
			} else {
				seenCatalogRef[s.CatalogRef] = i
			}
		}

		checkEnum(&problems, at("kind"), s.Kind, ValidKinds)
		checkEnum(&problems, at("authentication"), s.Authentication, ValidAuthentication)
		checkEnum(&problems, at("attribution_required"), s.AttributionRequired, ValidAttribution)
		checkEnum(&problems, at("access_status"), s.AccessStatus, ValidAccessStatus)

		// `unknown` is a permitted answer everywhere below. An EMPTY answer is
		// not: it is indistinguishable from an author who stopped typing, and
		// the point of the `unknown` value is that not knowing gets stated.
		for _, f := range []struct{ name, value string }{
			{"requested_priority", s.RequestedPriority},
			{"official_name", s.OfficialName},
			{"classification_meaning", s.ClassificationMeaning},
			{"quotas", s.Quotas},
			{"update_cadence", s.UpdateCadence},
			{"retention", s.Retention},
			{"withdrawal_behaviour", s.WithdrawalBehaviour},
			{"derived_data_restrictions", s.DerivedDataRestrictions},
			{"privacy_implications", s.PrivacyImplications},
			{"intended_permitted_use", s.IntendedPermittedUse},
			{"coverage_limitations", s.CoverageLimitations},
			{"operational_cost", s.OperationalCost},
			{"disposition_reason", s.DispositionReason},
		} {
			if strings.TrimSpace(f.value) == "" {
				problems = append(problems, Problem{at(f.name), "is empty; write `unknown` if that is the answer, so that not knowing is stated rather than implied"})
			}
		}

		if len(s.IndicatorTypes) == 0 {
			problems = append(problems, Problem{at("indicator_types"), "is empty; list the types the provider publishes, or [\"unknown\"] if the documentation does not say"})
		}
		for j, t := range s.IndicatorTypes {
			if strings.TrimSpace(t) == "" {
				problems = append(problems, Problem{at(fmt.Sprintf("indicator_types[%d]", j)), "is empty"})
			}
		}

		// A researched record is a claim about what documentation said, and an
		// undated claim states nothing current. `unresolved` is the one
		// disposition that may leave both `unknown`, because it means nobody
		// has looked.
		researched := s.AccessStatus != "unresolved" && contains(ValidAccessStatus, s.AccessStatus)
		if s.VerifiedOn == "unknown" {
			if researched {
				problems = append(problems, Problem{at("verified_on"), fmt.Sprintf("is `unknown`, but access_status is %q — a disposition other than `unresolved` is a claim about what the documentation said, and an undated claim states nothing current", s.AccessStatus)})
			}
		} else if problem := checkReadDate(s.VerifiedOn, asOf); problem != "" {
			problems = append(problems, Problem{at("verified_on"), problem})
		}

		if s.OfficialDocumentation == "unknown" {
			if researched {
				problems = append(problems, Problem{at("official_documentation"), fmt.Sprintf("is `unknown`, but access_status is %q — record the URL the disposition was read from", s.AccessStatus)})
			}
		} else if problem := checkDocumentationURL(s.OfficialDocumentation); problem != "" {
			problems = append(problems, Problem{at("official_documentation"), problem})
		}

		s.validateGrants(i, asOf, &problems)

		// Enabling. A source is enabled for the uses it DECLARES, and only when
		// every one of them is authorised by its own recorded terms. A grant
		// this source does not intend to exercise is irrelevant: requiring
		// redistribution rights to perform a permitted local lookup would be a
		// category error, and so would inferring publication rights from a
		// permission to query.
		if s.Enabled {
			if s.AccessStatus != "verified-available" {
				problems = append(problems, Problem{at("enabled"), fmt.Sprintf("is true while access_status is %q; only `verified-available` may be enabled", s.AccessStatus)})
			}
			if len(s.IntendedOperations) == 0 {
				problems = append(problems, Problem{at("intended_operations"), "is empty while the source is enabled; enabling nothing in particular is not a decision anyone can review"})
			}
			for _, why := range s.UnauthorizedIntendedOperations() {
				problems = append(problems, Problem{at("enabled"), "is true, but " + why})
			}
		}
	}

	r.validateLineage(&problems)
	r.validateLabels(&problems)
	r.validateTiers(&problems)

	sort.Slice(problems, func(a, b int) bool {
		if problems[a].Path != problems[b].Path {
			return problems[a].Path < problems[b].Path
		}
		return problems[a].Message < problems[b].Message
	})
	return problems
}

// checkReadDate returns "" when the date is a real, non-future day.
func checkReadDate(value string, asOf time.Time) string {
	d, err := time.Parse(DateLayout, value)
	switch {
	case err != nil:
		return fmt.Sprintf("is %q; it must be a date in %s form", value, DateLayout)
	case d.After(asOf):
		return fmt.Sprintf("is %s, which is in the future — documentation cannot have been read on a day that has not happened", value)
	}
	return ""
}

// checkDocumentationURL returns "" when the URL is usable as a citation.
//
// https is required. Documentation read over plaintext is documentation an
// intermediary can rewrite, and every rights claim in a record is a reading of
// such a page. If a provider is http-only that is a finding about the provider:
// record it in disposition_reason and leave the field `unknown`.
func checkDocumentationURL(value string) string {
	u, err := url.Parse(value)
	switch {
	case err != nil || u.Host == "":
		return fmt.Sprintf("is %q, which is not an absolute URL", value)
	case u.Scheme != "https":
		return fmt.Sprintf("uses scheme %q; documentation a record's claims are read from must be fetched over https", u.Scheme)
	}
	return ""
}

func checkEnum(problems *[]Problem, path, value string, allowed []string) {
	if contains(allowed, value) {
		return
	}
	*problems = append(*problems, Problem{path, fmt.Sprintf("is %q; permitted values are %s", value, strings.Join(allowed, ", "))})
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// Source returns the record with the given id.
//
// Lookup is by exact id and nothing else. There is deliberately no fallback to
// official_name or catalog_ref: a caller holding an id that no longer resolves
// has a provenance problem, and quietly resolving it by another field would
// hide exactly that.
func (r *Registry) Source(id string) (*Source, bool) {
	for i := range r.Sources {
		if r.Sources[i].SourceID == id {
			return &r.Sources[i], true
		}
	}
	return nil, false
}

// Retired reports whether an id was used once and withdrawn.
//
// This is the difference between "no such source" and "a source that used to
// exist and whose records must not be re-attributed". A caller holding a
// retired id is holding a reference to something that was deliberately taken
// out of service, and it must be told which of the two it has.
func (r *Registry) Retired(id string) bool {
	return contains(r.RetiredSourceIDs, id)
}
