// SPDX-License-Identifier: AGPL-3.0-only

package sourceregistry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dubyfls/Pinga53/engine/internal/strictjson"
)

// MaxRegistryBytes caps the input this package will consider.
//
// The registry is a hand-maintained document of at most a few hundred records.
// A file larger than this is not a big registry; it is a mistake or a hostile
// input, and refusing it costs nothing a legitimate author would notice. The
// limit exists because "parse whatever arrives" is how a parser becomes a
// denial-of-service surface, and because docs/SOURCE_REGISTRY.md §4 says
// downloaded records are untrusted input — the registry itself is no more
// trusted than the things it describes.
const MaxRegistryBytes = 8 << 20 // 8 MiB

// registrySchemaNames is this package's closed vocabulary: the JSON field
// names the registry's own Go types declare, collected from struct tags in
// this repository's source and never from a document.
//
// A key outside this set is located by position and never reproduced.
var registrySchemaNames = strictjson.FieldNames(Registry{})

// checkNoDuplicateKeys walks the raw JSON and refuses any object that names a
// key twice.
//
// # WHY THIS IS NOT LEFT TO THE DECODER
//
// encoding/json accepts duplicate keys and keeps the LAST one. That is not a
// parse error, it is a silent choice, and for this file it is the worst
// possible one: a record carrying
//
//	"commercial_use": "prohibited", ... "commercial_use": "permitted"
//
// decodes to `permitted` with no diagnostic. A reviewer reading the file sees
// the prohibition; the program sees the permission; both are reading the same
// bytes. Whichever way a decoder resolves that, resolving it at all is wrong
// here — the document is ambiguous and must be refused rather than
// interpreted.
//
// # WHY THE WALK ITSELF LIVES IN internal/strictjson
//
// It used to live here, as a near-copy of the one internal/evaluation grew for
// fixture sets. The two diverged: ORDER 6 corrected that one — an unbounded
// diagnostic, an unbounded collection, no depth bound, and a path assembled
// from the document's own key bytes — and this copy received none of it. A
// security-relevant parser control with two implementations has two behaviours
// the first time one of them is fixed, which is FINDING-128.
//
// There is now one walk. This function is the registry's adapter onto it: it
// keeps this package's Problem shape, which collects every failure rather than
// stopping at the first, and adds nothing of its own to the diagnostic.
func checkNoDuplicateKeys(b []byte) []Problem {
	found, total, err := strictjson.Duplicates(b, registrySchemaNames)
	if err != nil {
		// The only error the walk returns is a depth bound. It is a refusal,
		// not a crash, and it names no part of the document.
		return []Problem{{"the document", err.Error()}}
	}
	shown := found
	if len(shown) > strictjson.MaxReported {
		shown = shown[:strictjson.MaxReported]
	}
	problems := make([]Problem, 0, len(shown)+1)
	for _, d := range shown {
		problems = append(problems, Problem{
			d.Path,
			"appears twice in the same object — the document is ambiguous about its own contents and is refused rather than resolved to whichever value a decoder happens to keep",
		})
	}
	if omitted := total - len(shown); omitted > 0 {
		problems = append(problems, Problem{
			"the document",
			fmt.Sprintf("names a key twice in %d further places, which are not listed; a document does not get to choose how large this diagnostic becomes", omitted),
		})
	}
	return problems
}

// decodeStrict decodes one JSON document into v, refusing unknown fields and
// refusing trailing content after the value.
//
// Trailing content is checked because a decoder that reads the first value and
// stops will happily accept `{...}{...}`, taking the first object and silently
// discarding the second. For a document of record, "there was more here and it
// was ignored" is not an acceptable outcome.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing content after the top-level object; a registry file holds exactly one document")
	}
	return nil
}

// typeName renders a raw JSON value's type for a diagnostic, so that a
// malformed field says what it actually is rather than repeating Go's
// unmarshalling vocabulary at a person editing JSON.
func typeName(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "empty"
	}
	switch s[0] {
	case '{':
		return "an object"
	case '[':
		return "an array"
	case '"':
		return "a string"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	default:
		return "a number"
	}
}

// safeFieldName renders one key of a source record for a diagnostic.
//
// FINDING-131. This diagnostic used to be built with `fmt.Sprintf("sources[%d].%s", i, k)`,
// where k is a key the document chose. That is the same defect FINDING-128
// names one function away: a registry file is untrusted input
// (docs/SOURCE_REGISTRY.md §4), and an unknown key is precisely the case where
// the bytes are guaranteed not to be the schema's own. An escape sequence, a
// NUL, a megabyte of padding or a credential-shaped string reached the
// operator's terminal and the gate logs verbatim.
//
// A key the schema defines is this repository's own word and is safe to
// repeat. Anything else is located by position only.
func safeFieldName(key string) string {
	if registrySchemaNames[key] {
		return key
	}
	return strictjson.UnrecognisedSegment
}

// nearestSchemaField names the schema field a key most likely meant.
//
// # WHY A SUGGESTION AND NOT THE KEY
//
// The reason the old diagnostic echoed the key was a real one: `quota` for
// `quotas` is a typo, and a message that will not say which key is wrong
// sends its reader back to diff the file by hand. The suggestion recovers
// that without echoing anything — every byte of it comes from
// RequiredSourceFields, which is this package's own source.
//
// Returns "" when nothing is close enough to be worth guessing.
func nearestSchemaField(key string) string {
	// A key that is not plausibly a typo of anything is not worth guessing at,
	// and walking a megabyte of padding against 28 field names is work an
	// input gets to ask for. Both bounds are on OUR side of the decision.
	if len(key) == 0 || len(key) > 64 {
		return ""
	}
	best, bestDist := "", 4 // strictly better than 4 to be reported
	for _, f := range RequiredSourceFields {
		if d := editDistance(key, f); d < bestDist {
			best, bestDist = f, d
		}
	}
	return best
}

// editDistance is Levenshtein, iterative with one row.
func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, min(cur[j-1]+1, prev[j-1]+cost))
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

// OptionalSourceFields names keys the schema DEFINES but does not require.
// They are part of the Source struct with ,omitempty tags; a record that
// omits them is fine, a record that carries them is accepted. The list is
// kept in step with Source by hand, same discipline as RequiredSourceFields.
var OptionalSourceFields = []string{
	"upstream_labels",
	"trust_tier",
}

// unknownFieldProblems reports the keys of one source record that the schema
// does not define, without reproducing any of them and without letting the
// record choose how many problems it produces.
func unknownFieldProblems(idx int, raw map[string]json.RawMessage) []Problem {
	// Sorted, so a map's iteration order does not reorder a diagnostic
	// between runs. Unknown keys all render alike, but their suggestions do
	// not, and a gate that compares output needs the order to be stable.
	keys := make([]string, 0, len(raw))
	for k := range raw {
		if contains(RequiredSourceFields, k) {
			continue
		}
		if contains(OptionalSourceFields, k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	problems := make([]Problem, 0, len(keys))
	for _, k := range keys {
		if len(problems) >= strictjson.MaxReported {
			problems = append(problems, Problem{
				fmt.Sprintf("sources[%d]", idx),
				fmt.Sprintf("names %d further keys the schema does not define, which are not listed; a record does not get to choose how large this diagnostic becomes", len(keys)-len(problems)),
			})
			break
		}
		msg := "not a field in the schema — a misspelled key records nothing"
		if near := nearestSchemaField(k); near != "" {
			msg += fmt.Sprintf("; the closest field this schema defines is %q", near)
		}
		problems = append(problems, Problem{
			fmt.Sprintf("sources[%d].%s", idx, safeFieldName(k)),
			msg,
		})
	}
	return problems
}
