// SPDX-License-Identifier: AGPL-3.0-only

package pihole

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrAmbiguousResponse is returned for a response that has more than one
// reading. It is deliberately distinct from a syntax error: the bytes parsed,
// and that is the problem.
var ErrAmbiguousResponse = errors.New("response is ambiguous and was refused rather than resolved")

// maxJSONDepth bounds the duplicate-key walk.
//
// The walk is recursive, and its input is peer-supplied. Without a bound, a
// response consisting of a few kilobytes of `[[[[[...` would recurse until the
// goroutine stack was exhausted, which is a panic rather than an error — a
// denial of service reachable from anything that can answer on the port. The
// response size is already capped, but a size cap alone does not bound depth.
const maxJSONDepth = 64

// decodeResponse decodes one SUCCESSFUL Pi-hole response body into out.
//
// SCOPE, stated because it is narrower than "responses". This function is
// reached only from the 2xx path in attempt(). A non-2xx body takes a
// different route entirely — newAPIError parses it with json.Unmarshal — so
// duplicate keys and trailing content in an ERROR envelope are NOT rejected
// here and are resolved the way encoding/json resolves them. That asymmetry
// is deliberate and is safe for a different reason: an error envelope
// contributes only two VALUES to an APIError (.error.key and .error.message),
// both bounded by sanitizeMessage and both scrubbed of the session id and, on
// the authentication path, of the password. Its key NAMES are never
// reproduced at all. Do not read the guarantees below as covering it.
//
// FINDING-72 (trailing content) and FINDING-73 (duplicate keys).
//
// It refuses two shapes that encoding/json accepts silently, for the reason
// internal/sourceregistry/strictjson.go gives for the registry: a document
// this program acts on and an operator reads must have exactly one reading.
// A step D transcript is such a document.
//
//   - TRAILING CONTENT. json.Decoder reads one value and stops, so `{…}{…}`
//     is accepted, the first document is used and the second is discarded with
//     no diagnostic anywhere.
//   - DUPLICATE KEYS. An object naming a key twice decodes to the LAST
//     occurrence. That is not a parse error, it is a silent choice between two
//     readings, and it is the one an operator reading the captured body is
//     least likely to make.
//
// Unknown fields are NOT refused, and that asymmetry is deliberate. Pi-hole
// may add response fields in a future release; a client that rejected them
// would fail on an appliance upgrade rather than on a defect, which trades a
// problem that cannot happen for one that eventually will. Refusing ambiguity
// and refusing extension are different rules, and only the first is wanted
// here. TestAnUnknownFieldIsNotTreatedAsAmbiguity pins the distinction.
func decodeResponse(payload []byte, out any) error {
	if err := rejectDuplicateKeys(payload); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(out); err != nil {
		// The body is never included: it is the thing most likely to contain
		// something sensitive if the peer is not what we expect.
		return errors.New("malformed JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: content follows the response object", ErrAmbiguousResponse)
	}
	return nil
}

// rejectDuplicateKeys walks the raw JSON and refuses any object naming a key
// twice. The walk is over tokens rather than a decoded value, because by the
// time a value exists the duplicate is already gone.
//
// A syntax error is NOT reported here. The decode that follows reports it, in
// one vocabulary; reporting the same fault twice in two vocabularies makes the
// real problem harder to find.
func rejectDuplicateKeys(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	return walkForDuplicates(dec, 0)
}

// walkForDuplicates consumes exactly one JSON value from dec.
func walkForDuplicates(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: nested beyond %d levels", ErrAmbiguousResponse, maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil // malformed; the decode reports it
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil // a scalar; nothing nested to check
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil
			}
			key, ok := keyTok.(string)
			if !ok {
				return nil
			}
			if _, dup := seen[key]; dup {
				// FINDING-77. The key is NOT named, and omitting it is the
				// whole fix.
				//
				// The superseded error quoted it, on the reasoning that only a
				// VALUE could be sensitive. That reasoned about the wrong half
				// of the pair. A JSON key is peer-authored, and by the time
				// this decoder runs the peer has already been handed something
				// worth echoing: during authentication it has the PASSWORD,
				// and during an authenticated read it has the SESSION ID.
				// Either comes back as a duplicated key name and lands in the
				// error verbatim — and nothing downstream removes it, because
				// Login's scrub matches *APIError and this is a plain wrapped
				// error.
				//
				// Sanitising the key instead of omitting it would not help: no
				// heuristic can separate a credential echoed as a key from a
				// legitimate field name, since the peer chooses both. The
				// diagnostic value of the name does not outweigh that, and the
				// path is already identified by the caller's wrapper.
				return fmt.Errorf("%w: an object contains a duplicate key",
					ErrAmbiguousResponse)
			}
			seen[key] = struct{}{}
			if err := walkForDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
		_, _ = dec.Token() // consume '}'
	case '[':
		for dec.More() {
			if err := walkForDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
		_, _ = dec.Token() // consume ']'
	}
	return nil
}
