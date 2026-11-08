// SPDX-License-Identifier: AGPL-3.0-only

package mac_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/mac"
)

// C-09 and C-24 — a keyed tag, under a purpose label.
//
// Everything this tree identifies today is identified by an UNKEYED digest,
// and for a hostname that is not an identifier at all: anyone who can guess
// the name can compute the digest and confirm the guess, and the same digest
// appears in every installation, so two reports from two households can be
// correlated by a third party who has neither. A key is what makes an opaque
// identifier opaque.

func key(t *testing.T, b byte) *mac.Key {
	t.Helper()
	raw := make([]byte, mac.MinKeyBytes)
	for i := range raw {
		raw[i] = b
	}
	k, err := mac.NewKey(raw)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func TestTheSameInputUnderTwoKeysIsTwoIdentifiers(t *testing.T) {
	a := key(t, 0x11).Tag(mac.PurposeWithheldHost, "bad.example.com")
	b := key(t, 0x22).Tag(mac.PurposeWithheldHost, "bad.example.com")
	if a == b {
		t.Fatalf("two installations produced the same identifier for one host: %s", a)
	}
	if a == "" {
		t.Fatalf("Tag returned nothing")
	}
}

func TestTheSameInputUnderOneKeyIsStable(t *testing.T) {
	k := key(t, 0x11)
	host := "bad." + "example.com" // assembled, so staticcheck sees two expressions
	first := k.Tag(mac.PurposeWithheldHost, host)
	second := k.Tag(mac.PurposeWithheldHost, "bad.example.com")
	if first != second {
		t.Fatalf("the identifier is not stable across calls: %s then %s; a reader cannot correlate two reports",
			first, second)
	}
}

// TestAPurposeSeparatesTwoTagsOverTheSameBytes is C-24's rule. A tag computed
// to seal a stored record must not verify as a tag over a report, or a sealed
// record can be presented as one.
func TestAPurposeSeparatesTwoTagsOverTheSameBytes(t *testing.T) {
	k := key(t, 0x11)
	seen := map[string]mac.Purpose{}
	for _, p := range mac.AllPurposes {
		tag := k.Tag(p, "the same bytes under every purpose")
		if other, dup := seen[tag]; dup {
			t.Fatalf("%s and %s produce the same tag over the same input", p, other)
		}
		seen[tag] = p
	}
}

func TestAShortKeyIsRefused(t *testing.T) {
	for _, n := range []int{0, 1, mac.MinKeyBytes - 1} {
		if _, err := mac.NewKey(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte key was accepted", n)
		}
	}
}

func TestAnAllZeroKeyIsRefused(t *testing.T) {
	// A key of the right length and no entropy is the shape a caller lands in
	// when a read returned an empty buffer and nobody checked.
	if _, err := mac.NewKey(make([]byte, mac.MinKeyBytes)); err == nil {
		t.Fatalf("an all-zero key was accepted")
	}
}

func TestAnUnrecognisedPurposeIsRefused(t *testing.T) {
	k := key(t, 0x11)
	defer func() {
		if recover() == nil {
			t.Fatalf("an unrecognised purpose produced a tag; a purpose nobody declared separates nothing")
		}
	}()
	_ = k.Tag(mac.Purpose("something-nobody-declared"), "x")
}

func TestATagNamesNothingItWasComputedOver(t *testing.T) {
	tag := key(t, 0x11).Tag(mac.PurposeWithheldHost, "bad.example.com")
	if strings.Contains(tag, "example") || strings.Contains(tag, "bad") {
		t.Fatalf("the tag reproduces its input: %s", tag)
	}
	if len(tag) < 16 {
		t.Errorf("the tag is %d characters; too short to be unambiguous", len(tag))
	}
}

func TestANilKeyProducesNothingRatherThanAnUnkeyedDigest(t *testing.T) {
	// The whole point. A build with no key must report that it has none, not
	// fall back to something that looks like an identifier and is not one.
	var k *mac.Key
	if got := k.Tag(mac.PurposeWithheldHost, "bad.example.com"); got != "" {
		t.Fatalf("a nil key produced %q", got)
	}
}

func writeKeyFile(t *testing.T, content []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(p, content, mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	// WriteFile is subject to umask, so the mode is set explicitly.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return p
}

func TestAWorldReadableKeyFileIsRefused(t *testing.T) {
	good := make([]byte, mac.MinKeyBytes)
	for i := range good {
		good[i] = byte(i + 1)
	}
	p := writeKeyFile(t, good, 0o644)
	if _, err := mac.LoadKeyFile(p); err == nil {
		t.Fatalf("a world-readable identity key was accepted")
	} else if !strings.Contains(err.Error(), "world-readable") {
		t.Errorf("error = %v; it should say why", err)
	}
}

func TestAKeyFileIsLoadedAndATrailingNewlineIsNotKeyMaterial(t *testing.T) {
	good := make([]byte, mac.MinKeyBytes)
	for i := range good {
		good[i] = byte(i + 1)
	}
	plain := writeKeyFile(t, good, 0o600)
	withNL := writeKeyFile(t, append(append([]byte(nil), good...), '\n'), 0o600)

	a, err := mac.LoadKeyFile(plain)
	if err != nil {
		t.Fatalf("LoadKeyFile: %v", err)
	}
	b, err := mac.LoadKeyFile(withNL)
	if err != nil {
		t.Fatalf("LoadKeyFile (trailing newline): %v", err)
	}
	if a.Tag(mac.PurposeWithheldHost, "x") != b.Tag(mac.PurposeWithheldHost, "x") {
		t.Fatalf("an editor's trailing newline changed the installation's identity; every " +
			"identifier would move the first time somebody opened the file")
	}
}

func TestAShortKeyFileIsRefusedWithoutNamingItsContent(t *testing.T) {
	p := writeKeyFile(t, []byte("short"), 0o600)
	_, err := mac.LoadKeyFile(p)
	if err == nil {
		t.Fatalf("a 5-byte identity key was accepted")
	}
	if strings.Contains(err.Error(), "short") && !strings.Contains(err.Error(), "shorter") {
		t.Errorf("the error reproduces the key: %v", err)
	}
}
