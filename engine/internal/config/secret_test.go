// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/config"
)

const plaintext = "correct-horse-battery-staple-9F2x"

// TestSecretRedactsOnEveryFormattingPath is the central guarantee of this
// type. Each verb below is a real way a credential has leaked from real
// programs, so each is asserted rather than assumed.
func TestSecretRedactsOnEveryFormattingPath(t *testing.T) {
	s := config.NewSecretString(plaintext)

	cases := map[string]string{
		"%v":       fmt.Sprintf("%v", s),
		"%s":       fmt.Sprintf("%s", s),
		"%q":       fmt.Sprintf("%q", s),
		"%#v":      fmt.Sprintf("%#v", s),
		"%x":       fmt.Sprintf("%x", s),
		"%+v":      fmt.Sprintf("%+v", s),
		"%d":       fmt.Sprintf("%d", s),
		"String()": s.String(),
		"print":    fmt.Sprint(s),
	}
	for name, got := range cases {
		if strings.Contains(got, plaintext) {
			t.Errorf("%s leaked the secret: %s", name, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("%s did not redact: %s", name, got)
		}
	}
}

func TestSecretRedactsInsideContainingStruct(t *testing.T) {
	// The common leak is not printing the secret directly; it is printing a
	// struct that happens to contain one.
	type creds struct {
		User     string
		Password config.Secret
	}
	c := creds{User: "admin", Password: config.NewSecretString(plaintext)}

	for _, got := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(got, plaintext) {
			t.Errorf("struct formatting leaked the secret: %s", got)
		}
	}
}

func TestSecretRedactsOnJSONMarshal(t *testing.T) {
	type payload struct {
		Password config.Secret `json:"password"`
	}
	b, err := json.Marshal(payload{Password: config.NewSecretString(plaintext)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), plaintext) {
		t.Fatalf("JSON marshal leaked the secret: %s", b)
	}
}

func TestSecretRevealReturnsPlaintext(t *testing.T) {
	s := config.NewSecretString(plaintext)
	if s.Reveal() != plaintext {
		t.Fatal("Reveal must return the plaintext")
	}
	if s.Len() != len(plaintext) {
		t.Fatalf("Len = %d, want %d", s.Len(), len(plaintext))
	}
}

func TestSecretDestroyZeroes(t *testing.T) {
	b := []byte(plaintext)
	s := config.NewSecret(b)
	s.Destroy()
	if !s.IsZero() {
		t.Error("destroyed secret should report zero")
	}
	if s.Reveal() != "" {
		t.Error("destroyed secret should reveal nothing")
	}
	for i, c := range b {
		if c != 0 {
			t.Fatalf("backing array not zeroed at %d", i)
		}
	}
}

func writeSecretFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSecretFile(t *testing.T) {
	p := writeSecretFile(t, plaintext+"\n", 0o600)
	s, err := config.LoadSecretFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// A trailing newline is an artefact of writing the file, never part of the
	// credential.
	if s.Reveal() != plaintext {
		t.Fatalf("trailing newline was not stripped")
	}
}

func TestLoadSecretFileRejectsWorldReadable(t *testing.T) {
	p := writeSecretFile(t, plaintext, 0o644)
	_, err := config.LoadSecretFile(p)
	if err == nil {
		t.Fatal("expected refusal for a world-readable credential")
	}
	if !strings.Contains(err.Error(), "world-readable") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatal("error message leaked the secret")
	}
}

func TestLoadSecretFileRejectsEmpty(t *testing.T) {
	for _, content := range []string{"", "\n", "\r\n"} {
		p := writeSecretFile(t, content, 0o600)
		if _, err := config.LoadSecretFile(p); err == nil {
			t.Errorf("expected refusal for empty content %q", content)
		}
	}
}

func TestLoadSecretFileRejectsOversized(t *testing.T) {
	p := writeSecretFile(t, strings.Repeat("a", config.MaxSecretBytes+1), 0o600)
	_, err := config.LoadSecretFile(p)
	if err == nil {
		t.Fatal("expected refusal for oversized secret")
	}
	if !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadSecretFileRejectsDirectory(t *testing.T) {
	if _, err := config.LoadSecretFile(t.TempDir()); err == nil {
		t.Fatal("expected refusal for a directory")
	}
}

func TestLoadSecretFileMissing(t *testing.T) {
	if _, err := config.LoadSecretFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSecretErrorsNeverContainPlaintext(t *testing.T) {
	// Every failure path is checked, because an error string is one of the
	// easiest places for a credential to escape.
	paths := []string{
		writeSecretFile(t, plaintext, 0o644),
		writeSecretFile(t, "", 0o600),
		writeSecretFile(t, strings.Repeat(plaintext, 500), 0o600),
		filepath.Join(t.TempDir(), "absent"),
		t.TempDir(),
	}
	for _, p := range paths {
		if _, err := config.LoadSecretFile(p); err != nil {
			if strings.Contains(err.Error(), plaintext) {
				t.Fatalf("error leaked plaintext: %v", err)
			}
		}
	}
}
