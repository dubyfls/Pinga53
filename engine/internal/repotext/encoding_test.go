// SPDX-License-Identifier: AGPL-3.0-only

package repotext

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// repoRoot locates the repository from this package's directory.
//
// The walk is over TRACKED files only. An untracked scratch file is not part
// of the repository's text and must not be able to fail its gate; an ignored
// build artifact even less so.
func repoRoot(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available; the tracked-file walk needs the repository")
	}
	// ../.. is the ScamWall module root. It is deliberately NOT
	// `git rev-parse --show-toplevel`: ScamWall is a subtree of a larger
	// repository, whose toplevel holds files this gate does not own.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Skipf("cannot resolve the module root: %v", err)
	}
	if err := exec.Command("git", "-C", root, "rev-parse", "--is-inside-work-tree").Run(); err != nil {
		t.Skipf("not a usable repository here: %v", err)
	}
	return root
}

// trackedTextFiles lists every tracked file that is text.
//
// "Text" is decided by content, not by extension: a file with no NUL byte in
// its first 8 KiB is treated as text. Extension allow-lists miss exactly the
// files nobody thought about, which is where corruption survives longest.
func trackedTextFiles(t *testing.T, root string) []string {
	t.Helper()
	// reference/ is specification, not code, and is not part of any gate
	// (ORDER 10 section 3.5).
	out, err := exec.Command("git", "-C", root, "ls-files", "-z",
		"--", ".", ":(exclude)reference/").Output()
	if err != nil {
		t.Skipf("git ls-files failed: %v", err)
	}
	var files []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		abs := filepath.Join(root, rel)
		info, err := os.Stat(abs)
		if err != nil || !info.Mode().IsRegular() {
			continue // a deleted or non-regular entry is not this gate's subject
		}
		f, err := os.Open(abs)
		if err != nil {
			t.Fatalf("tracked file %s cannot be read: %v", rel, err)
		}
		head := make([]byte, 8192)
		n, _ := f.Read(head)
		f.Close()
		if bytes.IndexByte(head[:n], 0) >= 0 {
			continue // binary
		}
		files = append(files, rel)
	}
	if len(files) == 0 {
		t.Fatal("the tracked-text walk found no files; the gate would pass vacuously")
	}
	return files
}

// TestTrackedTextHasNoEncodingCorruption is the control itself.
//
// It fails on the corruption demonstrated at 3152485 and on any other run that
// inverts into different non-ASCII text.
func TestTrackedTextHasNoEncodingCorruption(t *testing.T) {
	root := repoRoot(t)
	files := trackedTextFiles(t, root)
	t.Logf("scanned %d tracked text files", len(files))

	failed := 0
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("tracked file %s cannot be read: %v", rel, err)
		}
		fs := Scan(data)
		if len(fs) == 0 {
			continue
		}
		failed++
		t.Errorf("%s: %d encoding defect(s)", rel, len(fs))
		for _, line := range Summarize(fs) {
			t.Errorf("    %s", line)
		}
		const showAt = 5
		for i, f := range fs {
			if i >= showAt {
				t.Errorf("    ... and %d more occurrence(s)", len(fs)-showAt)
				break
			}
			t.Errorf("    %s", f)
		}
	}
	if failed > 0 {
		t.Errorf("%d tracked text file(s) carry encoding corruption", failed)
	}
}

// TestDetectorFindsEveryDemonstratedSequence is the POSITIVE CONTROL.
//
// A gate that has never been shown to fail is not evidence of anything. This
// feeds the detector each corruption actually observed at 3152485 and requires
// it to report that corruption AND to name the right original character. A
// detector that reported "something is wrong" without recovering the intended
// text could not drive a repair.
func TestDetectorFindsEveryDemonstratedSequence(t *testing.T) {
	for _, d := range DemonstratedSequences {
		line := "the gate " + string(d.Bytes) + " must see this"
		fs := Scan([]byte(line))
		if len(fs) != 1 {
			t.Errorf("% X: got %d finding(s), want exactly 1", d.Bytes, len(fs))
			continue
		}
		f := fs[0]
		if f.Kind != KindMojibake {
			t.Errorf("% X: kind = %q, want %q", d.Bytes, f.Kind, KindMojibake)
		}
		if f.Want != d.Want {
			t.Errorf("% X: recovered %q, want %q", d.Bytes, f.Want, d.Want)
		}
		if f.Depth != d.Depth {
			t.Errorf("% X: fold depth = %d, want %d", d.Bytes, f.Depth, d.Depth)
		}
		if !bytes.Equal(f.Bytes, d.Bytes) {
			t.Errorf("% X: reported bytes % X, want % X", d.Bytes, f.Bytes, d.Bytes)
		}
	}
}

// TestDetectorDoesNotFlagLegitimateText is the NEGATIVE CONTROL.
//
// A detector that flags everything also "catches" every corruption, and is
// worth nothing. These are the characters the repaired documents legitimately
// contain, plus ordinary accented prose, and every one of them must pass.
func TestDetectorDoesNotFlagLegitimateText(t *testing.T) {
	clean := []string{
		"the API contract — the threat model",
		"See §5.",
		"and so on …",
		"a range 1–9 and a minus −3",
		"an arrow → here",
		"café, naïve, Ça ira, Zoë, año, Grüße",
		"pure ASCII with no punctuation at all",
		"§ alone, © alone, ® alone, ° alone, µ alone",
		"",
		"mixed: café — §7 … done",
	}
	for _, s := range clean {
		if fs := Scan([]byte(s)); len(fs) != 0 {
			t.Errorf("legitimate text %q was flagged: %v", s, fs)
		}
	}
}

// TestSingleLatin1CharacterIsNotMojibake pins the rule that keeps the negative
// control above true: one character in U+0080..U+00FF folds to one byte, which
// is never well-formed multi-byte UTF-8.
func TestSingleLatin1CharacterIsNotMojibake(t *testing.T) {
	for _, r := range []rune{0xA7, 0xA9, 0xAE, 0xB0, 0xB5, 0xE9, 0xFC, 0xC7} {
		if fs := Scan([]byte(string(r))); len(fs) != 0 {
			t.Errorf("U+%04X alone was flagged as mojibake: %v", r, fs)
		}
	}
}

// TestInvalidUTF8IsAFailureNotASkip guards the other direction: a file that is
// not UTF-8 at all must fail, rather than being quietly passed over because
// the mojibake walk needs well-formed input to run.
func TestInvalidUTF8IsAFailureNotASkip(t *testing.T) {
	bad := []byte("ok line\nbroken \xFF\xFE here\n")
	if utf8.Valid(bad) {
		t.Fatal("the fixture is valid UTF-8; it cannot test the invalid path")
	}
	fs := Scan(bad)
	if len(fs) != 1 || fs[0].Kind != KindInvalidUTF8 {
		t.Fatalf("invalid UTF-8 produced %v, want one %s finding", fs, KindInvalidUTF8)
	}
	if fs[0].Line != 2 {
		t.Errorf("reported line %d, want 2", fs[0].Line)
	}
}

// TestFoldRejectsWhatItCannotHaveProduced covers Fold's contract directly.
func TestFoldRejectsWhatItCannotHaveProduced(t *testing.T) {
	if _, ok := Fold("—"); ok {
		t.Error("Fold accepted a character above U+00FF")
	}
	if _, ok := Fold(""); ok {
		t.Error("Fold accepted the empty string")
	}
	if _, ok := Fold("ÿ"); ok {
		t.Error("Fold accepted a single byte that is not valid UTF-8")
	}
	// Written as escapes, never as the literal smear: a source file that
	// embedded it would be flagged by this package's own repository walk.
	const single = "\xC3\x82\xC2\xA7"
	got, ok := Fold(single)
	if !ok || got != "\u00a7" {
		t.Errorf("Fold(% X) = %q, %v; want the section sign, true", single, got, ok)
	}
}

// TestReportingACorruptionDoesNotReproduceIt is why Finding renders bytes as
// hex. A findings document that pasted the raw smear would be flagged by this
// very gate, and the repository would have no way to record what happened.
func TestReportingACorruptionDoesNotReproduceIt(t *testing.T) {
	for _, d := range DemonstratedSequences {
		fs := Scan(d.Bytes)
		if len(fs) == 0 {
			t.Fatalf("% X was not detected", d.Bytes)
		}
		rendered := fs[0].String()
		if strings.Contains(rendered, string(d.Bytes)) {
			t.Errorf("the rendered finding reproduces the raw corruption: %q", rendered)
		}
		if inner := Scan([]byte(rendered)); len(inner) != 0 {
			t.Errorf("the rendered finding is itself flagged as corrupt: %v", inner)
		}
	}
}

// TestControlStillFailsAgainstTheCorruptedBlob is the DISCRIMINATION control,
// and it is permanent.
//
// Once docs/REQUIREMENTS_MATRIX.md is repaired, the repository walk above
// passes — and a passing gate proves nothing on its own, because a detector
// that had been quietly broken would pass identically. This reads the exact
// corrupted blob out of history and requires the detector to still convict it,
// with the same census, for as long as that commit exists. If someone weakens
// Scan, this fails even though the working tree is clean.
func TestControlStillFailsAgainstTheCorruptedBlob(t *testing.T) {
	const (
		corruptCommit = "3152485b96cc669bca1f73b8fefa7fd171f7df6f"
		corruptPath   = "docs/REQUIREMENTS_MATRIX.md"
	)
	root := repoRoot(t)
	blob, err := exec.Command("git", "-C", root, "show", corruptCommit+":"+corruptPath).Output()
	if err != nil {
		t.Skipf("the corrupted blob is not reachable here: %v", err)
	}
	if !utf8.Valid(blob) {
		t.Fatal("the corrupted blob is not valid UTF-8; the premise of this " +
			"finding is that the damage SURVIVES a validity check")
	}

	fs := Scan(blob)
	if len(fs) == 0 {
		t.Fatal("the detector found nothing in the known-corrupt blob: it no " +
			"longer discriminates, and a clean working tree proves nothing")
	}

	// Census, keyed by the raw run, must match what was observed at that
	// commit exactly — not merely "some findings were produced".
	got := map[string]int{}
	for _, f := range fs {
		got[string(f.Bytes)]++
	}
	want := map[string]int{}
	total := 0
	for _, d := range DemonstratedSequences {
		want[string(d.Bytes)] = d.Count
		total += d.Count
	}
	if len(fs) != total {
		t.Errorf("found %d occurrence(s), census records %d", len(fs), total)
	}
	for seq, n := range want {
		if got[seq] != n {
			t.Errorf("% X: found %d, census records %d", []byte(seq), got[seq], n)
		}
	}
	for seq, n := range got {
		if _, ok := want[seq]; !ok {
			t.Errorf("% X: found %d occurrence(s) that the census does not record", []byte(seq), n)
		}
	}
}
