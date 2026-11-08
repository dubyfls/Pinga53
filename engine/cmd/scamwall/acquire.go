// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/feed"
)

// # WHAT `acquire` and `gen-signer-key` EXIST FOR
//
// The ScamWall receiver side consumes a signed evidence document and writes an
// RPZ zone. On a fresh Pinga53 install there is no upstream signer yet: the
// deploy generates a local signer key, and this command produces the signed
// evidence document the resolver's periodic run then feeds to `rpz`.
//
// Both commands are OFFLINE and read / write only the paths given. There is no
// configuration loader, no credential, no Pi-hole client. `acquire` currently
// writes a ZERO-RECORD manifest (the "no fetchers wired yet" shape) with the
// clock bound into IssuedAt / ExpiresAt; a future revision will fetch the
// enabled sources' feeds and attach records attributed to each source id.
//
// On signing: the ed25519 key is the operator's own secret, generated on this
// host, written mode 0600. The analogue of mac.LoadKeyFile applies: a key
// every process on the host can read is not a key, so this command refuses
// one that is world-readable.

// gen-signer-key writes a fresh ed25519 keypair.
//
// The seed is 32 bytes raw to --out, mode 0600 (matches `scamwall rpz --key`'s
// MAC file shape so the operator can reason about the two files identically).
// The public key is base64-encoded raw 32-byte bytes to --pub-out, suitable
// for pasting into the `public_key` field of a signers.json record.
func cmdGenSignerKey(w *os.File, args []string) int {
	fs := flag.NewFlagSet("gen-signer-key", flag.ContinueOnError)
	fs.SetOutput(w)
	outPath := fs.String("out", "", "write the ed25519 seed (32 bytes, raw) here (required; mode 0600)")
	pubPath := fs.String("pub-out", "", "write the base64-encoded raw ed25519 public key here (required)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *outPath == "" || *pubPath == "" {
		fmt.Fprintln(w, "gen-signer-key: --out and --pub-out are required")
		return exitUsage
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail(w, fmt.Errorf("generate ed25519 keypair: %w", err))
	}
	seed := priv.Seed()
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if err := writeExclusive(*outPath, seed, 0o600); err != nil {
		return fail(w, err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := writeExclusive(*pubPath, []byte(pubB64), 0o644); err != nil {
		// The seed on disk is now orphaned; name it so the operator can
		// remove it rather than discovering it later with no context.
		fmt.Fprintf(w, "warning: a seed was written to %s but %s could not be: %v\n",
			*outPath, *pubPath, err)
		return exitFailure
	}
	fmt.Fprintf(w, "wrote %s (seed, mode 0600) and %s (public key, base64)\n",
		*outPath, *pubPath)
	return exitOK
}

// writeExclusive refuses to overwrite. A keygen that silently replaces an
// existing key renders every signature it made unverifiable with no record of
// when the change happened — the shape every "lost a key" incident takes.
func writeExclusive(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "." {
		dir = ""
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists; this command does not overwrite a key (remove it on purpose if you intend to)", path)
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	return nil
}

// acquire builds and signs an evidence document.
//
// Two inputs vary at the command line (feed-id, out path), two are read from
// disk (signer seed, optional records manifest). The zero-record form is the
// default: on a fresh Pinga53 install the fetchers are not wired yet and the
// pipeline must still produce a zone — `rpz` with zero records and
// --allow-empty writes an empty zone, which is the shadow soak's starting
// state. See scripts/scamwall-run.sh.
func cmdAcquire(w *os.File, args []string) int {
	fs := flag.NewFlagSet("acquire", flag.ContinueOnError)
	fs.SetOutput(w)
	signerKeyPath := fs.String("signer-key", "", "path to the ed25519 signer seed file (required; 32 bytes, mode 0600)")
	keyID := fs.String("key-id", "", "signer key id as it appears in signers.json (required)")
	feedID := fs.String("feed-id", "pinga53-local", "feed id to bind into the manifest")
	outPath := fs.String("out", "", "path to write the signed evidence envelope to (required)")
	recordsPath := fs.String("records", "", "path to a JSON array of EvidenceRecords; omit for a zero-record manifest")
	ttl := fs.Duration("ttl", 24*time.Hour, "manifest ExpiresAt = now + ttl")
	issuedAtArg := fs.String("issued-at", "", "manifest IssuedAt, RFC 3339 (default: now)")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	for flagName, v := range map[string]string{
		"--signer-key": *signerKeyPath, "--key-id": *keyID, "--out": *outPath,
	} {
		if v == "" {
			fmt.Fprintf(w, "acquire: %s is required\n", flagName)
			return exitUsage
		}
	}

	seed, err := readSignerSeed(*signerKeyPath)
	if err != nil {
		return fail(w, err)
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	priv := ed25519.NewKeyFromSeed(seed)

	issuedAt := time.Now().UTC()
	if *issuedAtArg != "" {
		t, err := time.Parse(time.RFC3339, *issuedAtArg)
		if err != nil {
			fmt.Fprintf(w, "acquire: --issued-at is not an RFC 3339 instant: %v\n", err)
			return exitUsage
		}
		issuedAt = t.UTC()
	}

	var records []feed.EvidenceRecord
	if *recordsPath != "" {
		b, err := os.ReadFile(*recordsPath)
		if err != nil {
			return fail(w, fmt.Errorf("read records: %w", err))
		}
		if err := json.Unmarshal(b, &records); err != nil {
			return fail(w, fmt.Errorf("parse records: %w", err))
		}
	}
	payload, err := json.Marshal(feed.EvidenceManifest{
		ManifestVersion: feed.SupportedEvidenceManifestVersion,
		FeedID:          *feedID,
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(*ttl),
		Records:         records,
	})
	if err != nil {
		return fail(w, fmt.Errorf("marshal manifest: %w", err))
	}
	sig := ed25519.Sign(priv, payload)
	env, err := json.Marshal(struct {
		SchemaVersion int               `json:"schema_version"`
		Signature     map[string]string `json:"signature"`
		Payload       json.RawMessage   `json:"payload"`
	}{
		SchemaVersion: feed.EvidenceSchemaVersion,
		Signature: map[string]string{
			"algorithm": feed.SignatureAlgorithm,
			"key_id":    *keyID,
			"value":     base64.StdEncoding.EncodeToString(sig),
		},
		Payload: payload,
	})
	if err != nil {
		return fail(w, fmt.Errorf("marshal envelope: %w", err))
	}

	// Atomic replace: evidence.json is read by scamwall-run.service, and a
	// writer that truncated it mid-run would show the reader a document
	// that is neither valid JSON nor the previous one. tmp + rename.
	tmp := *outPath + ".tmp"
	if err := os.WriteFile(tmp, env, 0o644); err != nil {
		return fail(w, fmt.Errorf("write %s: %w", tmp, err))
	}
	if err := os.Rename(tmp, *outPath); err != nil {
		_ = os.Remove(tmp)
		return fail(w, fmt.Errorf("rename %s -> %s: %w", tmp, *outPath, err))
	}
	fmt.Fprintf(w, "wrote %s (feed_id=%q, %d record(s), signed by %q)\n",
		*outPath, *feedID, len(records), *keyID)
	return exitOK
}

// readSignerSeed reads a 32-byte ed25519 seed and refuses one anybody can
// read. Mirrors mac.LoadKeyFile's shape for the same reason: a key the whole
// host can read is not a key.
func readSignerSeed(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open signer key: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat signer key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("signer key %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o004 != 0 {
		return nil, fmt.Errorf("signer key %s has mode %#o and is world-readable; "+
			"a key every process on this host can read is not a key", path, info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, fmt.Errorf("read signer key: %w", err)
	}
	raw = bytes.TrimRight(raw, "\n")
	if len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("signer key %s is %d bytes, want %d (an ed25519 seed is exactly %d bytes)",
			path, len(raw), ed25519.SeedSize, ed25519.SeedSize)
	}
	return raw, nil
}
