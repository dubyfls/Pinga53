// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dubyfls/Pinga53/engine/internal/config"
)

// FuzzLoad drives the configuration decoder with arbitrary file content.
//
// The invariant that matters most here is not "does it parse". It is that a
// configuration this process cannot vouch for must never become one that is
// acted on — and in particular, must never yield a Config whose destination or
// transport settings would let a request leave the host on terms nobody chose.
// Configuration is the only attacker-adjacent input that runs BEFORE any
// credential is loaded, so a decoder that accepted a hostile file would do so
// with the credential still on disk and the network still available.
func FuzzLoad(f *testing.F) {
	seeds := []string{
		"", "{}", "null", "[]", "0", `"x"`,
		`{"pihole":{"host":"pi.hole","port":443}}`,
		`{"pihole":{"port":-1}}`,
		`{"pihole":{"port":99999}}`,
		`{"runtime":{"dry_run":false}}`,
		`{"pihole":{"request_timeout":"10s","total_timeout":"1s"}}`,
		`{"pihole":{"request_timeout":9223372036854775807}}`,
		`{"pihole":{"address_override":"evil.example.com:443"}}`,
		`{"pihole":{"host":"evil.example.com"}}`,
		`{"unknown_field":1}`,
		`{"feed":{"trust_public_key":"!!!not base64!!!"}}`,
		`{"feed":{"max_records":-5}}`,
		"{}{}",
		strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 200),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	dir := f.TempDir()
	path := filepath.Join(dir, "config.json")

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}

		// INVARIANT 1: no panic, whatever the bytes are.
		cfg, err := config.Load(path)
		if err != nil {
			// INVARIANT 2: a rejected configuration yields the zero value, so
			// a caller that ignores the error cannot proceed with a partially
			// applied file. A zero Config has no host and no paths, so it
			// cannot authenticate to anything.
			if cfg != (config.Config{}) {
				t.Fatalf("Load rejected the input but returned a populated config: %+v", cfg)
			}
			return
		}

		// INVARIANT 3: anything accepted satisfies Validate. Load must not be
		// able to return a config that Validate would refuse, or the checks in
		// Validate are decorative.
		if verr := cfg.Validate(); verr != nil {
			t.Fatalf("Load accepted a config that Validate rejects: %v", verr)
		}

		// INVARIANT 4: an accepted configuration is still read-only. There is
		// no byte sequence that turns enforcement on.
		if !cfg.Runtime.DryRun {
			t.Fatalf("a configuration file disabled dry-run: %q", data)
		}

		// INVARIANT 5: the destination is still HTTPS. A configuration that
		// could produce a plaintext base URL would send a session id in clear.
		if !strings.HasPrefix(cfg.BaseURL(), "https://") {
			t.Fatalf("BaseURL is not HTTPS: %q from %q", cfg.BaseURL(), data)
		}

		// INVARIANT 6: the credential path is not configurable. Redirecting it
		// would turn a configuration bug into a credential-disclosure bug, so
		// the field must remain what the code fixed it to.
		if cfg.Pihole.SecretPath != config.DefaultSecretPath {
			t.Fatalf("the secret path was changed by configuration: %q", cfg.Pihole.SecretPath)
		}

		// INVARIANT 7: bounds stay positive and finite. A zero or negative
		// timeout removes a deadline; a zero response limit removes a bound.
		if cfg.Pihole.TotalTimeout.D() <= 0 || cfg.Pihole.RequestTimeout.D() <= 0 ||
			cfg.Pihole.ConnectTimeout.D() <= 0 || cfg.Pihole.LogoutTimeout.D() <= 0 {
			t.Fatalf("a non-positive timeout was accepted: %+v", cfg.Pihole)
		}
		if cfg.Pihole.MaxResponseBytes <= 0 || cfg.Feed.MaxFileBytes <= 0 || cfg.Feed.MaxRecords <= 0 {
			t.Fatalf("a non-positive bound was accepted: %+v", cfg)
		}
		if cfg.Pihole.MaxRetries < 0 {
			t.Fatalf("a negative retry count was accepted: %d", cfg.Pihole.MaxRetries)
		}

		// INVARIANT 8: determinism. The same bytes produce the same config.
		again, err2 := config.Load(path)
		if err2 != nil || again != cfg {
			t.Fatalf("Load is not deterministic for %q", data)
		}
	})
}
