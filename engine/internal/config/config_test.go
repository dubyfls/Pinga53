// SPDX-License-Identifier: AGPL-3.0-only

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dubyfls/Pinga53/engine/internal/config"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultConfigIsValid(t *testing.T) {
	if err := config.Default().Validate(); err != nil {
		t.Fatalf("built-in defaults must be valid: %v", err)
	}
}

func TestDefaultIsDryRun(t *testing.T) {
	// Dry-run being the default is a Phase 1 boundary, not a preference.
	if !config.Default().Runtime.DryRun {
		t.Fatal("dry-run must be the default")
	}
}

func TestValidateRejectsEnforcement(t *testing.T) {
	c := config.Default()
	c.Runtime.DryRun = false
	err := c.Validate()
	if !errors.Is(err, config.ErrEnforcementAsked) {
		t.Fatalf("disabling dry-run must be refused, got: %v", err)
	}
}

func TestMissingConfigFileUsesDefaults(t *testing.T) {
	// A missing file is a complete configuration, not an error: the defaults
	// are deliberately a working, safe configuration.
	c, err := config.Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing config should fall back to defaults: %v", err)
	}
	if c.Pihole.Host != "pi.hole" {
		t.Errorf("unexpected host %q", c.Pihole.Host)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	p := writeConfig(t, `{
	  "pihole": {"host": "pi.hole", "port": 8443, "request_timeout": "3s"},
	  "feed": {"path": "/tmp/feed.json"}
	}`)
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Pihole.Port != 8443 {
		t.Errorf("port = %d", c.Pihole.Port)
	}
	if c.Pihole.RequestTimeout.D() != 3*time.Second {
		t.Errorf("request_timeout = %v", c.Pihole.RequestTimeout.D())
	}
	// Unspecified fields must retain their defaults.
	if c.Pihole.MaxResponseBytes != config.Default().Pihole.MaxResponseBytes {
		t.Error("unspecified field lost its default")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// A typo in a security-relevant setting must not look like it was applied.
	p := writeConfig(t, `{"pihole": {"hosst": "pi.hole"}}`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestLoadRejectsOversizedConfig(t *testing.T) {
	p := writeConfig(t, "{\"pihole\":{\"host\":\""+strings.Repeat("a", config.MaxConfigBytes)+"\"}}")
	_, err := config.Load(p)
	if err == nil || !errors.Is(err, config.ErrConfigTooLarge) {
		t.Fatalf("oversized config must be rejected, got %v", err)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*config.Config){
		"empty host":          func(c *config.Config) { c.Pihole.Host = "" },
		"ip as host":          func(c *config.Config) { c.Pihole.Host = "192.0.2.10" },
		"port zero":           func(c *config.Config) { c.Pihole.Port = 0 },
		"port too high":       func(c *config.Config) { c.Pihole.Port = 70000 },
		"relative ca path":    func(c *config.Config) { c.Pihole.CAPath = "ca.crt" },
		"relative secret":     func(c *config.Config) { c.Pihole.SecretPath = "pw" },
		"zero timeout":        func(c *config.Config) { c.Pihole.RequestTimeout = 0 },
		"negative body limit": func(c *config.Config) { c.Pihole.MaxResponseBytes = -1 },
		"too many retries":    func(c *config.Config) { c.Pihole.MaxRetries = 99 },
		"zero feed records":   func(c *config.Config) { c.Feed.MaxRecords = 0 },
		"bad trust key b64":   func(c *config.Config) { c.Feed.TrustPublicKey = "not!base64" },
		"short trust key":     func(c *config.Config) { c.Feed.TrustPublicKey = "AAAA" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := config.Default()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%s should be rejected", name)
			}
		})
	}
}

func TestValidateRejectsRequestTimeoutExceedingTotal(t *testing.T) {
	c := config.Default()
	c.Pihole.RequestTimeout = config.Duration(60 * time.Second)
	c.Pihole.TotalTimeout = config.Duration(10 * time.Second)
	if err := c.Validate(); err == nil {
		t.Fatal("request timeout above total timeout should be rejected")
	}
}

func TestBaseURLIsAlwaysHTTPS(t *testing.T) {
	c := config.Default()
	if !strings.HasPrefix(c.BaseURL(), "https://") {
		t.Fatalf("base URL must be https: %s", c.BaseURL())
	}
}

func TestDialAddressPinning(t *testing.T) {
	c := config.Default()
	if got := c.DialAddress(); got != "pi.hole:443" {
		t.Errorf("without override: %q", got)
	}

	// An override changes only which address is dialled. The base URL, and
	// therefore the verified identity, is unchanged.
	c.Pihole.AddressOverride = "192.0.2.10"
	if got := c.DialAddress(); got != "192.0.2.10:443" {
		t.Errorf("host-only override: %q", got)
	}
	if !strings.Contains(c.BaseURL(), "pi.hole") {
		t.Error("override must not change the verified hostname")
	}

	c.Pihole.AddressOverride = "192.0.2.10:8443"
	if got := c.DialAddress(); got != "192.0.2.10:8443" {
		t.Errorf("host:port override: %q", got)
	}
}

func TestDurationAcceptsStringAndNumber(t *testing.T) {
	p := writeConfig(t, `{"pihole": {"request_timeout": "1500ms", "connect_timeout": 2000000000}}`)
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Pihole.RequestTimeout.D() != 1500*time.Millisecond {
		t.Errorf("string duration: %v", c.Pihole.RequestTimeout.D())
	}
	if c.Pihole.ConnectTimeout.D() != 2*time.Second {
		t.Errorf("numeric duration: %v", c.Pihole.ConnectTimeout.D())
	}
}

func TestTrustPublicKeyBytes(t *testing.T) {
	c := config.Default()
	if _, err := c.TrustPublicKeyBytes(); err == nil {
		t.Fatal("unconfigured trust key should be an error")
	}
	c.Feed.TrustPublicKey = "ZZdzt8vw2UCXeoT95fcT9Fh0U80M7L0I1L/io4AeR7A="
	key, err := c.TrustPublicKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
}

func TestSecretPathIsNotConfigurableToAnArbitraryDefault(t *testing.T) {
	// The credential location is a constant so that a configuration mistake
	// cannot become a credential-disclosure bug.
	if config.DefaultSecretPath != "/run/secrets/pihole_app_password" {
		t.Fatalf("unexpected default secret path %q", config.DefaultSecretPath)
	}
}
