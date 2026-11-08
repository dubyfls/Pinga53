// SPDX-License-Identifier: AGPL-3.0-only

// Package config loads and validates ScamWall configuration.
//
// Configuration never carries a credential. The Pi-hole application password
// is read separately from a file mount, so that a configuration file can be
// committed, logged, or pasted into an issue without exposing anything.
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Fixed filesystem locations. These are deliberately constants rather than
// configurable: allowing the credential path to be redirected would turn a
// configuration bug into a credential-disclosure bug.
const (
	// DefaultSecretPath is the only location a Pi-hole password is read from.
	DefaultSecretPath = "/run/secrets/pihole_app_password"
	// DefaultCAPath is the only location the Pi-hole private CA is read from.
	DefaultCAPath = "/etc/scamwall/certs/pihole-ca.crt"
	// DefaultConfigPath is where the container expects its config mount.
	DefaultConfigPath = "/etc/scamwall/config.json"
	// DefaultFeedPath is the repository-owned test fixture used in Phase 1.
	DefaultFeedPath = "/etc/scamwall/feed.json"
)

// MaxConfigBytes bounds configuration file reads.
const MaxConfigBytes = 256 * 1024

// Errors returned by Load and Validate.
var (
	ErrConfigTooLarge   = errors.New("config file exceeds maximum size")
	ErrEnforcementAsked = errors.New("enforcement requested but not available in this build")
)

// Duration is a time.Duration that marshals as a Go duration string, so that
// configuration reads as "10s" rather than a nanosecond count.
type Duration time.Duration

// UnmarshalJSON accepts either a duration string or an integer nanosecond count.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string such as \"10s\" or an integer: %w", err)
	}
	*d = Duration(n)
	return nil
}

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// D returns the underlying time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Pihole configures the read-only Pi-hole API client.
type Pihole struct {
	// Host is the name the TLS certificate must be valid for. It is used for
	// SNI and hostname verification regardless of the address dialled.
	Host string `json:"host"`
	// Port is the HTTPS port.
	Port int `json:"port"`
	// AddressOverride pins name resolution to a specific "host:port" or "host".
	//
	// This is the exact analogue of `curl --resolve`: it changes which address
	// is dialled, never which identity is required. It exists because DNS for
	// the API name may point elsewhere on some networks. It is not, and must
	// never become, a way to skip verification.
	AddressOverride string `json:"address_override"`

	CAPath     string `json:"ca_path"`
	SecretPath string `json:"secret_path"`

	ConnectTimeout Duration `json:"connect_timeout"`
	RequestTimeout Duration `json:"request_timeout"`
	TotalTimeout   Duration `json:"total_timeout"`
	// LogoutTimeout bounds the logout attempt separately, so that a hung or
	// cancelled operation still gets a real chance to destroy its session
	// rather than inheriting an already-expired context.
	LogoutTimeout Duration `json:"logout_timeout"`

	MaxResponseBytes int64    `json:"max_response_bytes"`
	MaxRetries       int      `json:"max_retries"`
	RetryBaseDelay   Duration `json:"retry_base_delay"`
}

// Feed configures feed loading and trust.
type Feed struct {
	Path string `json:"path"`
	// TrustKeyID must match the key_id in a feed's signature block.
	TrustKeyID string `json:"trust_key_id"`
	// TrustPublicKey is a standard-base64 Ed25519 public key (32 bytes).
	TrustPublicKey string `json:"trust_public_key"`

	MaxFileBytes int64 `json:"max_file_bytes"`
	MaxRecords   int   `json:"max_records"`
}

// Runtime configures execution mode.
type Runtime struct {
	// DryRun must be true in Phase 1. It is present so the field exists and is
	// validated, not so it can be turned off.
	DryRun bool `json:"dry_run"`
}

// Config is the complete ScamWall configuration.
type Config struct {
	Pihole  Pihole  `json:"pihole"`
	Feed    Feed    `json:"feed"`
	Runtime Runtime `json:"runtime"`
}

// Default returns the built-in configuration.
//
// The defaults are deliberately conservative: short timeouts, small response
// ceiling, few retries. A read-only status client has no reason to hold a
// connection open or to buffer a large body, and a tight bound turns a
// misbehaving or hostile endpoint into a fast failure.
func Default() Config {
	return Config{
		Pihole: Pihole{
			Host:             "pi.hole",
			Port:             443,
			CAPath:           DefaultCAPath,
			SecretPath:       DefaultSecretPath,
			ConnectTimeout:   Duration(5 * time.Second),
			RequestTimeout:   Duration(10 * time.Second),
			TotalTimeout:     Duration(30 * time.Second),
			LogoutTimeout:    Duration(5 * time.Second),
			MaxResponseBytes: 1 << 20, // 1 MiB
			MaxRetries:       2,
			RetryBaseDelay:   Duration(200 * time.Millisecond),
		},
		Feed: Feed{
			Path:         DefaultFeedPath,
			MaxFileBytes: 1 << 20, // 1 MiB
			MaxRecords:   10000,
		},
		Runtime: Runtime{DryRun: true},
	}
}

// Load reads configuration from path, applying defaults for absent fields.
// A missing file is not an error: the defaults are a complete configuration.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return validated(cfg)
	}

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return validated(cfg)
		}
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()

	if info, err := f.Stat(); err == nil && info.Size() > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: %d bytes (max %d)", ErrConfigTooLarge, info.Size(), MaxConfigBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if int64(len(data)) > MaxConfigBytes {
		return Config{}, fmt.Errorf("%w: max %d", ErrConfigTooLarge, MaxConfigBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	// Unknown fields are an error rather than a silent no-op: a typo in a
	// security-relevant setting must not look like it was applied.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	return validated(cfg)
}

// validated returns cfg only if it passes Validate, and the ZERO Config
// otherwise.
//
// Returning a populated struct alongside an error is a footgun this package
// can simply not have: a caller that logs the error and carries on would be
// acting on settings that failed their own checks, with the credential still
// on disk and the network still available. The zero Config has no host and no
// paths, so it cannot authenticate to anything. Found by FuzzLoad, which
// asserted the property before the code had it.
func validated(cfg Config) (Config, error) {
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the configuration for internal consistency and for
// Phase 1 invariants.
func (c Config) Validate() error {
	var errs []error

	if c.Pihole.Host == "" {
		errs = append(errs, errors.New("pihole.host must not be empty"))
	}
	if ip := net.ParseIP(c.Pihole.Host); ip != nil {
		// The certificate is issued for a name. Using an address as the host
		// would either fail verification or, worse, invite someone to relax it.
		errs = append(errs, errors.New("pihole.host must be a DNS name, not an IP address; use address_override to pin resolution"))
	}
	if c.Pihole.Port <= 0 || c.Pihole.Port > 65535 {
		errs = append(errs, fmt.Errorf("pihole.port %d out of range", c.Pihole.Port))
	}
	if !filepath.IsAbs(c.Pihole.CAPath) {
		errs = append(errs, errors.New("pihole.ca_path must be an absolute path"))
	}
	if !filepath.IsAbs(c.Pihole.SecretPath) {
		errs = append(errs, errors.New("pihole.secret_path must be an absolute path"))
	}
	if c.Pihole.AddressOverride != "" {
		if err := validateHostPort(c.Pihole.AddressOverride); err != nil {
			errs = append(errs, fmt.Errorf("pihole.address_override: %w", err))
		}
	}
	for name, d := range map[string]Duration{
		"connect_timeout": c.Pihole.ConnectTimeout,
		"request_timeout": c.Pihole.RequestTimeout,
		"total_timeout":   c.Pihole.TotalTimeout,
		"logout_timeout":  c.Pihole.LogoutTimeout,
	} {
		if d.D() <= 0 {
			errs = append(errs, fmt.Errorf("pihole.%s must be positive", name))
		}
	}
	if c.Pihole.RequestTimeout.D() > c.Pihole.TotalTimeout.D() {
		errs = append(errs, errors.New("pihole.request_timeout must not exceed total_timeout"))
	}
	if c.Pihole.MaxResponseBytes <= 0 {
		errs = append(errs, errors.New("pihole.max_response_bytes must be positive"))
	}
	if c.Pihole.MaxRetries < 0 || c.Pihole.MaxRetries > 10 {
		errs = append(errs, errors.New("pihole.max_retries must be between 0 and 10"))
	}
	if c.Pihole.RetryBaseDelay.D() < 0 {
		errs = append(errs, errors.New("pihole.retry_base_delay must not be negative"))
	}

	if c.Feed.Path == "" {
		errs = append(errs, errors.New("feed.path must not be empty"))
	}
	if c.Feed.MaxFileBytes <= 0 {
		errs = append(errs, errors.New("feed.max_file_bytes must be positive"))
	}
	if c.Feed.MaxRecords <= 0 {
		errs = append(errs, errors.New("feed.max_records must be positive"))
	}
	if c.Feed.TrustPublicKey != "" {
		key, err := base64.StdEncoding.DecodeString(c.Feed.TrustPublicKey)
		if err != nil {
			errs = append(errs, errors.New("feed.trust_public_key is not valid base64"))
		} else if len(key) != 32 {
			errs = append(errs, fmt.Errorf("feed.trust_public_key must be 32 bytes, got %d", len(key)))
		}
	}

	// Phase 1 invariant. Dry-run is not a preference here; it is the boundary.
	if !c.Runtime.DryRun {
		errs = append(errs, ErrEnforcementAsked)
	}

	return errors.Join(errs...)
}

// TrustPublicKeyBytes decodes the configured Ed25519 public key.
func (c Config) TrustPublicKeyBytes() ([]byte, error) {
	if c.Feed.TrustPublicKey == "" {
		return nil, errors.New("feed.trust_public_key is not configured")
	}
	key, err := base64.StdEncoding.DecodeString(c.Feed.TrustPublicKey)
	if err != nil {
		return nil, errors.New("feed.trust_public_key is not valid base64")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("feed.trust_public_key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// BaseURL returns the HTTPS origin of the Pi-hole API.
func (c Config) BaseURL() string {
	return "https://" + net.JoinHostPort(c.Pihole.Host, strconv.Itoa(c.Pihole.Port))
}

// DialAddress returns the address the client should actually dial. When no
// override is set this is the configured host and port.
func (c Config) DialAddress() string {
	if c.Pihole.AddressOverride == "" {
		return net.JoinHostPort(c.Pihole.Host, strconv.Itoa(c.Pihole.Port))
	}
	if _, _, err := net.SplitHostPort(c.Pihole.AddressOverride); err == nil {
		return c.Pihole.AddressOverride
	}
	return net.JoinHostPort(c.Pihole.AddressOverride, strconv.Itoa(c.Pihole.Port))
}

func validateHostPort(s string) error {
	host := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("invalid port %q", p)
		}
	}
	if host == "" {
		return errors.New("host must not be empty")
	}
	return nil
}
