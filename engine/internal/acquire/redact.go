// SPDX-License-Identifier: AGPL-3.0-only

package acquire

import "github.com/dubyfls/Pinga53/engine/internal/audit"

// Redact removes credential-bearing parts of any URL appearing in s.
//
// One implementation, in internal/audit, because that is where the guarantee
// has to hold anyway — a log line is the place a leaked credential is most
// durable — and two copies of a redaction is two chances to fix one of them.
// See internal/audit/url.go for why the redaction is inside the value rather
// than by field name.
//
// It is called here as well as by the logger because an attempt row is stored
// and re-read, not only logged: a row that carries the key is a leak whether
// or not anything ever prints it.
func Redact(s string) string { return audit.RedactURLs(s) }
