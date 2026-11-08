// SPDX-License-Identifier: AGPL-3.0-only

//go:build !enforce

package policy

import "errors"

// EnforcementCompiledIn reports whether this binary contains any code capable
// of applying a plan to Pi-hole.
//
// In Phase 1 it is always false, and there is deliberately no counterpart file
// providing a value of true. Building with `-tags enforce` therefore fails to
// compile rather than quietly producing an enforcing binary: the safest
// version of "disabled" is "does not exist".
const EnforcementCompiledIn = false

// ErrEnforcementUnavailable is returned by Apply in every Phase 1 build.
var ErrEnforcementUnavailable = errors.New(
	"enforcement is not compiled into this build; ScamWall Phase 1 is read-only and dry-run only")

// Apply exists so that callers have a single, obvious symbol to look for, and
// so that its absence of an implementation is explicit rather than implied.
//
// It never contacts Pi-hole. It cannot: this package does not import the
// Pi-hole adapter, and the adapter exposes no write method.
func Apply(_ *Plan) error { return ErrEnforcementUnavailable }
