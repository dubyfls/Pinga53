// SPDX-License-Identifier: AGPL-3.0-only

package feedsources

import "time"

func init() {
	// Keep the retry loop in tests but don't wait seconds between attempts.
	retryBackoff = func(int) time.Duration { return time.Millisecond }
}
