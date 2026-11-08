// SPDX-License-Identifier: AGPL-3.0-only

package acquire_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheFetcherIsNotReachableFromTheCommand.
//
// ORDER 8 declined to build a feed fetcher unattended, on the grounds that a
// half-built network path is worse than none, and that judgement stands. What
// this package adds is the BOUNDS a fetch has to carry, proven against local
// test servers, so that whoever wires the component up starts from a
// transport that has already been attacked in a test rather than from a bare
// http.Get.
//
// Until that wiring is reviewed, `scamwall` must not be able to open a
// connection to a feed server. A comment saying so is not a control; this is.
//
// It uses `go list -deps` rather than reading imports, because a transitive
// import would reach the network just as well as a direct one and only the
// toolchain knows the whole graph.
func TestTheFetcherIsNotReachableFromTheCommand(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../../cmd/...").CombinedOutput()
	if err != nil {
		t.Skipf("go list unavailable in this environment: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "github.com/dubyfls/Pinga53/engine/internal/acquire" {
			t.Fatalf("cmd/ now reaches internal/acquire. The fetcher is one call from a real feed " +
				"server; ORDER 8's reason for not shipping one unattended has to be answered before " +
				"this test is changed")
		}
	}
}
