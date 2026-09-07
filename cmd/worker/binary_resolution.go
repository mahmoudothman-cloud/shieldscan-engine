package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// resolveBinary applies DEVELOPMENT-PATTERNS Pattern 2 (env-var-binary)
// at the wiring tier: SHIELDSCAN_<TOOL>_BINARY env var first;
// exec.LookPath(toolName) fallback; fail-fast structured error if both
// empty. Returns an absolute path on success.
//
// Pattern instance accounting (per H.E from M6.8 scope):
//   - 12 cumulative call sites of the SHIELDSCAN_<TOOL>_BINARY pattern
//     across M6 (each tool's NewXxxRunner caller resolves a path).
//   - This is the 2nd resolveBinary helper (1st: internal/tools/recon
//     /recon.go, package-private to recon).
//
// Why local at cmd/worker/ rather than a shared package: the recon
// helper and this helper sit at different architectural layers (recon
// is a leaf tool package; this is the binary-assembly tier). Two
// instances at different layers is correct architectural placement;
// a shared package would be premature abstraction. Promotion trigger:
// a 3rd different-layer instance OR a 3rd wiring-tier instance.
//
// Failure semantics: returns error so the caller (buildRegistry +
// runMain) can fail-fast at startup with exit code 1 — operationally
// preferable to silently registering a runner that points at a
// missing binary and then failing every job at runtime. Distinct
// from Phase 1's runtime fail-soft stat-check (binary path derived
// but file missing/non-executable): different layer, different
// failure mode (see DRIFT entry 5 sub-note).
func resolveBinary(envVar, toolName string) (string, error) {
	if path := os.Getenv(envVar); path != "" {
		return path, nil
	}
	path, err := exec.LookPath(toolName)
	if err != nil {
		return "", fmt.Errorf("%s: binary not found; set %s env var or ensure %s is on $PATH",
			toolName, envVar, toolName)
	}
	return path, nil
}

// envEnabled reports whether an env var is set to an affirmative value.
//
// Accepts the forms an operator actually types — "1", "true", "yes",
// "on", any case — rather than only Go's strconv.ParseBool set, because
// the failure mode of a stricter parser is a flag that silently does
// nothing. Anything else, including unset, is false.
func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
