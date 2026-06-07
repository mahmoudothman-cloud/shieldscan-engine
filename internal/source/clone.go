// Package source provides host-side source-code acquisition primitives
// for SCA / SAST tool runners that scan a local filesystem tree (e.g.
// Trivy fs-mode at M7.1; Semgrep + Gitleaks + dependency_check at
// M6.2/M6.5/M6.6 when wired).
//
// Per Source-Ingestion Fix task (shieldscan-docs commits 90fc933
// design + 04f44a9 plan + 9d6ab25 TOOL-ARCH §3.2 addendum +
// shieldscan-api 8dbcbab orchestrator threading) — Drift #54 root-
// cause repair. The package owns:
//
//   - CloneRepo: host-side `os/exec git clone --depth=1` against a
//     pre-validated HTTPS URL (the api-side validator at
//     src/app/schemas/projects.py is the primary defense; this
//     package's URL guard is belt-and-braces).
//
//   - StagingManager: per-scan tempdir lifecycle under a configurable
//     base path (defaults to `$TRIVY_SCAN_BASE_PATH` so the existing
//     trivy-fs warm-pool bind mount surfaces the staging tree as
//     `/scan/<scan-id>` inside the container, ReadOnly).
//
// Architectural locks per design doc §1: Q-CLONE-LIB (a) os/exec;
// Q-STAGING-PATH (a) co-located under $TRIVY_SCAN_BASE_PATH;
// Q-DEPTH --depth=1; Q-CLEANUP per-scan `defer os.RemoveAll`;
// Q-AUTH public-HTTPS v1; Q-WIRE engine-clones (wire carries URL,
// engine clones at job-pickup); Q-RECON-TIMING lazy per-job at worker.
//
// Phase 0 v2 empirical anchors (this lifecycle session): NodeGoat
// depth=1 clone 0.76s/3.3M/1.2M .git; trivy fs 75 findings; Docker
// ReadOnly mount enforced. ZERO pivot triggers.
package source

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
)

// CloneRepo clones the given HTTPS git URL into stagingDir at
// `--depth=1`. The directory tree under stagingDir is created if it
// doesn't exist. Returns a wrapped error containing the git subprocess
// stderr/stdout tail on failure (Q-FAILURE-MODE structured-error
// surface); nil on success.
//
// ctx cancellation propagates via exec.CommandContext per ADR-021
// Rule 1 — cancel SIGKILLs the git subprocess naturally.
//
// HTTPS-scheme is enforced defensively. The api-side validator
// (src/app/schemas/projects.py _validate_source_repo_url) is the
// primary defense; rejecting at the engine boundary catches both
// (a) misconfigured wire emissions and (b) hypothetical bypasses of
// the api validator (e.g. a future agent-direct queue producer).
func CloneRepo(ctx context.Context, gitURL, stagingDir string) error {
	if gitURL == "" {
		return errors.New("source.CloneRepo: gitURL is required")
	}
	if stagingDir == "" {
		return errors.New("source.CloneRepo: stagingDir is required")
	}
	parsed, err := url.Parse(gitURL)
	if err != nil {
		return fmt.Errorf("source.CloneRepo: parse url %q: %w", gitURL, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf(
			"source.CloneRepo: HTTPS required; got scheme %q",
			parsed.Scheme,
		)
	}
	if parsed.Host == "" {
		return fmt.Errorf("source.CloneRepo: hostless URL %q", gitURL)
	}
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf(
			"source.CloneRepo: mkdir %q: %w", stagingDir, err,
		)
	}
	// --depth=1 per Q-DEPTH lock (Phase 0 v2 empirically bounded
	// at 3.3M total / 1.2M .git for NodeGoat). exec.CommandContext
	// per ADR-021 Rule 1.
	cmd := exec.CommandContext(
		ctx, "git", "clone", "--depth=1", gitURL, stagingDir,
	)
	output, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return fmt.Errorf(
			"source.CloneRepo: git clone %q failed (output: %s): %w",
			gitURL, truncateOutput(output), runErr,
		)
	}
	return nil
}

// maxOutputBytes bounds the stderr/stdout tail included in error
// messages so a runaway-progress-output git failure doesn't bloat
// audit logs. 2 KiB is enough to retain the actual error line
// (typically "fatal: ..." or "remote: ...").
const maxOutputBytes = 2048

func truncateOutput(b []byte) string {
	if len(b) <= maxOutputBytes {
		return string(b)
	}
	return "..." + string(b[len(b)-maxOutputBytes:])
}
