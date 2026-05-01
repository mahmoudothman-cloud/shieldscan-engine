// Package buildguard holds cross-cutting test invariants that pin
// architectural commitments at the build-graph layer rather than by
// code review.
//
// Tests in this package are forcing functions for:
//   - ADR-013: cmd/worker/ MUST NOT import any PostgreSQL driver.
//   - ADR-016: go.mod MUST NOT depend on github.com/hibiken/asynq.
//   - ADR-021: goleak template demonstrates the ctx-discipline
//     forcing function used in test packages that spawn goroutines.
//
// If any test in this package fails, an architectural commitment has
// been violated. Read the failing test's docstring + the cited ADR
// before "fixing" by removing the assertion.
package buildguard

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// repoRoot returns the repository root, used as cwd for `go list`
// invocations so they resolve module-relative paths correctly.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// thisFile = .../shieldscan-engine/internal/buildguard/buildguard_test.go
	// repo root is three directories up.
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ""))
}

// TestWorkerBinary_DoesNotImportPostgresDriver pins ADR-013's
// forcing function: the cmd/worker/... build target MUST exclude
// every PostgreSQL driver. Workers communicate state changes via
// Redis events only; they never touch PostgreSQL.
//
// Verified via `go list -deps ./cmd/worker/...`. If a future change
// transitively introduces lib/pq or pgx into the worker dependency
// graph, this test fails immediately — the engineer is forced to
// either revert the import or escalate ADR-013 for revision.
func TestWorkerBinary_DoesNotImportPostgresDriver(t *testing.T) {
	// ADR-021 Rule 1: subprocess via exec.CommandContext.
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "./cmd/worker/...")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go list -deps failed: %s", string(out))

	deps := string(out)
	forbidden := []string{
		"github.com/lib/pq",
		"github.com/jackc/pgx",
		"database/sql",
	}
	for _, dep := range forbidden {
		assert.NotContains(t, deps, dep,
			"cmd/worker MUST NOT import %s (ADR-013 forcing function — workers do not touch PostgreSQL)",
			dep)
	}
}

// TestGoMod_ExcludesAsynq pins ADR-016's forcing function: the
// engine's dependency graph MUST NOT contain github.com/hibiken/asynq.
//
// ADR-016 dropped Asynq in favor of raw Redis LPUSH/BRPOP matching
// the M4 Python orchestrator's already-shipped dispatch path. The
// two protocols are not interoperable; mixing breaks the queue.
//
// Verified via `go list -m all`. If a future change introduces asynq
// transitively, this test catches it before the wire-protocol
// incompatibility manifests as runtime queue corruption.
func TestGoMod_ExcludesAsynq(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-m", "all")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go list -m all failed: %s", string(out))

	mods := string(out)
	assert.NotContains(t, mods, "github.com/hibiken/asynq",
		"asynq MUST NOT appear in dependency graph (ADR-016 — raw Redis matches M4 dispatch contract)")
}

// TestGoMod_ExcludesGlobalPostgresDriver verifies the engine's
// current dependency graph carries no PG driver at all. This is
// supplemental to TestWorkerBinary_DoesNotImportPostgresDriver: the
// per-binary check enforces the worker's exclusion specifically,
// while this check enforces the repo-wide absence as long as no
// other binary (e.g., cmd/admin/) needs DB access.
//
// When cmd/admin/ is created and legitimately needs lib/pq or pgx,
// this test will fail. At that point it should be removed or
// narrowed to "no DB driver in cmd/worker/'s closure" — but the
// per-binary buildguard above continues to enforce ADR-013.
func TestGoMod_ExcludesGlobalPostgresDriver(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-m", "all")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go list -m all failed: %s", string(out))

	mods := string(out)
	for _, mod := range []string{"github.com/lib/pq", "github.com/jackc/pgx"} {
		assert.NotContains(t, mods, mod,
			"%s MUST NOT appear in dependency graph until cmd/admin/ is added "+
				"(see DRIFT-LOG 2026-05-01 lib/pq removal entry; ADR-013 forcing function)",
			mod)
	}
}

// TestGoleakTemplate_DetectsLeak demonstrates that go.uber.org/goleak
// is correctly imported and operational. ADR-021 requires every test
// package that spawns goroutines to use goleak.VerifyTestMain(m); this
// test pins the import and proves the leak-detection primitive works.
//
// Implementation: spin a goroutine that's intentionally left running
// after the function returns, then run goleak.Find with a tight
// timeout. We expect goleak to detect the leak. Properly clean up by
// signaling the goroutine to exit so this test itself doesn't leak.
func TestGoleakTemplate_DetectsLeak(t *testing.T) {
	stop := make(chan struct{})
	leaked := make(chan struct{})
	go func() {
		defer close(leaked)
		<-stop
	}()

	// Defer cleanup BEFORE invoking goleak so that even if assertions
	// fail, the goroutine exits and TestMain's goleak check passes.
	defer func() {
		close(stop)
		<-leaked
	}()

	// goleak.Find returns nil when no leaks are detected. With our
	// goroutine deliberately blocked on `stop`, it should detect a leak.
	// We use a tight timeout to keep the test fast.
	err := goleak.Find(
		goleak.IgnoreTopFunction("testing.(*M).Run"),
		goleak.IgnoreCurrent(),
	)
	// Restore: we want a leak detected here. IgnoreCurrent snapshots
	// goroutines existing at call time, so it would mask our leak.
	// Re-run without IgnoreCurrent to actually detect.
	_ = err
	err = goleak.Find()
	assert.Error(t, err, "goleak should detect the deliberately-leaked goroutine")
	assert.Contains(t, err.Error(), "goroutine",
		"goleak error should describe the leaked goroutine")
}

// TestMain wires goleak.VerifyTestMain as the package-wide forcing
// function for ADR-021 ctx-discipline. Any test in this package that
// leaks a goroutine fails the suite. Serves as the template for
// 5.2-5.6 test packages that spawn goroutines.
//
// IgnoreTopFunction entries here are for known-OK background workers
// that the Go runtime or imported libraries spawn at TestMain time.
// Add new entries only after verifying the goroutine is benign + cite
// the source.
func TestMain(m *testing.M) {
	// Touch context to keep the import live in test packages that
	// transitively reference ctx-discipline patterns. context is the
	// load-bearing primitive ADR-021 enforces.
	_ = context.Background()

	// Add goleak.IgnoreTopFunction(...) entries as benign goroutines
	// are discovered. None expected at 5.1 because the buildguard
	// suite spawns no real goroutines (the leak-detection demo cleans
	// itself up via its own defer). Tasks 5.2-5.6 will accumulate
	// IgnoreTopFunction entries for go-redis pool reapers, etc.
	goleak.VerifyTestMain(m)
}
