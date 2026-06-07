package trivy

import (
	"context"
	"strings"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/source"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/rs/zerolog"
)

// newSentinelPool returns a non-nil but otherwise empty *docker.WarmPool
// for tests that exercise FsSourceRunner construction and pre-delegation
// guards (Name / Category / ScanID guard). These tests never reach the
// pool's checkout path; a zero-valued struct is sufficient. Real
// pool-driven coverage lives in integration_test.go.
func newSentinelPool(_ *testing.T) *docker.WarmPool {
	return &docker.WarmPool{}
}

// TestNewFsSourceRunner_RejectsNilPool verifies the construction
// guard. Wiring (cmd/worker/docker_wiring.go) should always pass a
// non-nil pool; this guard catches programmer error.
func TestNewFsSourceRunner_RejectsNilPool(t *testing.T) {
	staging, _ := source.NewStagingManager("/tmp")
	_, err := NewFsSourceRunner(nil, staging, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "pool required") {
		t.Fatalf("expected pool-required error; got %v", err)
	}
}

// TestNewFsSourceRunner_RejectsNilStagingMgr verifies the staging-
// manager construction guard.
func TestNewFsSourceRunner_RejectsNilStagingMgr(t *testing.T) {
	// Sentinel pool — never invoked thanks to the staging-nil guard.
	pool := newSentinelPool(t)
	_, err := NewFsSourceRunner(pool, nil, zerolog.Nop())
	if err == nil || !strings.Contains(err.Error(), "stagingMgr required") {
		t.Fatalf("expected stagingMgr-required error; got %v", err)
	}
}

// TestFsSourceRunner_NameAndCategory verifies the shim delegates
// Name + Category to the inner DockerRunner. Preserves the
// registry-key + RawFinding-enrichment contract.
func TestFsSourceRunner_NameAndCategory(t *testing.T) {
	pool := newSentinelPool(t)
	staging, _ := source.NewStagingManager("/tmp")
	runner, err := NewFsSourceRunner(pool, staging, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewFsSourceRunner: %v", err)
	}
	if runner.Name() != "trivy-fs" {
		t.Fatalf("Name(): got %q, want %q", runner.Name(), "trivy-fs")
	}
	if runner.Category() != "sca" {
		t.Fatalf("Category(): got %q, want %q", runner.Category(), "sca")
	}
}

// TestFsSourceRunner_RejectsMissingScanIDWhenSourceURLPresent
// verifies the ScanID guard surfaces a clean error rather than
// silently producing a corrupt staging path. ScanID is normally
// threaded by jobDispatchToTarget from JobDispatch.ScanID; a missing
// value indicates a misconfigured wire emission or a direct-Run
// caller that skipped processor enrichment.
func TestFsSourceRunner_RejectsMissingScanIDWhenSourceURLPresent(t *testing.T) {
	pool := newSentinelPool(t)
	staging, _ := source.NewStagingManager(t.TempDir())
	runner, err := NewFsSourceRunner(pool, staging, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewFsSourceRunner: %v", err)
	}
	_, runErr := runner.Run(
		context.Background(),
		tools.Target{
			TargetType:    "source",
			SourceRepoURL: "https://github.com/OWASP/NodeGoat.git",
			// ScanID intentionally empty
		},
		tools.ScanConfig{},
	)
	if runErr == nil || !strings.Contains(runErr.Error(), "ScanID required") {
		t.Fatalf("expected ScanID-required error; got %v", runErr)
	}
}
