package docker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopBuildArgs / noopParseOutput are the minimal closures most
// DockerRunner tests need (single-arg echo + empty parse).
func noopBuildArgs(_ tools.Target, _ tools.ScanConfig) []string {
	return []string{"echo"}
}

func noopParseOutput(_ []byte) ([]events.RawFinding, error) {
	return nil, nil
}

// newTestRunner constructs a DockerRunner with a stub-backed
// WarmPool suitable for unit tests. Callers can override BuildArgs /
// ParseOutput by setting fields after construction.
func newTestRunner(t *testing.T) *DockerRunner {
	t.Helper()
	return &DockerRunner{
		ToolName:     "test-tool",
		ToolCategory: "test-category",
		Pool:         newTestPool(t, Config{MaxSize: 2}),
		BuildArgs:    noopBuildArgs,
		ParseOutput:  noopParseOutput,
		Timeout:      5 * time.Second,
		Log:          noopLog(),
	}
}

// ─── Construction validation (3) ─────────────────────────────────────

func TestDockerRunner_Run_RequiresPool(t *testing.T) {
	r := &DockerRunner{
		ToolName:    "test-tool",
		BuildArgs:   noopBuildArgs,
		ParseOutput: noopParseOutput,
	}
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Pool required")
}

func TestDockerRunner_Run_RequiresBuildArgs(t *testing.T) {
	r := newTestRunner(t)
	r.BuildArgs = nil
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BuildArgs required")
}

func TestDockerRunner_Run_RequiresParseOutput(t *testing.T) {
	r := newTestRunner(t)
	r.ParseOutput = nil
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ParseOutput required")
}

// ─── Identity (2) ────────────────────────────────────────────────────

func TestDockerRunner_Name_ReturnsToolName(t *testing.T) {
	r := newTestRunner(t)
	r.ToolName = "trivy"
	assert.Equal(t, "trivy", r.Name())
}

func TestDockerRunner_Category_ReturnsCategory(t *testing.T) {
	r := newTestRunner(t)
	r.ToolCategory = "sca"
	assert.Equal(t, "sca", r.Category())
}

// ─── Compile-time interface compliance (1) ───────────────────────────

// TestDockerRunner_SatisfiesToolRunnerInterface verifies the
// compile-time `var _ tools.ToolRunner = (*DockerRunner)(nil)`
// assertion in dockerrunner.go holds with a real instance. The
// runtime assertions are belt-and-suspenders alongside the compile-
// time check; if the file-scope assertion ever fails, this test file
// also fails to compile, doubling the regression-guard surface.
func TestDockerRunner_SatisfiesToolRunnerInterface(t *testing.T) {
	r := newTestRunner(t)
	var _ tools.ToolRunner = r
	var _ tools.ToolRunner = (*DockerRunner)(nil)
	assert.Equal(t, r.ToolName, r.Name())
	assert.Equal(t, r.ToolCategory, r.Category())
}

// ─── Run lifecycle (5) ───────────────────────────────────────────────

func TestDockerRunner_Run_CallsBuildArgsWithTargetAndConfig(t *testing.T) {
	var capturedTarget tools.Target
	var capturedCfg tools.ScanConfig
	r := newTestRunner(t)
	r.BuildArgs = func(target tools.Target, cfg tools.ScanConfig) []string {
		capturedTarget = target
		capturedCfg = cfg
		return []string{"echo", "hello"}
	}

	target := tools.Target{URL: "https://example.com", TargetType: "web"}
	cfg := tools.ScanConfig{Depth: "standard", MaxRPS: 50}
	_, err := r.Run(context.Background(), target, cfg)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com", capturedTarget.URL,
		"BuildArgs receives the Target verbatim")
	assert.Equal(t, "standard", capturedCfg.Depth,
		"BuildArgs receives the ScanConfig verbatim")
	assert.Equal(t, 50, capturedCfg.MaxRPS)
}

func TestDockerRunner_Run_ReturnsParsedFindingsEnriched(t *testing.T) {
	// ParseOutput returns minimal findings; Run should enrich them
	// with ToolName, EngineCategory, DiscoveredAt, Fingerprint per
	// the ToolRunner contract (mirrors NativeRunner native.go:284-289).
	r := newTestRunner(t)
	r.ToolName = "trivy"
	r.ToolCategory = "sca"
	r.ParseOutput = func(_ []byte) ([]events.RawFinding, error) {
		return []events.RawFinding{
			{Title: "CVE-2024-1234", Severity: "high", FindingType: "cve"},
			{Title: "CVE-2024-5678", Severity: "medium", FindingType: "cve"},
		}, nil
	}

	findings, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, "trivy", f.ToolName, "ToolName enriched from runner")
		assert.Equal(t, "sca", f.EngineCategory, "EngineCategory enriched from runner")
		assert.NotEmpty(t, f.DiscoveredAt, "DiscoveredAt enriched (RFC3339)")
		assert.NotEmpty(t, f.Fingerprint, "Fingerprint enriched (computed)")
	}
}

func TestDockerRunner_Run_PropagatesParseError(t *testing.T) {
	r := newTestRunner(t)
	r.ParseOutput = func(_ []byte) ([]events.RawFinding, error) {
		return nil, errors.New("parse failed")
	}

	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestDockerRunner_Run_ReturnsContainerToPoolOnSuccess(t *testing.T) {
	r := newTestRunner(t)
	require.Equal(t, 0, r.Pool.Available(), "pool starts empty")

	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.NoError(t, err)

	// Synchronization: the Return runs in a defer; allow a brief
	// settle window before asserting.
	require.Eventually(t, func() bool {
		return r.Pool.Available() == 1
	}, 500*time.Millisecond, 10*time.Millisecond,
		"container should be returned to pool after Run")
}

func TestDockerRunner_Run_ReturnsContainerToPoolOnParseError(t *testing.T) {
	r := newTestRunner(t)
	r.ParseOutput = func(_ []byte) ([]events.RawFinding, error) {
		return nil, errors.New("parse failed")
	}

	_, _ = r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})

	require.Eventually(t, func() bool {
		return r.Pool.Available() == 1
	}, 500*time.Millisecond, 10*time.Millisecond,
		"container MUST be returned to pool even on parse error (defer pattern)")
}

// ─── Exit-code leniency (2) ──────────────────────────────────────────

// Note: Phase 3 stubDockerClient always returns exitCode=0 from
// ContainerExecInspect. To test non-zero exit code paths, swap to
// fakeClient (container_test.go) which allows configuring inspect
// response. Keeping these tests at the basic level here; per-tool
// tasks (Trivy, Nmap, SQLMap) exercise leniency-specific behavior
// via fakeClient.
//
// What we CAN test here is the validation path (no exit-code mock
// needed) and the default-strict posture (zero value).

func TestDockerRunner_ExitCodeLenient_DefaultStrict(t *testing.T) {
	r := newTestRunner(t)
	assert.False(t, r.ExitCodeLenient,
		"default-strict matches dominant 'exit-zero-on-clean' convention; "+
			"tools that don't follow it must opt in explicitly")
}

func TestDockerRunner_ExitCodeLenient_CanBeSet(t *testing.T) {
	r := newTestRunner(t)
	r.ExitCodeLenient = true
	// Compiles + assignable — sufficient pin for the field surface.
	assert.True(t, r.ExitCodeLenient)
}

// ─── Timeout precedence (3) ──────────────────────────────────────────

func TestDockerRunner_EffectiveTimeout_DefaultsToDockerDefault(t *testing.T) {
	r := newTestRunner(t)
	r.Timeout = 0
	got := r.effectiveTimeout(tools.ScanConfig{Timeout: 0})
	assert.Equal(t, DefaultDockerTimeout, got,
		"both zero → DefaultDockerTimeout (mirrors NativeRunner precedence)")
}

func TestDockerRunner_EffectiveTimeout_RunnerOverridesDefault(t *testing.T) {
	r := newTestRunner(t)
	r.Timeout = 7 * time.Minute
	got := r.effectiveTimeout(tools.ScanConfig{Timeout: 0})
	assert.Equal(t, 7*time.Minute, got,
		"DockerRunner.Timeout > 0 overrides default")
}

func TestDockerRunner_EffectiveTimeout_ScanConfigOverridesAll(t *testing.T) {
	r := newTestRunner(t)
	r.Timeout = 7 * time.Minute
	got := r.effectiveTimeout(tools.ScanConfig{Timeout: 120}) // seconds
	assert.Equal(t, 2*time.Minute, got,
		"cfg.Timeout > 0 (in seconds) overrides DockerRunner.Timeout")
}

// ─── Context safety (1) ──────────────────────────────────────────────

// TestDockerRunner_Run_DoesNotHangOnTimeout pins the ADR-021
// ctx-discipline contract: a sub-second timeout must not cause Run
// to hang. The exact return value (success vs ctx.DeadlineExceeded)
// depends on stub speed; either is acceptable as long as Run
// returns within bounded time.
func TestDockerRunner_Run_DoesNotHangOnTimeout(t *testing.T) {
	r := newTestRunner(t)
	r.Timeout = 1 * time.Microsecond

	done := make(chan struct{})
	go func() {
		_, _ = r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
		close(done)
	}()

	select {
	case <-done:
		// completed within bound — pass
	case <-time.After(2 * time.Second):
		t.Fatal("Run hung past timeout — ADR-021 ctx-discipline broken")
	}
}
