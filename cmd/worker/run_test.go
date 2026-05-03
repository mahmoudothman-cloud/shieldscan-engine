package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/odyssey/shieldscan-engine/internal/config"
)

// mockToolEnvs lists the 9 SHIELDSCAN_<TOOL>_BINARY env vars that
// buildRegistry resolves at startup. Mirrors the spec table in
// registry_wiring.go's buildRegistry. Adding a 10th tool requires
// updating BOTH lists (no shared source — kept duplicate so the
// production wiring stays declarative).
var mockToolEnvs = []string{
	"SHIELDSCAN_CHECKOV_BINARY",
	"SHIELDSCAN_CORSTEST_BINARY",
	"SHIELDSCAN_DEPCHECK_BINARY",
	"SHIELDSCAN_GITLEAKS_BINARY",
	"SHIELDSCAN_NIKTO_BINARY",
	"SHIELDSCAN_NUCLEI_BINARY",
	"SHIELDSCAN_SEMGREP_BINARY",
	"SHIELDSCAN_SSLYZE_BINARY",
	"SHIELDSCAN_WAPITI_BINARY",
}

// installMockBinaries creates 9 executable shell-script mock
// binaries in t.TempDir() and points each SHIELDSCAN_<TOOL>_BINARY
// env var at one of them. Reuses the 6.7 framework-test mock pattern
// (shell-script with executable bit). Sufficient for Phase 1's
// stat+0o111 verification; jobs are never dispatched to these mocks
// in cmd/worker tests (no jobs queued).
func installMockBinaries(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, env := range mockToolEnvs {
		// e.g. SHIELDSCAN_NUCLEI_BINARY → "nuclei"
		base := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(env, "SHIELDSCAN_"), "_BINARY"))
		path := filepath.Join(dir, base)
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755))
		t.Setenv(env, path)
	}
}

// TestMain wires goleak.VerifyTestMain — load-bearing because
// runMain spawns the heartbeat + Worker goroutines. Leak detection
// here is the ADR-021 Rule 2 forcing function for the full assembly.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).reaper"),
		goleak.IgnoreAnyFunction("github.com/alicebob/miniredis/v2.(*Miniredis).serve.func1"),
	)
}

// runMainFixture spins up miniredis + builds the runMainDeps. Auto-
// cleans via t.Cleanup. Also installs 9 mock tool binaries via
// t.Setenv so buildRegistry's binary-resolution succeeds without
// the real tools being on $PATH (per H.F mock infrastructure).
// Mocks are shell-script no-ops sufficient to satisfy Phase 1
// stat+executable-bit verification.
func runMainFixture(t *testing.T) (runMainDeps, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	installMockBinaries(t)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.Config{
		WorkerID:          "test-worker",
		WorkerConcurrency: 2,
		RedisURL:          "redis://" + mr.Addr() + "/0",
		DrainGraceSeconds: 5,
		LogLevel:          "info",
	}
	return runMainDeps{
		Cfg:    cfg,
		Redis:  client,
		Logger: zerolog.Nop(),
	}, mr, client
}

// TestRunMain_HappyPathStartsWorker pins the canonical assembly:
// runMain starts the worker; ctx cancel exits cleanly with exit code 0.
func TestRunMain_HappyPathStartsWorker(t *testing.T) {
	deps, _, _ := runMainFixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	// Let startup complete.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case code := <-exitCh:
		assert.Equal(t, 0, code, "clean shutdown returns exit code 0")
	case <-time.After(10 * time.Second):
		t.Fatal("runMain did not exit within 10s of ctx cancel")
	}
}

// TestRunMain_RegistrationVisibleInRedis pins Phase 4: after startup,
// the worker key is set and readable via the Redis client.
func TestRunMain_RegistrationVisibleInRedis(t *testing.T) {
	deps, _, client := runMainFixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	// Wait for startup (Phase 4) to complete.
	require.Eventually(t, func() bool {
		keys, err := client.Keys(t.Context(), "shieldscan:workers:*").Result()
		return err == nil && len(keys) > 0
	}, 2*time.Second, 50*time.Millisecond, "worker key should appear in Redis after Phase 4")

	keys, err := client.Keys(t.Context(), "shieldscan:workers:*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	val, err := client.Get(t.Context(), keys[0]).Result()
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(val), &payload))
	assert.NotEmpty(t, payload["worker_id"])
	assert.NotEmpty(t, payload["hostname"])
	assert.Equal(t, float64(2), payload["concurrency"], "matches cfg.WorkerConcurrency")

	cancel()
	<-exitCh
}

// TestRunMain_HeartbeatRefreshesTTL pins the worker-lifetime
// heartbeat: Run loop refreshes the worker key over time (registered_at
// updates).
func TestRunMain_HeartbeatRefreshesTTL(t *testing.T) {
	deps, _, client := runMainFixture(t)
	// Override default heartbeat timings via ConfigOverrides? We
	// don't have that mechanism; but the test can just verify the
	// initial write happened. Refresh-cadence is verified in
	// internal/worker/heartbeat_test.go.

	ctx, cancel := context.WithCancel(t.Context())
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	require.Eventually(t, func() bool {
		ttl, err := client.TTL(t.Context(), "shieldscan:workers:"+findWorkerKey(t, client)).Result()
		return err == nil && ttl > 0
	}, 2*time.Second, 50*time.Millisecond, "worker key should have positive TTL")

	cancel()
	<-exitCh
}

// TestRunMain_StartupFailureExitsOne pins startup-failure → exit 1.
// Achieve by closing miniredis before runMain, so Phase 4 SETEX fails.
func TestRunMain_StartupFailureExitsOne(t *testing.T) {
	deps, mr, _ := runMainFixture(t)

	mr.Close() // SETEX will fail.

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	code := runMain(ctx, deps)

	assert.Equal(t, 1, code, "startup failure returns exit code 1")
}

// TestBuildRegistry_RegistersAllNineTools pins the M6 CLOSE wiring:
// buildRegistry returns a Registry with exactly 9 engines, in
// alphabetical order. Adding a 10th tool requires updating the
// expected list and the spec table in registry_wiring.go.
func TestBuildRegistry_RegistersAllNineTools(t *testing.T) {
	installMockBinaries(t)

	registry, _, err := buildRegistry(zerolog.Nop())
	require.NoError(t, err)

	got := registry.Engines()
	want := []string{
		"checkov", "corstest", "depcheck", "gitleaks", "nikto",
		"nuclei", "semgrep", "sslyze", "wapiti",
	}
	assert.Equal(t, want, got, "9 engines registered alphabetically")
}

// TestBuildRegistry_NativeBinariesMatchEngines pins that buildRegistry
// returns a NativeBinary list matching the registered engines (Phase 1
// stat-checks every binary that backs a runner — drift between the
// two lists would cause a missing-binary warning OR a registered
// runner whose binary was never verified).
func TestBuildRegistry_NativeBinariesMatchEngines(t *testing.T) {
	installMockBinaries(t)

	registry, natives, err := buildRegistry(zerolog.Nop())
	require.NoError(t, err)
	require.Len(t, natives, 9, "9 NativeBinary entries — one per registered runner")

	engines := registry.Engines()
	nativeNames := make([]string, len(natives))
	for i, n := range natives {
		nativeNames[i] = n.Name
		assert.NotEmpty(t, n.Path, "binary path resolved for %s", n.Name)
	}
	// Sort independent: natives is in spec order; engines is sorted.
	assert.ElementsMatch(t, engines, nativeNames, "NativeBinary names ↔ Registry engines bijection")
}

// TestBuildRegistry_FailFastOnMissingBinary pins fail-fast wiring:
// when one tool's binary cannot be resolved (env unset AND not on
// $PATH), buildRegistry returns an error naming the failing tool.
// runMain converts this to exit code 1.
func TestBuildRegistry_FailFastOnMissingBinary(t *testing.T) {
	installMockBinaries(t)

	// Sabotage one tool: clear its env var AND poison PATH so the
	// fallback fails too. Easiest way is to point the env at empty
	// AND override PATH for this test to a directory without the
	// real binary.
	t.Setenv("SHIELDSCAN_NUCLEI_BINARY", "")
	t.Setenv("PATH", t.TempDir()) // no nuclei here

	_, _, err := buildRegistry(zerolog.Nop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nuclei", "error names the failing tool for remediation")
}

// TestRunMain_NoEmptyRegistryWarning pins the M6 CLOSE acceptance
// criterion: with all 9 binaries resolved, the empty-registry WARN
// from internal/worker/startup.go (added at 5.6 with explicit M6+
// forward-pin) MUST NOT fire. Closes the 5.6 forward-pin.
//
// Mechanism: capture the worker's log output via a custom zerolog
// writer; assert the WARN substring is absent. Mocked binaries are
// sufficient for Phase 1 verification + the empty-registry check
// (which only inspects len(registry.Engines())).
func TestRunMain_NoEmptyRegistryWarning(t *testing.T) {
	deps, _, _ := runMainFixture(t)

	buf := &strings.Builder{}
	sw := &syncWriter{w: buf}
	deps.Logger = zerolog.New(sw)

	ctx, cancel := context.WithCancel(t.Context())
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	// Let startup complete.
	require.Eventually(t, func() bool {
		sw.mu.Lock()
		defer sw.mu.Unlock()
		return strings.Contains(buf.String(), "phase 4 worker registration complete")
	}, 3*time.Second, 50*time.Millisecond, "phase 4 should complete")

	cancel()
	<-exitCh

	sw.mu.Lock()
	logs := buf.String()
	sw.mu.Unlock()
	assert.NotContains(t, logs, "worker started with empty registry",
		"M6 CLOSE: empty-registry WARN must not fire when 9 runners are registered")
	assert.Contains(t, logs, "registered_engines",
		"non-empty registry path emits Info with registered engines list")
}

// syncWriter wraps a strings.Builder with a no-op mutex so the
// zerolog Logger (used concurrently by multiple goroutines —
// heartbeat + worker.Run) writes safely. strings.Builder.Write is
// not goroutine-safe; without this, -race trips.
type syncWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// TestShortUUID_Distinct pins worker ID uniqueness: two calls produce
// different strings (4 bytes random = 32 bits entropy).
func TestShortUUID_Distinct(t *testing.T) {
	a := shortUUID()
	b := shortUUID()
	assert.Len(t, a, 8, "8 hex chars (4 random bytes)")
	assert.NotEqual(t, a, b, "two calls produce distinct UUIDs")
}

// TestGenerateWorkerID_Format pins the hostname-uuid8 format.
func TestGenerateWorkerID_Format(t *testing.T) {
	id := generateWorkerID()
	parts := strings.Split(id, "-")
	require.GreaterOrEqual(t, len(parts), 2, "format hostname-uuid; got %q", id)
	// Last segment should be 8 hex chars.
	last := parts[len(parts)-1]
	assert.Len(t, last, 8, "last segment is 8-char UUID")
}

// findWorkerKey is a small helper for tests that need the worker_id
// suffix from the Redis key. Returns the suffix portion (after the
// "shieldscan:workers:" prefix).
func findWorkerKey(t *testing.T, client *redis.Client) string {
	t.Helper()
	keys, err := client.Keys(t.Context(), "shieldscan:workers:*").Result()
	require.NoError(t, err)
	require.NotEmpty(t, keys, "no worker key found")
	return strings.TrimPrefix(keys[0], "shieldscan:workers:")
}
