package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// stubDockerService is a dockerHealthChecker for startup tests.
type stubDockerService struct {
	name      string
	healthErr error
}

func (s *stubDockerService) Name() string { return s.name }
func (s *stubDockerService) HealthCheck(_ context.Context) error {
	return s.healthErr
}

// newStartupFixture wires Startup with a Heartbeat backed by miniredis.
// Empty registry by default (5.6 baseline); tests that need populated
// engines pass via the registry param.
func newStartupFixture(t *testing.T, registry *Registry, native []NativeBinary, docker []dockerHealthChecker) (*Startup, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	hb := NewHeartbeat(client, "worker-startup-01", map[string]any{
		"hostname": "test.local",
	}, zerolog.Nop())

	if registry == nil {
		registry = NewRegistry(map[string]tools.ToolRunner{})
	}
	s := NewStartup(StartupDeps{
		Registry:    registry,
		NativeTools: native,
		DockerSvcs:  docker,
		Heartbeat:   hb,
		Logger:      zerolog.Nop(),
	})
	return s, client
}

// TestStartup_RunEmptyRegistrySucceeds pins the 5.6 default behavior:
// empty registry, no native tools, no docker services → Phases 1+2
// no-op; Phase 4 writes worker key successfully.
func TestStartup_RunEmptyRegistrySucceeds(t *testing.T) {
	s, client := newStartupFixture(t, nil, nil, nil)

	require.NoError(t, s.Run(t.Context()))

	// Phase 4 produced the registration entry.
	val, err := client.Get(t.Context(), "shieldscan:workers:worker-startup-01").Result()
	require.NoError(t, err)
	assert.Contains(t, val, "worker-startup-01")
}

// TestStartup_RegistrationFailureFatal pins Phase 4 fail-fast: if the
// Heartbeat WriteOnce fails (Redis unreachable), Run returns an error.
func TestStartup_RegistrationFailureFatal(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	hb := NewHeartbeat(client, "worker-fail", map[string]any{}, zerolog.Nop())
	s := NewStartup(StartupDeps{
		Registry:  NewRegistry(map[string]tools.ToolRunner{}),
		Heartbeat: hb,
		Logger:    zerolog.Nop(),
	})

	// Close miniredis so SETEX fails.
	mr.Close()

	err := s.Run(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "phase 4 worker registration")
}

// TestStartup_NativeBinaryWarnLogsButProceeds pins Phase 1 fail-soft.
// With a missing binary path configured, Phase 1 logs a warning but
// Run continues to Phase 4 and registers the worker.
func TestStartup_NativeBinaryWarnLogsButProceeds(t *testing.T) {
	native := []NativeBinary{
		{Name: "nonexistent", Path: "/usr/local/bin/this-binary-does-not-exist"},
	}
	s, client := newStartupFixture(t, nil, native, nil)

	// Should NOT error despite missing binary.
	require.NoError(t, s.Run(t.Context()))

	// Phase 4 still ran (worker registered).
	val, err := client.Get(t.Context(), "shieldscan:workers:worker-startup-01").Result()
	require.NoError(t, err)
	assert.NotEmpty(t, val)
}

// TestStartup_DockerServiceUnreachableWarnLogsButProceeds pins Phase
// 2 fail-soft. Stub service reports HealthCheck error; Run continues
// to Phase 4.
func TestStartup_DockerServiceUnreachableWarnLogsButProceeds(t *testing.T) {
	docker := []dockerHealthChecker{
		&stubDockerService{name: "mobsf", healthErr: errors.New("connection refused")},
	}
	s, client := newStartupFixture(t, nil, nil, docker)

	require.NoError(t, s.Run(t.Context()))

	val, err := client.Get(t.Context(), "shieldscan:workers:worker-startup-01").Result()
	require.NoError(t, err)
	assert.NotEmpty(t, val)
}

// TestStartup_NativeBinaryFoundLogsSuccess covers the inverse of the
// missing-binary case: a configured binary that DOES exist
// (/bin/echo, available on every POSIX system) verifies cleanly.
func TestStartup_NativeBinaryFoundLogsSuccess(t *testing.T) {
	// /bin/echo exists on Ubuntu CI.
	native := []NativeBinary{
		{Name: "echo", Path: "/bin/echo"},
	}
	s, _ := newStartupFixture(t, nil, native, nil)
	require.NoError(t, s.Run(t.Context()))
}

// TestStartup_NonExecutableBinaryWarns pins the second Phase 1
// failure mode: file exists but lacks execute permission. Creates
// a non-executable temp file and points Phase 1 at it.
func TestStartup_NonExecutableBinaryWarns(t *testing.T) {
	tmpdir := t.TempDir()
	notExec := filepath.Join(tmpdir, "not-executable")
	require.NoError(t, os.WriteFile(notExec, []byte("placeholder"), 0o644))

	native := []NativeBinary{{Name: "broken", Path: notExec}}
	s, _ := newStartupFixture(t, nil, native, nil)

	// Fail-soft: Run still succeeds.
	require.NoError(t, s.Run(t.Context()))
}
