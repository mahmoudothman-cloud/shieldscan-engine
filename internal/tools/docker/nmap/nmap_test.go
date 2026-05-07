package nmap

import (
	"testing"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImage_HasDigestPin(t *testing.T) {
	assert.Contains(t, Image, "@sha256:", "Image must have digest pin per ADR-006 risk #14")
	assert.Contains(t, Image, "instrumentisto/nmap:7.94", "Image must reference instrumentisto/nmap version tag")
}

func TestPoolMaxSize_Q9Lock(t *testing.T) {
	assert.Equal(t, 4, PoolMaxSize, "MaxSize 4 per Q9 brainstorming lock")
}

func TestRunnerTimeout_FrameworkDefault(t *testing.T) {
	assert.Equal(t, 30*time.Minute, RunnerTimeout, "30min matches docker.DefaultDockerTimeout per ADR-026")
}

func TestNewPool_RequiresClient(t *testing.T) {
	_, err := NewPool(nil, zerolog.Nop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker client required")
}

// newTestPool constructs a stub-backed WarmPool for nmap_test.go unit
// tests. Mirrors the pattern from internal/tools/docker/dockerrunner_test.go
// (newTestRunner) — stub satisfies docker.dockerClient structurally.
func newTestPool(t *testing.T) *docker.WarmPool {
	t.Helper()
	pool, err := docker.New(docker.Config{
		Image:       Image,
		MaxSize:     PoolMaxSize,
		Cleanup:     docker.NoCleanup,
		HealthCheck: nil,
	}, newStubDockerClient(t), zerolog.Nop())
	require.NoError(t, err)
	return pool
}

func TestNewRunner_FieldsPopulated(t *testing.T) {
	runner := NewRunner(newTestPool(t), zerolog.Nop())
	require.NotNil(t, runner)
	assert.Equal(t, "nmap", runner.ToolName)
	assert.Equal(t, "recon", runner.ToolCategory)
	assert.NotNil(t, runner.Pool)
	assert.NotNil(t, runner.BuildArgs)
	assert.NotNil(t, runner.ParseOutput)
	assert.False(t, runner.ExitCodeLenient, "Nmap exits 0 on successful scan; non-zero is real failure")
	assert.Equal(t, RunnerTimeout, runner.Timeout)
}

func TestNewRunner_NameMethod(t *testing.T) {
	runner := NewRunner(newTestPool(t), zerolog.Nop())
	assert.Equal(t, "nmap", runner.Name())
}

func TestNewRunner_CategoryMethod(t *testing.T) {
	runner := NewRunner(newTestPool(t), zerolog.Nop())
	assert.Equal(t, "recon", runner.Category())
}

func TestBuildArgsAdapter_ReturnsArgsOnSuccess(t *testing.T) {
	args := buildArgsAdapter(tools.Target{URL: "example.com"}, tools.ScanConfig{})
	require.NotNil(t, args)
	assert.Equal(t, "nmap", args[0])
	assert.Equal(t, "example.com", args[len(args)-1])
}

func TestBuildArgsAdapter_ReturnsNilOnError(t *testing.T) {
	// 127.0.0.1 fails Layer 3 validation; adapter swallows error → nil args
	args := buildArgsAdapter(tools.Target{URL: "127.0.0.1"}, tools.ScanConfig{})
	assert.Nil(t, args, "validation error → adapter returns nil per DockerRunner BuildArgs contract")
}

func TestParseOutputForDocker_AdaptsToFrameworkSignature(t *testing.T) {
	// Minimal valid Nmap XML with one open port
	xml := []byte(`<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.99" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>`)

	findings, err := parseOutputForDocker(xml)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	// target empty per Phase 3 contract (DockerRunner.ParseOutput
	// signature has no target parameter; forward-pin documented in
	// nmap.go parseOutputForDocker docstring)
	assert.Equal(t, "", findings[0].Metadata["target"])
}
