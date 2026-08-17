package sqlmap

import (
	"regexp"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImage_DigestPinFormat verifies Image const matches the canonical
// digest-pin format per ADR-026 risk #14 + Phase 0 v2 V1 lock.
// Format: <repo>:<tag>@sha256:<64-hex>.
func TestImage_DigestPinFormat(t *testing.T) {
	re := regexp.MustCompile(`^parrotsec/sqlmap:latest@sha256:[0-9a-f]{64}$`)
	assert.Regexp(t, re, Image, "Image must match parrotsec/sqlmap:latest@sha256:<64-hex> per Phase 0 v2 V1 lock")
}

// TestPoolMaxSize_Q8Lock verifies PoolMaxSize=4 cross-consumer
// convention per Q8 (a) matching Nmap + Trivy precedents.
func TestPoolMaxSize_Q8Lock(t *testing.T) {
	assert.Equal(t, 4, PoolMaxSize, "PoolMaxSize=4 per Q8 (a) cross-consumer convention")
}

// TestRunnerTimeout_30Min verifies framework-default 30-minute timeout
// per ADR-026 + Q8 (a) lock.
func TestRunnerTimeout_30Min(t *testing.T) {
	assert.Equal(t, 30*time.Minute, RunnerTimeout, "RunnerTimeout matches framework default per ADR-026")
}

// TestNewPool_RequiresClient verifies nil client error per framework
// contract (mirrors Nmap + Trivy precedent).
func TestNewPool_RequiresClient(t *testing.T) {
	_, err := NewPool(nil, "test-worker", zerolog.Nop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker client required")
}

// TestNewRunner_Shape verifies DockerRunner field population per
// Drift #28 W1 (a) ToolCategory="dast" + Q1-Q9 architectural locks.
// Pool reference nil is acceptable for shape-only assertions; integration
// test exercises real-pool construction separately.
func TestNewRunner_Shape(t *testing.T) {
	runner := NewRunner(nil, zerolog.Nop())
	require.NotNil(t, runner)
	assert.Equal(t, "sqlmap", runner.ToolName, "Q9 (a) canonical tool name")
	assert.Equal(t, "dast", runner.ToolCategory,
		"Drift #28 W1 (a) lock: ToolCategory=\"dast\" (NOT \"injection\" per ToolRunner.Category() enum constraint)")
	assert.False(t, runner.ExitCodeLenient,
		"SQLMap exit-0-on-clean canonical (deviates from Trivy ExitCodeLenient:true)")
	assert.Equal(t, RunnerTimeout, runner.Timeout)
	assert.NotNil(t, runner.BuildArgs, "buildArgs function reference required")
	assert.NotNil(t, runner.ParseOutput, "parseSQLMapOutput function reference required (direct signature match per Group 1 closure)")
}

// TestNewRunner_NameMethod verifies the ToolRunner.Name() contract
// returns the configured ToolName ("sqlmap").
func TestNewRunner_NameMethod(t *testing.T) {
	runner := NewRunner(nil, zerolog.Nop())
	assert.Equal(t, "sqlmap", runner.Name())
}

// TestNewRunner_CategoryMethod verifies the ToolRunner.Category()
// contract returns "dast" per Drift #28 W1 (a) lock.
func TestNewRunner_CategoryMethod(t *testing.T) {
	runner := NewRunner(nil, zerolog.Nop())
	assert.Equal(t, "dast", runner.Category())
}
