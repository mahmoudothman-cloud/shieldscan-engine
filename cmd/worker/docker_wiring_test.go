package main

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildDockerRegistry_IncludesZap pins that the ZAP DAST service runner is
// wired into the docker registry map (the fix that takes full_web from 5/6 to
// 6/6 — the worker previously had no "zap" runner, so registry.Get("zap")
// errored). Registration is construction-only (no Docker daemon contact — the
// SDK client + warm pools are lazy), so this runs without Docker.
func TestBuildDockerRegistry_IncludesZap(t *testing.T) {
	t.Setenv("SHIELDSCAN_ZAP_API_KEY", "test-key")
	runners, _, err := buildDockerRegistry("test-worker", zerolog.Nop())
	require.NoError(t, err)

	zapRunner, ok := runners["zap"]
	require.True(t, ok, "docker registry must include the zap engine")
	assert.Equal(t, "zap", zapRunner.Name())
	assert.Equal(t, "dast", zapRunner.Category())
}

// TestBuildDockerRegistry_ZapRegistersWithoutAPIKey pins the "warn + register"
// decision: a missing SHIELDSCAN_ZAP_API_KEY must NOT drop zap from the
// registry (that would recreate the "no runner registered" confusion) nor fail
// startup (that would break the other 12 engines over one optional tool). zap
// stays present; a missing key then surfaces as the explicit per-scan
// "zap: APIKey required" error.
func TestBuildDockerRegistry_ZapRegistersWithoutAPIKey(t *testing.T) {
	t.Setenv("SHIELDSCAN_ZAP_API_KEY", "")
	runners, _, err := buildDockerRegistry("test-worker", zerolog.Nop())
	require.NoError(t, err)

	_, ok := runners["zap"]
	assert.True(t, ok, "zap must remain registered even without an API key (warn + register)")
}
