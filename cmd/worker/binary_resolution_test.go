package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveBinary_EnvVarTakesPrecedence pins Pattern 2 precedence:
// SHIELDSCAN_<TOOL>_BINARY env var wins over $PATH lookup. Mirrors
// the recon helper's resolveBinary contract (12th + 13th instance
// of the pattern; 2nd-instance at different layer per H.E).
func TestResolveBinary_EnvVarTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	mockPath := filepath.Join(dir, "mocknuclei")
	require.NoError(t, os.WriteFile(mockPath, []byte("#!/bin/sh\n"), 0o755))

	t.Setenv("SHIELDSCAN_NUCLEI_BINARY", mockPath)

	got, err := resolveBinary("SHIELDSCAN_NUCLEI_BINARY", "nuclei")
	require.NoError(t, err)
	assert.Equal(t, mockPath, got, "env var path returned verbatim")
}

// TestResolveBinary_PathFallback pins the exec.LookPath fallback when
// the env var is empty. Uses "sh" which is reliably on $PATH for any
// Unix CI environment.
func TestResolveBinary_PathFallback(t *testing.T) {
	t.Setenv("SHIELDSCAN_FAKE_BINARY", "")

	got, err := resolveBinary("SHIELDSCAN_FAKE_BINARY", "sh")
	require.NoError(t, err)
	assert.NotEmpty(t, got)
	assert.True(t, strings.HasSuffix(got, "/sh"), "exec.LookPath returns absolute path; got %q", got)
}

// TestResolveBinary_FailFastOnMissing pins fail-fast: when env var is
// empty AND the binary is not on $PATH, resolveBinary returns an
// actionable error mentioning both remediation paths.
func TestResolveBinary_FailFastOnMissing(t *testing.T) {
	t.Setenv("SHIELDSCAN_DEFINITELY_NOT_REAL_BINARY", "")

	_, err := resolveBinary("SHIELDSCAN_DEFINITELY_NOT_REAL_BINARY", "definitely-not-a-real-binary-9f8e7d6c")
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "SHIELDSCAN_DEFINITELY_NOT_REAL_BINARY", "error names env var for remediation")
	assert.Contains(t, msg, "definitely-not-a-real-binary-9f8e7d6c", "error names tool for context")
	assert.Contains(t, msg, "PATH", "error mentions $PATH fallback")
}

// TestResolveBinary_EmptyEnvFallsThroughToPath pins that an empty
// (set-but-blank) env var is treated as "unset" and we fall through
// to exec.LookPath. Matches recon.resolveBinary semantics.
func TestResolveBinary_EmptyEnvFallsThroughToPath(t *testing.T) {
	t.Setenv("SHIELDSCAN_EMPTY_BINARY", "")

	got, err := resolveBinary("SHIELDSCAN_EMPTY_BINARY", "sh")
	require.NoError(t, err)
	assert.NotEmpty(t, got, "empty env falls through to PATH lookup")
}
