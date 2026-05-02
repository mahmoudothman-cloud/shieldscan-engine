// Package sslyze holds tests for the SSLyze native runner factory,
// parser, and plugin-rules dispatch.
//
// Test conventions per ../../../CLAUDE.md and ADR-021. Per-rule unit
// tests live in rules_test.go; this file covers construction +
// BuildArgs + parser-integration cases.
package sslyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", name)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath(t, name))
	require.NoError(t, err)
	return data
}

func noopLog() zerolog.Logger {
	return zerolog.New(nil).Level(zerolog.Disabled)
}

func testConfig() Config {
	return Config{BinaryPath: "/bin/echo"}
}

// ─── Construction (3) ────────────────────────────────────────────────

func TestNewSSLyzeRunner_IdentityFields(t *testing.T) {
	r := NewSSLyzeRunner(testConfig(), noopLog())
	assert.Equal(t, "sslyze", r.Name())
	assert.Equal(t, "ssl", r.Category(),
		"category 'ssl' (single-word, convention symmetry with sast/dast/secrets)")
}

// TestNewSSLyzeRunner_DefaultsApplied pins the load-bearing defaults:
// ExitCodeLenient=false (naturally-clean per pre-prep, 2nd instance
// after Nuclei) + Env contains PYTHONWARNINGS=ignore (defense-in-
// depth, 2nd instance after Semgrep).
func TestNewSSLyzeRunner_DefaultsApplied(t *testing.T) {
	r := NewSSLyzeRunner(testConfig(), noopLog())
	assert.Equal(t, 5*time.Minute, r.Timeout)
	assert.Equal(t, 50*1024*1024, r.MaxStdoutBytes)
	assert.False(t, r.ExitCodeLenient,
		"SSLyze is naturally-clean: exit 0 even with weak ciphers")
	assert.Contains(t, r.Env, "PYTHONWARNINGS=ignore",
		"defense-in-depth (2nd instance of Env pattern)")
}

// Compile-time interface assertion (per H.12 trim from 6.5).
var _ tools.ToolRunner = (*tools.NativeRunner)(nil)

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--json_out=-",
		"--certinfo",
		"--heartbleed",
		"--robot",
		"--openssl_ccs",
		"--reneg",
		"--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
		"--compression",
		"--fallback",
		"--ems",
	} {
		assert.Contains(t, joined, want, "missing required flag %q", want)
	}
}

// TestBuildArgs_NoRegularFlag pins the regression guard for the
// TOOL-ARCH §6.5 surgical patch: --regular is invalid in 6.1.0.
func TestBuildArgs_NoRegularFlag(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	assert.NotContains(t, strings.Join(args, " "), "--regular",
		"--regular is invalid in SSLyze 6.1.0 (TOOL-ARCH §6.5 patched at M6.4)")
}

// TestBuildArgs_TargetIsTrailing covers the per-target invocation
// shape (Option X). Target hostport derived from URL is the final
// positional argument.
func TestBuildArgs_TargetIsTrailing(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com:8443/some/path"},
		tools.ScanConfig{},
	)
	require.NotEmpty(t, args)
	last := args[len(args)-1]
	assert.Equal(t, "app.example.com:8443", last,
		"target as final positional, hostname:port derived from URL")
}

// ─── ParseOutput (5) ─────────────────────────────────────────────────

func TestParseOutput_ModernNoFindings(t *testing.T) {
	raw := readFixture(t, "sslyze_modern.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	assert.Empty(t, findings, "modern TLS config: 0 findings expected")
}

func TestParseOutput_WeakMultiFindings(t *testing.T) {
	raw := readFixture(t, "sslyze_weak.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)

	// weak fixture: TLS 1.0 supported + TLS 1.1 supported + no-EMS.
	require.Len(t, findings, 3,
		"3 findings: tls-1.0-supported + tls-1.1-supported + no-ems")

	// Severity distribution: 2 medium (protocols) + 1 low (EMS).
	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	assert.Equal(t, 2, sev["medium"])
	assert.Equal(t, 1, sev["low"])

	// TargetURL populated on every finding from server_location.
	for _, f := range findings {
		assert.Equal(t, "weak.example.com:443", f.TargetURL)
	}
}

func TestParseOutput_Empty(t *testing.T) {
	raw := readFixture(t, "sslyze_empty.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err, "empty server_scan_results MUST NOT error")
	assert.Empty(t, findings)
}

// TestParseOutput_ConnectivityFailedSkippedWithWarn pins H.4: per-
// server scan_status=ERROR_* is skipped with WARN log, batch
// continues. Drop silently — do NOT emit info finding.
func TestParseOutput_ConnectivityFailedSkippedWithWarn(t *testing.T) {
	raw := readFixture(t, "sslyze_connectivity_failed.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err, "ERROR_NO_CONNECTIVITY MUST NOT cause Go error")
	assert.Empty(t, findings, "no findings synthesized for failed scans")
}

// TestParseOutput_MalformedJSONFatal: top-level malformed JSON IS
// fatal. Matches Semgrep + Gitleaks posture.
func TestParseOutput_MalformedJSONFatal(t *testing.T) {
	garbage := []byte(`{"server_scan_results": [MALFORMED]`)
	_, err := parseOutput(noopLog())(garbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sslyze")
}
