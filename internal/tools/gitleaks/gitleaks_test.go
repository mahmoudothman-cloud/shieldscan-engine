// Package gitleaks holds tests for the Gitleaks native runner factory
// and closures. Test conventions per ../../../CLAUDE.md and ADR-021.
package gitleaks

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

// TestMain wires goleak per ADR-021. Gitleaks runner spawns no
// goroutines of its own.
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

// ─── Construction (2; ReturnsToolRunner trimmed per H.12) ────────────

func TestNewGitleaksRunner_IdentityFields(t *testing.T) {
	r := NewGitleaksRunner(testConfig(), noopLog())
	assert.Equal(t, "gitleaks", r.Name())
	assert.Equal(t, "secrets", r.Category())
}

// TestNewGitleaksRunner_DefaultsApplied pins the load-bearing
// defaults: ExitCodeLenient=false (configuration-not-leniency at
// flag level via --exit-code=0) + Env=nil (Go binary; no warnings to
// suppress, contrast with M6.2 Semgrep).
func TestNewGitleaksRunner_DefaultsApplied(t *testing.T) {
	r := NewGitleaksRunner(testConfig(), noopLog())
	assert.Equal(t, 5*time.Minute, r.Timeout)
	assert.Equal(t, 50*1024*1024, r.MaxStdoutBytes)
	assert.False(t, r.ExitCodeLenient,
		"Gitleaks uses configuration-not-leniency: --exit-code=0 forces "+
			"clean tool exit, runner stays strict")
	assert.Nil(t, r.Env,
		"Go-built binary; no Python warnings to suppress (asymmetric "+
			"with M6.2 Semgrep which sets PYTHONWARNINGS=ignore)")
}

// Compile-time interface assertion replaces the runtime
// TestNewGitleaksRunner_ReturnsToolRunner test (per H.12 trim).
var _ tools.ToolRunner = (*tools.NativeRunner)(nil)

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"detect",
		"--source=/src/repo",
		"--report-format=json",
		"--report-path=/dev/stdout",
		"--exit-code=0",
		"--no-banner",
	} {
		assert.Contains(t, joined, want, "missing required flag/arg %q", want)
	}
}

// TestBuildArgs_ExitCodeZeroPresent is the configuration-not-leniency
// regression guard. If a future change removes --exit-code=0 without
// updating ExitCodeLenient, Gitleaks would fail every job that finds
// secrets (default exit code is 1 on findings).
func TestBuildArgs_ExitCodeZeroPresent(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	assert.Contains(t, strings.Join(args, " "), "--exit-code=0",
		"configuration-not-leniency invariant: --exit-code=0 MUST be present")
}

func TestBuildArgs_SourcePathFromTarget(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/some/path"},
		tools.ScanConfig{},
	)
	assert.Contains(t, strings.Join(args, " "), "--source=/some/path")
}

// ─── ParseOutput (8) ─────────────────────────────────────────────────

func TestParseOutput_BasicSingleFinding(t *testing.T) {
	raw := readFixture(t, "gitleaks_basic.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.NotEmpty(t, f.FindingType, "FindingType from RuleID")
	assert.NotEmpty(t, f.CodeFile, "CodeFile from File")
	assert.NotZero(t, f.CodeLine, "CodeLine from StartLine")
	assert.Equal(t, SeverityCritical, f.Severity)
	assert.Equal(t, CWEHardcodedCredentials, f.CWEID)
}

func TestParseOutput_MultiFindings(t *testing.T) {
	raw := readFixture(t, "gitleaks_multi.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 6)

	// All six findings are constants-only severity + CWE.
	for _, f := range findings {
		assert.Equal(t, SeverityCritical, f.Severity)
		assert.Equal(t, CWEHardcodedCredentials, f.CWEID)
	}

	// Multi-rule diversity check.
	rules := map[string]bool{}
	for _, f := range findings {
		rules[f.FindingType] = true
	}
	assert.GreaterOrEqual(t, len(rules), 4,
		"multi fixture covers diverse rules")
}

func TestParseOutput_Empty(t *testing.T) {
	raw := readFixture(t, "gitleaks_empty.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutput_MalformedJSONFatal: a top-level malformed JSON
// document IS fatal (cannot recover partial findings from a broken
// array). Matches Semgrep posture; differs from Nuclei JSONL where
// per-line drops keep the batch alive.
func TestParseOutput_MalformedJSONFatal(t *testing.T) {
	garbage := []byte(`[{"RuleID": MALFORMED]`)
	_, err := parseOutput(noopLog())(garbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gitleaks")
}

// TestParseOutput_MissingRequiredFieldsSkipped: fixtures has 4
// records; 2 valid + 2 missing required fields → 2 surviving findings.
func TestParseOutput_MissingRequiredFieldsSkipped(t *testing.T) {
	raw := readFixture(t, "gitleaks_missing_fields.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	ids := []string{findings[0].FindingType, findings[1].FindingType}
	assert.Contains(t, ids, "aws-access-token")
	assert.Contains(t, ids, "github-pat")
}

// TestParseOutput_ConstantSeverityCritical pins constant Severity
// across every record from every fixture (regression guard for
// constants-only mapping pattern).
func TestParseOutput_ConstantSeverityCritical(t *testing.T) {
	for _, name := range []string{"gitleaks_basic.json", "gitleaks_multi.json"} {
		findings, err := parseOutput(noopLog())(readFixture(t, name))
		require.NoError(t, err, "fixture %s", name)
		for i, f := range findings {
			assert.Equal(t, "critical", f.Severity,
				"fixture %s finding %d: every Gitleaks finding MUST be critical",
				name, i)
		}
	}
}

// TestParseOutput_ConstantCWE798: every Gitleaks finding maps to
// CWE-798 (Use of Hard-coded Credentials).
func TestParseOutput_ConstantCWE798(t *testing.T) {
	for _, name := range []string{"gitleaks_basic.json", "gitleaks_multi.json"} {
		findings, err := parseOutput(noopLog())(readFixture(t, name))
		require.NoError(t, err, "fixture %s", name)
		for i, f := range findings {
			assert.Equal(t, "CWE-798", f.CWEID,
				"fixture %s finding %d: every Gitleaks finding MUST be CWE-798",
				name, i)
		}
	}
}

// TestParseOutput_CommitMetadataFolded: multi fixture's findings have
// commit metadata; verify the fold suffix shape (commit short-SHA +
// author + date-only).
func TestParseOutput_CommitMetadataFolded(t *testing.T) {
	raw := readFixture(t, "gitleaks_multi.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	// At least one finding has the fold suffix (multi fixture has all
	// commit metadata populated for every record).
	foldedSeen := false
	for _, f := range findings {
		if strings.Contains(f.Description, "(commit ") &&
			strings.Contains(f.Description, " by ") &&
			strings.Contains(f.Description, " on 2026-01-15)") {
			foldedSeen = true
			break
		}
	}
	assert.True(t, foldedSeen,
		"expected at least one finding with fold suffix "+
			"'(commit SHA8 by Author on YYYY-MM-DD)'")
}

// ─── commitFold helper (3) ───────────────────────────────────────────

// TestCommitFold_AllPresent: all three fields populated → suffix
// appended; SHA truncated to 8 chars; date trimmed to YYYY-MM-DD.
func TestCommitFold_AllPresent(t *testing.T) {
	got := commitFold(
		"Detected an AWS Access Token",
		"a1b2c3d4e5f6789012345678901234567890abcd",
		"Anonymous Developer",
		"2026-01-15T12:00:00Z",
	)
	assert.Equal(t,
		"Detected an AWS Access Token (commit a1b2c3d4 by Anonymous Developer on 2026-01-15)",
		got)
}

// TestCommitFold_PartiallyMissing: any one of three empty → base
// unchanged. Covers all three scenarios symmetrically.
func TestCommitFold_PartiallyMissing(t *testing.T) {
	base := "base description"
	cases := []struct {
		name                 string
		commit, author, date string
	}{
		{"commit-empty", "", "Author", "2026-01-15"},
		{"author-empty", "abcd1234", "", "2026-01-15"},
		{"date-empty", "abcd1234", "Author", ""},
		{"all-empty", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, base,
				commitFold(base, c.commit, c.author, c.date),
				"all-or-nothing rule: any missing field → base unchanged")
		})
	}
}

// TestCommitFold_DateTrimsTimestamp pins the YYYY-MM-DD date trim:
// RFC3339 timestamp loses its time component in the fold.
func TestCommitFold_DateTrimsTimestamp(t *testing.T) {
	got := commitFold("base", "abcdefgh", "Dev", "2026-01-15T12:34:56.789Z")
	assert.Contains(t, got, " on 2026-01-15)",
		"date trimmed to YYYY-MM-DD; time component dropped")
	assert.NotContains(t, got, "12:34:56",
		"time component MUST NOT survive the fold")
}
