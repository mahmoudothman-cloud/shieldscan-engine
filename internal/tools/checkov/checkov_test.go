// Package checkov holds tests for the Checkov IaC native runner.
package checkov

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

func testConfig() Config { return Config{BinaryPath: "/bin/echo"} }

// ─── Construction (3) ────────────────────────────────────────────────

func TestNewCheckovRunner_IdentityFields(t *testing.T) {
	r := NewCheckovRunner(testConfig(), noopLog())
	assert.Equal(t, "checkov", r.Name())
	assert.Equal(t, "iac", r.Category())
}

// TestNewCheckovRunner_DefaultsApplied pins load-bearing defaults:
// ExitCodeLenient=false (--soft-fail handles via flag, NOT runner-
// tolerates); Env contains PYTHONWARNINGS=ignore (3rd instance →
// triggers DEVELOPMENT-PATTERNS.md Pattern 3 promotion); stdout-mode
// (OutputFile=false; not file-output like Dep-Check).
func TestNewCheckovRunner_DefaultsApplied(t *testing.T) {
	r := NewCheckovRunner(testConfig(), noopLog())
	assert.Equal(t, 5*time.Minute, r.Timeout)
	assert.Equal(t, 50*1024*1024, r.MaxStdoutBytes)
	assert.False(t, r.ExitCodeLenient,
		"configuration-not-leniency: --soft-fail in BuildArgs forces clean exit")
	assert.Contains(t, r.Env, "PYTHONWARNINGS=ignore",
		"3rd instance of pipx-Python Env pattern → promotion to DEVELOPMENT-PATTERNS Pattern 3")
	assert.False(t, r.OutputFile,
		"Checkov writes JSON to stdout natively (NOT file-output mode)")
	assert.NotNil(t, r.ParseOutput)
	assert.Nil(t, r.ParseOutputFile)
}

// TestNewCheckovRunner_ConstantsExported regression-guards the
// constants-only contract: SeverityMedium and CWEIaCMisconfiguration
// are stable values used by every Checkov RawFinding and accessible
// to downstream tooling (M9 AI pipeline, etc.).
func TestNewCheckovRunner_ConstantsExported(t *testing.T) {
	assert.Equal(t, "medium", SeverityMedium)
	assert.Equal(t, "CWE-1032", CWEIaCMisconfiguration)
}

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/iac"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-d", "/src/iac",
		"-o", "json",
		"--quiet",
		"--soft-fail",
	} {
		assert.Contains(t, joined, want, "missing required flag/arg %q", want)
	}
}

// TestBuildArgs_SoftFailPresent regression-guards the configuration-
// not-leniency contract: --soft-fail forces clean exit even when
// failures present. Without it, ExitCodeLenient=false would surface
// every Checkov scan with findings as Run error.
func TestBuildArgs_SoftFailPresent(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/iac"},
		tools.ScanConfig{},
	)
	assert.Contains(t, strings.Join(args, " "), "--soft-fail",
		"configuration-not-leniency invariant: --soft-fail MUST be present")
}

func TestBuildArgs_SourcePathFromTarget(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/some/iac/dir"},
		tools.ScanConfig{},
	)
	assert.Contains(t, strings.Join(args, " "), "-d /some/iac/dir")
}

// ─── ParseOutput (5) ─────────────────────────────────────────────────

func TestParseOutput_BasicSingleFinding(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "checkov_basic.json"))
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.NotEmpty(t, f.FindingType, "FindingType from check_id")
	assert.NotEmpty(t, f.CodeFile, "CodeFile from file_path")
	assert.NotZero(t, f.CodeLine, "CodeLine from file_line_range[0]")
	assert.Equal(t, SeverityMedium, f.Severity)
	assert.Equal(t, CWEIaCMisconfiguration, f.CWEID)
	assert.NotEmpty(t, f.Title, "Title from check_name")
	assert.NotEmpty(t, f.CodeSnippet, "CodeSnippet from flattened code_block")

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024) —
	// Checkov retrofit per design doc §4.1.5: References from
	// guideline (single URL string wrapped as []string).
	assert.Equal(t, []string{
		"https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-networking-policies/networking-31",
	}, f.References)
	// Other new fields stay nil/empty (Checkov has no tags/CVSS/multi-CWE source).
	assert.Nil(t, f.Tags)
	assert.Empty(t, f.CVSSVector)
	assert.Nil(t, f.AdditionalCWEs)
}

// TestParseOutput_BackwardCompatNoGuideline pins the empty-guideline
// case: when Checkov omits guideline (custom rules; older versions),
// References stays nil so omitempty drops the field.
func TestParseOutput_BackwardCompatNoGuideline(t *testing.T) {
	raw := []byte(`{"results":{"failed_checks":[{"check_id":"X","file_path":"f","check_name":"n","file_line_range":[1,1],"resource":"r"}]}}`)
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].References, "missing guideline → nil References")
}

func TestParseOutput_MultiFindings(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "checkov_multi.json"))
	require.NoError(t, err)
	require.Len(t, findings, 10)

	// Constants applied to every finding.
	for _, f := range findings {
		assert.Equal(t, SeverityMedium, f.Severity)
		assert.Equal(t, CWEIaCMisconfiguration, f.CWEID)
	}

	// Diversity check: ≥5 unique check_ids in the multi fixture.
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.FindingType] = true
	}
	assert.GreaterOrEqual(t, len(ids), 5, "multi fixture should cover diverse checks")
}

func TestParseOutput_Empty(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "checkov_empty.json"))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutput_MalformedJSONFatal: top-level malformed JSON IS
// fatal (consistent with prior single-doc parsers).
func TestParseOutput_MalformedJSONFatal(t *testing.T) {
	garbage := []byte(`{"results": MALFORMED]`)
	_, err := parseOutput(noopLog())(garbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checkov")
}

// TestParseOutput_KubernetesFramework pins framework-agnosticism: the
// parser doesn't branch on check_type; same shape parses.
func TestParseOutput_KubernetesFramework(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "checkov_kubernetes.json"))
	require.NoError(t, err)
	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, SeverityMedium, f.Severity)
		assert.Contains(t, f.FindingType, "CKV_K8S")
	}
}

// ─── flattenCodeBlock helper (1 — table-driven) ──────────────────────

func TestFlattenCodeBlock(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, ""},
		{"wrong-type-string", "not an array", ""},
		{"empty-array", []any{}, ""},
		{
			"three-lines",
			[]any{
				[]any{float64(1), "line one\n"},
				[]any{float64(2), "line two\n"},
				[]any{float64(3), "line three\n"},
			},
			"line one\nline two\nline three\n",
		},
		{
			"malformed-pair-skipped",
			[]any{
				[]any{float64(1), "valid\n"},
				[]any{float64(2)}, // single-element pair → skip
				"not-a-pair",      // wrong type → skip
				[]any{float64(3), "also valid\n"},
			},
			"valid\nalso valid\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, flattenCodeBlock(c.in))
		})
	}
}
