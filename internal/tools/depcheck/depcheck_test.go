// Package depcheck holds tests for the OWASP Dependency-Check native
// runner. First M6 tool to use NativeRunner's OutputFile mode (per
// ADR-023).
package depcheck

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

func noopLog() zerolog.Logger {
	return zerolog.New(nil).Level(zerolog.Disabled)
}

func testConfig() Config { return Config{BinaryPath: "/bin/echo"} }

// ─── Construction (3) ────────────────────────────────────────────────

func TestNewDepCheckRunner_IdentityFields(t *testing.T) {
	r := NewDepCheckRunner(testConfig(), noopLog())
	assert.Equal(t, "depcheck", r.Name())
	assert.Equal(t, "sca", r.Category())
}

// TestNewDepCheckRunner_DefaultsApplied pins the load-bearing defaults.
// FIRST USE of NativeRunner.OutputFile=true (ADR-023). Regression-
// guarded: ParseOutputFile != nil; ParseOutput == nil; placeholder
// is "{{outputFile}}".
func TestNewDepCheckRunner_DefaultsApplied(t *testing.T) {
	r := NewDepCheckRunner(testConfig(), noopLog())
	assert.Equal(t, 15*time.Minute, r.Timeout)
	assert.Equal(t, 50*1024*1024, r.MaxStdoutBytes)
	assert.False(t, r.ExitCodeLenient,
		"naturally-clean: Dep-Check exits 0 by default; --failOnCVSS deliberately omitted")
	assert.True(t, r.OutputFile, "Dep-Check writes findings to file via --out")
	assert.Equal(t, "{{outputFile}}", r.OutputFilePlaceholder,
		"placeholder MUST match the BuildArgs --out value for substitution")
	assert.NotNil(t, r.ParseOutputFile,
		"file-output mode requires ParseOutputFile (ADR-023)")
	assert.Nil(t, r.ParseOutput,
		"file-output mode does NOT use ParseOutput; both fields set is a code smell")
}

// TestNewDepCheckRunner_NoEnvWarningsSuppression pins anti-pattern guard:
// Dep-Check is JVM-based, NOT pipx-installed Python. PYTHONWARNINGS=ignore
// would be misleading scaffolding here.
func TestNewDepCheckRunner_NoEnvWarningsSuppression(t *testing.T) {
	r := NewDepCheckRunner(testConfig(), noopLog())
	assert.Nil(t, r.Env,
		"Dep-Check is JVM-based; PYTHONWARNINGS=ignore would be misleading")
}

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--scan", "/src/repo",
		"--format", "JSON",
		"--out", "{{outputFile}}",
	} {
		assert.Contains(t, joined, want, "missing required flag/arg %q", want)
	}
}

// TestBuildArgs_NoFailOnCVSSFlag is the naturally-clean regression
// guard. If --failOnCVSS slips in, Dep-Check would exit non-zero on
// findings → ExitCodeLenient=false would surface as Run error.
func TestBuildArgs_NoFailOnCVSSFlag(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	assert.NotContains(t, strings.Join(args, " "), "--failOnCVSS",
		"naturally-clean invariant: --failOnCVSS MUST NOT be present")
}

// TestBuildArgs_OutputPlaceholderPresent regression-guards the
// placeholder substitution contract: BuildArgs MUST include
// "{{outputFile}}" exactly as NativeRunner expects to substitute.
func TestBuildArgs_OutputPlaceholderPresent(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	found := false
	for _, a := range args {
		if a == "{{outputFile}}" {
			found = true
			break
		}
	}
	assert.True(t, found,
		"BuildArgs MUST include literal '{{outputFile}}' for NativeRunner substitution")
}

// ─── ParseOutputFile (5) ─────────────────────────────────────────────

func TestParseOutputFile_BasicSingleCVE(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "depcheck_basic.json"))
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "CVE-2021-44228", f.FindingType)
	assert.Equal(t, "CVE-2021-44228", f.Title)
	assert.Equal(t, "critical", f.Severity)
	assert.Equal(t, "CWE-502", f.CWEID, "first CWE only (consistent with Nuclei)")
	assert.InDelta(t, 10.0, f.CVSSScore, 0.001)
	assert.Equal(t, "repo/lib/log4j-core-2.14.0.jar", f.CodeFile)
	assert.Contains(t, f.Description, "log4j-core-2.14.0.jar",
		"fileName folded into Description")

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024) —
	// Dep-Check retrofit per design doc §4.1.4.
	//
	// References: extracted from references[].url.
	assert.Equal(t, []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
		f.References)
	// AdditionalCWEs: cwes is ["CWE-502","CWE-20"] → primary CWEID
	// stays "CWE-502", AdditionalCWEs picks up ["CWE-20"]. LOAD-BEARING
	// for SPEC §8.2 forward-pin per ADR-024 §3.1.4.
	assert.Equal(t, []string{"CWE-20"}, f.AdditionalCWEs)
	// CVSSVector: fixture has only attackVector populated (no full
	// 8-dimension cvssv3); composeCVSSVector graceful-degrades to "".
	assert.Empty(t, f.CVSSVector,
		"partial cvssv3 → composeCVSSVector returns \"\" (graceful)")
}

// TestParseOutputFile_FullCVSSv3Composition pins the happy path
// for CVSSVector composition: a synthetic vulnerability with all
// 8 cvssv3 dimensions populated produces a canonical CVSS:3.1/...
// string via composeCVSSVector + the cvssWordToLetter map.
func TestParseOutputFile_FullCVSSv3Composition(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "full_cvss.json")
	full := `{"dependencies":[{"filePath":"/p/lib.jar","fileName":"lib.jar","vulnerabilities":[{"name":"CVE-2024-9999","severity":"Critical","description":"d","cwes":["CWE-89","CWE-20","CWE-78"],"cvssv3":{"baseScore":9.8,"attackVector":"NETWORK","attackComplexity":"LOW","privilegesRequired":"NONE","userInteraction":"NONE","scope":"UNCHANGED","confidentialityImpact":"HIGH","integrityImpact":"HIGH","availabilityImpact":"HIGH"},"references":[{"url":"https://example.com/a"},{"url":"https://example.com/b"}]}]}]}`
	require.NoError(t, os.WriteFile(tmp, []byte(full), 0o644))

	findings, err := parseOutputFile(noopLog())(tmp)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	f := findings[0]

	// CVSSVector composed from all 8 dimensions (per FIRST.org CVSS
	// 3.1 spec; see internal/tools/depcheck/cvss_mapping.go).
	assert.Equal(t,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		f.CVSSVector)
	// Multi-CWE intersection: primary stays CWE-89; remaining 2 → AdditionalCWEs.
	assert.Equal(t, "CWE-89", f.CWEID)
	assert.Equal(t, []string{"CWE-20", "CWE-78"}, f.AdditionalCWEs)
	// References: both URLs extracted.
	assert.Equal(t, []string{"https://example.com/a", "https://example.com/b"}, f.References)
}

func TestParseOutputFile_MultiCVEAcrossDeps(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "depcheck_multi_cve.json"))
	require.NoError(t, err)
	require.Len(t, findings, 7, "3 deps × {3, 2, 2} CVE counts = 7 findings")

	// Severity distribution: 3 critical + 1 high + 1 medium + 1 low
	// + others; verify spread.
	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	assert.Equal(t, 3, sev["critical"], "log4j critical+critical + spring critical")
	assert.GreaterOrEqual(t, sev["high"], 1)
	assert.GreaterOrEqual(t, sev["medium"], 1)
	assert.GreaterOrEqual(t, sev["low"], 1)

	// Per-CVE granularity: log4j-core appears 3 times (3 CVEs).
	log4jCount := 0
	for _, f := range findings {
		if strings.Contains(f.CodeFile, "log4j-core") {
			log4jCount++
		}
	}
	assert.Equal(t, 3, log4jCount, "log4j-core dep should produce 3 findings (one per CVE)")
}

func TestParseOutputFile_Empty(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "depcheck_empty.json"))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutputFile_MalformedJSONFatal: top-level malformed JSON IS
// fatal (consistent with Semgrep + Gitleaks + SSLyze postures).
func TestParseOutputFile_MalformedJSONFatal(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(tmp, []byte(`{"dependencies": [MALFORMED]`), 0o644))
	_, err := parseOutputFile(noopLog())(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "depcheck")
}

// TestParseOutputFile_MissingRequiredFieldsSkipped: per-dep missing
// filePath drops the whole dep; per-CVE missing name skips that CVE.
// Fixture has 4 deps; expect 2 findings (one from "good.jar", one
// from "partial.jar"'s valid CVE).
func TestParseOutputFile_MissingRequiredFieldsSkipped(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "depcheck_missing_fields.json"))
	require.NoError(t, err)
	require.Len(t, findings, 2)

	ids := []string{findings[0].FindingType, findings[1].FindingType}
	assert.Contains(t, ids, "CVE-2020-1234")
	assert.Contains(t, ids, "CVE-2021-5678")
}

// ─── Severity mapping (1) ────────────────────────────────────────────

func TestMapSeverity_AllLevels(t *testing.T) {
	cases := map[string]string{
		"Critical":      "critical",
		"CRITICAL":      "critical",
		"High":          "high",
		"Medium":        "medium",
		"Moderate":      "medium", // also observed in NVD
		"Low":           "low",
		"Info":          "info",
		"Informational": "info",
		"":              "info",
		"unknown":       "info",
	}
	for in, want := range cases {
		assert.Equal(t, want, mapSeverity(in), "severity %q mapping", in)
	}
}
