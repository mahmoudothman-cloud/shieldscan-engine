// Package wapiti holds tests for the Wapiti DAST native runner.
// Second ADR-023 OutputFile-mode consumer (after Dep-Check at 6.7).
package wapiti

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

func noopLog() zerolog.Logger { return zerolog.New(nil).Level(zerolog.Disabled) }
func testConfig() Config      { return Config{BinaryPath: "/bin/echo"} }

// ─── Construction (3) ────────────────────────────────────────────────

func TestNewWapitiRunner_IdentityFields(t *testing.T) {
	r := NewWapitiRunner(testConfig(), noopLog())
	assert.Equal(t, "wapiti", r.Name())
	assert.Equal(t, "dast", r.Category())
}

// TestNewWapitiRunner_DefaultsApplied pins ADR-023 2nd consumer
// (OutputFile=true) + Pattern 3 4th instance (PYTHONWARNINGS=ignore).
func TestNewWapitiRunner_DefaultsApplied(t *testing.T) {
	r := NewWapitiRunner(testConfig(), noopLog())
	assert.Equal(t, 15*time.Minute, r.Timeout)
	assert.False(t, r.ExitCodeLenient, "naturally-clean: exit 0 even with vulns")
	assert.True(t, r.OutputFile,
		"ADR-023 2nd consumer: Wapiti writes JSON to file (-o /dev/stdout corrupts)")
	assert.Equal(t, "{{outputFile}}", r.OutputFilePlaceholder)
	assert.NotNil(t, r.ParseOutputFile)
	assert.Nil(t, r.ParseOutput, "OutputFile mode: ParseOutput unused")
	assert.Contains(t, r.Env, "PYTHONWARNINGS=ignore",
		"4th instance of Pattern 3 (Semgrep+SSLyze+Checkov+Wapiti)")
}

// TestNewWapitiRunner_PYTHONWARNINGSReinforcesPattern3 explicitly
// regression-guards the 4th-instance reinforcement.
func TestNewWapitiRunner_PYTHONWARNINGSReinforcesPattern3(t *testing.T) {
	r := NewWapitiRunner(testConfig(), noopLog())
	found := false
	for _, e := range r.Env {
		if e == "PYTHONWARNINGS=ignore" {
			found = true
			break
		}
	}
	assert.True(t, found, "Pattern 3 4th instance must include PYTHONWARNINGS=ignore")
}

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-u", "https://app.example.com",
		"-f", "json",
		"-o", "{{outputFile}}",
		"--flush-session",
	} {
		assert.Contains(t, joined, want, "missing required flag/arg %q", want)
	}
}

// TestBuildArgs_NoStdoutOutput regression-guards the Wapiti bug
// workaround: -o /dev/stdout corrupts JSON; MUST use placeholder.
func TestBuildArgs_NoStdoutOutput(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	assert.NotContains(t, joined, "/dev/stdout",
		"Wapiti -o /dev/stdout corrupts JSON; MUST use OutputFile placeholder")
}

func TestBuildArgs_FlushSessionPresent(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	assert.Contains(t, strings.Join(args, " "), "--flush-session",
		"per-scan fresh state invariant")
}

// ─── ParseOutputFile (5) ─────────────────────────────────────────────

func TestParseOutputFile_BasicSingleFinding(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "wapiti_basic.json"))
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "wapiti-clickjacking-protection", f.FindingType,
		"category name slug-ified into FindingType")
	assert.Contains(t, f.Description, "X-Frame-Options")
	assert.Equal(t, "info", f.Severity, "level=1 maps to info")
	assert.Contains(t, f.TargetURL, "example.com",
		"TargetURL combines infos.target + path")

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024) —
	// Wapiti retrofit per design doc §4.1.6: References from wstg[];
	// Tags from module wrapped (filtered against engine_category —
	// "http_headers" survives).
	assert.Equal(t, []string{"OSHP-X-Frame-Options"}, f.References)
	assert.Equal(t, []string{"http_headers"}, f.Tags)
	assert.Empty(t, f.CVSSVector)
	assert.Nil(t, f.AdditionalCWEs)
}

// TestParseOutputFile_TagsFilteredAgainstEngineCategory pins the
// ADR-024 §3.1.2 invariant: a synthetic Wapiti record whose module
// equals "dast" must produce nil Tags via FilterEngineCategoryTags.
func TestParseOutputFile_TagsFilteredAgainstEngineCategory(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "engcat.json")
	doc := `{"infos":{"target":"https://x.test/"},"vulnerabilities":{"X":[{"info":"i","level":1,"path":"/","module":"dast","wstg":["W-1"]}]}}`
	require.NoError(t, os.WriteFile(tmp, []byte(doc), 0o644))
	findings, err := parseOutputFile(noopLog())(tmp)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].Tags,
		"module=\"dast\" matches engine_category → filtered to nil")
	assert.Equal(t, []string{"W-1"}, findings[0].References)
}

func TestParseOutputFile_MultiFindings(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "wapiti_multi.json"))
	require.NoError(t, err)
	require.Len(t, findings, 3,
		"3 vuln classes × 1 instance each = 3 findings")

	// Diversity check.
	types := map[string]bool{}
	for _, f := range findings {
		types[f.FindingType] = true
	}
	assert.GreaterOrEqual(t, len(types), 3)
}

func TestParseOutputFile_Empty(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "wapiti_empty.json"))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutputFile_MalformedJSONFatal: top-level malformed JSON
// IS fatal (consistent with prior single-doc parsers).
func TestParseOutputFile_MalformedJSONFatal(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(tmp, []byte(`{"vulnerabilities": MALFORMED]`), 0o644))
	_, err := parseOutputFile(noopLog())(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wapiti")
}

// TestParseOutputFile_SeverityMix exercises the full level→severity
// table via the synthetic fixture (level 3, 4, 5 across 2 classes).
func TestParseOutputFile_SeverityMix(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "wapiti_severity_mix.json"))
	require.NoError(t, err)
	require.Len(t, findings, 3)

	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	assert.Equal(t, 1, sev["medium"], "level=3 → medium")
	assert.Equal(t, 1, sev["high"], "level=4 → high")
	assert.Equal(t, 1, sev["critical"], "level=5 → critical")
}

// ─── Severity mapping (2) ────────────────────────────────────────────

func TestMapSeverity_AllLevels(t *testing.T) {
	cases := map[int]string{
		1: "info",
		2: "low",
		3: "medium",
		4: "high",
		5: "critical",
		// Defensive defaults.
		0:   "info",
		-1:  "info",
		99:  "info",
		100: "info",
	}
	for in, want := range cases {
		assert.Equal(t, want, mapSeverity(in), "level %d mapping", in)
	}
}

// TestSlugifyCategoryName regression-guards the FindingType derivation:
// "Clickjacking Protection" → "wapiti-clickjacking-protection".
func TestSlugifyCategoryName(t *testing.T) {
	cases := map[string]string{
		"Clickjacking Protection":               "clickjacking-protection",
		"HTTP Strict Transport Security (HSTS)": "http-strict-transport-security-hsts",
		"Cross Site Scripting":                  "cross-site-scripting",
		"SQL Injection":                         "sql-injection",
		"":                                      "",
	}
	for in, want := range cases {
		assert.Equal(t, want, slugifyCategoryName(in), "input %q", in)
	}
}
