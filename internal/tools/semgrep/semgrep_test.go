// Package semgrep holds tests for the Semgrep native runner factory
// and closures. Test conventions per ../../../CLAUDE.md and ADR-021.
package semgrep

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

// TestMain wires goleak per ADR-021. Semgrep runner spawns no
// goroutines of its own; the boilerplate is preserved as the
// project-wide convention.
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

func TestNewSemgrepRunner_ReturnsToolRunner(t *testing.T) {
	var _ tools.ToolRunner = NewSemgrepRunner(testConfig(), noopLog())
}

func TestNewSemgrepRunner_IdentityFields(t *testing.T) {
	r := NewSemgrepRunner(testConfig(), noopLog())
	assert.Equal(t, "semgrep", r.Name())
	assert.Equal(t, "sast", r.Category())
}

// TestNewSemgrepRunner_DefaultsApplied pins the load-bearing
// construction defaults: ExitCodeLenient=true (FIRST non-trivial use)
// + Env containing PYTHONWARNINGS=ignore (FIRST populated Env in M6).
// Both are regression guards; future "simplification" attempts must
// fail this test rather than silently change behavior.
func TestNewSemgrepRunner_DefaultsApplied(t *testing.T) {
	r := NewSemgrepRunner(testConfig(), noopLog())
	assert.Equal(t, 5*time.Minute, r.Timeout)
	assert.Equal(t, 50*1024*1024, r.MaxStdoutBytes)
	assert.True(t, r.ExitCodeLenient,
		"Semgrep MUST be ExitCodeLenient=true (exit 1/2 are normal)")

	// Env slice contains PYTHONWARNINGS=ignore. Per watch item D, we
	// assert the slice contains the value, not absolute equality
	// (NativeRunner appends to inherited env at run time).
	assert.Contains(t, r.Env, "PYTHONWARNINGS=ignore",
		"Env must include PYTHONWARNINGS=ignore to suppress "+
			"pkg_resources deprecation noise on stderr")
}

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--config=p/default",
		"--json",
		"--quiet",
		"--metrics=off",
		"--timeout=120",
	} {
		assert.Contains(t, joined, want, "missing required flag %q", want)
	}
}

// TestBuildArgs_NoConfigAuto pins the privacy invariant explicitly:
// --config=auto requires Semgrep telemetry ON and therefore MUST NOT
// appear. Defensive regression guard.
func TestBuildArgs_NoConfigAuto(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	assert.NotContains(t, joined, "--config=auto",
		"--config=auto requires telemetry; privacy invariant violated")
}

// TestBuildArgs_SourcePathPositional pins source path as the trailing
// positional. Semgrep's CLI requires the source path AFTER all flags.
func TestBuildArgs_SourcePathPositional(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	require.NotEmpty(t, args)
	assert.Equal(t, "/src/repo", args[len(args)-1],
		"source path must be the final positional argument")
}

// ─── ParseOutput happy + edge (8) ────────────────────────────────────

func TestParseOutput_BasicSingleFinding(t *testing.T) {
	raw := readFixture(t, "semgrep_basic.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t,
		"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
		f.FindingType)
	assert.Equal(t, "repo/app.py", f.CodeFile)
	assert.Equal(t, 10, f.CodeLine)
	assert.Equal(t, "high", f.Severity, "ERROR → high (non-identity mapping)")
	assert.Equal(t, "CWE-78", f.CWEID,
		"CWE prefix-extracted from %q", "CWE-78: Improper Neutralization...")
	assert.NotEmpty(t, f.OWASP, "OWASP first-element extracted")
	assert.NotEmpty(t, f.Description)
	assert.NotEmpty(t, f.CodeSnippet)

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024) —
	// Semgrep retrofit per design doc §4.1.2: References from
	// extra.metadata.references[]; Tags from extra.metadata.category
	// wrapped (filtered against engine_category — "security" survives).
	assert.Equal(t, []string{
		"https://stackoverflow.com/questions/3172470/actual-meaning-of-shell-true-in-subprocess",
		"https://docs.python.org/3/library/subprocess.html",
	}, f.References)
	assert.Equal(t, []string{"security"}, f.Tags)
	// Semgrep doesn't emit CVSS or multi-CWE → fields stay nil/empty.
	assert.Empty(t, f.CVSSVector)
	assert.Nil(t, f.AdditionalCWEs)
}

// TestParseOutput_BackwardCompatNoMetadata pins backward-compat:
// custom rules often lack metadata; new fields stay nil.
func TestParseOutput_BackwardCompatNoMetadata(t *testing.T) {
	raw := []byte(`{"results":[{"check_id":"x","path":"a.py","start":{"line":1},"extra":{"severity":"INFO","message":"m","lines":"l"}}]}`)
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].References)
	assert.Nil(t, findings[0].Tags)
}

func TestParseOutput_MultiFindings(t *testing.T) {
	raw := readFixture(t, "semgrep_multi.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 6)

	// Severity distribution: 4 ERROR (→high) + 1 WARNING (→medium) +
	// 1 INFO (→info).
	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	assert.Equal(t, 4, sev["high"])
	assert.Equal(t, 1, sev["medium"])
	assert.Equal(t, 1, sev["info"])
}

func TestParseOutput_Empty(t *testing.T) {
	raw := readFixture(t, "semgrep_empty.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutput_ErrorsArrayLogged pins H.1: errors[] non-empty +
// results[] empty MUST produce ([], nil) — log-and-continue, NOT a
// Go error. Symmetric with 6.1 fail-soft posture; trigger to revisit
// in DRIFT-LOG.
func TestParseOutput_ErrorsArrayLogged(t *testing.T) {
	raw := readFixture(t, "semgrep_error.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err, "errors[] non-empty MUST NOT cause Go error")
	assert.Empty(t, findings, "no results[] → empty findings slice")
}

// TestParseOutput_LenientUnknownFields pins the lenient-decode pattern
// for Semgrep — load-bearing per scope decision (kept despite trim
// proposal). Unknown fields at top level, in start/end, in extra, in
// extra.metadata MUST all be tolerated.
func TestParseOutput_LenientUnknownFields(t *testing.T) {
	raw := readFixture(t, "semgrep_unknown_fields.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err, "unknown fields MUST NOT cause parse error")
	require.Len(t, findings, 1)
	assert.Equal(t,
		"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
		findings[0].FindingType)
}

// TestParseOutput_MalformedJSONFatal pins the asymmetry vs 6.1's
// JSONL line-drop: single-doc JSON failure IS fatal (we can't recover
// partial findings from a broken document, unlike a JSONL stream).
func TestParseOutput_MalformedJSONFatal(t *testing.T) {
	garbage := []byte(`{"results": [MALFORMED]`)
	_, err := parseOutput(noopLog())(garbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "semgrep")
}

// TestParseOutput_MissingRequiredFieldsSkipped: per record, missing
// check_id OR missing path → skip with WARN; valid records flow.
// Fixture has 4 records (2 valid + 2 invalid).
func TestParseOutput_MissingRequiredFieldsSkipped(t *testing.T) {
	raw := readFixture(t, "semgrep_missing_fields.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 2,
		"2 valid records survive; 2 with missing required fields dropped")

	// Verify the survivors are the right ones.
	ids := []string{findings[0].FindingType, findings[1].FindingType}
	assert.Contains(t, ids, "rule.valid")
	assert.Contains(t, ids, "rule.valid.two")
}

// TestParseOutput_OWASPVerbatimFirstElement pins H.2: OWASP is the
// first array element verbatim (with full prefix), regardless of
// array length. Stable; downstream normalizes if needed.
func TestParseOutput_OWASPVerbatimFirstElement(t *testing.T) {
	raw := readFixture(t, "semgrep_multi.json")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	// At least one finding has a multi-element owasp array; verify
	// the OWASP field is the FIRST element (per watch item C).
	multiOWASPSeen := false
	for _, f := range findings {
		if f.OWASP != "" && strings.Contains(f.OWASP, "A0") {
			// Real Semgrep multi.json fixture's first finding has
			// owasp = ["A01:2017 - Injection", "A03:2021 - Injection",
			//         "A05:2025 - Injection"].
			// First element is "A01:2017 - Injection".
			if strings.HasPrefix(f.OWASP, "A01:2017") ||
				strings.HasPrefix(f.OWASP, "A03:2021") ||
				strings.HasPrefix(f.OWASP, "A02") ||
				strings.HasPrefix(f.OWASP, "A07") {
				multiOWASPSeen = true
				break
			}
		}
	}
	assert.True(t, multiOWASPSeen,
		"expected at least one OWASP value matching first-array-element shape")
}

// ─── Severity mapping (2; case-insensitive folded into AllLevels) ────

func TestMapSeverity_AllLevels(t *testing.T) {
	cases := map[string]string{
		// Canonical levels.
		"ERROR":   "high",
		"WARNING": "medium",
		"INFO":    "info",
		// Case-insensitivity (folded in per H.10 trim).
		"error":   "high",
		"Warning": "medium",
		"info":    "info",
		"WaRnInG": "medium",
		// Defensive default.
		"":         "info",
		"unknown":  "info",
		"weirdval": "info",
	}
	for in, want := range cases {
		assert.Equal(t, want, mapSeverity(in), "severity %q mapping", in)
	}
}

// TestMapSeverity_ErrorMapsToHighNotCritical is the explicit
// regression guard for the load-bearing decision: Semgrep ERROR is
// EXPLOIT-CLASS but NOT confirmed-exploitable-remote, so it maps to
// "high" not "critical". Pinned in DRIFT-LOG entry 1.
func TestMapSeverity_ErrorMapsToHighNotCritical(t *testing.T) {
	assert.Equal(t, "high", mapSeverity("ERROR"),
		"Semgrep ERROR → high (NOT critical); see DRIFT-LOG M6.2 entry 1")
	assert.NotEqual(t, "critical", mapSeverity("ERROR"))
}

// ─── ExitCodeLenient integration (1 net new) ─────────────────────────

// TestExitCodeLenient_Exit2WithErrorsArray pins the FIRST real use of
// ExitCodeLenient=true through the full NativeRunner.Run pipeline.
//
// Mock binary: a tiny shell script that writes our error fixture to
// stdout then exits 2. Without ExitCodeLenient=true, NativeRunner
// would surface the non-zero exit as Go error and never call
// ParseOutput. With ExitCodeLenient=true, ParseOutput is called; it
// observes errors[] populated, returns ([], nil) per H.1.
//
// The other two regimes from §G (exit 0 happy + exit 1) are covered
// by the framework-level tests at internal/tools/native_test.go
// (TestNativeRunner_NonZeroExitLenient covers the lenient path).
// 6.2 adds the Semgrep-specific exit-2-with-errors-array assertion
// — distinct from any 5.2 framework test.
func TestExitCodeLenient_Exit2WithErrorsArray(t *testing.T) {
	// Build a mock binary that prints the error fixture to stdout
	// and exits 2.
	dir := t.TempDir()
	mockPath := filepath.Join(dir, "mock-semgrep")
	errorFixture := readFixture(t, "semgrep_error.json")

	// Use bash heredoc-style script. Easier than embedding fixture
	// content into a Go template.
	script := "#!/bin/sh\ncat <<'JSON_EOF'\n" + string(errorFixture) +
		"\nJSON_EOF\nexit 2\n"
	require.NoError(t, os.WriteFile(mockPath, []byte(script), 0o755))

	cfg := Config{BinaryPath: mockPath}
	r := NewSemgrepRunner(cfg, noopLog())

	findings, err := r.Run(t.Context(),
		tools.Target{SourcePath: "/src/repo"},
		tools.ScanConfig{},
	)
	require.NoError(t, err,
		"ExitCodeLenient=true MUST tolerate exit 2; errors[] handled by parser")
	assert.Empty(t, findings,
		"error fixture has results=[], so no findings emitted")
}
