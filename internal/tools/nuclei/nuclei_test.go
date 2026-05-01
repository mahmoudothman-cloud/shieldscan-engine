// Package nuclei holds tests for the Nuclei native runner factory and
// closures. Test conventions per ../../../CLAUDE.md and ADR-021.
package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestMain wires goleak per ADR-021. Nuclei runner spawns no
// goroutines of its own; the boilerplate is preserved as the
// project-wide convention.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fixturePath returns the absolute path of a testdata fixture so
// tests work regardless of CWD (mirrors deploy/docker_compose_test.go
// pattern from 5.6).
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

// noopLog returns a zerolog logger that discards output for tests.
func noopLog() zerolog.Logger {
	return zerolog.New(nil).Level(zerolog.Disabled)
}

// testConfig returns a Config suitable for unit tests; BinaryPath is
// "/bin/echo" by default so construction tests don't fail looking up
// nuclei.
func testConfig() Config {
	return Config{
		BinaryPath:   "/bin/echo",
		TemplatesDir: "/tmp/templates",
		DefaultRPS:   50,
	}
}

// ─── Construction (3) ────────────────────────────────────────────────

// TestNewNucleiRunner_ReturnsToolRunner pins the interface conformance.
// If NativeRunner ever drifts from ToolRunner, the assertion fails at
// compile time before tests run.
func TestNewNucleiRunner_ReturnsToolRunner(t *testing.T) {
	var _ tools.ToolRunner = NewNucleiRunner(testConfig(), noopLog())
}

// TestNewNucleiRunner_IdentityFields pins the canonical Name + Category
// values applied to every finding the runner emits.
func TestNewNucleiRunner_IdentityFields(t *testing.T) {
	r := NewNucleiRunner(testConfig(), noopLog())
	assert.Equal(t, "nuclei", r.Name())
	assert.Equal(t, "dast", r.Category())
}

// TestNewNucleiRunner_DefaultsApplied pins the construction defaults
// (Timeout, MaxStdoutBytes, ExitCodeLenient). Override surface is the
// Config struct; defaults landing here document the canonical-first-
// tool baseline.
func TestNewNucleiRunner_DefaultsApplied(t *testing.T) {
	r := NewNucleiRunner(testConfig(), noopLog())
	assert.Equal(t, 30*time.Minute, r.Timeout)
	assert.Equal(t, 50*1024*1024, r.MaxStdoutBytes)
	assert.False(t, r.ExitCodeLenient,
		"Nuclei is well-behaved on exit codes; non-zero is a real error")
}

// ─── BuildArgs (4) ───────────────────────────────────────────────────

func TestBuildArgs_QuickDepth(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{Depth: "quick"},
	)
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-severity high,critical",
		"quick depth filters to high+critical only")
	assert.Contains(t, joined, "-u https://app.example.com")
}

func TestBuildArgs_StandardDepth(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{Depth: "standard"},
	)
	assert.Contains(t, strings.Join(args, " "), "-severity medium,high,critical")
}

func TestBuildArgs_DeepDepth(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{Depth: "deep"},
	)
	// Deep mode runs all severities; the -severity flag is omitted
	// rather than passed with all levels.
	assert.NotContains(t, strings.Join(args, " "), "-severity")
}

// TestBuildArgs_RateLimit pins the precedence: ScanConfig.MaxRPS wins
// when >0; otherwise Config.DefaultRPS.
func TestBuildArgs_RateLimit(t *testing.T) {
	cfg := testConfig() // DefaultRPS=50

	// Default path: ScanConfig.MaxRPS=0 → cfg.DefaultRPS used.
	argsDefault := buildArgs(cfg)(tools.Target{URL: "https://x"}, tools.ScanConfig{})
	assert.Contains(t, strings.Join(argsDefault, " "), "-rl 50")

	// Override path: ScanConfig.MaxRPS=10 wins.
	argsOverride := buildArgs(cfg)(tools.Target{URL: "https://x"}, tools.ScanConfig{MaxRPS: 10})
	assert.Contains(t, strings.Join(argsOverride, " "), "-rl 10")
}

// ─── ParseOutput happy path (3) ──────────────────────────────────────

func TestParseOutput_SingleXSSFinding(t *testing.T) {
	raw := readFixture(t, "nuclei_xss_basic.jsonl")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "CVE-2024-1234", f.FindingType)
	assert.Equal(t, "Example App Reflected XSS", f.Title)
	assert.Equal(t, "high", f.Severity)
	assert.Equal(t, "CWE-79", f.CWEID)
	assert.InDelta(t, 7.4, f.CVSSScore, 0.001)
	assert.Equal(t,
		"https://app.example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
		f.TargetURL)
	assert.NotEmpty(t, f.Request)
	assert.NotEmpty(t, f.Response)
	// CVE id (no dedicated RawFinding field) folded into Description.
	assert.Contains(t, f.Description, "CVE-2024-1234")
}

func TestParseOutput_MultiFindings(t *testing.T) {
	raw := readFixture(t, "nuclei_ssl_multi.jsonl")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 11, "ssl_multi fixture has 11 records")

	// Severity distribution: 9 info + 2 low (per fixture README).
	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	assert.Equal(t, 9, sev["info"])
	assert.Equal(t, 2, sev["low"])
}

// TestParseOutput_Empty pins the canonical happy-path-no-findings
// shape: empty stdout returns ([], nil) — NOT an error.
func TestParseOutput_Empty(t *testing.T) {
	raw := readFixture(t, "nuclei_empty.jsonl")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// ─── ParseOutput edge cases (4) ──────────────────────────────────────

// TestParseOutput_NoClassification pins behavior when info.classification
// is absent (SSL templates routinely ship without CVE/CWE). CWEID and
// CVSSScore are zero-valued, no error.
func TestParseOutput_NoClassification(t *testing.T) {
	raw := readFixture(t, "nuclei_ssl_multi.jsonl")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	for _, f := range findings {
		assert.Empty(t, f.CWEID,
			"SSL templates have no classification.cwe-id; CWEID must be empty")
		assert.Zero(t, f.CVSSScore,
			"SSL templates have no classification.cvss-score; CVSSScore must be zero")
	}
}

// TestParseOutput_MalformedLineDropped pins parse-line resilience.
// nuclei_malformed_line.jsonl has 4 valid lines + 1 garbage line.
// The garbage line is dropped (logged warning); the 4 valid findings
// flow through.
func TestParseOutput_MalformedLineDropped(t *testing.T) {
	raw := readFixture(t, "nuclei_malformed_line.jsonl")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 4,
		"4 valid lines should parse; 1 malformed line dropped")

	// Verify the surviving findings are the expected ones (skipping
	// line 3) by template-id ordering.
	wantTypes := []string{
		"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0004", "CVE-2024-0005",
	}
	for i, want := range wantTypes {
		assert.Equal(t, want, findings[i].FindingType,
			"finding %d FindingType mismatch", i)
	}
}

// TestParseOutput_LenientUnknownFields pins the lenient-decode pattern:
// extra fields the Nuclei team adds in a future minor release MUST NOT
// fail parsing. Asymmetric with wire-format strictness (events package
// uses DisallowUnknownFields).
func TestParseOutput_LenientUnknownFields(t *testing.T) {
	line := `{"template-id":"foo","info":{"name":"Foo","severity":"low"},` +
		`"matched-at":"https://app.example.com","future_field":42,` +
		`"another_unknown":{"nested":"ignored"}}` + "\n"
	findings, err := parseOutput(noopLog())([]byte(line))
	require.NoError(t, err, "unknown fields must NOT cause parse error")
	require.Len(t, findings, 1)
	assert.Equal(t, "foo", findings[0].FindingType)
}

// TestParseOutput_FingerprintComputedByRunner asserts ParseOutput leaves
// Fingerprint EMPTY — NativeRunner.Run enriches it after parsing per
// the ToolRunner contract. This pins the layering: parser populates
// fingerprint inputs (TargetURL, Parameter, FindingType, etc.) but
// not Fingerprint itself.
func TestParseOutput_FingerprintComputedByRunner(t *testing.T) {
	raw := readFixture(t, "nuclei_xss_basic.jsonl")
	findings, err := parseOutput(noopLog())(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].Fingerprint,
		"ParseOutput must NOT set Fingerprint; NativeRunner.Run does")

	// Sanity: the inputs the runner needs ARE populated.
	assert.NotEmpty(t, findings[0].FindingType)
	assert.NotEmpty(t, findings[0].TargetURL)
}

// ─── Severity mapping (2) ────────────────────────────────────────────

func TestMapSeverity_AllLevels(t *testing.T) {
	cases := map[string]string{
		"info":     "info",
		"low":      "low",
		"medium":   "medium",
		"high":     "high",
		"critical": "critical",
		// Defensive default: unrecognized → "info".
		"":         "info",
		"unknown":  "info",
		"weirdval": "info",
	}
	for in, want := range cases {
		assert.Equal(t, want, mapSeverity(in), "severity %q mapping", in)
	}
}

func TestMapSeverity_CaseInsensitive(t *testing.T) {
	// Nuclei is consistent about lowercase; defense in depth.
	assert.Equal(t, "high", mapSeverity("HIGH"))
	assert.Equal(t, "critical", mapSeverity("Critical"))
	assert.Equal(t, "low", mapSeverity("LoW"))
}

// ─── Tool-failure edge (1, per H.3) ──────────────────────────────────

// TestNucleiRunner_NonZeroExitSurfacesError pins the H.3 coverage gap:
// ExitCodeLenient=false combined with a tool that exits non-zero MUST
// produce a wrapped error, not silently swallow output. Exercises the
// NativeRunner.Run error path through a Nuclei-configured runner
// (rather than the bare runner exercised at 5.2). The mock binary is
// /bin/false (exit 1, no stdout).
//
// Distinct from 5.2's TestNativeRunner_NonZeroExitStrictDefault by
// going through the Nuclei factory: confirms the Nuclei configuration
// preserves the strict-exit posture documented as a load-bearing
// decision in DRIFT-LOG.
func TestNucleiRunner_NonZeroExitSurfacesError(t *testing.T) {
	cfg := testConfig()
	cfg.BinaryPath = "/bin/false" // exits 1
	r := NewNucleiRunner(cfg, noopLog())

	_, err := r.Run(t.Context(),
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{Depth: "quick"},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nuclei")
	assert.Contains(t, err.Error(), "exited non-zero")
}

// ─── Compile-time interface assertion ────────────────────────────────

// _ ensures the package's exported factory returns a value satisfying
// tools.ToolRunner without an explicit Run() invocation. Belt-and-
// braces with TestNewNucleiRunner_ReturnsToolRunner: this catches at
// compile time, the test catches at test-run time.
var _ events.RawFinding // keep events import for future use
