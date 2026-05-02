// Package corstest holds tests for the CORStest CORS misconfiguration
// scanner native runner. First text-with-ANSI parser shape in M6.
package corstest

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

func noopLog() zerolog.Logger { return zerolog.New(nil).Level(zerolog.Disabled) }
func testConfig() Config      { return Config{BinaryPath: "/bin/echo"} }

// ─── Construction (3) ────────────────────────────────────────────────

func TestNewCORStestRunner_IdentityFields(t *testing.T) {
	r := NewCORStestRunner(testConfig(), noopLog())
	assert.Equal(t, "corstest", r.Name())
	assert.Equal(t, "api", r.Category())
}

// TestNewCORStestRunner_DefaultsApplied pins load-bearing defaults
// including SeverityMedium constant export (Pattern 4) + Pattern 3
// 5th-instance reinforcement.
func TestNewCORStestRunner_DefaultsApplied(t *testing.T) {
	r := NewCORStestRunner(testConfig(), noopLog())
	assert.Equal(t, 10*time.Minute, r.Timeout)
	assert.False(t, r.ExitCodeLenient, "naturally-clean: CORStest exits 0")
	assert.False(t, r.OutputFile, "stdout-mode (text parser)")
	assert.Contains(t, r.Env, "PYTHONWARNINGS=ignore",
		"5th instance of Pattern 3 (Python script invocation)")
}

func TestNewCORStestRunner_ConstantsExported(t *testing.T) {
	assert.Equal(t, "medium", SeverityMedium)
	assert.Equal(t, "CWE-942", CWEPermissiveCrossDomain)
}

// ─── BuildArgs (3) ───────────────────────────────────────────────────

// TestBuildArgs_GeneratesURLFile pins H.3 inline-tempfile workaround:
// BuildArgs creates a tempfile containing target.URL, passes its path
// as positional arg to corstest.
func TestBuildArgs_GeneratesURLFile(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://api.example.com"},
		tools.ScanConfig{},
	)
	require.NotEmpty(t, args)

	// Find the urlfile path argument (second-to-last; -v is last).
	// Format: [<urlfile>, "-v"] or similar.
	var urlfilePath string
	for _, a := range args {
		if strings.HasPrefix(a, "/tmp/") || strings.Contains(a, "shieldscan-corstest-") {
			urlfilePath = a
			break
		}
	}
	require.NotEmpty(t, urlfilePath, "expected tempfile path in args; got %v", args)

	// Verify file exists and contains target URL.
	data, err := os.ReadFile(urlfilePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "https://api.example.com")

	// Cleanup tempfile (parser would do this in real Run; tests clean up directly).
	_ = os.Remove(urlfilePath)
}

func TestBuildArgs_VerboseFlagPresent(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://api.example.com"},
		tools.ScanConfig{},
	)
	defer func() {
		// Cleanup any tempfile leftover.
		for _, a := range args {
			if strings.Contains(a, "shieldscan-corstest-") {
				_ = os.Remove(a)
			}
		}
	}()
	assert.Contains(t, strings.Join(args, " "), "-v",
		"verbose mode required for multi-line per-host record output")
}

func TestBuildArgs_NoUFlag(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://api.example.com"},
		tools.ScanConfig{},
	)
	defer func() {
		for _, a := range args {
			if strings.Contains(a, "shieldscan-corstest-") {
				_ = os.Remove(a)
			}
		}
	}()
	// Regression guard for TOOL-ARCH §6.9 patch: -u <url> stale; CORStest takes positional urlfile.
	for _, a := range args {
		assert.NotEqual(t, "-u", a, "-u is invalid for CORStest; positional urlfile required")
	}
}

// ─── ParseOutput (5) ─────────────────────────────────────────────────

func TestParseOutput_BasicVulnerable(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "corstest_basic.txt"))
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "medium", f.Severity, "Pattern 4: constant SeverityMedium")
	assert.Equal(t, "CWE-942", f.CWEID, "Pattern 4: constant CWE-942")
	assert.Contains(t, f.TargetURL, "api.example.com")
	assert.Contains(t, f.Description, "any origin allowed with credentials")
	// ANSI codes MUST NOT survive into Description.
	assert.NotContains(t, f.Description, "\x1b",
		"ANSI codes MUST be stripped from output fields")
}

// TestParseOutput_NotVulnerableSkipped pins the filter invariant:
// hosts marked "Not vulnerable" emit zero findings.
func TestParseOutput_NotVulnerableSkipped(t *testing.T) {
	// multi fixture has 3 vulnerable + 2 not-vulnerable; not-vulnerable filtered.
	findings, err := parseOutput(noopLog())(readFixture(t, "corstest_multi.txt"))
	require.NoError(t, err)
	require.Len(t, findings, 3, "5 hosts: 3 vulnerable + 2 not-vulnerable filtered = 3")

	// Verify no finding has "Not vulnerable" in Description.
	for _, f := range findings {
		assert.NotContains(t, f.Description, "Not vulnerable",
			"not-vulnerable hosts MUST be filtered out, not emitted")
	}
}

func TestParseOutput_Empty(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "corstest_empty.txt"))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutput_MalformedRecordsSkipped pins state-machine
// resilience. Fixture: 1 complete + 1 orphan-status-line + 1 missing-
// status record + 1 valid-after-bad. Net: 2 findings (complete +
// valid-after-bad).
func TestParseOutput_MalformedRecordsSkipped(t *testing.T) {
	findings, err := parseOutput(noopLog())(readFixture(t, "corstest_malformed.txt"))
	require.NoError(t, err)
	require.Len(t, findings, 2,
		"3 records: complete + orphan-skipped + no-status-skipped + valid-after-bad = 2")
}

// TestParseOutput_ANSICodesStripped is the explicit regression guard
// for the ANSI-stripping invariant: synthetic input with multiple
// escape sequences MUST produce clean Description text.
func TestParseOutput_ANSICodesStripped(t *testing.T) {
	input := "------\nResource: https://x.example.com\n" +
		"Origin:   https://x.example.com\n" +
		"ACAO:     -\nACAC:     -\n" +
		"\x1b[31m\x1b[1mx.example.com - Vulnerable: \x1b[0mtest desc\x1b[0m\n"
	findings, err := parseOutput(noopLog())([]byte(input))
	require.NoError(t, err)
	require.Len(t, findings, 1)

	for _, f := range findings {
		assert.NotContains(t, f.Description, "\x1b",
			"every output field MUST be ANSI-stripped")
		assert.NotContains(t, f.TargetURL, "\x1b")
		assert.NotContains(t, f.Title, "\x1b")
	}
}

// ─── stripANSI helper (1; table-driven) ──────────────────────────────

func TestStripANSI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no-codes", "plain text", "plain text"},
		{"single-code", "\x1b[31mred\x1b[0m", "red"},
		{"multi-codes", "\x1b[97;100mfg-bg\x1b[0m \x1b[1mbold\x1b[0m", "fg-bg bold"},
		{"reset-only", "\x1b[0mreset", "reset"},
		{"complex-fg-bg", "\x1b[38;5;202morange\x1b[0m", "orange"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, stripANSI(c.in))
		})
	}
}
