// Package nikto holds tests for the Nikto native runner. First
// XML parser shape in M6 (encoding/xml).
package nikto

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

func TestNewNiktoRunner_IdentityFields(t *testing.T) {
	r := NewNiktoRunner(testConfig(), noopLog())
	assert.Equal(t, "nikto", r.Name())
	assert.Equal(t, "infrastructure", r.Category())
}

// TestNewNiktoRunner_DefaultsApplied pins load-bearing defaults
// including SeverityLow constant export (Pattern 4).
func TestNewNiktoRunner_DefaultsApplied(t *testing.T) {
	r := NewNiktoRunner(testConfig(), noopLog())
	assert.Equal(t, 15*time.Minute, r.Timeout)
	assert.False(t, r.ExitCodeLenient, "naturally-clean: Nikto exits 0 even with findings")
	assert.Nil(t, r.Env, "Perl tool; no Python warnings to suppress")
	assert.True(t, r.OutputFile,
		"OutputFile mode: Nikto's XML plugin requires -o, it does not stream to stdout")
	assert.Equal(t, "{{outputFile}}", r.OutputFilePlaceholder)
	assert.NotNil(t, r.ParseOutputFile)
}

// TestNewNiktoRunner_ConstantsExported regression-guards Pattern 4
// constants-only contract: SeverityLow is a stable exported value
// applied to every Nikto RawFinding.
func TestNewNiktoRunner_ConstantsExported(t *testing.T) {
	assert.Equal(t, "low", SeverityLow)
}

// ─── BuildArgs (3) ───────────────────────────────────────────────────

func TestBuildArgs_HasAllRequiredFlags(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"-h",
		"-Format", "xml",
		"-o", "{{outputFile}}",
		"-ask", "no",
		"-nointeractive",
	} {
		assert.Contains(t, joined, want, "missing required flag/arg %q", want)
	}
}

// TestBuildArgs_HasNonEmptyOutputPath is the regression guard for the
// live full_web finding: `-Format xml` WITHOUT `-o` made Nikto open an
// empty filename ("Unable to open ” for write") and exit 2. buildArgs
// MUST pass a non-empty output-path argument immediately after -o.
func TestBuildArgs_HasNonEmptyOutputPath(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	var oValue string
	for i, a := range args {
		if a == "-o" && i+1 < len(args) {
			oValue = args[i+1]
			break
		}
	}
	require.NotEmpty(t, oValue, "-o must be present with a non-empty output path")
	assert.Equal(t, "{{outputFile}}", oValue,
		"-o must carry the ADR-023 OutputFile placeholder NativeRunner substitutes")
}

// TestBuildArgs_NoTextFormat is the regression guard for the
// TOOL-ARCH §6.7 surgical patch: -Format txt was stale; XML chosen
// for parser stability.
func TestBuildArgs_NoTextFormat(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	assert.NotContains(t, joined, "Format txt",
		"-Format txt deprecated at M6.6; XML parser invariant")
}

func TestBuildArgs_TargetIsHostport(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com:8443/path"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-h app.example.com:8443",
		"target derived as hostname:port from URL")
}

// ─── ParseOutput (5) ─────────────────────────────────────────────────

func TestParseOutput_BasicSingleFinding(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_basic.xml"))
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "nikto-999976", f.FindingType,
		"FindingType is 'nikto-' prefix + item id")
	assert.Contains(t, f.Description, "X-Frame-Options")
	assert.Equal(t, "low", f.Severity, "Pattern 4: constant SeverityLow")
	assert.Equal(t, "https://example.com:443/", f.TargetURL,
		"TargetURL derived from sitename + uri")
}

func TestParseOutput_MultiFindings(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_multi.xml"))
	require.NoError(t, err)
	require.Len(t, findings, 5)

	// All have constant severity.
	for _, f := range findings {
		assert.Equal(t, "low", f.Severity)
	}

	// Verify diversity — at least one finding mentions admin
	// (validates uri+sitename combination per finding).
	adminSeen := false
	for _, f := range findings {
		if strings.Contains(f.TargetURL, "/admin/") {
			adminSeen = true
			break
		}
	}
	assert.True(t, adminSeen, "expected /admin/ finding in multi fixture")
}

func TestParseOutput_Empty(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_empty.xml"))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestParseOutput_MalformedXMLFatal: top-level malformed XML IS
// fatal. Matches single-doc parser convention from 6.2/6.5/6.7.
func TestParseOutput_MalformedXMLFatal(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "malformed.xml")
	require.NoError(t,
		os.WriteFile(tmp, []byte(`<niktoscan><scandetails><item id="X"`), 0o644))
	_, err := parseOutputFile(noopLog())(tmp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nikto")
}

// TestParseOutput_MissingFieldsSkipped: items lacking `id` OR
// empty `description` are skipped with WARN; valid items flow.
// Fixture has 4 items; expect 2 surviving findings.
func TestParseOutput_MissingFieldsSkipped(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_missing_fields.xml"))
	require.NoError(t, err)
	require.Len(t, findings, 2,
		"4 items: 2 valid + missing-id + empty-description = 2 surviving")

	for _, f := range findings {
		assert.NotEmpty(t, f.FindingType)
		assert.NotEmpty(t, f.Description)
	}
}

// ─── deriveTargetHostport helper (1) ─────────────────────────────────

func TestDeriveTargetHostport(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"https-default-port", "https://example.com", "example.com:443"},
		{"https-explicit-port", "https://example.com:8443/path", "example.com:8443"},
		{"http-default-port", "http://example.com", "example.com:80"},
		{"raw-hostport", "example.com:8080", "example.com:8080"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, deriveTargetHostport(c.url))
		})
	}
}
