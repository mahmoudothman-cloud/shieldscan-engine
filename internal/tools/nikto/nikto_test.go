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

// mockNiktoScript writes a mock nikto that honors -o: it locates the -o
// value in its args and writes valid nikto XML to THAT path (like real
// nikto's XML plugin). If -o is empty (the placeholder was never
// substituted), it emits nikto's real failure and exits 2.
func mockNiktoScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "nikto-mock.sh")
	// Mirrors real nikto: the XML report plugin infers format from the -o
	// extension and refuses anything that isn't .xml (empty / unsubstituted
	// / .out all fail with the empty-path error). The description and the
	// http-on-443 sitename are copied verbatim from a real 2.1.5 run — a
	// paraphrased message would classify differently from the real thing,
	// which is the mistake the old fixtures made.
	body := `#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
case "$out" in
  *.xml) ;;
  *)
    echo "Unable to open '' for write at nikto_report_xml.plugin line 60" >&2
    exit 2
    ;;
esac
cat > "$out" <<'XML'
<niktoscan><scandetails sitename="http://example.com:443"><item id="999976"><description>The anti-clickjacking X-Frame-Options header is not present.</description><uri>/</uri></item></scandetails></niktoscan>
XML
`
	require.NoError(t, os.WriteFile(p, []byte(body), 0o755))
	return p
}

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
	assert.Equal(t, ".xml", r.OutputFileExtension,
		"Nikto's XML plugin infers format from the -o extension; must be .xml, not the default .out")
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
	assert.Equal(t, "nikto-missing-xfo", f.FindingType,
		"FindingType is the derived class slug, not the raw item id")
	assert.Equal(t, "The anti-clickjacking X-Frame-Options header is not present.", f.Title,
		"Title comes from the message text")
	assert.Contains(t, f.Description, "X-Frame-Options")
	assert.Equal(t, "low", f.Severity, "Pattern 4: constant SeverityLow")
	// Captured from a real run against a TLS host: Nikto 2.1.5 writes
	// "http://" for a target on 443 because it never negotiated TLS. The
	// fixture used to say "https://", which real Nikto never emits — the
	// hand-written value is why nothing caught that.
	assert.Equal(t, "http://example.com:443/", f.TargetURL,
		"TargetURL derived from sitename + uri")
}

// TestParseOutput_MultiFindings runs the real captured output of a Nikto
// scan against a live application. The fixture holds 11 items, six of
// which are the "Uncommon header" class; five findings survive.
func TestParseOutput_MultiFindings(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_multi.xml"))
	require.NoError(t, err)
	require.Len(t, findings, 5,
		"11 items minus 6 Uncommon-header observations = 5 findings")

	for _, f := range findings {
		assert.Equal(t, "low", f.Severity)
		assert.NotEqual(t, f.Title, f.FindingType,
			"Title must be the message, not a repeat of the identifier")
	}

	// Per-item uri is combined with sitename, so different items on the
	// same host get different TargetURLs.
	var urls []string
	for _, f := range findings {
		urls = append(urls, f.TargetURL)
	}
	assert.Contains(t, urls, "http://shop.example.com:3000/ftp/")
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
		assert.NotEmpty(t, f.Title)
	}
}

// ─── OutputFile substitution end-to-end (1) ──────────────────────────

// TestNiktoRunner_OutputFilePlaceholderSubstituted is the end-to-end
// regression guard for the live full_web finding (nikto -o ”). It drives
// the REAL NewNiktoRunner().Run() with a mock nikto that writes XML only
// when its -o path ends in .xml (mirroring nikto's XML plugin, which
// infers format from the extension). It passes only if the runner both
// substitutes {{outputFile}} for a real tempfile AND mints it with the
// .xml extension (OutputFileExtension). If the placeholder were left
// literal, OR the tempfile kept the framework-default .out, the mock
// exits 2 with nikto's real "open '' for write" message and Run errors.
// Unlike the parser tests (which bypass Run), this exercises the exact
// path that failed live.
//
// TLSCapable is set so the preflight does not refuse the https target
// before the subprocess runs. This test is about placeholder
// substitution; the TLS policy has its own tests below.
func TestNiktoRunner_OutputFilePlaceholderSubstituted(t *testing.T) {
	r := NewNiktoRunner(
		Config{BinaryPath: mockNiktoScript(t), TLSCapable: true}, noopLog())
	findings, err := r.Run(
		t.Context(),
		tools.Target{URL: "https://example.com"},
		tools.ScanConfig{},
	)
	require.NoError(t, err,
		"Run must succeed: -o {{outputFile}} must be substituted to a real tempfile path")
	require.Len(t, findings, 1,
		"the finding proves the mock wrote to the substituted -o path and ParseOutputFile read it")
	assert.Equal(t, "nikto-missing-xfo", findings[0].FindingType)
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
