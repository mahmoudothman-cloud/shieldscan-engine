// Package nikto holds tests for the Nikto native runner. First
// XML parser shape in M6 (encoding/xml).
package nikto

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// NOTE: the empty-quote sequence in the message below lives in a Go
	// string literal, which gofmt leaves alone. Do NOT paste it into a
	// doc comment: gofmt's doc-comment pass rewrites two apostrophes into
	// a typographic close-quote, silently corrupting the quoted error.
	// That has now happened twice in this file. Describe the message in
	// comments; quote it only in code.
	//
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
	assert.True(t, r.ExitCodeLenient,
		"Nikto 2.5.0 exits 1 whenever it reports a finding (nikto.pl: "+
			"`exit $is_failure`), so a strict runner keeps only the scans that "+
			"found nothing; the parse is the gate instead")
	assert.Equal(t, []string{"PWD=" + filepath.Dir(testConfig().BinaryPath)}, r.Env,
		"PWD is pinned to the binary's directory so Nikto's EXECDIR probe "+
			"(`-d $ENV{PWD}/plugins`) cannot pick up a plugins/ dir that "+
			"happens to sit in the worker's launch directory")
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
// empty filename, reporting "Unable to open ... for write" against an
// empty path, and exit 2. buildArgs
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

// TestBuildArgs_TargetIsHostport pins the PLAIN-HTTP form.
//
// This test used to pass an https:// URL and assert the hostport form,
// which is precisely the Drift #71 mechanism written down as an
// expectation: Nikto does not infer TLS from the port, so "-h
// host:8443" scans plain HTTP and, against a TLS-only server, reports
// on the error page. The assertion was true of the code and wrong about
// the world. It now covers the case the hostport form is actually
// correct for; the TLS case is TestBuildArgs_TLSTargetIsPassedAsAURL.
func TestBuildArgs_TargetIsHostport(t *testing.T) {
	args := buildArgs(testConfig())(
		tools.Target{URL: "http://app.example.com:8443/path"},
		tools.ScanConfig{},
	)
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-h app.example.com:8443",
		"a plain-HTTP target is derived as hostname:port from the URL")
}

// TestBuildArgs_RaisesFailureLimitAboveTheSNIFloor pins the -Option
// override.
//
// Upstream nikto.conf ships FAILURES=20, and a TLS vhost hits that
// during normal operation: two plugins probe the target by IP, LW2 puts
// that IP in the SNI, and a name-based vhost rejects every one — 214
// such errors against a live host, all intrinsic. At 20 the scan was
// aborting a fifth of the way in and losing real findings (/.htpasswd
// among them). The limit must therefore clear the floor with margin.
//
// The value must reach Nikto as an ARGUMENT. It was first "fixed" by
// editing nikto.conf on the deployed host, which no rebuild reproduces
// and no repo records — the whole point of asserting it here.
func TestBuildArgs_RaisesFailureLimitAboveTheSNIFloor(t *testing.T) {
	assert.Greater(t, niktoFailureLimit, 214,
		"the limit must exceed the errors an SNI-requiring vhost produces "+
			"intrinsically, or every TLS scan aborts early")
	assert.NotZero(t, niktoFailureLimit,
		"0 disables the limit entirely; a blackholed host must still abort "+
			"rather than burn the full 15-minute timeout")

	args := buildArgs(testConfig())(
		tools.Target{URL: "https://app.example.com"},
		tools.ScanConfig{},
	)
	var optValue string
	for i, a := range args {
		if a == "-Option" && i+1 < len(args) {
			optValue = args[i+1]
			break
		}
	}
	assert.Equal(t, "FAILURES="+strconv.Itoa(niktoFailureLimit), optValue,
		"-Option must carry the failure-limit override")
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
// regression guard for the live full_web finding (nikto -o with an empty
// path). It drives
// the REAL NewNiktoRunner().Run() with a mock nikto that writes XML only
// when its -o path ends in .xml (mirroring nikto's XML plugin, which
// infers format from the extension). It passes only if the runner both
// substitutes {{outputFile}} for a real tempfile AND mints it with the
// .xml extension (OutputFileExtension). If the placeholder were left
// literal, OR the tempfile kept the framework-default .out, the mock
// exits 2 with nikto's real empty-path open error and Run errors.
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

// ─── Exit-code leniency (3) ──────────────────────────────────────────

// mockNiktoExiting writes a mock nikto that emits `report` to its -o
// path and then exits with `code`, so a test can drive the real runner
// through any (exit status, report contents) combination.
//
// The mock ignores the -o extension check the other mock enforces; the
// concern here is the exit gate, not placeholder substitution.
func mockNiktoExiting(t *testing.T, report string, code int) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "nikto-mock.sh")
	body := `#!/bin/sh
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
printf '%s' '` + report + `' > "$out"
echo "mock nikto: exiting ` + strconv.Itoa(code) + `" >&2
exit ` + strconv.Itoa(code) + `
`
	require.NoError(t, os.WriteFile(p, []byte(body), 0o755))
	return p
}

const mockValidReport = `<niktoscan><scandetails sitename="https://example.com:443">` +
	`<item id="999976"><description>The anti-clickjacking X-Frame-Options header is not present.</description>` +
	`<uri>/</uri></item></scandetails></niktoscan>`

// TestNiktoRunner_NonZeroExitWithReportStillYieldsFindings is the
// regression guard for the defect that made every real Nikto scan
// disappear.
//
// Nikto 2.5.0 sets `$is_failure = 1` when total_errors or total_vulns
// is non-zero and ends with `exit $is_failure`, so it exits 1 precisely
// when the scan WORKED. 2.1.5 always exited 0, which is why the runner
// was built strict. Measured on one target with identical flags: 2.1.5
// → exit 0, 2.5.0 → exit 1 alongside 7932 requests and 158 items.
//
// Under the old ExitCodeLenient=false the framework returned "nikto
// exited non-zero" and never called the parser, so the only scan that
// could reach the database was one that found nothing — indistinguishable
// from a flaky tool, which is what it was mistaken for.
func TestNiktoRunner_NonZeroExitWithReportStillYieldsFindings(t *testing.T) {
	r := NewNiktoRunner(Config{
		BinaryPath: mockNiktoExiting(t, mockValidReport, 1),
		TLSCapable: true,
	}, noopLog())

	findings, err := r.Run(t.Context(),
		tools.Target{URL: "https://example.com"}, tools.ScanConfig{})

	require.NoError(t, err,
		"exit 1 is Nikto 2.5.0 reporting that it FOUND something; the report "+
			"must still be parsed")
	require.Len(t, findings, 1)
	assert.Equal(t, "nikto-missing-xfo", findings[0].FindingType)
}

// TestNiktoRunner_LenientExitDoesNotSwallowCrash is the counterweight.
//
// Making the runner lenient removes the only signal the framework had
// that the subprocess failed, so the parse has to be a real gate rather
// than a formality. Each case below is a way Nikto can die that leaves
// a non-zero exit status the runner now ignores:
//
//   - no report at all: the process died before its XML plugin ran, or
//     the interpreter never started. NativeRunner mints the tempfile,
//     so this arrives as a ZERO-BYTE file rather than a missing one —
//     which the parser used to treat as a clean scan with no findings.
//   - truncated report: killed mid-write. Well-formedness is what
//     catches it.
//   - garbage on the output path: a Perl die, a usage message, an
//     interpreter error — anything that is not the XML we asked for.
//
// If any of these ever returns nil, a crashed scan is being recorded as
// a clean host.
func TestNiktoRunner_LenientExitDoesNotSwallowCrash(t *testing.T) {
	cases := []struct {
		name    string
		report  string
		code    int
		wantErr string
	}{
		{
			name:    "no report written",
			report:  ``,
			code:    2,
			wantErr: "empty",
		},
		{
			name:    "report truncated mid-write",
			report:  `<niktoscan><scandetails sitename="https://example.com:443"><item id="999976"`,
			code:    137,
			wantErr: "parse",
		},
		{
			name:    "interpreter error on the output path",
			report:  `Can&apos;t locate LW2.pm in @INC`,
			code:    2,
			wantErr: "parse",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewNiktoRunner(Config{
				BinaryPath: mockNiktoExiting(t, c.report, c.code),
				TLSCapable: true,
			}, noopLog())

			findings, err := r.Run(t.Context(),
				tools.Target{URL: "https://example.com"}, tools.ScanConfig{})

			require.Error(t, err,
				"a crashed nikto must fail the job; leniency covers the exit "+
					"code, not the report")
			assert.Contains(t, err.Error(), c.wantErr)
			assert.Empty(t, findings)
		})
	}
}

// TestNiktoRunner_PWDReachesTheSubprocess proves the EXECDIR guard is
// real and not merely a struct field.
//
// nikto.pl:345 resolves EXECDIR — the root for plugins/, databases/ and
// templates/ — by testing `-d "$ENV{'PWD'}/plugins"` BEFORE falling back
// to the script's own directory, and the shipped nikto.conf leaves
// EXECDIR unset. Go passes the parent environment through and cmd.Dir
// does not rewrite PWD, so without this the value Nikto reads is
// wherever the worker's shell was launched from.
//
// The assertion goes through Run rather than reading r.Env, because the
// question is what the CHILD sees: NativeRunner appends Env to the
// inherited environment, and it is os/exec's last-wins de-duplication
// that makes the override actually take effect.
//
// The mock is PERL, deliberately, and reports $ENV{'PWD'} — the exact
// expression nikto.pl evaluates. A /bin/sh mock reading $PWD proves
// nothing: POSIX shells recompute PWD from their own working directory
// at startup, so such a test passes or fails on the shell's behaviour
// rather than on the environment we set. (It failed here for that
// reason, reporting the go test working directory.) Perl does no such
// recomputation; %ENV is the raw inherited environment.
func TestNiktoRunner_PWDReachesTheSubprocess(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed; the mechanism under test is Perl's ENV hash")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "nikto-mock.pl")
	body := `#!/usr/bin/env perl
use strict;
use warnings;
my $out = "";
for my $i (0 .. $#ARGV - 1) { $out = $ARGV[$i + 1] if $ARGV[$i] eq "-o"; }
open(my $fh, ">", $out) or die "cannot open $out: $!";
print $fh '<niktoscan><scandetails sitename="https://example.com:443">'
        . '<item id="900001"><description>PWD=' . ($ENV{'PWD'} // "unset")
        . '</description><uri>/</uri></item></scandetails></niktoscan>';
close($fh);
`
	require.NoError(t, os.WriteFile(bin, []byte(body), 0o755))

	r := NewNiktoRunner(Config{BinaryPath: bin, TLSCapable: true}, noopLog())
	findings, err := r.Run(t.Context(),
		tools.Target{URL: "https://example.com"}, tools.ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	assert.Equal(t, "PWD="+dir, findings[0].Description,
		"the subprocess must see PWD pointing at the nikto binary's own "+
			"directory, not at the worker's launch directory")
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
