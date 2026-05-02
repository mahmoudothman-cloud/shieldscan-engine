// Package corstest wires the CORStest CORS misconfiguration scanner
// native runner.
//
// CORStest (https://github.com/RUB-NDS/CORStest) is a small Python
// research tool invoked as a subprocess via tools.NativeRunner. This
// package supplies the BuildArgs + ParseOutput closures that adapt
// CORStest's text-with-ANSI output to events.RawFinding.
//
// First-instance patterns at M6.6:
//
//   - First text-with-ANSI parser shape in M6 (5th format after
//     JSONL + single-doc JSON + JSON-array + XML). 1st-instance
//     pattern; track for 3rd-instance promotion.
//
//   - Pattern 4 (Constants-only field mapping) application: every
//     CORStest finding is uniformly a CORS misconfiguration →
//     SeverityMedium + CWE-942 (Permissive Cross-domain Policy with
//     Untrusted Domains).
//
//   - InputFile workaround per H.3 (inline-tempfile-cleanup-in-
//     parser): CORStest takes a positional URL-list file, NOT a -u
//     flag. BuildArgs mints a per-Run tempfile via os.CreateTemp,
//     writes target.URL to it, passes path. Cleanup is best-effort
//     (defer in BuildArgs not possible; OS-level /tmp cleanup
//     handles eventual reaping). Documented as workaround, NOT
//     canonical: future input-file tools should propose framework
//     extension (InputFile mode similar to ADR-023 OutputFile) at
//     3rd instance per asymmetric-cost reasoning.
//
// Operational notes (OPS milestone M11):
//
//   - CORStest is git-pinned (no semver). VERSIONS.md mentions
//     "Pin to specific commit SHA" but no SHA listed; OPS milestone
//     needs to pick one.
//
//   - CORStest is invoked as `python3 corstest.py <urlfile>`. SHIELDSCAN_
//     CORSTEST_BINARY env should point to a wrapper script (e.g.,
//     /usr/local/bin/corstest) that does `exec python3 /opt/CORStest/
//     corstest.py "$@"`. PYTHONWARNINGS=ignore Env applies to the
//     python3 subprocess.
//
//   - Pattern 3 (PYTHONWARNINGS=ignore) reaches 5 instances at M6.6
//     (Semgrep + SSLyze + Checkov + Wapiti + CORStest).
//
// What this package does NOT do at M6.6:
//   - Register the runner with worker.Registry (deferred to M6.8).
//   - Apply ScanConfig.Depth (CORStest has no depth knob).
//   - Multi-target batch invocation (CORStest takes a URL file but
//     M6.6 uses single-URL-per-file per Option X precedent).
package corstest

import (
	"os"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Constants applied to every CORStest finding (Pattern 4 — constants-
// only field mapping). Exported so M9 AI pipeline + downstream tooling
// can reference canonical values.
//
// SeverityMedium: CORS misconfigs are medium-severity per OWASP API
// Top 10 + OWASP A01:2021 (Broken Access Control). Wildcard-with-
// credentials and origin-reflection both fall in this band.
//
// CWEPermissiveCrossDomain: CWE-942 covers all CORStest-class
// findings (permissive cross-domain policy with untrusted domains).
//
// Trigger to revisit: customer asks for per-CORS-class severity
// (wildcard-with-credentials → high; null-origin → medium; reflected-
// origin → low). At that point, replace constants with mapping
// function driven by the description text.
const (
	SeverityMedium           = "medium"
	CWEPermissiveCrossDomain = "CWE-942"
)

// Config carries CORStest-specific runtime configuration.
type Config struct {
	// BinaryPath is the absolute path to the CORStest invocation
	// wrapper. Resolved via SHIELDSCAN_CORSTEST_BINARY env
	// (DEVELOPMENT-PATTERNS.md Pattern 2; 9th instance) or
	// exec.LookPath("corstest") fallback.
	BinaryPath string
}

const corstestTimeout = 10 * time.Minute

// NewCORStestRunner constructs a *tools.NativeRunner wired for CORStest.
//
// Construction defaults pinned (regression-guarded by
// TestNewCORStestRunner_DefaultsApplied):
//   - ToolName="corstest", ToolCategory="api"
//   - Timeout=10m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (naturally-clean; 6th instance)
//   - Env=["PYTHONWARNINGS=ignore"] (Pattern 3 5th instance)
//   - OutputFile=false (text parser stdout-mode)
func NewCORStestRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:        "corstest",
		ToolCategory:    "api",
		BinaryPath:      cfg.BinaryPath,
		Timeout:         corstestTimeout,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: false,
		Env:             []string{"PYTHONWARNINGS=ignore"},
		BuildArgs:       buildArgs(cfg),
		ParseOutput:     parseOutput(log),
	}
}

// buildArgs returns a closure constructing the CORStest command line.
//
// Invocation (replaces TOOL-ARCH §6.9 stale `-u <url>` literal at
// M6.6 docs commit):
//
//	corstest <urlfile> -v
//
// Per H.3 inline-tempfile workaround: BuildArgs creates a per-Run
// tempfile via os.CreateTemp, writes target.URL to it, passes path
// as positional argument. -v enables verbose multi-line per-host
// records that the parser consumes.
//
// CRITICAL: tempfile cleanup is best-effort (no defer hook in
// BuildArgs surface; ParseOutput cannot reach a path created here
// without closure-shared state). OS-level /tmp cleanup handles
// eventual reaping. Acceptable for small URL files (a few hundred
// bytes typically).
//
// Trigger to formalize as framework extension (InputFile mode per
// ADR-023 sibling): 3rd instance of input-file-needing tool. At
// that point, asymmetric-cost reasoning may justify the abstraction
// (similar to ADR-023's threshold override).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		// Mint per-Run tempfile; concurrency-safe via os.CreateTemp.
		// Cleanup is OS-level /tmp reaping (best-effort; documented
		// limitation per H.3 inline-tempfile workaround).
		f, err := os.CreateTemp("", "shieldscan-corstest-*.urls")
		if err != nil {
			// On tempfile creation failure, return args without urlfile.
			// Subprocess will fail with a clear error; runner surfaces
			// it as Run error. Better than panicking.
			return []string{"-v"}
		}
		urlfilePath := f.Name()
		// Write target URL + newline; CORStest reads URLs line-by-line.
		_, _ = f.WriteString(target.URL + "\n")
		_ = f.Close()

		return []string{urlfilePath, "-v"}
	}
}
