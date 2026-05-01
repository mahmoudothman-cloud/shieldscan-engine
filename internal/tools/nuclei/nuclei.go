// Package nuclei wires the Nuclei native runner factory.
//
// Nuclei (https://github.com/projectdiscovery/nuclei) is a template-
// driven DAST scanner invoked as a subprocess via tools.NativeRunner.
// This package supplies the BuildArgs + ParseOutput closures that
// adapt Nuclei's JSONL output to events.RawFinding.
//
// Architectural commitments (per M5 chassis inheritance):
//   - Returns *tools.NativeRunner; subprocess lifecycle, timeout,
//     stdout cap, ctx cancellation, and fingerprint enrichment are
//     handled by NativeRunner.Run (Task 5.2).
//   - Tool-output decode is LENIENT (map[string]any + type-asserted
//     extraction); asymmetric with wire-format strictness in
//     internal/events. See engine DRIFT-LOG M6.1 entry.
//   - ExitCodeLenient=false: Nuclei is well-behaved on exit codes,
//     so non-zero exit is a real error.
//   - Auth (ScanConfig + Target.AuthConfig) is reserved for ADR-015;
//     this package ships no auth-injection logic at M6.1.
//
// What this package does NOT do:
//   - Register the runner with worker.Registry — deferred to M6.8
//     wiring task per landscape Finding 1.
//   - Provide a CLI entrypoint — cmd/worker/run.go calls
//     NewNucleiRunner during 6.8 Phase 1 binary-verification +
//     registry population.
package nuclei

import (
	"strconv"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Config carries the Nuclei-specific runtime configuration resolved
// from env / config.Config by cmd/worker/run.go (at 6.8). All fields
// are required for a fully-functional runner; default values are
// supplied by the caller, not by this package.
type Config struct {
	// BinaryPath is the absolute path to the nuclei binary. Resolved
	// from SHIELDSCAN_NUCLEI_BINARY env (lean per H.1) or
	// exec.LookPath("nuclei") fallback.
	BinaryPath string

	// TemplatesDir is the absolute path to the Nuclei templates
	// directory. Resolved from SHIELDSCAN_NUCLEI_TEMPLATES env (lean
	// per H.8) or default ~/nuclei-templates.
	TemplatesDir string

	// DefaultRPS is the rate-limit fallback when ScanConfig.MaxRPS
	// is zero. 50 is the canonical default per plan §6.1; operators
	// may tune via config.
	DefaultRPS int
}

// nucleiTimeout is the default per-tool timeout. 30 minutes covers
// deep scans against large targets; cfg.Timeout (when >0) overrides
// at job-dispatch time per NativeRunner.effectiveTimeout precedence.
const nucleiTimeout = 30 * time.Minute

// NewNucleiRunner constructs a *tools.NativeRunner wired for Nuclei.
//
// The returned runner is registered with worker.Registry under the
// engine name "nuclei" by cmd/worker/run.go at M6.8.
func NewNucleiRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:        "nuclei",
		ToolCategory:    "dast",
		BinaryPath:      cfg.BinaryPath,
		Timeout:         nucleiTimeout,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: false,
		BuildArgs:       buildArgs(cfg),
		ParseOutput:     parseOutput(log),
	}
}

// buildArgs returns a closure that constructs Nuclei's command-line
// arguments per target + scan config.
//
// Base flags (always present):
//
//	-u <target.URL>                    single target URL
//	-t <cfg.TemplatesDir>              templates directory
//	-jsonl                             JSONL output to stdout
//	-silent                            suppress banner/progress
//	-no-color                          disable ANSI in output
//	-duc                               disable update-check (offline-safe)
//	-rl <rps>                          rate limit
//
// Depth-derived flag:
//
//	"quick"    → -severity high,critical
//	"standard" → -severity medium,high,critical
//	"deep"     → (omitted; runs all severities)
//	other      → treated as "deep" (no filter)
//
// Notes:
//   - Auth handling is intentionally absent (ADR-015 reservation). If
//     Target.AuthConfig is non-nil at runtime, the underlying tool is
//     still invoked without auth flags; M6.1 does NOT error on this
//     path because Target.AuthConfig is reserved for future use and
//     the processor does not yet populate it.
//   - The template categories field on ScanConfig (TemplateCategories)
//     is reserved for an extension; M6.1 ignores it and relies on
//     -severity for depth tuning. Trigger to use: customer ask for
//     OWASP-only or CVE-only template scoping.
func buildArgs(cfg Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, scanCfg tools.ScanConfig) []string {
		args := []string{
			"-u", target.URL,
			"-t", cfg.TemplatesDir,
			"-jsonl",
			"-silent",
			"-no-color",
			"-duc",
		}

		// Rate limit: ScanConfig.MaxRPS overrides Config.DefaultRPS.
		rps := cfg.DefaultRPS
		if scanCfg.MaxRPS > 0 {
			rps = scanCfg.MaxRPS
		}
		if rps > 0 {
			args = append(args, "-rl", strconv.Itoa(rps))
		}

		// Depth → severity filter. "deep" / unknown → no filter.
		switch scanCfg.Depth {
		case "quick":
			args = append(args, "-severity", "high,critical")
		case "standard":
			args = append(args, "-severity", "medium,high,critical")
		}

		return args
	}
}

// Compile-time assertion: nucleiRunnerType signals that NewNucleiRunner
// returns a value satisfying tools.ToolRunner. The runtime test
// TestNewNucleiRunner_ReturnsToolRunner is the test-time complement.
var _ tools.ToolRunner = (*tools.NativeRunner)(nil)

// _ keeps the events import alive for godoc; lineToFinding consumes
// events.RawFinding internally but the linker may otherwise GC the
// import in IDE displays.
var _ = events.RawFinding{}
