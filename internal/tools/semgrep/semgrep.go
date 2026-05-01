// Package semgrep wires the Semgrep native runner factory.
//
// Semgrep (https://semgrep.dev/) is a SAST tool invoked as a
// subprocess via tools.NativeRunner. This package supplies the
// BuildArgs + ParseOutput closures that adapt Semgrep's `--json`
// single-doc output to events.RawFinding.
//
// First non-trivial M6 patterns introduced here:
//
//   - First non-identity severity mapping (ERROR/WARNING/INFO →
//     high/medium/info; see severity.go + DRIFT-LOG M6.2 entry 1).
//   - First ExitCodeLenient=true real use (Semgrep exits non-zero on
//     genuine tool errors, exit 0 with `--config=p/default` on
//     findings).
//   - First populated NativeRunner.Env (PYTHONWARNINGS=ignore, to
//     suppress pkg_resources deprecation noise on stderr).
//   - First populated CodeFile/CodeLine/CodeSnippet/OWASP in
//     RawFinding outputs (Nuclei left these empty — DAST vs SAST).
//
// What this package does NOT do:
//   - Register the runner with worker.Registry — deferred to M6.8
//     wiring task.
//   - Apply ScanConfig.Depth (Semgrep's `p/default` ruleset has no
//     quick/standard/deep knob; trigger to revisit: customer demand
//     for tiered SAST).
//   - Validate Target.SourcePath existence (processor populates;
//     Semgrep itself errors cleanly via errors[] if missing).
package semgrep

import (
	"strconv"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Config carries Semgrep-specific runtime configuration resolved by
// cmd/worker/run.go (at 6.8) from env / config.Config.
type Config struct {
	// BinaryPath is the absolute path to the semgrep binary.
	// Resolved from SHIELDSCAN_SEMGREP_BINARY env (lean per H.6;
	// SECOND instance of this pattern after Nuclei) or
	// exec.LookPath("semgrep") fallback. On Ubuntu 24.04 with pipx
	// install, the typical path is ~/.local/bin/semgrep.
	BinaryPath string
}

// semgrepTimeout is the per-tool default timeout. SAST is fast;
// 5 minutes covers typical repos. Large monorepos that exceed this
// can override via ScanConfig.Timeout at job-dispatch time per
// NativeRunner.effectiveTimeout precedence.
const semgrepTimeout = 5 * time.Minute

// semgrepPerFileTimeoutSeconds is Semgrep's per-file regex-execution
// timeout. Distinct from the outer NativeRunner timeout: protects
// against pathological regex backtracking on a single file. 120s per
// TOOL-ARCH §6.2.
const semgrepPerFileTimeoutSeconds = 120

// NewSemgrepRunner constructs a *tools.NativeRunner wired for Semgrep.
//
// Construction defaults pinned (regression-guarded by
// TestNewSemgrepRunner_DefaultsApplied):
//   - ToolName="semgrep", ToolCategory="sast"
//   - Timeout=5m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=true (FIRST non-trivial M6 use)
//   - Env=["PYTHONWARNINGS=ignore"] (FIRST populated Env in M6;
//     suppresses pkg_resources deprecation warning emitted by
//     Semgrep 1.95.0 on Python 3.12 with setuptools<81 workaround)
//
// The returned runner is registered with worker.Registry under
// engine name "semgrep" by cmd/worker/run.go at M6.8.
func NewSemgrepRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:        "semgrep",
		ToolCategory:    "sast",
		BinaryPath:      cfg.BinaryPath,
		Timeout:         semgrepTimeout,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: true,
		Env:             []string{"PYTHONWARNINGS=ignore"},
		BuildArgs:       buildArgs(cfg),
		ParseOutput:     parseOutput(log),
	}
}

// buildArgs returns a closure constructing the Semgrep command line.
//
// Invocation shape (per TOOL-ARCH §6.2 with M6.2 privacy patches):
//
//	semgrep scan \
//	    --config=p/default \      privacy: built-in fixed ruleset
//	    --json \                  single-doc JSON to stdout
//	    --quiet \                 suppress banner/progress
//	    --metrics=off \           defense-in-depth: no telemetry
//	    --timeout=120 \           per-file regex catastrophe guard
//	    {target.SourcePath}
//
// Notes:
//   - --config=auto NOT used: requires Semgrep telemetry ON (verified
//     empirically; see DRIFT-LOG M6.2 entry 4). p/default is the
//     privacy-preserving alternative.
//   - --error NOT used: keeps exit-code semantics simple (0 on clean
//     run, 2 on tool error). ExitCodeLenient=true tolerates either
//     regime; omitting --error reduces surprise.
//   - ScanConfig.Depth is silently ignored at M6.2 (Semgrep's
//     p/default has no depth knob).
//   - ScanConfig.MaxRPS is N/A (SAST is filesystem-bound).
//   - Auth: N/A (Semgrep operates on filesystem; no network auth
//     surface).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"scan",
			"--config=p/default",
			"--json",
			"--quiet",
			"--metrics=off",
			"--timeout=" + strconv.Itoa(semgrepPerFileTimeoutSeconds),
			target.SourcePath,
		}
	}
}
