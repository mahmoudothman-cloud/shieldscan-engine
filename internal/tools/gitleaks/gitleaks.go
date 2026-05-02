// Package gitleaks wires the Gitleaks native runner factory.
//
// Gitleaks (https://github.com/gitleaks/gitleaks) is a secrets-
// scanning tool invoked as a subprocess via tools.NativeRunner. This
// package supplies the BuildArgs + ParseOutput closures that adapt
// Gitleaks's JSON-array output to events.RawFinding.
//
// First-instance patterns introduced at M6.5:
//
//   - Constants-only field mapping. Gitleaks emits no per-finding
//     severity or CWE; both are tool-class constants
//     (SeverityCritical + CWEHardcodedCredentials). First instance in
//     M6; tracked for promotion at 3rd instance.
//
//   - Configuration-not-leniency exit-code handling. Gitleaks exits
//     non-zero on findings by default. We force clean exit at the
//     tool level via --exit-code=0; the runner stays
//     ExitCodeLenient=false. Third option in M6's exit-code
//     vocabulary (after naturally-clean at 6.1, runner-tolerates at
//     6.2).
//
//   - JSON-array parse format. Third format observed in M6, after
//     Nuclei JSONL (6.1) and Semgrep single-doc (6.2).
//
// What this package does NOT do:
//   - Register the runner with worker.Registry — deferred to M6.8.
//   - Provide Phase 1 startup binary verification — deferred to M6.8
//     wiring (per M6.5 watch item E).
//   - Apply ScanConfig.Depth (Gitleaks has no depth knob).
package gitleaks

import (
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Severity and CWE constants applied to every Gitleaks finding.
// Exported so M9 AI pipeline + downstream tooling can reference the
// canonical values without parsing them out of strings.
//
// SeverityCritical: secrets in source are exploit-class by definition.
// CWEHardcodedCredentials: CWE-798, Use of Hard-coded Credentials.
//
// Trigger to revisit: Gitleaks 8.x (or 9.x) ships per-rule severity
// or CWE. At that point, replace constants with a mapping function
// driven by the new fields.
const (
	SeverityCritical        = "critical"
	CWEHardcodedCredentials = "CWE-798"
)

// Config carries Gitleaks-specific runtime configuration resolved by
// cmd/worker/run.go (at 6.8) from env / config.Config.
type Config struct {
	// BinaryPath is the absolute path to the gitleaks binary.
	// Resolved from SHIELDSCAN_GITLEAKS_BINARY env (per the
	// SHIELDSCAN_<TOOL>_BINARY pattern promoted to
	// DEVELOPMENT-PATTERNS.md at M6.5; THIRD instance after Nuclei
	// + Semgrep) or exec.LookPath("gitleaks") fallback.
	BinaryPath string
}

// gitleaksTimeout is the per-tool default timeout. SAST-class;
// matches 6.2 Semgrep. Large-monorepo full-history scans that exceed
// this can override via ScanConfig.Timeout.
const gitleaksTimeout = 5 * time.Minute

// NewGitleaksRunner constructs a *tools.NativeRunner wired for
// Gitleaks.
//
// Construction defaults pinned (regression-guarded by
// TestNewGitleaksRunner_DefaultsApplied):
//   - ToolName="gitleaks", ToolCategory="secrets"
//   - Timeout=5m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (configuration-not-leniency: --exit-code=0
//     in BuildArgs forces tool to exit clean)
//   - Env=nil (Go-built binary; no Python warnings to suppress;
//     asymmetric with M6.2 Semgrep)
//
// The returned runner is registered with worker.Registry under
// engine name "gitleaks" by cmd/worker/run.go at M6.8.
func NewGitleaksRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:        "gitleaks",
		ToolCategory:    "secrets",
		BinaryPath:      cfg.BinaryPath,
		Timeout:         gitleaksTimeout,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: false,
		Env:             nil,
		BuildArgs:       buildArgs(cfg),
		ParseOutput:     parseOutput(log),
	}
}

// buildArgs returns a closure constructing the Gitleaks command line.
//
// Invocation shape (per TOOL-ARCH §6.6, verified valid in 8.21.2 at
// M6.5 pre-prep — no surgical patches needed):
//
//	gitleaks detect \
//	    --source={target.SourcePath} \
//	    --report-format=json \
//	    --report-path=/dev/stdout \
//	    --exit-code=0 \              # configuration-not-leniency
//	    --no-banner
//
// Notes:
//   - `gitleaks detect` is not deprecated in 8.21.2 (the newer
//     `git`/`dir` subcommands are alternatives, not replacements).
//   - --exit-code=0 forces clean exit even with leaks present. Pairs
//     with NativeRunner.ExitCodeLenient=false to keep exit semantics
//     strict-by-default while still tolerating the find-secrets-then-
//     succeed flow.
//   - --no-banner suppresses the ASCII-art Gitleaks banner that
//     emits on stderr.
//   - --no-git is NOT enabled: full-history scanning is the value-add
//     (catches removed-but-still-in-history secrets per TOOL-ARCH
//     §6.6). Trigger to revisit: customer with non-git source paths.
//   - ScanConfig.Depth silently ignored (no depth knob in Gitleaks).
//   - Auth: N/A (filesystem operation; no network surface).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"detect",
			"--source=" + target.SourcePath,
			"--report-format=json",
			"--report-path=/dev/stdout",
			"--exit-code=0",
			"--no-banner",
		}
	}
}
