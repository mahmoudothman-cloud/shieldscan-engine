// Package checkov wires the Checkov IaC native runner.
//
// Checkov (https://github.com/bridgecrewio/checkov) is a multi-
// framework IaC scanner invoked as a subprocess via tools.NativeRunner.
// This package supplies the BuildArgs + ParseOutput closures that
// adapt Checkov's `-o json` single-doc output to events.RawFinding.
//
// First-instance and pattern-promotion notes at M6.7:
//
//   - Constants-only field mapping (2nd instance after Gitleaks).
//     OSS Checkov emits severity=null for all checks; CWE absent.
//     SeverityMedium + CWEIaCMisconfiguration are exported constants
//     applied to every finding.
//
//   - Configuration-not-leniency exit-code (2nd instance after
//     Gitleaks). --soft-fail in BuildArgs forces clean exit;
//     ExitCodeLenient stays false.
//
//   - PYTHONWARNINGS=ignore Env (3rd instance — promotion to
//     DEVELOPMENT-PATTERNS.md Pattern 3 lands at M6.7 commit).
//     Defense-in-depth despite no observed warnings at 3.2.340.
//
// What this package does NOT do at M6.7:
//   - Register the runner with worker.Registry (deferred to M6.8).
//   - Multi-framework dispatch (one Run() = one invocation =
//     one check_type; Checkov autodetects all framework files in
//     the target directory).
//   - Apply ScanConfig.Depth (no quick/standard/deep knob).
package checkov

import (
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Constants applied to every Checkov finding (per H.NEW.1 + H.NEW.2).
//
// SeverityMedium: OSS Checkov emits severity=null; "medium" is the
// industry-standard default for IaC misconfigurations.
//
// CWEIaCMisconfiguration: CWE-1032 covers all Checkov rule classes
// (S3 misconfig, security-group misconfig, missing-encryption, etc.).
//
// Exported so M9 AI pipeline + downstream tooling can reference the
// canonical values without parsing them out of strings. Trigger to
// revisit: Checkov adds per-check severity (commercial Bridgecrew
// Cloud feature; unlikely in OSS but possible).
const (
	SeverityMedium         = "medium"
	CWEIaCMisconfiguration = "CWE-1032"
)

// Config carries Checkov-specific runtime configuration resolved by
// cmd/worker/run.go (at 6.8).
type Config struct {
	// BinaryPath is the absolute path to checkov binary. Resolved
	// via SHIELDSCAN_CHECKOV_BINARY env (DEVELOPMENT-PATTERNS.md
	// Pattern 2; 6th instance after Nuclei + Semgrep + Gitleaks +
	// SSLyze + Dep-Check) or exec.LookPath("checkov") fallback.
	// On Ubuntu 24.04 with pipx install: ~/.local/bin/checkov.
	BinaryPath string
}

const checkovTimeout = 5 * time.Minute

// NewCheckovRunner constructs a *tools.NativeRunner wired for
// Checkov in stdout-mode.
//
// Construction defaults pinned (regression-guarded by
// TestNewCheckovRunner_DefaultsApplied):
//   - ToolName="checkov", ToolCategory="iac"
//   - Timeout=5m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (paired with --soft-fail flag in
//     BuildArgs — configuration-not-leniency 2nd instance after
//     6.5 Gitleaks)
//   - Env=["PYTHONWARNINGS=ignore"] (3rd instance → DEVELOPMENT-
//     PATTERNS.md Pattern 3 promotion)
//   - OutputFile=false (Checkov writes JSON to stdout natively)
func NewCheckovRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:        "checkov",
		ToolCategory:    "iac",
		BinaryPath:      cfg.BinaryPath,
		Timeout:         checkovTimeout,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: false,
		Env:             []string{"PYTHONWARNINGS=ignore"},
		BuildArgs:       buildArgs(cfg),
		ParseOutput:     parseOutput(log),
	}
}

// buildArgs returns a closure constructing the Checkov command line.
//
// Invocation shape (matches TOOL-ARCH §6.11; verified valid at M6.7
// pre-prep with v3.2.340):
//
//	checkov -d {target.SourcePath} \
//	        -o json \
//	        --quiet \
//	        --soft-fail
//
// Notes:
//   - --soft-fail forces exit 0 even when failures present. Pairs
//     with ExitCodeLenient=false (configuration-not-leniency 2nd
//     instance).
//   - -o json (single-doc output to stdout).
//   - --quiet suppresses progress chatter on stderr.
//   - Multi-framework: one invocation autodetects all framework
//     files in the directory. Per H.4 lean: one Run() = one
//     invocation; per-framework invocation deferred until customer
//     ask.
//   - ScanConfig.Depth ignored (no Checkov knob).
//   - Auth: N/A (filesystem-only operation).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"-d", target.SourcePath,
			"-o", "json",
			"--quiet",
			"--soft-fail",
		}
	}
}
