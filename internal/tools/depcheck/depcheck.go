// Package depcheck wires the OWASP Dependency-Check native runner.
//
// Dep-Check (https://github.com/jeremylong/DependencyCheck) is an
// SCA scanner invoked as a subprocess via tools.NativeRunner. This
// package supplies the BuildArgs + ParseOutputFile closures.
//
// FIRST USE of NativeRunner.OutputFile mode (ADR-023). Dep-Check
// writes findings to a file path passed via --out, NOT to stdout
// (whose content is logging chatter). The framework extension
// landed in M6.7 specifically to support this shape; the hack
// alternatives (closure-shared state, fixed paths, per-PID nanosec
// timestamps) were all evaluated and rejected as race-prone or
// architecturally messy.
//
// Operational notes (OPS milestone M11 picks up):
//
//   - Dep-Check requires JDK at runtime (verified at M6.7 pre-prep:
//     `apt install default-jre` resolves; bundled OpenJDK 21 works).
//     provision-worker.sh must install Java alongside the Dep-Check
//     unzip.
//
//   - NVD scans require an API key (NVD's unauthenticated endpoint
//     returns 403/404 as of 2026). Set DEPCHECK_NVD_API_KEY env or
//     pass --nvdApiKey via NativeRunner.Env. M6.7 ships the env
//     passthrough but does NOT ship a key.
//
// What this package does NOT do at M6.7:
//   - Register the runner with worker.Registry (deferred to M6.8).
//   - Configure the NVD API key (deferred to OPS milestone).
//   - Apply ScanConfig.Depth (no quick/standard/deep knob in
//     Dep-Check's invocation model).
package depcheck

import (
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Config carries Dep-Check-specific runtime configuration resolved
// by cmd/worker/run.go (at 6.8).
type Config struct {
	// BinaryPath is the absolute path to dependency-check.sh
	// (script, NOT a single binary like Go tools). Resolved via
	// SHIELDSCAN_DEPCHECK_BINARY env (DEVELOPMENT-PATTERNS.md
	// Pattern 2; 5th instance after Nuclei + Semgrep + Gitleaks +
	// SSLyze) or exec.LookPath("dependency-check.sh") fallback.
	BinaryPath string
}

// depcheckTimeout is the per-tool default. SCA scans on monorepos
// can take 5-10 minutes; 15-min has 1.5× margin per TOOL-ARCH §6.10.
const depcheckTimeout = 15 * time.Minute

// outputFilePlaceholder is the literal substring NativeRunner
// substitutes with the per-Run tempfile path (ADR-023).
const outputFilePlaceholder = "{{outputFile}}"

// NewDepCheckRunner constructs a *tools.NativeRunner wired for
// Dep-Check in NativeRunner.OutputFile mode.
//
// Construction defaults pinned (regression-guarded by
// TestNewDepCheckRunner_DefaultsApplied):
//   - ToolName="depcheck", ToolCategory="sca"
//   - Timeout=15m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (naturally-clean; --failOnCVSS
//     deliberately omitted; 3rd instance of pattern after 6.1, 6.4)
//   - OutputFile=true (FIRST USE in M6 of ADR-023 framework feature)
//   - OutputFilePlaceholder="{{outputFile}}"
//   - ParseOutputFile set; ParseOutput nil (mutually exclusive
//     in valid configs)
//   - Env=nil (JVM tool; PYTHONWARNINGS pattern doesn't apply)
func NewDepCheckRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:              "depcheck",
		ToolCategory:          "sca",
		BinaryPath:            cfg.BinaryPath,
		Timeout:               depcheckTimeout,
		MaxStdoutBytes:        tools.DefaultMaxStdoutBytes,
		ExitCodeLenient:       false,
		Env:                   nil,
		OutputFile:            true,
		OutputFilePlaceholder: outputFilePlaceholder,
		BuildArgs:             buildArgs(cfg),
		ParseOutputFile:       parseOutputFile(log),
	}
}

// buildArgs returns a closure constructing the Dep-Check command line.
//
// Invocation shape (matches TOOL-ARCH §6.10; verified valid at
// M6.7 pre-prep with v9.2.0):
//
//	dependency-check.sh \
//	    --scan {target.SourcePath} \
//	    --format JSON \
//	    --out {{outputFile}}      # NativeRunner substitutes per-Run
//	    --project {project_name}
//
// Notes:
//   - --failOnCVSS DELIBERATELY OMITTED. Naturally-clean exit-code
//     pattern (3rd instance after 6.1 Nuclei + 6.4 SSLyze).
//   - --noupdate / --nvdApiKey configuration deferred to OPS
//     milestone (DEPCHECK_NVD_API_KEY env var passthrough).
//   - --project is passed as a stable string ("shieldscan-scan")
//     for the report header; doesn't affect findings.
//   - ScanConfig.Depth ignored (no Dep-Check knob).
//   - Auth: N/A (filesystem-only operation).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"--scan", target.SourcePath,
			"--format", "JSON",
			"--out", outputFilePlaceholder,
			"--project", "shieldscan-scan",
		}
	}
}
