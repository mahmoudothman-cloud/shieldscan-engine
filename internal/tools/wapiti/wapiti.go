// Package wapiti wires the Wapiti DAST native runner.
//
// Wapiti (https://wapiti-scanner.github.io/) is a web-application
// vulnerability scanner invoked as a subprocess via tools.NativeRunner.
// This package supplies the BuildArgs + ParseOutputFile closures.
//
// SECOND consumer of NativeRunner OutputFile mode (ADR-023; first
// consumer was Dep-Check at M6.7). Wapiti is forced into file-output
// mode by a Wapiti bug: `-o /dev/stdout` corrupts the JSON output
// stream by injecting a "report has been generated" message INTO the
// JSON. Verified empirically at M6.6 pre-prep. ADR-023 OutputFile
// mode is the documented workaround.
//
// Pattern advances at M6.6:
//
//   - ADR-023 OutputFile mode reaches 2 instances (Dep-Check +
//     Wapiti). Track for 3rd-instance promotion to a possible
//     framework-tier pattern entry.
//   - PYTHONWARNINGS=ignore Env reaches 4 instances (Pattern 3 from
//     6.7 reinforced; no new promotion needed).
//   - Domain-rules severity mapping reaches 2 instances (SSLyze 1st
//     at 6.4, Wapiti 2nd at 6.6 with level int → canonical). Track.
//
// Distinction from SSLyze plugin-rules pattern (DRIFT-LOG M6.6 entry 6):
// Wapiti's `vulnerabilities` map is category-keyed iteration where
// every per-instance shape is uniform. SSLyze's `scan_result` map
// has structurally distinct per-plugin diagnostic shapes (heartbleed
// has bool field; certificate_info has chain array; etc.). Plugin-
// rules pattern stays at 1 instance — Wapiti is "category-keyed
// iteration", a simpler variant.
//
// What this package does NOT do at M6.6:
//   - Register the runner with worker.Registry (deferred to M6.8).
//   - Parse `anomalies` or `additionals` blocks (non-vulnerability
//     observations; not actionable as findings at MVP).
//   - Apply ScanConfig.Depth (no Wapiti knob with that semantic).
package wapiti

import (
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Config carries Wapiti-specific runtime configuration.
type Config struct {
	// BinaryPath is the absolute path to the wapiti binary. Resolved
	// via SHIELDSCAN_WAPITI_BINARY env (DEVELOPMENT-PATTERNS.md
	// Pattern 2; 8th instance) or exec.LookPath("wapiti") fallback.
	// pipx default: ~/.local/bin/wapiti.
	BinaryPath string
}

const wapitiTimeout = 15 * time.Minute // DAST scans are slow

// outputFilePlaceholder matches Dep-Check's convention (ADR-023).
const outputFilePlaceholder = "{{outputFile}}"

// NewWapitiRunner constructs a *tools.NativeRunner wired for Wapiti
// in NativeRunner.OutputFile mode (ADR-023 2nd consumer).
//
// Construction defaults pinned (regression-guarded by
// TestNewWapitiRunner_DefaultsApplied):
//   - ToolName="wapiti", ToolCategory="dast"
//   - Timeout=15m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (naturally-clean; 5th instance)
//   - Env=["PYTHONWARNINGS=ignore"] (Pattern 3 4th instance)
//   - OutputFile=true (ADR-023 2nd consumer; Wapiti bug workaround)
//   - OutputFilePlaceholder="{{outputFile}}" (matches Dep-Check)
//   - ParseOutputFile set; ParseOutput nil
func NewWapitiRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:              "wapiti",
		ToolCategory:          "dast",
		BinaryPath:            cfg.BinaryPath,
		Timeout:               wapitiTimeout,
		MaxStdoutBytes:        tools.DefaultMaxStdoutBytes,
		ExitCodeLenient:       false,
		Env:                   []string{"PYTHONWARNINGS=ignore"},
		OutputFile:            true,
		OutputFilePlaceholder: outputFilePlaceholder,
		BuildArgs:             buildArgs(cfg),
		ParseOutputFile:       parseOutputFile(log),
	}
}

// buildArgs returns a closure constructing the Wapiti command line.
//
// Invocation (replaces TOOL-ARCH §6.8 stale `-o /dev/stdout` literal
// at M6.6 docs commit):
//
//	wapiti -u <target.URL> \
//	       -f json \
//	       -o {{outputFile}} \
//	       --flush-session
//
// Per-flag rationale:
//   - -u <URL>: target URL.
//   - -f json: JSON output format.
//   - -o {{outputFile}}: ADR-023 OutputFile placeholder. Wapiti bug:
//     -o /dev/stdout corrupts JSON. Using a real tempfile is the
//     documented workaround.
//   - --flush-session: discard persistent state from prior runs.
//     Per-scan fresh state avoids stale-session bugs across customer
//     scans.
//
// ScanConfig.Depth ignored at M6.6 (no Wapiti --max-scan-time set
// at this layer; outer NativeRunner timeout 15min applies).
// Auth: N/A (deferred to ADR-015 reservation).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"-u", target.URL,
			"-f", "json",
			"-o", outputFilePlaceholder,
			"--flush-session",
		}
	}
}
