// Package nikto wires the Nikto web-server scanner native runner.
//
// Nikto (https://github.com/sullo/nikto) is a Perl-based web-server
// security auditor invoked as a subprocess via tools.NativeRunner.
// This package supplies the BuildArgs + ParseOutputFile closures that
// adapt Nikto's `-Format xml` file output to events.RawFinding
// (ADR-023 OutputFile mode — Nikto's XML plugin requires -o).
//
// First-instance patterns at M6.6:
//
//   - First XML parser shape in M6 (encoding/xml). 4th format after
//     JSONL (6.1) + single-doc JSON (6.2) + JSON-array (6.5).
//
//   - Constants-only field mapping (Pattern 4 application; 3rd
//     instance after Gitleaks + Checkov in the promotion sequence).
//     Every Nikto finding is informational web-server misconfig →
//     SeverityLow constant.
//
// Operational notes (OPS milestone M11):
//
//   - Nikto pinned at 2.5.0 in VERSIONS.md but Ubuntu apt only ships
//     2.1.5. Either accept apt's 2.1.5 (recommended; XML parser
//     stable across 2.x) or install from source for 2.5.0.
//
//   - SHIELDSCAN_NIKTO_BINARY env var (Pattern 2 from 6.5; 7th
//     instance) or exec.LookPath("nikto") fallback.
//
// What this package does NOT do at M6.6:
//   - Register the runner with worker.Registry (deferred to M6.8).
//   - Apply ScanConfig.Depth (Nikto has no quick/standard/deep knob
//     in the same sense; Tuning options exist but operator-tuned).
//   - Configure a per-finding CWE — Nikto rules span too many CWE
//     classes for a meaningful constant; CWEID stays empty per
//     finding.
package nikto

import (
	"net/url"
	"strconv"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// SeverityLow is the constant Severity applied to every Nikto
// finding (Pattern 4 — constants-only field mapping).
//
// Nikto findings are uniformly informational web-server misconfigs
// (missing security headers, uncommon banners, directory listings).
// Industry-standard severity for these is "low".
//
// Exported so M9 AI pipeline + downstream tooling can reference the
// canonical value.
//
// Trigger to revisit: customer asks for finer-grained Nikto severity
// OR Nikto 3.x adds per-finding severity field.
const SeverityLow = "low"

// Config carries Nikto-specific runtime configuration.
type Config struct {
	// BinaryPath is the absolute path to the nikto binary. Resolved
	// via SHIELDSCAN_NIKTO_BINARY env (DEVELOPMENT-PATTERNS.md
	// Pattern 2; 7th instance) or exec.LookPath("nikto") fallback.
	// Ubuntu apt: /usr/bin/nikto.
	BinaryPath string
}

const niktoTimeout = 15 * time.Minute // Nikto runs ~6500 checks; can be slow

// outputFilePlaceholder matches the Wapiti / Dep-Check convention
// (ADR-023 OutputFile mode).
const outputFilePlaceholder = "{{outputFile}}"

// NewNiktoRunner constructs a *tools.NativeRunner wired for Nikto.
//
// Construction defaults pinned (regression-guarded by
// TestNewNiktoRunner_DefaultsApplied):
//   - ToolName="nikto", ToolCategory="infrastructure"
//   - Timeout=15m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (naturally-clean; 4th instance)
//   - Env=nil (Perl tool; no Python warnings)
//   - OutputFile=true (ADR-023; Nikto's XML plugin REQUIRES -o, it does
//     not stream XML to stdout — see buildArgs)
//   - OutputFilePlaceholder="{{outputFile}}"; ParseOutputFile set
//   - OutputFileExtension=".xml" (Nikto's XML plugin infers format from
//     the -o extension and rejects the framework-default ".out")
func NewNiktoRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:              "nikto",
		ToolCategory:          "infrastructure",
		BinaryPath:            cfg.BinaryPath,
		Timeout:               niktoTimeout,
		MaxStdoutBytes:        tools.DefaultMaxStdoutBytes,
		ExitCodeLenient:       false,
		Env:                   nil,
		OutputFile:            true,
		OutputFilePlaceholder: outputFilePlaceholder,
		// Nikto's XML report plugin infers format from the -o extension
		// and refuses a ".out" file — the tempfile MUST end in ".xml".
		OutputFileExtension: ".xml",
		BuildArgs:           buildArgs(cfg),
		ParseOutputFile:     parseOutputFile(log),
	}
}

// buildArgs returns a closure constructing the Nikto command line.
//
// Invocation:
//
//	nikto -h <hostname:port> -Format xml -o {{outputFile}} -ask no -nointeractive
//
// Per-flag rationale:
//   - -h <target>: target hostname (with port). Derived from
//     target.URL via deriveTargetHostport (similar to 6.4 SSLyze).
//   - -Format xml: XML output. Stable across Nikto 2.1.5 and 2.5.0.
//     NOT -Format txt (deprecated parser shape; XML is structured).
//   - -o {{outputFile}}: ADR-023 OutputFile placeholder. REQUIRED —
//     Nikto's XML report plugin (nikto_report_xml.plugin) writes to a
//     file and does NOT stream to stdout; `-Format xml` WITHOUT `-o`
//     makes it open an empty filename and exit 2 with
//     "Unable to open ” for write" (found on live full_web bring-up).
//     The M6.6 "XML to stdout" assumption was wrong; corrected to
//     OutputFile mode (3rd ADR-023 consumer, after Dep-Check + Wapiti).
//   - -ask no: never prompt for user input (CI safety).
//   - -nointeractive: no terminal interaction.
//
// ScanConfig.Depth ignored at 6.6 (no Nikto knob with that semantic).
// Auth: N/A (Nikto operates on HTTP-handshake-level probes).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"-h", deriveTargetHostport(target.URL),
			"-Format", "xml",
			"-o", outputFilePlaceholder,
			"-ask", "no",
			"-nointeractive",
		}
	}
}

// deriveTargetHostport converts target.URL into Nikto's expected
// "<hostname>:<port>" -h argument:
//
//   - HTTPS URL → host:443 (default) or explicit port
//   - HTTP URL → host:80 (default) or explicit port
//   - parse failure → return verbatim (operator-supplied "host:port")
//   - empty → empty
//
// Mirrors 6.4 SSLyze deriveBuildArgsTarget shape.
func deriveTargetHostport(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	host := u.Hostname()
	if host == "" {
		return rawURL
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https", "wss":
			port = strconv.Itoa(443)
		case "http", "ws":
			port = strconv.Itoa(80)
		}
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}
