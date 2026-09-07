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
//   - Nikto 2.5.0 is required for HTTPS and is NOT available from apt,
//     which ships 2.1.5. That gap was never cosmetic: 2.1.5 cannot
//     negotiate TLS, so for the life of the deployment it produced
//     findings describing the server's plain-HTTP error page on every
//     HTTPS scan. Installed from source; see Config.TLSCapable.
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
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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

	// TLSCapable declares that the resolved binary can actually scan an
	// HTTPS target. Default false, which makes every TLS target a
	// recorded skip (see preflight).
	//
	// It defaults to false because the DEFAULT binary cannot: Ubuntu apt
	// ships Nikto 2.1.5 (2015), and no invocation of it reaches a TLS
	// server. Measured with Net::SSLeay 1.94 and IO::Socket::SSL 2.085
	// installed, so this was never a missing Perl module — the full
	// matrix is in buildTargetArg.
	//
	// Nikto 2.5.0, installed from source, DOES work, and the deployment
	// sets SHIELDSCAN_NIKTO_TLS_CAPABLE=1 against it. Verified against a
	// live TLS host: sitename "https://host:443/", 6951 checks run, and
	// findings naming the reverse proxy and real paths rather than the
	// error page.
	//
	// It stays a knob rather than a constant so that verifying a binary
	// needs no rebuild — flip it, run one scan, read the sitename — and
	// so the guard still fires if a host is ever rebuilt onto apt's
	// nikto, which REBUILD-RUNBOOK §3.2 installs by default.
	TLSCapable bool
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
		Preflight:           preflight(cfg),
		BuildArgs:           buildArgs(cfg),
		ParseOutputFile:     parseOutputFile(log),
	}
}

// ErrTLSUnsupported is returned for a TLS target when the configured
// Nikto cannot negotiate TLS.
//
// Deliberately an error and not an empty result. Nikto ran against every
// HTTPS target for the life of the deployment and reported the server's
// plain-HTTP error page as findings, which was indistinguishable from a
// clean scan in every artefact anyone looked at: the job completed, the
// count was non-zero, the findings had titles. Failing loudly is the
// point — the job goes terminal as job_completed(status=failed) carrying
// this text in error_message, which is persisted on scan_jobs and
// printed in the per-job log line.
var ErrTLSUnsupported = errors.New("nikto: cannot scan a TLS target")

// preflight refuses TLS targets unless the binary is known to handle
// them. Returns nil for plain-HTTP targets, which Nikto scans correctly.
func preflight(cfg Config) func(tools.Target, tools.ScanConfig) error {
	return func(target tools.Target, _ tools.ScanConfig) error {
		if cfg.TLSCapable || !targetUsesTLS(target.URL) {
			return nil
		}
		return fmt.Errorf(
			"%w (%s). This worker's Nikto is not declared TLS-capable. Ubuntu "+
				"apt ships 2.1.5, which speaks plain HTTP to the TLS port and "+
				"parses the server's error page as the site, while its -ssl "+
				"mode fails to connect at all; either way the findings "+
				"describe nothing real, so the scan is skipped rather than "+
				"reported. Fix: install Nikto 2.5.0 from source (VERSIONS.md "+
				"§2.5) and set SHIELDSCAN_NIKTO_TLS_CAPABLE=1 after confirming "+
				"the XML sitename reads https:// and not http://",
			ErrTLSUnsupported, target.URL)
	}
}

// targetUsesTLS reports whether reaching the target requires TLS.
//
// Scheme first, since that is what the orchestrator sets. Port 443 is a
// fallback for a scheme-less "host:port" target, which deriveTargetHostport
// already accepts.
func targetUsesTLS(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		switch u.Scheme {
		case "https", "wss":
			return true
		case "http", "ws":
			return false
		}
		return u.Port() == "443"
	}
	return strings.HasSuffix(rawURL, ":443")
}

// buildArgs returns a closure constructing the Nikto command line.
//
// Invocation:
//
//	nikto -h <hostname:port> -Format xml -o {{outputFile}} -ask no -nointeractive
//
// Per-flag rationale:
//   - -h <target>: a bare "host:port" for plain HTTP, but the FULL URL
//     for a TLS target — see buildTargetArg. Nikto has no auto-detect:
//     "-h host:443" is plain HTTP on every version tested, including
//     2.5.0. The scheme in a URL is what turns TLS on.
//   - -Format xml: XML output. Stable across Nikto 2.1.5 and 2.5.0.
//     NOT -Format txt (deprecated parser shape; XML is structured).
//   - -o {{outputFile}}: ADR-023 OutputFile placeholder. REQUIRED —
//     Nikto's XML report plugin (nikto_report_xml.plugin) writes to a
//     file and does NOT stream to stdout; `-Format xml` WITHOUT `-o`
//     makes it open an empty filename and exit 2 with
//     an "Unable to open ... for write" error naming an empty path
//     (found on live full_web bring-up).
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
			"-h", buildTargetArg(target.URL),
			"-Format", "xml",
			"-o", outputFilePlaceholder,
			"-ask", "no",
			"-nointeractive",
		}
	}
}

// buildTargetArg renders the -h value.
//
// Nikto does not infer TLS from the port. "-h host:443" speaks plain
// HTTP on every version measured — 2.1.5 and 2.5.0 both — and against a
// TLS-only server that yields the "400 The plain HTTP request was sent
// to HTTPS port" page, which Nikto then reports on as if it were the
// site. That is engine Drift #71, and passing a hostport was the whole
// mechanism.
//
// A URL target is what enables TLS. Measured against a live server:
//
//	2.1.5  -h host:443            → sitename "http://host:443"   (broken)
//	2.1.5  -h https://host/       → sitename "http://host:443"   (broken)
//	2.1.5  -h host:443 -ssl       → "No web server found"        (broken)
//	2.5.0  -h host:443            → sitename "http://host:443"   (broken)
//	2.5.0  -h https://host/       → sitename "https://host:443"  (WORKS)
//	2.5.0  -h host:443 -ssl       → sitename "https://host:443"  (works)
//
// The URL form is chosen over -ssl because the flag and the target are
// two things that have to agree, and the failure mode when they do not
// is silent: you get a scan of an error page that looks like a scan. A
// URL carries its own scheme, so there is nothing to keep in sync.
//
// Plain-HTTP targets keep the hostport form, which they have always
// used and which works.
func buildTargetArg(rawURL string) string {
	if targetUsesTLS(rawURL) {
		return rawURL
	}
	return deriveTargetHostport(rawURL)
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
