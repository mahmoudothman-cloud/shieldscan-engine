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
//   - Nikto 2.5.0 EXITS NON-ZERO WHENEVER IT REPORTS ANYTHING, which
//     inverts the meaning of a successful scan — see ExitCodeLenient in
//     NewNiktoRunner. This is the single most important thing to know
//     about running this tool from a program.
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
	"path/filepath"
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

// niktoTimeout bounds a single-target scan. Nikto runs ~6950 checks.
//
// Measured: a complete scan of a live TLS host (Caddy-fronted, small
// site) takes 460s — 8266 requests — so one target sits comfortably
// inside 15 minutes. Note this is PER TARGET and the runner is invoked
// per target: a full_web scan of four subdomains is ~4x460s of wall
// clock spread across four runs, each with its own 15-minute budget.
// That is a scan-duration consideration for the orchestrator, not a
// timeout problem here; left as-is deliberately.
const niktoTimeout = 15 * time.Minute

// niktoFailureLimit is the value passed as `-Option FAILURES=`, which
// overrides the FAILURES setting in the installed nikto.conf.
//
// Nikto aborts a host once it accumulates this many request errors.
// Upstream ships FAILURES=20, and against any TLS vhost that number is
// reached during normal operation, killing the scan a fifth of the way
// in: two plugins deliberately connect to the target BY IP —
// nikto_headers' IIS internal-IP check (18 URIs) and nikto_sitefiles,
// which tries every path twice, once with the Host header and once
// "requested by IP address". LW2 derives the TLS SNI from the same
// field it connects to, so those probes present an IP literal as the
// SNI name, and any name-based vhost (Caddy, nginx server_name) answers
// with a TLS alert. Measured against a live host: 884 connects, of
// which 400 were by-IP and ALL 400 failed, for 214 counted errors.
//
// So ~214 errors is a floor for a perfectly healthy target, not a
// symptom — the by-IP probes cannot succeed against an SNI-requiring
// server and there is no flag to disable just that half (the
// with-Host-header half of nikto_sitefiles is real coverage worth
// keeping). The limit therefore has to clear the floor with margin
// for a larger sitefiles database, which 1000 does at ~4.5x.
//
// It is deliberately not 0 ("disable entirely"). A genuinely dead or
// blackholed host should still abort rather than burn the full
// 15-minute timeout; at the observed ~5 errors/sec, 1000 aborts such a
// host in ~3 minutes.
//
// This lives here, in the args, and NOT in nikto.conf on the host. A
// setting that exists only in the deployed nikto.conf is invisible to
// the repo and does not survive REBUILD-RUNBOOK §3.2 — which is
// exactly how it was first "fixed", and exactly why the scan that
// found this regressed the moment the box was considered rebuildable.
const niktoFailureLimit = 1000

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
//   - ExitCodeLenient=true — Nikto 2.5.0 exits 1 on ANY finding (see below)
//   - Env pins PWD (see niktoEnv; EXECDIR resolution)
//   - OutputFile=true (ADR-023; Nikto's XML plugin REQUIRES -o, it does
//     not stream XML to stdout — see buildArgs)
//   - OutputFilePlaceholder="{{outputFile}}"; ParseOutputFile set
//   - OutputFileExtension=".xml" (Nikto's XML plugin infers format from
//     the -o extension and rejects the framework-default ".out")
//
// ExitCodeLenient is true because Nikto 2.5.0's exit status is inverted
// relative to every other tool in the engine. nikto.pl:189 does:
//
//	if ($mark->{'total_errors'} > 0 || $mark->{'total_vulns'} > 0) {
//	    $is_failure = 1;
//	}
//	...
//	exit $is_failure;
//
// so the tool exits 1 precisely when it has something to report. 2.1.5
// ended in a bare `exit;` and always returned 0, which is why the
// runner was built strict and why nothing caught this until 2.5.0 was
// installed. Measured on one target (OWASP Juice Shop, plain HTTP,
// identical flags): 2.1.5 → exit 0; 2.5.0 → exit 1 with 7932 requests,
// 158 items and 2 errors — a completely successful scan. Under
// ExitCodeLenient=false the framework discards the report before
// parsing it, so the ONLY nikto scan that could reach the database was
// one that found nothing. A tool that fails whenever it succeeds.
//
// Leniency is safe here because the parse is the real gate, and it is
// a strict one: ParseOutputFile errors on an unreadable file, on an
// empty file, and on malformed XML, so a nikto that dies mid-write or
// never runs still fails the job (TestNiktoRunner_LenientExitDoesNot
// SwallowCrash). What leniency gives up is the ability to distinguish
// a complete scan from one Nikto aborted on its error limit — both
// write well-formed XML with a <statistics> element. That is why
// niktoFailureLimit is set high enough that the abort means a real
// outage rather than routine SNI mismatches.
func NewNiktoRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:              "nikto",
		ToolCategory:          "infrastructure",
		BinaryPath:            cfg.BinaryPath,
		Timeout:               niktoTimeout,
		MaxStdoutBytes:        tools.DefaultMaxStdoutBytes,
		ExitCodeLenient:       true,
		Env:                   niktoEnv(cfg),
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

// niktoEnv pins PWD to the directory holding the nikto script, which
// makes Nikto's plugin/database resolution independent of wherever the
// worker process happens to have been launched from.
//
// This is a guard against a live landmine. nikto.pl's setup_dirs
// resolves EXECDIR — the root for plugins/, databases/, templates/ and
// docs/ — in this order (nikto.pl:345):
//
//	unless (defined $CONFIGFILE{'EXECDIR'}) {
//	    if    (-d "$ENV{'PWD'}/plugins")   { ... = $ENV{'PWD'} }
//	    elsif (-d "$CURRENTDIR/plugins")   { ... = $CURRENTDIR }
//
// The environment's PWD wins over the script's own location, and the
// shipped nikto.conf leaves EXECDIR commented out, so that first branch
// is live. Go's exec passes the parent's environment through, and
// setting cmd.Dir does NOT rewrite PWD — so the value Nikto reads is
// whatever directory the worker's shell was in at launch. Today that is
// the engine checkout, which has no plugins/ subdirectory, so it falls
// through and everything works. The day anyone adds one — a Go package
// named plugins, a vendored tool tree — Nikto would silently load
// plugins and vulnerability databases from the engine repo instead of
// from its own install, with no error and no log line.
//
// Pointing PWD at the binary's own directory makes both branches agree
// and removes the coupling. It is also correct for the fallback case:
// if BinaryPath is apt's /usr/bin/nikto, /usr/bin/plugins does not
// exist, so resolution falls through to the script directory exactly as
// it does today.
//
// Returns nil when BinaryPath is empty (exec.LookPath fallback), which
// leaves the inherited environment untouched.
func niktoEnv(cfg Config) []string {
	if cfg.BinaryPath == "" {
		return nil
	}
	dir, err := filepath.Abs(filepath.Dir(cfg.BinaryPath))
	if err != nil {
		return nil
	}
	return []string{"PWD=" + dir}
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
//	nikto -h <target> -Format xml -o {{outputFile}} -ask no \
//	      -nointeractive -Option FAILURES=1000
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
//   - -Option FAILURES=<n>: raises the per-host error limit above the
//     ~214 errors an SNI-requiring vhost produces intrinsically — see
//     niktoFailureLimit for the mechanism and the measurement.
//     -Option is Nikto 2.5.0's general "override any nikto.conf
//     setting from the command line" flag; it is what lets this be a
//     property of the engine rather than a hand-edit on one host.
//     Verified to win over the installed nikto.conf: with the shipped
//     FAILURES=20 the same scan aborts at 19s ("Error limit (20)
//     reached for host"), and with -Option FAILURES=1000 it does not.
//     2.1.5 does not have -Option, but 2.1.5 cannot reach a TLS target
//     at all, so it never gets far enough to need it.
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
			"-Option", "FAILURES=" + strconv.Itoa(niktoFailureLimit),
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
