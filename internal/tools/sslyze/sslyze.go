// Package sslyze wires the SSLyze native runner factory.
//
// SSLyze (https://github.com/nabla-c0d3/sslyze) is an SSL/TLS
// configuration scanner invoked as a subprocess via tools.NativeRunner.
// This package supplies the BuildArgs + ParseOutput closures that
// adapt SSLyze's --json_out plugin diagnostics to events.RawFinding.
//
// Architecturally significant first-instance patterns at M6.4:
//
//   - "Plugin-rules parser" / "synthetic-finding parser" pattern.
//     SSLyze emits structured plugin diagnostics, NOT a finding list.
//     Our parser SYNTHESIZES findings via per-plugin domain rules
//     (rules.go). 1st instance in M6; tracked for promotion at 3rd
//     instance (likely 6.6 Wapiti or 6.7 Dep-Check).
//
//   - "Domain-rules severity mapping" pattern. Per-plugin severity
//     and CWE tables (severity.go) reflect real exploit-class /
//     vulnerability-class judgments rather than identity passthrough
//     or constants. 1st instance; tracked for promotion.
//
//   - First-time-populated RawFinding fields: CipherSuite (cipher
//     findings) and CertSubject (certificate findings). Both fields
//     have been defined in events.RawFinding since M5.1 but were
//     dormant until M6.4 finally exercised them.
//
// What this package does NOT do at M6.4:
//   - Register the runner with worker.Registry (deferred to M6.8).
//   - Detect HSTS (deferred to DAST layer per Nuclei templates).
//   - Detect TLS 1.2 / TLS 1.3 cipher weaknesses (modern protocol
//     SUPPORT is GOOD, not a finding; weak-cipher-on-modern-protocol
//     detection deferred until customer demand).
//   - Apply ScanConfig.Depth (no quick/standard/deep knob in
//     SSLyze's plugin model).
package sslyze

import (
	"net/url"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Config carries SSLyze-specific runtime configuration resolved by
// cmd/worker/run.go (at 6.8) from env / config.Config.
type Config struct {
	// BinaryPath is the absolute path to the sslyze binary.
	// Resolved via the SHIELDSCAN_<TOOL>_BINARY pattern
	// (DEVELOPMENT-PATTERNS.md Pattern 2; 4th instance after
	// Nuclei + Semgrep + Gitleaks).
	BinaryPath string
}

const sslyzeTimeout = 5 * time.Minute

// NewSSLyzeRunner constructs a *tools.NativeRunner wired for SSLyze.
//
// Construction defaults pinned (regression-guarded by
// TestNewSSLyzeRunner_DefaultsApplied):
//   - ToolName="sslyze", ToolCategory="ssl"
//   - Timeout=5m
//   - MaxStdoutBytes=tools.DefaultMaxStdoutBytes (50 MiB)
//   - ExitCodeLenient=false (naturally-clean per pre-prep; 2nd
//     instance after M6.1 Nuclei)
//   - Env=["PYTHONWARNINGS=ignore"] (defense-in-depth; 2nd instance
//     of Env pattern after M6.2; not yet at promotion threshold)
func NewSSLyzeRunner(cfg Config, log zerolog.Logger) *tools.NativeRunner {
	return &tools.NativeRunner{
		ToolName:        "sslyze",
		ToolCategory:    "ssl",
		BinaryPath:      cfg.BinaryPath,
		Timeout:         sslyzeTimeout,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: false,
		Env:             []string{"PYTHONWARNINGS=ignore"},
		BuildArgs:       buildArgs(cfg),
		ParseOutput:     parseOutput(log),
	}
}

// buildArgs returns a closure constructing the SSLyze command line.
//
// Invocation shape (replaces TOOL-ARCH §6.5 stale `--regular`
// literal at the M6.4 docs commit; see DRIFT-LOG entry 12):
//
//	sslyze --json_out=- \
//	    --certinfo \
//	    --heartbleed --robot --openssl_ccs --reneg \
//	    --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
//	    --compression --fallback --ems \
//	    {hostname}:{port}
//
// Per-flag notes:
//   - --json_out=-: stream JSON to stdout (verified working in 6.1.0
//     at pre-prep).
//   - --regular: deliberately omitted; invalid in 6.1.0
//     (unrecognized arguments error). TOOL-ARCH §6.5 patched at
//     M6.4 docs commit.
//   - Per-target invocation (Option X per pre-prep H.NEW.2);
//     ScanConfig.MaxRPS / Depth ignored (no SSLyze knob).
//   - Auth: N/A (TLS-handshake-level probe; no application-layer
//     auth surface).
func buildArgs(_ Config) func(tools.Target, tools.ScanConfig) []string {
	return func(target tools.Target, _ tools.ScanConfig) []string {
		return []string{
			"--json_out=-",
			"--certinfo",
			"--heartbleed", "--robot", "--openssl_ccs", "--reneg",
			"--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
			"--compression", "--fallback", "--ems",
			deriveBuildArgsTarget(target),
		}
	}
}

// deriveBuildArgsTarget converts a Target into SSLyze's expected
// "<hostname>[:<port>]" argument:
//
//   - target.URL parsed as URL → use Hostname() + Port() (default 443
//     when scheme is https and no explicit port)
//   - parse failure → fall back to target.URL verbatim (operator-
//     supplied "host:port" string)
//
// Per H.13: target syntax pinned in DRIFT-LOG entry 13.
func deriveBuildArgsTarget(target tools.Target) string {
	if target.URL == "" {
		return ""
	}
	u, err := url.Parse(target.URL)
	if err != nil || u.Host == "" {
		return target.URL
	}
	host := u.Hostname()
	if host == "" {
		return target.URL
	}
	port := u.Port()
	if port == "" {
		// Default to 443 for https/wss; otherwise leave port unset
		// so SSLyze applies its own default.
		switch u.Scheme {
		case "https", "wss":
			port = "443"
		}
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}
