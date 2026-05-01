package semgrep

import "strings"

// mapSeverity converts a Semgrep `extra.severity` to the canonical
// RawFinding.Severity. FIRST non-identity severity table in M6
// (contrast with internal/tools/nuclei/severity.go which is identity).
//
// Mapping (load-bearing decisions; see engine DRIFT-LOG M6.2 entry 1):
//
//	Semgrep   →  Canonical  Why
//	─────────────────────────────────────────────────────────────
//	ERROR     →  high       Exploit-class (RCE, SQLi, secrets).
//	                        NOT "critical" — critical reserves for
//	                        confirmed-exploitable + remote (CVSS≥9).
//	                        ERROR-but-not-critical leaves room for
//	                        AI pipeline to upgrade-to-critical via
//	                        context.
//	WARNING   →  medium     Best-practice violation (missing CSRF
//	                        middleware, weak crypto).
//	INFO      →  info       Style/maintainability.
//	(empty)   →  info       Defensive default (mirrors 6.1 posture).
//	(unknown) →  info       Same.
//
// Case-insensitive: Semgrep is consistent about uppercase, but
// folding costs nothing and survives upstream casing drift.
func mapSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	case "INFO":
		return "info"
	default:
		return "info"
	}
}
