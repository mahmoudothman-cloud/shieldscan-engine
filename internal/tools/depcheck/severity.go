package depcheck

import "strings"

// mapSeverity converts Dep-Check vulnerability severity strings to
// the canonical RawFinding.Severity vocabulary.
//
// Dep-Check derives the per-CVE severity field from CVSSv3
// `baseSeverity` (capitalized: "Critical", "High", "Medium", "Low",
// "Info"). NVD also occasionally emits "Moderate" as an alias for
// "Medium" — handled.
//
// First multi-rule severity table for an SCA tool in M6. Distinct
// from prior tables:
//   - 6.1 Nuclei: identity (5 levels passthrough)
//   - 6.2 Semgrep: 3-level → 5-level mapping
//   - 6.4 SSLyze: domain-rules table per FindingType
//   - 6.5 Gitleaks: constants-only
//   - 6.7 Dep-Check: 5-level → 5-level case-insensitive identity
//     (with Moderate alias)
func mapSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM", "MODERATE":
		return "medium"
	case "LOW":
		return "low"
	case "INFO", "INFORMATIONAL":
		return "info"
	default:
		return "info" // defensive default (mirrors prior tools)
	}
}
