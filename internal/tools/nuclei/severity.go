package nuclei

import "strings"

// mapSeverity normalizes a Nuclei `info.severity` string to the
// canonical RawFinding.Severity values.
//
// The mapping is identity for the five Nuclei-emitted levels (info,
// low, medium, high, critical). Empty / unknown inputs default to
// "info" rather than dropping the finding — better operational signal
// than a silent miss, and severity overstatement is worse than under-
// statement (incident triage prefers conservative defaults).
//
// Pinning the table — even as identity — is deliberate: code review
// without it leaves the question "is severity validated?" ambiguous.
// See engine DRIFT-LOG M6.1 entry "severity mapping table (Nuclei
// identity)".
func mapSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return "info"
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return "info"
	}
}
