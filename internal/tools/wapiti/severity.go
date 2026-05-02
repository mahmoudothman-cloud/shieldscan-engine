package wapiti

// mapSeverity converts Wapiti's `level` integer to canonical
// RawFinding.Severity. Wapiti convention (verified at M6.6 pre-prep):
//
//	level 1 = info       (best-practice notes)
//	level 2 = low        (minor issues)
//	level 3 = medium     (real vulnerabilities; default for most modules)
//	level 4 = high       (significant findings)
//	level 5 = critical   (rare; reserved for confirmed high-impact)
//
// Defensive default: out-of-range levels (0, negative, ≥6) → "info"
// (mirrors prior tools' defensive defaults).
//
// Domain-rules severity mapping pattern, 2nd instance after 6.4
// SSLyze. Track for promotion at 3rd instance per project's
// three-instance threshold convention. See engine DRIFT-LOG M6.6
// entry 7.
func mapSeverity(level int) string {
	switch level {
	case 1:
		return "info"
	case 2:
		return "low"
	case 3:
		return "medium"
	case 4:
		return "high"
	case 5:
		return "critical"
	default:
		return "info"
	}
}
