// Package jsonx contains lenient extraction helpers for parsing
// security-tool JSON output into typed values.
//
// Why a shared package. Security tools (Nuclei, Semgrep, Gitleaks,
// SSLyze, etc.) emit JSON with shapes that drift across releases:
// fields are added, optional fields appear/disappear, types may shift
// (string vs []string for tags). The strict `json.Unmarshal` into
// typed structs would break on every minor upstream release.
//
// The lenient pattern: decode into `map[string]any`, then walk it
// with type-asserted helpers that return zero values on type
// mismatch / missing keys. Tools' parsers stay stable across
// upstream churn.
//
// Asymmetric with `internal/events` wire-format strictness, which
// uses `DisallowUnknownFields` — wire format is a cross-repo
// contract, tool output is upstream-driven.
//
// Three-instance threshold. This package was extracted at M6.5
// (Gitleaks) when `extractString`-shaped helpers reached their third
// callsite (after M6.1 Nuclei + M6.2 Semgrep). Per project's
// three-instance promotion convention. See engine DRIFT-LOG M6.5
// entry "Helper-extraction promoted to internal/tools/jsonx/".
//
// The 6 helpers cover the access patterns observed across the three
// callsites; expansion (extractInt, dotted-path walkers, etc.) is
// driven by genuine new-tool needs, not speculation.
package jsonx

// ExtractString walks m[key] expecting a string. Returns "" on:
//   - nil map
//   - missing key
//   - value present but not a string
//
// SINGLE-KEY only. Does NOT walk dotted paths; callers compose by
// chaining ExtractMap calls when traversing nested structures.
func ExtractString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// ExtractMap walks m[key] expecting map[string]any. Returns nil on
// nil map / missing key / type mismatch. Composable: chain
// ExtractMap(ExtractMap(root, "a"), "b") to access root["a"]["b"].
func ExtractMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	mm, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return mm
}

// ExtractStringSlice walks m[key] expecting []any of strings.
// Returns:
//   - nil on nil map / missing key
//   - filtered slice (only string elements survive) for []any inputs
//   - []string{s} for a bare string (tolerates Nuclei-pre-v3 single-
//     element-as-bare-string quirk)
//   - nil for any other type
func ExtractStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	if arr, ok := v.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	if s, ok := v.(string); ok {
		return []string{s}
	}
	return nil
}

// ExtractFloat walks m[key] expecting a number. Returns 0 on nil
// map / missing key / type mismatch.
//
// JSON numbers decode as float64 via the stdlib's `json.Unmarshal`
// into `any` — this helper relies on that contract. Callers needing
// integer values cast the returned float64 (e.g., `int(...)`).
func ExtractFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

// FirstString returns slice[0] or "" for an empty slice. Helper for
// the common "take first element of a string array" pattern.
func FirstString(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// Truncate caps s to n bytes; appends "..." if cut. Used by tool
// parsers to bound CodeSnippet / Request / Response field sizes
// per task-specific decisions (typically 2 KiB or 4 KiB caps).
//
// Byte-truncation, not rune-aware: a multi-byte UTF-8 character at
// position n could be cut mid-byte. Acceptable for the tool-output
// use case (ASCII-dominant code/secret strings); revisit if
// CodeSnippet content ever needs to round-trip through human-text
// renderers that care about UTF-8 boundaries.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
