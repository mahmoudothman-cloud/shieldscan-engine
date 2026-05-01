package semgrep

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/rs/zerolog"
)

// codeSnippetMaxBytes caps RawFinding.CodeSnippet at 2 KiB. Per H.3:
// covers 99% of real Semgrep extra.lines payloads (matched line + 1-2
// context lines). Trigger to revisit: customer "can't see matched
// code" report.
const codeSnippetMaxBytes = 2048

// cwePrefixRE extracts just the "CWE-NNNN" prefix from Semgrep's
// human-readable cwe entry, e.g.:
//
//	"CWE-78: Improper Neutralization of Special Elements..."  →  "CWE-78"
//
// Anchored at start (^) — won't match "WCWE-78" or other variants.
// See engine DRIFT-LOG M6.2 entry 2.
var cwePrefixRE = regexp.MustCompile(`^(CWE-\d+)`)

// parseOutput returns a closure that parses a Semgrep `--json`
// single-doc payload into RawFindings. Returned closure satisfies
// NativeRunner.ParseOutput.
//
// Asymmetries vs internal/tools/nuclei/parse.go (M6.1):
//   - Single-doc decode (one json.Unmarshal call), NOT JSONL line
//     loop. A malformed top-level document is FATAL — we cannot
//     recover partial findings from a broken object. (Contrast with
//     6.1's per-line drop-and-continue.)
//   - Top-level `errors[]` non-empty + `results[]` empty is
//     log-and-continue, NOT fatal (per M6.2 H.1; see DRIFT-LOG
//     entry 3). Symmetric with 6.1's malformed-line tolerance.
//   - Per-record required fields: check_id + path. Missing either →
//     skip with WARN (mirror 6.1's template-id+matched-at gate).
//
// ParseOutput leaves these RawFinding fields EMPTY (NativeRunner.Run
// enriches them after parsing per the ToolRunner contract):
//   - ToolName ("semgrep")
//   - EngineCategory ("sast")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutput(log zerolog.Logger) func([]byte) ([]events.RawFinding, error) {
	return func(stdout []byte) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		if len(stdout) == 0 {
			return findings, nil
		}

		var raw map[string]any
		if err := json.Unmarshal(stdout, &raw); err != nil {
			return nil, fmt.Errorf("semgrep: parse JSON: %w", err)
		}

		// errors[] handling (H.1 Option A: log and continue).
		if errs, ok := raw["errors"].([]any); ok && len(errs) > 0 {
			for _, e := range errs {
				em, _ := e.(map[string]any)
				log.Warn().
					Str("type", extractString(em, "type")).
					Str("path", extractString(em, "path")).
					Str("message", extractString(em, "message")).
					Msg("semgrep: tool error reported in errors[]; continuing")
			}
		}

		results, ok := raw["results"].([]any)
		if !ok {
			// Missing or wrong-type results → empty happy path.
			return findings, nil
		}

		for i, item := range results {
			rec, ok := item.(map[string]any)
			if !ok {
				log.Warn().Int("index", i).
					Msg("semgrep: result entry not an object; dropping")
				continue
			}
			f, ok := recordToFinding(rec)
			if !ok {
				log.Warn().
					Int("index", i).
					Str("check_id", extractString(rec, "check_id")).
					Str("path", extractString(rec, "path")).
					Msg("semgrep: record missing required fields; dropping")
				continue
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

// recordToFinding extracts a RawFinding from a single Semgrep result
// record. Returns (zero, false) when required fields are absent.
//
// Field map (Semgrep result → RawFinding):
//
//	check_id                          →  FindingType
//	path                              →  CodeFile
//	start.line                        →  CodeLine
//	extra.message                     →  Description
//	extra.severity (mapped)           →  Severity
//	extra.metadata.cwe[0] (prefix)    →  CWEID  ("CWE-78: ..." → "CWE-78")
//	extra.metadata.owasp[0] verbatim  →  OWASP  (first array element)
//	extra.lines (truncated 2 KiB)     →  CodeSnippet
//
// Unmapped Semgrep fields (engine_kind, fingerprint, fix, is_ignored,
// metavars, validation_state, end.*, lines→CodeSnippet only) are
// intentionally dropped.
func recordToFinding(rec map[string]any) (events.RawFinding, bool) {
	checkID := extractString(rec, "check_id")
	path := extractString(rec, "path")
	if checkID == "" || path == "" {
		return events.RawFinding{}, false
	}

	start := extractMap(rec, "start")
	line := int(extractFloat(start, "line"))

	extra := extractMap(rec, "extra")
	severity := mapSeverity(extractString(extra, "severity"))
	description := extractString(extra, "message")
	snippet := truncate(extractString(extra, "lines"), codeSnippetMaxBytes)

	metadata := extractMap(extra, "metadata")
	cweID := cweFromMetadata(metadata)
	owasp := firstString(extractStringSlice(metadata, "owasp"))

	return events.RawFinding{
		Title:       checkID, // Semgrep has no separate title; rule id is the canonical name
		Description: description,
		Severity:    severity,
		FindingType: checkID,
		CWEID:       cweID,
		OWASP:       owasp,
		CodeFile:    path,
		CodeLine:    line,
		CodeSnippet: snippet,
	}, true
}

// cweFromMetadata extracts the "CWE-N" prefix from the first element
// of metadata.cwe. Returns "" on missing array, empty array, or
// malformed first element. See engine DRIFT-LOG M6.2 entry 2.
func cweFromMetadata(metadata map[string]any) string {
	arr := extractStringSlice(metadata, "cwe")
	if len(arr) == 0 {
		return ""
	}
	if m := cwePrefixRE.FindStringSubmatch(arr[0]); len(m) > 1 {
		return m[1]
	}
	return ""
}

// ─── lenient-decode helpers ─────────────────────────────────────────
//
// Copy of the helpers from internal/tools/nuclei/parse.go. SECOND
// instance of this shape across M6 tools. Per project's three-instance
// threshold, extraction to a shared internal/tools/jsonx/ package is
// triggered at the THIRD instance — likely M6.4 (SSLyze). See engine
// DRIFT-LOG M6.2 entry 9 for the trigger reminder.

// extractString walks m[key] expecting a string; returns "" on type
// mismatch or missing key.
func extractString(m map[string]any, key string) string {
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

// extractMap walks m[key] expecting map[string]any; returns nil on
// type mismatch or missing key.
func extractMap(m map[string]any, key string) map[string]any {
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

// extractStringSlice walks m[key] expecting []any of strings; returns
// empty slice on type mismatch. Tolerates a bare string instead of a
// single-element array (wraps it).
func extractStringSlice(m map[string]any, key string) []string {
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

// extractFloat walks m[key] expecting a number (json.Number-decoded
// as float64); returns 0 on type mismatch.
func extractFloat(m map[string]any, key string) float64 {
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

// firstString returns slice[0] or "" for empty.
func firstString(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// truncate caps s to n bytes; appends "..." if cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
