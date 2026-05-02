package semgrep

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
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
// Field-extraction helpers come from internal/tools/jsonx/ as of M6.5
// (3rd-instance threshold met; helpers extracted from per-package
// duplicates).
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
					Str("type", jsonx.ExtractString(em, "type")).
					Str("path", jsonx.ExtractString(em, "path")).
					Str("message", jsonx.ExtractString(em, "message")).
					Msg("semgrep: tool error reported in errors[]; continuing")
			}
		}

		results, ok := raw["results"].([]any)
		if !ok {
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
					Str("check_id", jsonx.ExtractString(rec, "check_id")).
					Str("path", jsonx.ExtractString(rec, "path")).
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
	checkID := jsonx.ExtractString(rec, "check_id")
	path := jsonx.ExtractString(rec, "path")
	if checkID == "" || path == "" {
		return events.RawFinding{}, false
	}

	start := jsonx.ExtractMap(rec, "start")
	line := int(jsonx.ExtractFloat(start, "line"))

	extra := jsonx.ExtractMap(rec, "extra")
	severity := mapSeverity(jsonx.ExtractString(extra, "severity"))
	description := jsonx.ExtractString(extra, "message")
	snippet := jsonx.Truncate(jsonx.ExtractString(extra, "lines"), codeSnippetMaxBytes)

	metadata := jsonx.ExtractMap(extra, "metadata")
	cweID := cweFromMetadata(metadata)
	owasp := jsonx.FirstString(jsonx.ExtractStringSlice(metadata, "owasp"))

	return events.RawFinding{
		Title:       checkID,
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
	arr := jsonx.ExtractStringSlice(metadata, "cwe")
	if len(arr) == 0 {
		return ""
	}
	if m := cwePrefixRE.FindStringSubmatch(arr[0]); len(m) > 1 {
		return m[1]
	}
	return ""
}
