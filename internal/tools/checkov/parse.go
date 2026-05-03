package checkov

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
	"github.com/rs/zerolog"
)

// codeSnippetMaxBytes caps RawFinding.CodeSnippet at 2 KiB.
// Consistent with 6.2/6.4/6.5 conventions.
const codeSnippetMaxBytes = 2048

// parseOutput returns a closure satisfying NativeRunner.ParseOutput.
//
// Single-doc JSON shape (Checkov 3.2.340 `-o json`):
//
//	{
//	  "check_type": "terraform" | "kubernetes" | ...,
//	  "results":   {"failed_checks": [...]},
//	  "summary":   {...}
//	}
//
// Per-failed_check field map (Checkov → RawFinding):
//
//	check_id              → FindingType (and Title fallback)
//	check_name            → Title (preferred); Description (fallback)
//	file_path             → CodeFile
//	file_line_range[0]    → CodeLine
//	code_block (2-D)      → CodeSnippet (flattened, 2 KiB)
//	resource              → folded into Description
//	(constant)            → Severity = SeverityMedium
//	(constant)            → CWEID    = CWEIaCMisconfiguration
//
// Constants-only mapping (2nd instance after Gitleaks): OSS Checkov
// emits severity=null for all checks; CWE absent. M6.7 H.NEW.1 + H.NEW.2
// pin SeverityMedium + CWEIaCMisconfiguration as universal defaults.
//
// ParseOutput leaves these RawFinding fields EMPTY (NativeRunner.Run
// enriches after parsing):
//   - ToolName ("checkov"), EngineCategory ("iac")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutput(log zerolog.Logger) func([]byte) ([]events.RawFinding, error) {
	return func(stdout []byte) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		if len(stdout) == 0 {
			return findings, nil
		}

		var doc map[string]any
		if err := json.Unmarshal(stdout, &doc); err != nil {
			return nil, fmt.Errorf("checkov: parse JSON: %w", err)
		}

		results := jsonx.ExtractMap(doc, "results")
		failedAny, _ := results["failed_checks"].([]any)
		for i, item := range failedAny {
			rec, ok := item.(map[string]any)
			if !ok {
				log.Warn().Int("index", i).
					Msg("checkov: failed_check entry not an object; dropping")
				continue
			}
			f, ok := recordToFinding(rec)
			if !ok {
				log.Warn().
					Int("index", i).
					Str("check_id", jsonx.ExtractString(rec, "check_id")).
					Str("file_path", jsonx.ExtractString(rec, "file_path")).
					Msg("checkov: record missing required fields; dropping")
				continue
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

// recordToFinding extracts a RawFinding from a single Checkov failed_check
// record. Returns (zero, false) when required fields (check_id +
// file_path) are absent.
//
// Reductions applied (DRIFT-LOG M6.7 entry 10):
//   - bc_check_id          DROP (Bridgecrew-internal)
//   - guideline            DROP (external doc URL)
//   - evaluations, caller_file_*, entity_tags, connected_node,
//     definition_context_file_path → DROP (tool internals)
//   - code_block 2-D structure → flattened to source string
func recordToFinding(rec map[string]any) (events.RawFinding, bool) {
	checkID := jsonx.ExtractString(rec, "check_id")
	filePath := jsonx.ExtractString(rec, "file_path")
	if checkID == "" || filePath == "" {
		return events.RawFinding{}, false
	}

	checkName := jsonx.ExtractString(rec, "check_name")
	title := checkName
	if title == "" {
		title = checkID // fallback
	}

	// file_line_range is a 2-element [start, end] array of numbers.
	startLine := 0
	if rangeAny, ok := rec["file_line_range"].([]any); ok && len(rangeAny) > 0 {
		if v, ok := rangeAny[0].(float64); ok {
			startLine = int(v)
		}
	}

	resource := jsonx.ExtractString(rec, "resource")
	description := checkName
	if resource != "" {
		description = description + " (resource: " + resource + ")"
	}

	snippet := flattenCodeBlock(rec["code_block"])

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024).
	// Checkov retrofit per design doc §4.1.5:
	//   - References ← guideline (single URL string wrapped as []string;
	//                  nil if empty). Constants-only Pattern 4
	//                  preserved: SeverityMedium and
	//                  CWEIaCMisconfiguration still constants.
	var references []string
	if guideline := jsonx.ExtractString(rec, "guideline"); guideline != "" {
		references = []string{guideline}
	}

	return events.RawFinding{
		Title:       title,
		Description: description,
		Severity:    SeverityMedium,
		FindingType: checkID,
		CWEID:       CWEIaCMisconfiguration,
		CodeFile:    filePath,
		CodeLine:    startLine,
		CodeSnippet: snippet,
		References:  references,
	}, true
}

// flattenCodeBlock converts Checkov's 2-D `code_block` (array of
// `[lineNumber, codeText]` pairs) into a single string preserving
// line content. Truncated to 2 KiB via jsonx.Truncate consistent
// with 6.2/6.4/6.5.
//
// Format example:
//
//	in:  [[5, "resource X {\n"], [6, "  attr = ...\n"]]
//	out: "resource X {\n  attr = ...\n"
//
// Returns "" on nil / wrong-type / empty input. Per-pair malformed
// entries are skipped silently.
func flattenCodeBlock(blockAny any) string {
	arr, ok := blockAny.([]any)
	if !ok || len(arr) == 0 {
		return ""
	}
	var b strings.Builder
	for _, pair := range arr {
		p, ok := pair.([]any)
		if !ok || len(p) < 2 {
			continue
		}
		if line, ok := p[1].(string); ok {
			b.WriteString(line)
		}
	}
	return jsonx.Truncate(b.String(), codeSnippetMaxBytes)
}
