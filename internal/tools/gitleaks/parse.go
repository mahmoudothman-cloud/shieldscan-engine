package gitleaks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
	"github.com/rs/zerolog"
)

// codeSnippetMaxBytes caps RawFinding.CodeSnippet at 2 KiB.
// Consistent with 6.2 Semgrep. Private-key matches are typically
// ~250 bytes (4 lines of base64). 2 KiB has margin; truncation
// marker signals when more is available.
const codeSnippetMaxBytes = 2048

// parseOutput returns a closure that parses Gitleaks `--report-format=
// json` output (a JSON array of finding objects) into RawFindings.
// Returned closure satisfies NativeRunner.ParseOutput.
//
// Format asymmetries vs prior M6 parsers:
//   - 6.1 Nuclei: JSONL (newline-separated single-line objects).
//   - 6.2 Semgrep: single-doc JSON {"results": [...], "errors": [...]}.
//   - 6.5 Gitleaks: bare JSON array [{...}, {...}].
//
// Decoding is lenient (map[string]any walked via jsonx helpers).
// Top-level malformed JSON is FATAL (we cannot recover partial
// findings from a broken array). Per-record missing required fields
// (RuleID + File) is non-fatal — log and skip.
//
// ParseOutput leaves these RawFinding fields EMPTY (NativeRunner.Run
// enriches them after parsing per the ToolRunner contract):
//   - ToolName ("gitleaks")
//   - EngineCategory ("secrets")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutput(log zerolog.Logger) func([]byte) ([]events.RawFinding, error) {
	return func(stdout []byte) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		if len(stdout) == 0 {
			return findings, nil
		}

		// []any with per-item type-assert (per H.6 lean): more
		// tolerant than []map[string]any, which would fail-fast on
		// any non-object array element.
		var raw []any
		if err := json.Unmarshal(stdout, &raw); err != nil {
			return nil, fmt.Errorf("gitleaks: parse JSON: %w", err)
		}

		for i, item := range raw {
			rec, ok := item.(map[string]any)
			if !ok {
				log.Warn().Int("index", i).
					Msg("gitleaks: array entry not an object; dropping")
				continue
			}
			f, ok := recordToFinding(rec)
			if !ok {
				log.Warn().
					Int("index", i).
					Str("rule_id", jsonx.ExtractString(rec, "RuleID")).
					Str("file", jsonx.ExtractString(rec, "File")).
					Msg("gitleaks: record missing required fields; dropping")
				continue
			}
			findings = append(findings, f)
		}
		return findings, nil
	}
}

// recordToFinding extracts a RawFinding from a single Gitleaks JSON
// record. Returns (zero, false) when required fields (RuleID + File)
// are absent.
//
// Field map (Gitleaks → RawFinding):
//
//	RuleID                              →  FindingType, Title
//	File                                →  CodeFile (required)
//	StartLine                           →  CodeLine
//	Match (truncated 2 KiB)             →  CodeSnippet
//	Description (+ commit fold)         →  Description
//	(constant)                          →  Severity = SeverityCritical
//	(constant)                          →  CWEID = CWEHardcodedCredentials
//
// Reductions (DRIFT-LOG M6.5 entry 4):
//   - Author/Email/Commit/Date/Message → folded into Description IFF
//     Commit + Author + Date all present (commitFold).
//   - Entropy, StartColumn, EndColumn, EndLine, Tags, SymlinkFile,
//     Secret, Fingerprint → dropped (no RawFinding home; not
//     actionable for finding consumers).
func recordToFinding(rec map[string]any) (events.RawFinding, bool) {
	ruleID := jsonx.ExtractString(rec, "RuleID")
	file := jsonx.ExtractString(rec, "File")
	if ruleID == "" || file == "" {
		return events.RawFinding{}, false
	}

	startLine := int(jsonx.ExtractFloat(rec, "StartLine"))
	match := jsonx.Truncate(jsonx.ExtractString(rec, "Match"), codeSnippetMaxBytes)
	baseDescription := jsonx.ExtractString(rec, "Description")

	// Commit-metadata fold (all-or-nothing per M6.5 Confirmation B).
	commit := jsonx.ExtractString(rec, "Commit")
	author := jsonx.ExtractString(rec, "Author")
	date := jsonx.ExtractString(rec, "Date")
	description := commitFold(baseDescription, commit, author, date)

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024).
	// Gitleaks retrofit per design doc §4.1.3:
	//   - Tags ← Tags[] (currently dropped per 6.5 reductions),
	//            filtered against engine_category to drop "secrets"-
	//            shaped duplicates.
	// Constants-only Pattern 4 preserved: SeverityCritical and
	// CWEHardcodedCredentials still constants. Tags is per-finding.
	tags := jsonx.FilterEngineCategoryTags(jsonx.ExtractStringSlice(rec, "Tags"))

	return events.RawFinding{
		Title:       ruleID,
		Description: description,
		Severity:    SeverityCritical,
		FindingType: ruleID,
		CWEID:       CWEHardcodedCredentials,
		CodeFile:    file,
		CodeLine:    startLine,
		CodeSnippet: match,
		Tags:        tags,
	}, true
}

// commitFold appends commit metadata to baseDescription IFF Commit,
// Author, and Date are ALL non-empty (all-or-nothing per M6.5
// Confirmation B). Date is trimmed to YYYY-MM-DD; the full RFC3339
// timestamp is dropped.
//
// Format: "<base> (commit <SHA8> by <Author> on <YYYY-MM-DD>)"
//
// When commit metadata is absent (Gitleaks `dir` mode, or `git` mode
// against a target without commit history), returns base unchanged.
//
// See engine DRIFT-LOG M6.5 entry "Commit-metadata fold all-or-
// nothing format + Date trimming".
func commitFold(base, commit, author, date string) string {
	if commit == "" || author == "" || date == "" {
		return base
	}
	sha8 := commit
	if len(sha8) > 8 {
		sha8 = sha8[:8]
	}
	if i := strings.Index(date, "T"); i > 0 {
		date = date[:i]
	}
	return base + " (commit " + sha8 + " by " + author + " on " + date + ")"
}
