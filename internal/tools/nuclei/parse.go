package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/rs/zerolog"
)

// maxScanLineBytes caps the bufio.Scanner line size at 1 MiB.
//
// Default 64 KiB is insufficient for Nuclei JSONL: when a finding
// embeds the full HTTP request + response (request can be a few KiB,
// response can be tens of KiB for HTML), single records exceed 64 KiB
// regularly. 1 MiB covers realistic max with margin; pathological
// lines exceeding this cap are dropped with a warning (same fail-soft
// posture as malformed-line handling).
//
// Trigger to revisit: customer report of "finding visible in nuclei
// stdout but not in our DB" → check warning logs for too-long drops;
// at that point consider streaming json.Decoder over io.Reader.
//
// See engine DRIFT-LOG M6.1 entry "bufio.Scanner MaxScanTokenSize
// 1MB decision".
const maxScanLineBytes = 1 * 1024 * 1024

// parseOutput returns a closure that parses Nuclei JSONL stdout into
// RawFindings. Returned closure satisfies NativeRunner.ParseOutput.
//
// The parser is lenient by design (asymmetric with wire-format
// strictness in internal/events): tools evolve their JSON shapes
// between minor releases, and unknown fields / malformed lines must
// not poison the whole batch. Per-line decode failures are logged at
// WARN and the line is dropped; subsequent lines continue parsing.
//
// ParseOutput leaves the following RawFinding fields EMPTY — they are
// enriched by NativeRunner.Run after this returns:
//   - ToolName (set to "nuclei" by NativeRunner)
//   - EngineCategory (set to "dast" by NativeRunner)
//   - DiscoveredAt (RFC3339 set at enrichment)
//   - Fingerprint (computed via tools.ComputeFingerprint)
func parseOutput(log zerolog.Logger) func([]byte) ([]events.RawFinding, error) {
	return func(stdout []byte) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		if len(stdout) == 0 {
			return findings, nil
		}

		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		scanner.Buffer(make([]byte, 0, 64*1024), maxScanLineBytes)

		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}

			var raw map[string]any
			if err := json.Unmarshal(line, &raw); err != nil {
				// Lenient: log the bad line and continue. Per-tool
				// quirks (subprocess killed mid-write, stray banner
				// stderr leaking to stdout) shouldn't poison the
				// batch.
				log.Warn().
					Err(err).
					Int("line_num", lineNum).
					Msg("nuclei: dropping malformed JSONL line")
				continue
			}

			f, ok := lineToFinding(raw)
			if !ok {
				log.Warn().
					Int("line_num", lineNum).
					Msg("nuclei: line missing required fields; dropping")
				continue
			}
			findings = append(findings, f)
		}

		if err := scanner.Err(); err != nil {
			// Cap-exceeded or read error. Surface per-cap as warning
			// and return what we have (don't poison successful
			// parses); other read errors propagate.
			if err == bufio.ErrTooLong {
				log.Warn().
					Int("line_num", lineNum+1).
					Int("max_bytes", maxScanLineBytes).
					Msg("nuclei: dropping line exceeding scanner buffer cap")
				return findings, nil
			}
			return findings, fmt.Errorf("nuclei: scanner: %w", err)
		}
		return findings, nil
	}
}

// lineToFinding extracts a RawFinding from a single decoded Nuclei
// JSONL record. Returns (finding, true) on success, (zero, false) if
// the record lacks the minimum identifying fields (template-id +
// matched-at/host).
//
// Field map (Nuclei → RawFinding):
//
//	template-id              → FindingType
//	info.name                → Title
//	info.description         → Description (CVE id appended if present)
//	info.severity            → Severity (via mapSeverity)
//	info.classification.cwe-id[0]    → CWEID
//	info.classification.cvss-score   → CVSSScore
//	matched-at (or host)     → TargetURL
//	request                  → Request (truncated to 4KB)
//	response                 → Response (truncated to 4KB)
//
// Unmapped Nuclei fields (template-encoded, ip, timestamp, type,
// matcher-name, extractor-name) are intentionally dropped; they're
// not part of the canonical finding shape.
func lineToFinding(raw map[string]any) (events.RawFinding, bool) {
	templateID := extractString(raw, "template-id")
	if templateID == "" {
		return events.RawFinding{}, false
	}

	targetURL := extractString(raw, "matched-at")
	if targetURL == "" {
		targetURL = extractString(raw, "host")
	}
	if targetURL == "" {
		return events.RawFinding{}, false
	}

	info := extractMap(raw, "info")
	severity := mapSeverity(extractString(info, "severity"))
	title := extractString(info, "name")
	description := extractString(info, "description")

	classification := extractMap(info, "classification")
	cweID := firstString(extractStringSlice(classification, "cwe-id"))
	cveID := firstString(extractStringSlice(classification, "cve-id"))
	cvssScore := extractFloat(classification, "cvss-score")

	// CVE id has no dedicated RawFinding field at SPEC §7's schema; fold
	// into Description so it surfaces in dedup + UI without losing the
	// semantic. Future SPEC schema extension MAY add CVEID; this fold
	// is reversible.
	if cveID != "" {
		if description == "" {
			description = cveID
		} else {
			description = description + " (" + cveID + ")"
		}
	}

	return events.RawFinding{
		Title:       title,
		Description: description,
		Severity:    severity,
		FindingType: templateID,
		CWEID:       cweID,
		CVSSScore:   cvssScore,
		TargetURL:   targetURL,
		Request:     truncate(extractString(raw, "request"), 4096),
		Response:    truncate(extractString(raw, "response"), 4096),
	}, true
}

// extractString walks raw[key] expecting a string; returns "" on any
// type mismatch or missing key. Lenient by design.
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

// extractMap walks raw[key] expecting map[string]any; returns nil on
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

// extractStringSlice walks raw[key] expecting []any of strings;
// returns empty slice on any type mismatch. Tolerates the case where
// Nuclei emits a bare string instead of a single-element array (rare
// but observed in older versions): wraps into []string{s}.
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

// extractFloat walks raw[key] expecting a number (json.Number-decoded
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

// truncate caps s to n bytes; appends "..." if cut. Mirrors
// internal/tools/native.go's truncate so the truncation marker is
// consistent across the engine.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
