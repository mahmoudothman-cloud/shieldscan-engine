package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
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
// Field-extraction helpers come from internal/tools/jsonx/ as of M6.5
// (3rd-instance threshold met; helpers extracted from per-package
// duplicates).
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
	templateID := jsonx.ExtractString(raw, "template-id")
	if templateID == "" {
		return events.RawFinding{}, false
	}

	targetURL := jsonx.ExtractString(raw, "matched-at")
	if targetURL == "" {
		targetURL = jsonx.ExtractString(raw, "host")
	}
	if targetURL == "" {
		return events.RawFinding{}, false
	}

	info := jsonx.ExtractMap(raw, "info")
	severity := mapSeverity(jsonx.ExtractString(info, "severity"))
	title := jsonx.ExtractString(info, "name")
	description := jsonx.ExtractString(info, "description")

	classification := jsonx.ExtractMap(info, "classification")
	cweIDs := jsonx.ExtractStringSlice(classification, "cwe-id")
	cweID := jsonx.FirstString(cweIDs)
	cveID := jsonx.FirstString(jsonx.ExtractStringSlice(classification, "cve-id"))
	cvssScore := jsonx.ExtractFloat(classification, "cvss-score")

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024).
	// Nuclei retrofit per design doc §4.1.1:
	//   - References ← info.reference[]
	//   - Tags       ← info.tags[] (filtered to drop engine_category)
	//   - CVSSVector ← info.classification.cvss-metrics
	references := jsonx.ExtractStringSlice(info, "reference")
	if len(references) == 0 {
		references = nil
	}
	tags := jsonx.FilterEngineCategoryTags(jsonx.ExtractStringSlice(info, "tags"))
	cvssVector := jsonx.ExtractString(classification, "cvss-metrics")
	// Nuclei typically emits a single CWE; AdditionalCWEs stays nil
	// when cweIDs has 0 or 1 entries. Multi-CWE Nuclei templates exist
	// (rare); populate AdditionalCWEs with cweIDs[1:] for those.
	var additionalCWEs []string
	if len(cweIDs) > 1 {
		additionalCWEs = cweIDs[1:]
	}

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
		Title:          title,
		Description:    description,
		Severity:       severity,
		FindingType:    templateID,
		CWEID:          cweID,
		CVSSScore:      cvssScore,
		TargetURL:      targetURL,
		Request:        jsonx.Truncate(jsonx.ExtractString(raw, "request"), 4096),
		Response:       jsonx.Truncate(jsonx.ExtractString(raw, "response"), 4096),
		References:     references,
		Tags:           tags,
		CVSSVector:     cvssVector,
		AdditionalCWEs: additionalCWEs,
	}, true
}
