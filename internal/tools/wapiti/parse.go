package wapiti

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
	"github.com/rs/zerolog"
)

// requestMaxBytes caps RawFinding.Request at 4 KiB. Mirrors Nuclei
// (6.1) precedent for embedded HTTP request truncation.
const requestMaxBytes = 4096

// nonAlphaNumRE captures runs of non-alphanumeric characters (used
// for category-name slugification).
var nonAlphaNumRE = regexp.MustCompile(`[^a-z0-9]+`)

// parseOutputFile returns a closure satisfying NativeRunner.ParseOutputFile.
//
// Wapiti `-f json -o <path>` writes a single-doc JSON with the shape:
//
//	{
//	  "vulnerabilities": {<class_name>: [<vuln_instance>, ...], ...},
//	  "anomalies":       {<class_name>: [...], ...},  // not parsed at 6.6
//	  "additionals":     {<class_name>: [...], ...},  // not parsed at 6.6
//	  "infos":           {"target": "...", "version": "...", ...},
//	  "classifications": {...}                         // dropped per reductions
//	}
//
// File-output mode (ADR-023): NativeRunner provides outputFilePath;
// stdout is discarded. Wapiti `-o /dev/stdout` corrupts JSON output;
// using OutputFile mode is the documented workaround (DRIFT-LOG
// M6.6 entry 5).
//
// Category-keyed iteration: each class_name keys a list of uniform-
// shape vuln instances. Distinct from SSLyze's per-plugin diagnostic
// shape (DRIFT-LOG M6.6 entry 6); plugin-rules pattern stays at 1
// instance.
//
// At M6.6 we parse `vulnerabilities` only. `anomalies` and
// `additionals` blocks are emitted by Wapiti for non-vulnerability
// observations (server errors, fingerprinting); not actionable as
// findings. Trigger to revisit: customer asks for cross-tool
// fingerprinting consolidation.
//
// ParseOutputFile leaves these RawFinding fields EMPTY (NativeRunner
// enriches after parsing):
//   - ToolName ("wapiti"), EngineCategory ("dast")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutputFile(log zerolog.Logger) func(string) ([]events.RawFinding, error) {
	return func(outputFilePath string) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		data, err := os.ReadFile(outputFilePath) //nolint:gosec // G304: NativeRunner-minted tempfile
		if err != nil {
			return nil, fmt.Errorf("wapiti: read output file: %w", err)
		}
		if len(data) == 0 {
			return findings, nil
		}

		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("wapiti: parse JSON: %w", err)
		}

		// Derive target from infos.target for combining with per-finding paths.
		infos := jsonx.ExtractMap(doc, "infos")
		baseTarget := jsonx.ExtractString(infos, "target")

		vulns := jsonx.ExtractMap(doc, "vulnerabilities")
		// Iterate category-keyed map. Map iteration order is randomized
		// in Go; for deterministic finding order, callers should sort
		// by Fingerprint downstream. (At M6.6 we accept Wapiti-natural
		// ordering since processor + AI pipeline dedup by fingerprint.)
		for className, instAny := range vulns {
			items, ok := instAny.([]any)
			if !ok {
				continue
			}
			for i, inst := range items {
				rec, ok := inst.(map[string]any)
				if !ok {
					log.Warn().
						Str("class", className).Int("index", i).
						Msg("wapiti: vuln instance not an object; dropping")
					continue
				}
				findings = append(findings, instanceToFinding(className, rec, baseTarget))
			}
		}
		return findings, nil
	}
}

// instanceToFinding builds a RawFinding from a single Wapiti vuln
// instance + its category context.
//
// Field map (Wapiti → RawFinding):
//
//	<class_name>           → Title (verbatim) + FindingType (slug-ified)
//	info                   → Description
//	level (int 1-5)        → Severity (via mapSeverity)
//	infos.target + path    → TargetURL (combined per H.NEW.B lean)
//	parameter              → Parameter
//	http_request (4 KiB)   → Request
//
// Reductions (DRIFT-LOG M6.6 entry 12):
//   - method (folded into Description)
//   - curl_command (DROP — reproducibility-only)
//   - referer (DROP if empty; folded otherwise)
//   - module (DROP — tool internals)
//   - wstg[] (DROP — no References field)
func instanceToFinding(className string, rec map[string]any, baseTarget string) events.RawFinding {
	level := int(jsonx.ExtractFloat(rec, "level"))
	method := jsonx.ExtractString(rec, "method")
	path := jsonx.ExtractString(rec, "path")
	info := jsonx.ExtractString(rec, "info")
	parameter := jsonx.ExtractString(rec, "parameter")
	httpRequest := jsonx.ExtractString(rec, "http_request")
	referer := jsonx.ExtractString(rec, "referer")

	// Combine baseTarget + path → TargetURL (H.NEW.B lean).
	targetURL := combineTargetPath(baseTarget, path)

	// Description: info + method context (+ referer if non-empty).
	description := info
	if method != "" {
		description = method + " " + path + ": " + description
	}
	if referer != "" {
		description = description + " (referer: " + referer + ")"
	}

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024).
	// Wapiti retrofit per design doc §4.1.6:
	//   - References ← wstg[] (OWASP WSTG identifiers; currently dropped
	//                  per 6.6 reductions)
	//   - Tags       ← module wrapped as []string (filtered against
	//                  engine_category to drop "dast"-shaped duplicates)
	references := jsonx.ExtractStringSlice(rec, "wstg")
	if len(references) == 0 {
		references = nil
	}
	var tags []string
	if module := jsonx.ExtractString(rec, "module"); module != "" {
		tags = jsonx.FilterEngineCategoryTags([]string{module})
	}

	return events.RawFinding{
		Title:       className,
		Description: description,
		Severity:    mapSeverity(level),
		FindingType: "wapiti-" + slugifyCategoryName(className),
		TargetURL:   targetURL,
		Parameter:   parameter,
		Request:     jsonx.Truncate(httpRequest, requestMaxBytes),
		References:  references,
		Tags:        tags,
	}
}

// combineTargetPath merges a base target ("https://example.com/")
// with a per-finding path ("/admin"). Defensive against either being
// empty.
//
// Per H.NEW.B lean: combine when both present; canonical URLs
// preserve scheme+host+path.
func combineTargetPath(baseTarget, path string) string {
	if baseTarget == "" {
		return path
	}
	if path == "" {
		return baseTarget
	}
	base := strings.TrimSuffix(baseTarget, "/")
	if !strings.HasPrefix(path, "/") {
		return base + "/" + path
	}
	return base + path
}

// slugifyCategoryName converts a Wapiti category name like
// "Clickjacking Protection" to a kebab-case slug
// "clickjacking-protection" suitable for FindingType usage.
//
// Algorithm: lowercase → replace non-alphanumeric runs with single
// hyphens → trim leading/trailing hyphens.
func slugifyCategoryName(name string) string {
	if name == "" {
		return ""
	}
	lower := strings.ToLower(name)
	slug := nonAlphaNumRE.ReplaceAllString(lower, "-")
	return strings.Trim(slug, "-")
}
