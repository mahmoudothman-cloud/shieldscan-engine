// Package sqlmap implements the Task 7.6 SQLMap consumer — exec-shape
// DockerRunner consumer per ADR-026 framework + M7.6 commitment (SPEC
// §13 ADR-026 lines 1193 + 2019 + 2029).
//
// Per Phase 0 v2 empirical verification (parrotsec/sqlmap:latest
// @sha256:740197a8...0d9bec; SQLMap 1.10.4 stable) against DVWA SQLi
// endpoint /vulnerabilities/sqli/?id=1&Submit=Submit:
//
//   - V1: image pin + ENTRYPOINT=[sqlmap] covered by Task 7.5e D-PLAN-
//     7.5e-Phase2-Entrypoint universal fix automatically
//   - V2: vulnerables/web-dvwa canonical testbed
//   - V3: --batch + --disable-coloring automation flags mandatory
//   - V4: DOMINANT — per-section heterogeneous output (injection
//     findings per-Parameter blocks + DBMS-fingerprint trailing
//     single-object block); structurally satisfies 1c6041d 2nd-instance
//     per-section-adaptor forward-pin language
//   - V5: cold ≈ warm ~12s timing baseline
//
// Per Q2 (a) per-section adaptor lock + 1c6041d 2nd-instance pattern
// empirical grounding: 2 adaptors (adaptInjectionFindings +
// adaptDBMSFingerprint). MobSF (1st instance; 7 adaptors at
// service/mobsf/sections.go) + SQLMap (2nd instance; 2 adaptors) = real
// 2-instance pattern. 3rd-instance threshold not yet reached; pattern
// stays at 2 instances pending future consumer per Task 7.1 P5.D
// aa3fb5f scope-mismatch methodology.
package sqlmap

import (
	"errors"
	"regexp"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// findingsHeader marks the start of the injection-findings region in
// SQLMap stdout. Per V4 empirical observation: SQLMap emits this exact
// header line immediately before the first `---` block-delimiter.
const findingsHeader = "sqlmap identified the following injection point(s)"

// blockDelimiter is the inter-block separator (a line containing only
// three dashes). Per V4 empirical observation: appears before first
// Parameter block AND after last Parameter block (closing delimiter).
const blockDelimiter = "---"

// parseSQLMapOutput is the top-level dispatcher per Q1 (a) stdout-parsing
// lock + Q2 (a) per-section adaptor pattern. Receives DockerRunner stdout
// bytes; signature exactly matches DockerRunner.ParseOutput contract per
// pre-verification finding (direct match; no adapter wrapper).
//
// Identity-field delegation per ToolRunner interface contract
// (internal/tools/runner.go): ToolName + EngineCategory + DiscoveredAt
// + Fingerprint populated by the DockerRunner framework AFTER parse;
// ScanID + OrgID populated by the processor.
//
// A scan with zero findings returns ([], nil); malformed input is
// handled gracefully — if no findings header is present, returns
// ([], nil) (sqlmap produces no findings on non-injectable targets).
func parseSQLMapOutput(stdout []byte) ([]events.RawFinding, error) {
	if len(stdout) == 0 {
		return nil, errors.New("sqlmap: empty stdout")
	}
	text := stripLogPrefixes(string(stdout))

	// Locate findings region. Absent → no-injection scan; return empty.
	headerIdx := strings.Index(text, findingsHeader)
	if headerIdx < 0 {
		return nil, nil
	}
	findingsRegion := text[headerIdx:]

	// Extract target URL from the pre-findings region (sqlmap log emits
	// `URL:\nGET <url>` or `[INFO] testing URL '<url>'`). Forward-look
	// from start for cleanest match.
	targetURL := extractTargetURL(text)

	// Split findings region at top-level `---` delimiters.
	injectionText, dbmsText := splitFindingsRegion(findingsRegion)

	var out []events.RawFinding
	out = append(out, adaptInjectionFindings(injectionText, targetURL)...)
	if dbmsFinding, ok := adaptDBMSFingerprint(dbmsText, targetURL); ok {
		out = append(out, dbmsFinding)
	}
	return out, nil
}

// stripLogPrefixes scrubs SQLMap's bracketed log-prefix lines from the
// input so block-delimited content remains parseable. Per V3 empirical
// (--disable-coloring eliminates ANSI; log prefixes still bracket
// metadata-noise lines). Lines starting with `[<timestamp>] [<level>]`
// or `[!]` or `[*]` are dropped; block content (`Parameter:`,
// `Type:`, `Title:`, `Payload:`, `web server`, etc.) preserved.
//
// Defensive: drops empty lines surrounded by stripped log noise but
// preserves block-internal blank lines (between per-technique entries).
func stripLogPrefixes(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		// SQLMap log prefixes: `[HH:MM:SS] [LEVEL]`, `[!]`, `[*]`,
		// `[1/1] URL:`, `[<info>]` shapes. Match any line beginning
		// with `[` as log-prefix candidate; keep block content
		// (Parameter:/Type:/Title:/Payload: indented or non-bracketed).
		if strings.HasPrefix(trimmed, "[") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// extractTargetURL pulls the scanned URL out of SQLMap's pre-findings
// log. Per V4 empirical: stdout contains `GET <url>` on its own line
// AND `testing URL '<url>'` in log-prefixed line (stripped by
// stripLogPrefixes). The GET line survives stripping.
//
// Returns empty string if no URL identifiable; downstream caller
// tolerates empty TargetURL (omit-when-empty).
func extractTargetURL(text string) string {
	// Match `GET <url>` or `POST <url>` line.
	re := regexp.MustCompile(`(?m)^(?:GET|POST|PUT|DELETE)\s+(\S+)`)
	if match := re.FindStringSubmatch(text); len(match) >= 2 {
		return match[1]
	}
	return ""
}

// splitFindingsRegion separates the post-header text into the
// injection-blocks region (between first and second `---` delimiters)
// and the DBMS-fingerprint region (after the closing `---`).
//
// Per V4 empirical block layout:
//
//	sqlmap identified the following injection point(s)...
//	---
//	Parameter: id (GET)
//	    Type: boolean-based blind
//	    Title: ...
//	    Payload: ...
//	    [more technique entries]
//	---
//	web server operating system: Linux Debian 9 (stretch)
//	web application technology: Apache 2.4.25
//	back-end DBMS: MySQL >= 5.1 (MariaDB fork)
//
// Multi-parameter scans would have multiple `Parameter:` blocks
// between the two `---` delimiters (no inter-parameter delimiter
// observed in v1.10.4 — defensive parsing assumes single contiguous
// injection region between opening and closing `---`).
func splitFindingsRegion(region string) (injectionText, dbmsText string) {
	lines := strings.Split(region, "\n")
	// Find indices of `---` lines in sequence.
	delimIdxs := []int{}
	for i, line := range lines {
		if strings.TrimSpace(line) == blockDelimiter {
			delimIdxs = append(delimIdxs, i)
		}
	}
	if len(delimIdxs) < 1 {
		return "", ""
	}
	openIdx := delimIdxs[0]
	closeIdx := openIdx
	if len(delimIdxs) >= 2 {
		closeIdx = delimIdxs[1]
	}
	injectionText = strings.Join(lines[openIdx+1:closeIdx], "\n")
	if closeIdx < len(lines)-1 {
		dbmsText = strings.Join(lines[closeIdx+1:], "\n")
	}
	return injectionText, dbmsText
}

// parameterHeaderRe matches `Parameter: <name> (<place>)` block headers.
var parameterHeaderRe = regexp.MustCompile(`^Parameter:\s+(.+?)\s+\(([^)]+)\)`)

// adaptInjectionFindings parses the per-Parameter block region and
// flattens to N findings per parameter (one per technique entry) per
// Q3 (a) per-technique granularity lock.
//
// Block structure (per V4 empirical):
//
//	Parameter: <name> (<place>)
//	    Type: <technique>
//	    Title: <title>
//	    Payload: <payload>
//	    [blank line]
//	    Type: <next-technique>
//	    Title: ...
//	    Payload: ...
//
// Indentation NOT load-bearing for parsing (regex anchors on field
// names + their colons); inter-technique blank lines preserved as
// natural entry separators.
func adaptInjectionFindings(text, targetURL string) []events.RawFinding {
	var out []events.RawFinding
	if text == "" {
		return out
	}
	var currentParam, currentPlace string
	var currentType, currentTitle, currentPayload string

	flush := func() {
		if currentParam != "" && currentType != "" {
			out = append(out, buildInjectionFinding(
				currentParam, currentPlace, currentType,
				currentTitle, currentPayload, targetURL,
			))
		}
		currentType, currentTitle, currentPayload = "", "", ""
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if m := parameterHeaderRe.FindStringSubmatch(trimmed); len(m) >= 3 {
			flush() // close any in-flight technique from previous param
			currentParam = m[1]
			currentPlace = m[2]
			continue
		}
		if strings.HasPrefix(trimmed, "Type:") {
			flush() // close previous technique
			currentType = strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Title:") {
			currentTitle = strings.TrimSpace(strings.TrimPrefix(trimmed, "Title:"))
			continue
		}
		if strings.HasPrefix(trimmed, "Payload:") {
			currentPayload = strings.TrimSpace(strings.TrimPrefix(trimmed, "Payload:"))
			continue
		}
	}
	flush() // close final technique at region end
	return out
}

// buildInjectionFinding maps one SQLMap injection technique entry to
// one RawFinding. Typed-fields-first per ADR-024 + Q6 lock.
//
// Q6 typed-field reuse:
//
//   - Title ← per-technique title
//   - Severity ← mapSqlmapSeverity(technique) — per Q5 rubric
//   - FindingType ← "sql_injection"
//   - CWEID ← "CWE-89" (SQL Injection canonical)
//   - OWASP ← "A03:2021 Injection"
//   - TargetURL ← scan URL
//   - Parameter ← parameter name
//   - Payload ← injection payload string
//
// Metadata (snake_case per ADR-027; omit-when-empty):
//   - technique ← per-technique Type
//   - place ← parameter place (GET / POST / COOKIE / HEADER)
func buildInjectionFinding(
	parameter, place, technique, title, payload, targetURL string,
) events.RawFinding {
	finding := events.RawFinding{
		Title:       title,
		Severity:    mapSqlmapSeverity(technique),
		Description: "SQL injection vulnerability detected via " + technique + " technique on " + place + " parameter " + parameter,
		FindingType: "sql_injection",
		CWEID:       "CWE-89",
		OWASP:       "A03:2021 Injection",
		TargetURL:   targetURL,
		Parameter:   parameter,
		Payload:     payload,
	}
	meta := map[string]string{}
	setIfNonEmpty(meta, "technique", technique)
	setIfNonEmpty(meta, "place", place)
	if len(meta) > 0 {
		finding.Metadata = meta
	}
	return finding
}

// dbmsTypeRe extracts the first whitespace-delimited token from the
// `back-end DBMS:` value as the canonical DBMS type, with the remainder
// captured as version + qualifier text. Example:
//
//	"MySQL >= 5.1 (MariaDB fork)" → type="MySQL"; version=">= 5.1 (MariaDB fork)"
//	"PostgreSQL"                  → type="PostgreSQL"; version=""
var dbmsTypeRe = regexp.MustCompile(`^(\S+)(?:\s+(.+))?$`)

// adaptDBMSFingerprint parses the trailing 3-line single-object DBMS
// fingerprint block per Q4 (a) lock. Returns finding + presence-bool
// (DBMS section only present when ≥1 injection found per V4 empirical;
// no-injection scans skip emission).
//
// Block structure (per V4 empirical):
//
//	web server operating system: Linux Debian 9 (stretch)
//	web application technology: Apache 2.4.25
//	back-end DBMS: MySQL >= 5.1 (MariaDB fork)
//
// All three lines may have additional trailing noise (stripped log
// prefixes' residue, ending markers). The `back-end DBMS:` line is
// the canonical anchor — if absent, no DBMS finding emitted.
func adaptDBMSFingerprint(text, targetURL string) (events.RawFinding, bool) {
	if text == "" {
		return events.RawFinding{}, false
	}
	var dbmsOS, webAppTech, dbmsRaw string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "web server operating system:"):
			dbmsOS = strings.TrimSpace(strings.TrimPrefix(trimmed, "web server operating system:"))
		case strings.HasPrefix(trimmed, "web application technology:"):
			webAppTech = strings.TrimSpace(strings.TrimPrefix(trimmed, "web application technology:"))
		case strings.HasPrefix(trimmed, "back-end DBMS:"):
			dbmsRaw = strings.TrimSpace(strings.TrimPrefix(trimmed, "back-end DBMS:"))
		}
	}
	if dbmsRaw == "" {
		return events.RawFinding{}, false
	}
	var dbmsType, dbmsVersion string
	if m := dbmsTypeRe.FindStringSubmatch(dbmsRaw); len(m) >= 2 {
		dbmsType = m[1]
		if len(m) >= 3 {
			dbmsVersion = m[2]
		}
	}
	return buildDBMSFinding(dbmsType, dbmsVersion, dbmsOS, webAppTech, targetURL), true
}

// buildDBMSFinding maps the DBMS-fingerprint block to one RawFinding.
// Typed-fields-first per Q6; FindingType="dbms_fingerprint";
// Severity="info" (lowercase canonical per Q4 + ZAP/MobSF/Trivy
// precedent).
func buildDBMSFinding(
	dbmsType, dbmsVersion, dbmsOS, webAppTech, targetURL string,
) events.RawFinding {
	title := "DBMS detected: " + dbmsType
	if dbmsVersion != "" {
		title += " " + dbmsVersion
	}
	desc := "Back-end DBMS fingerprinted as " + dbmsType
	if dbmsVersion != "" {
		desc += " " + dbmsVersion
	}
	if dbmsOS != "" {
		desc += " on " + dbmsOS
	}
	finding := events.RawFinding{
		Title:       title,
		Severity:    "info",
		Description: desc,
		FindingType: "dbms_fingerprint",
		TargetURL:   targetURL,
	}
	meta := map[string]string{}
	setIfNonEmpty(meta, "dbms_type", dbmsType)
	setIfNonEmpty(meta, "dbms_version", dbmsVersion)
	setIfNonEmpty(meta, "dbms_os", dbmsOS)
	setIfNonEmpty(meta, "web_app_tech", webAppTech)
	if len(meta) > 0 {
		finding.Metadata = meta
	}
	return finding
}

// mapSqlmapSeverity maps per-technique rubric → ShieldScan canonical
// lowercase severity per Q5 rubric + ZAP/MobSF/Trivy lowercase precedent:
//
//	boolean-based blind / error-based / UNION query / stacked queries → "high"
//	    (active exploitation paths; reliable data exfiltration)
//	time-based blind                                                   → "medium"
//	    (slower exploitation; same vulnerability class but operationally degraded)
//	(unknown/default)                                                  → "high"
//	    (defensive forward-compat for future SQLMap technique names)
//
// Per Q5 lock + Task 7.4 1c6041d severity-helper convention. Convention
// naming `mapSqlmapSeverity` mirrors `mapMobSFSeverity` + `mapZAPRisk`
// + `mapTrivySeverity` 3-instance precedent; Phase 5.D evaluation
// defers per Task 7.1 P5.D aa3fb5f scope-mismatch methodology
// (engine-side patterns stay out of canonical application-side document).
func mapSqlmapSeverity(technique string) string {
	switch strings.ToLower(strings.TrimSpace(technique)) {
	case "time-based blind":
		return "medium"
	case "boolean-based blind", "error-based", "union query", "stacked queries":
		return "high"
	default:
		return "high" // defensive forward-compat
	}
}

// setIfNonEmpty implements omit-when-empty Metadata discipline per
// ADR-027. Mirrors Trivy precedent at parser.go.
func setIfNonEmpty(m map[string]string, key, value string) {
	if value == "" {
		return
	}
	m[key] = value
}
