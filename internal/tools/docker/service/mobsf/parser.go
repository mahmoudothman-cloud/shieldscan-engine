package mobsf

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// codeAnalysisRule mirrors the per-rule object under
// report_json.code_analysis.findings[<rule_id>] per Phase 0 V4
// grounded reality (NOT the mobsfscan README schema; D1).
//
// Drifts captured (Phase 0):
//   - D1: Files is map[string]string (path → comma-separated line
//     numbers), NOT []FileMatch{path, lines[]int} as suggested by
//     mobsfscan README.
//   - D2: Metadata key is "ref" (often null), NOT "reference".
//   - D3: Metadata.OWASPMobile is "M7: Client Code Quality" (colon
//     separator), NOT "M7-Client Code Quality" (hyphen).
//   - D4: Metadata.MASVS is full identifier "MSTG-STORAGE-2", NOT
//     short form "code-8".
//   - V5: Severity is lowercase ("high","warning","info"), NOT
//     uppercase.
type codeAnalysisRule struct {
	Files    map[string]string    `json:"files"` // D1: path → "3,21,32"
	Metadata codeAnalysisMetadata `json:"metadata"`
}

type codeAnalysisMetadata struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // V5: lowercase
	CVSS        any    `json:"cvss"`
	CWE         string `json:"cwe"`
	OWASPMobile string `json:"owasp-mobile"` // D3: colon form
	MASVS       string `json:"masvs"`        // D4: full form
	Ref         string `json:"ref"`          // D2: ref (not reference)
}

// reportV4 is the top-level subset of the MobSF v4.4.6 report_json
// payload this consumer cares about. Heterogeneous per-section
// shapes — see sections.go for adaptors. Unknown fields silently
// ignored (forward-compat with v4.x additive schema changes).
type reportV4 struct {
	AppName          string                     `json:"app_name"`
	PackageName      string                     `json:"package_name"`
	VersionName      string                     `json:"version_name"`
	VersionCode      string                     `json:"version_code"`
	MainActivity     string                     `json:"main_activity"`
	Hash             string                     `json:"hash"`
	FileName         string                     `json:"file_name"`
	CodeAnalysis     codeAnalysisSection        `json:"code_analysis"`
	ManifestAnalysis manifestSection            `json:"manifest_analysis"`
	Permissions      map[string]permissionEntry `json:"permissions"`
	NetworkSecurity  networkSecuritySection     `json:"network_security"`
	BinaryAnalysis   json.RawMessage            `json:"binary_analysis"`
	Secrets          []string                   `json:"secrets"`
	CertAnalysis     certAnalysisSection        `json:"certificate_analysis"`
	Trackers         trackersSection            `json:"trackers"`

	// iOS-specific sections per Task 7.4 V10 Phase 0 v2 empirical
	// findings (DVIA-v2-swift v2.0 scan). Routed at parseReport
	// platform-gated invocation block per Q1 (γ) lock.
	InfoPlist      string                `json:"info_plist"`
	ATSAnalysis    atsAnalysisSection    `json:"ats_analysis"`
	DylibAnalysis  []dylibEntry          `json:"dylib_analysis"`
	BundleURLTypes []bundleURLTypeEntry  `json:"bundle_url_types"`
}

type codeAnalysisSection struct {
	Findings map[string]codeAnalysisRule `json:"findings"`
}

// mapMobSFSeverity normalizes a MobSF v4.4.6 lowercase severity string
// (V5) to the shieldscan-api Severity enum value. Per Phase 0 V8 +
// Task 7.3 ZAP precedent: shieldscan-api enum =
// {"critical","high","medium","low","info"} (all lowercase).
//
// Drops empty / "secure" / "good" (not findings; positive-state markers
// per Phase 0 V4 V14 binary_analysis observation).
func mapMobSFSeverity(sev string) (severity string, drop bool) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "high":
		return "high", false
	case "warning":
		return "medium", false
	case "info":
		return "info", false
	case "", "secure", "good":
		return "", true
	default:
		// Unknown values surface as "info" rather than drop —
		// defensive forward-compat (new MobSF versions add new
		// severity buckets).
		return "info", false
	}
}

// extractCWENumber pulls the numeric ID from MobSF's "CWE-89: Improper
// Neutralization..." form. Returns "" if no CWE-NNN prefix. Description
// suffix preserved in Metadata.cwe_description by the caller.
func extractCWENumber(cwe string) (number, description string) {
	cwe = strings.TrimSpace(cwe)
	if !strings.HasPrefix(strings.ToUpper(cwe), "CWE-") {
		return "", cwe
	}
	rest := cwe[4:] // drop "CWE-"
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return strings.TrimSpace(rest), ""
	}
	number = strings.TrimSpace(rest[:colonIdx])
	description = strings.TrimSpace(rest[colonIdx+1:])
	return number, description
}

// extractMobSFTags converts per-rule metadata identifiers to canonical
// RawFinding.Tags entries per Phase 0 D3 + D4 corrections.
//
// owasp-mobile form (D3): "M7: Client Code Quality" → "OWASP-M7".
// masvs form (D4): "MSTG-STORAGE-2" → "MSTG-STORAGE-2" (pass-through).
// Empty inputs return nil. Output sorted for deterministic Fingerprint
// hashing downstream.
func extractMobSFTags(owaspMobile, masvs string) []string {
	var out []string
	if owaspMobile = strings.TrimSpace(owaspMobile); owaspMobile != "" {
		// D3: extract "M<n>" prefix before colon (if present).
		head := owaspMobile
		if colonIdx := strings.Index(head, ":"); colonIdx >= 0 {
			head = strings.TrimSpace(head[:colonIdx])
		}
		if head != "" {
			out = append(out, "OWASP-"+head)
		}
	}
	if masvs = strings.TrimSpace(masvs); masvs != "" {
		// D4: pass-through canonical form (no extraction needed).
		out = append(out, masvs)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// fileMatch represents one (file_path, line_numbers) pair extracted
// from D1 files-dict shape.
type fileMatch struct {
	Path  string
	Lines []int
}

// parseFilesDict converts MobSF v4.4.6 code_analysis files-dict shape
// (map[path]string-of-csv-line-numbers; D1) to a stable, iterable
// []fileMatch. Empty / malformed inputs produce empty slice (not error
// — defensive against v4.x schema drift). Path order is deterministic
// (alphabetical) for downstream Fingerprint stability.
func parseFilesDict(files map[string]string) []fileMatch {
	if len(files) == 0 {
		return nil
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := make([]fileMatch, 0, len(paths))
	for _, p := range paths {
		raw := strings.TrimSpace(files[p])
		var lines []int
		if raw != "" {
			for _, tok := range strings.Split(raw, ",") {
				tok = strings.TrimSpace(tok)
				if tok == "" {
					continue
				}
				n, err := strconv.Atoi(tok)
				if err != nil {
					continue // skip malformed token defensively
				}
				lines = append(lines, n)
			}
		}
		out = append(out, fileMatch{Path: p, Lines: lines})
	}
	return out
}

// parseReport decodes MobSF v4.4.6 report_json bytes and produces
// RawFindings across all sections per Phase 0 V11-V17 + V8 typed-fields-
// first per Q8 mapping.
//
// Identity fields (ToolName, EngineCategory, DiscoveredAt, Fingerprint)
// populated by service.DockerServiceRunner.Run enrichment loop per
// Task 7.5b service.go pattern.
//
// platform is propagated into RawFinding.MobileOS (android|ios).
// Per Task 7.4 V10 (shieldscan-docs commits 0347a79 design + 7c4fe75
// plan + d4f6ca7 V10 status RESOLVED): parseReport routes 4
// platform-agnostic adaptors unconditionally + 4 Android-specific
// adaptors gated to platform=="android" + 5 iOS-specific adaptors
// gated to platform=="ios". Q1 (γ) section-dispatch architecture
// lock. Q3 (a) binary_analysis json.RawMessage shape-collision
// resolution: parser passes raw bytes to platform-conditional adaptor
// (adaptBinaryAnalysis Android list-shape OR adaptIOSBinary iOS dict
// shape).
func parseReport(body []byte, platform string) ([]events.RawFinding, error) {
	var r reportV4
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("mobsf parser: unmarshal report: %w", err)
	}
	var out []events.RawFinding

	// Platform-agnostic adaptors (V3 empirical: present in both
	// Android + iOS reports with same shape per V-CK).
	out = append(out, parseCodeAnalysis(r.CodeAnalysis, platform)...)
	out = append(out, adaptPermissions(r.Permissions, platform)...)
	out = append(out, adaptSecrets(r.Secrets, platform)...)
	out = append(out, adaptTrackers(r.Trackers, platform)...)

	switch platform {
	case "android":
		out = append(out, adaptManifestFindings(r.ManifestAnalysis, platform)...)
		out = append(out, adaptNetworkSecurity(r.NetworkSecurity, platform)...)
		out = append(out, adaptCertificateFindings(r.CertAnalysis, platform)...)
		out = append(out, adaptBinaryAnalysis(r.BinaryAnalysis, platform)...)
	case "ios":
		out = append(out, adaptInfoPlist(r.InfoPlist, platform)...)
		out = append(out, adaptATSFindings(r.ATSAnalysis, platform)...)
		out = append(out, adaptDylibAnalysis(r.DylibAnalysis, platform)...)
		out = append(out, adaptIOSBinary(r.BinaryAnalysis, platform)...)
		out = append(out, adaptBundleURLTypes(r.BundleURLTypes, platform)...)
	}
	return out, nil
}

// parseCodeAnalysis is the primary section parser per Q8 mapping +
// Phase 0 D1-D4 + V5 drifts. One RawFinding per (rule_id, file_path)
// pair — multiple files for the same rule produce multiple findings
// (downstream dedup via Fingerprint handles cross-rule overlap).
func parseCodeAnalysis(section codeAnalysisSection, platform string) []events.RawFinding {
	if len(section.Findings) == 0 {
		return nil
	}
	// Deterministic rule_id ordering for Fingerprint stability.
	ruleIDs := make([]string, 0, len(section.Findings))
	for rid := range section.Findings {
		ruleIDs = append(ruleIDs, rid)
	}
	sort.Strings(ruleIDs)

	var out []events.RawFinding
	for _, rid := range ruleIDs {
		rule := section.Findings[rid]
		severity, drop := mapMobSFSeverity(rule.Metadata.Severity)
		if drop {
			continue
		}
		cweNum, cweDesc := extractCWENumber(rule.Metadata.CWE)
		tags := extractMobSFTags(rule.Metadata.OWASPMobile, rule.Metadata.MASVS)
		matches := parseFilesDict(rule.Files)
		if len(matches) == 0 {
			// Surface the rule itself even without file refs (defensive
			// — some rules apply at app-level, not file-level).
			out = append(out, events.RawFinding{
				Title:       rid, // V8: rule_id as Title (decision-lock)
				Severity:    severity,
				Description: rule.Metadata.Description,
				CWEID:       cweNum,
				Tags:        tags,
				MobileOS:    platform,
				Metadata:    buildCodeMetadata(rid, rule.Metadata, cweDesc, ""),
			})
			continue
		}
		for _, m := range matches {
			f := events.RawFinding{
				Title:       rid, // V8 decision-lock
				Severity:    severity,
				Description: rule.Metadata.Description,
				CWEID:       cweNum,
				Tags:        tags,
				MobileOS:    platform,
				CodeFile:    m.Path,
				Metadata:    buildCodeMetadata(rid, rule.Metadata, cweDesc, formatLines(m.Lines)),
			}
			if len(m.Lines) > 0 {
				f.CodeLine = m.Lines[0] // first occurrence as canonical
			}
			out = append(out, f)
		}
	}
	return out
}

// buildCodeMetadata constructs Metadata for code_analysis findings per
// ADR-027 snake_case convention + Q8 mapping. Empty values omitted to
// keep payload compact.
func buildCodeMetadata(ruleID string, meta codeAnalysisMetadata, cweDesc, lines string) map[string]string {
	m := map[string]string{
		"rule_id": ruleID,
	}
	if cweDesc != "" {
		m["cwe_description"] = cweDesc
	}
	if meta.OWASPMobile != "" {
		m["owasp_mobile"] = meta.OWASPMobile
	}
	if meta.MASVS != "" {
		m["masvs"] = meta.MASVS
	}
	if meta.Ref != "" {
		m["ref"] = meta.Ref // D2: ref not reference
	}
	if cvss := stringifyCVSS(meta.CVSS); cvss != "" {
		m["cvss"] = cvss
	}
	if lines != "" {
		m["code_lines"] = lines
	}
	return m
}

// stringifyCVSS handles MobSF's heterogeneous cvss field — sometimes
// numeric, sometimes string, sometimes null.
func stringifyCVSS(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == 0 {
			return ""
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	default:
		return ""
	}
}

// formatLines joins line numbers as a comma-separated string for
// Metadata.code_lines (audit/correlation use).
func formatLines(lines []int) string {
	if len(lines) == 0 {
		return ""
	}
	parts := make([]string, len(lines))
	for i, n := range lines {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}
