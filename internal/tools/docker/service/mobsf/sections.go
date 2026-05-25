package mobsf

import (
	"encoding/json"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// manifestSection mirrors report_json.manifest_analysis per Phase 0
// V11. Per-finding shape: {rule, title, severity, description, name,
// component[]}.
type manifestSection struct {
	Findings []manifestFinding `json:"manifest_findings"`
}

type manifestFinding struct {
	Rule        string   `json:"rule"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Name        string   `json:"name"`
	Component   []string `json:"component"`
}

// adaptManifestFindings — V11 per-section adaptor. severity per V5
// lowercase normalization; component[] joined into
// Metadata.manifest_component for cross-component cardinality.
func adaptManifestFindings(section manifestSection, platform string) []events.RawFinding {
	if len(section.Findings) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(section.Findings))
	for _, mf := range section.Findings {
		severity, drop := mapMobSFSeverity(mf.Severity)
		if drop {
			continue
		}
		title := mf.Title
		if title == "" {
			title = mf.Rule
		}
		f := events.RawFinding{
			Title:         title,
			Severity:      severity,
			Description:   mf.Description,
			MobileOS:      platform,
			ComponentName: mf.Name,
			Metadata: map[string]string{
				"rule_id": mf.Rule,
				"section": "manifest_analysis",
			},
		}
		if len(mf.Component) > 0 {
			f.Metadata["manifest_component"] = strings.Join(mf.Component, ",")
		}
		out = append(out, f)
	}
	return out
}

// permissionEntry mirrors report_json.permissions[permission_name]
// per Phase 0 V12.
type permissionEntry struct {
	Status      string `json:"status"`
	Info        string `json:"info"`
	Description string `json:"description"`
}

// adaptPermissions — V12 dict-keyed section. Only status="dangerous"
// emits findings (status="normal"/"signature"/etc. are informational
// platform attributes, not findings).
func adaptPermissions(perms map[string]permissionEntry, platform string) []events.RawFinding {
	if len(perms) == 0 {
		return nil
	}
	// Deterministic ordering.
	names := make([]string, 0, len(perms))
	for name := range perms {
		names = append(names, name)
	}
	stringsSortInPlace(names)

	var out []events.RawFinding
	for _, name := range names {
		entry := perms[name]
		if strings.ToLower(entry.Status) != "dangerous" {
			continue
		}
		out = append(out, events.RawFinding{
			Title:       "Dangerous permission: " + name,
			Severity:    "medium",
			Description: entry.Description,
			MobileOS:    platform,
			Permission:  name,
			Metadata: map[string]string{
				"section":         "permissions",
				"permission_info": entry.Info,
			},
		})
	}
	return out
}

// networkSecuritySection — V13: schema verified at Phase 0 v2 against
// MobSF v4.4.6 reality (shieldscan-docs cd933c5). Per-finding shape:
// {scope: []string, description: string, severity: string}. Decoded
// as raw map for forward-additive schema resilience.
type networkSecuritySection struct {
	NetworkFindings []map[string]any `json:"network_findings"`
}

// coerceScope normalizes the V13 `scope` field which empirically
// arrives as []any (typically []any{"*"}) but may also surface as a
// bare string under schema drift. Returns the joined string form for
// Title use; empty string when scope absent/unrecognized.
func coerceScope(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []any:
		parts := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok && str != "" {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

// adaptNetworkSecurity — V13 adaptor. Per Phase 0 v2 empirical
// verification (DDG /tmp/ddg-scan.json; 4 populated network_findings):
// scope arrives as []string (silent type-fallback in pre-Phase-0-v2
// parser produced default Title). Coerces list→string for Title;
// preserves raw scope value via scope_list Metadata key (ADR-027
// snake_case + omit-when-empty).
func adaptNetworkSecurity(section networkSecuritySection, platform string) []events.RawFinding {
	if len(section.NetworkFindings) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(section.NetworkFindings))
	for _, nf := range section.NetworkFindings {
		raw, _ := json.Marshal(nf)
		severityRaw, _ := nf["severity"].(string)
		severity, drop := mapMobSFSeverity(severityRaw)
		if drop {
			continue
		}
		title := coerceScope(nf["scope"])
		if title == "" {
			title = "Network security finding"
		}
		desc, _ := nf["description"].(string)
		meta := map[string]string{
			"section":         "network_security",
			"raw_finding":     string(raw),
			"forward_pin_v13": "verified against v4.4.6 reality (Phase 0 v2; shieldscan-docs cd933c5)",
		}
		if scopeRaw, err := json.Marshal(nf["scope"]); err == nil && nf["scope"] != nil {
			meta["scope_list"] = string(scopeRaw)
		}
		out = append(out, events.RawFinding{
			Title:       title,
			Severity:    severity,
			Description: desc,
			MobileOS:    platform,
			Metadata:    meta,
		})
	}
	return out
}

// binaryAnalysisEntry — V14 list-of-objects with 8 sub-checks per
// binary. Per Phase 0: each sub-check object has {severity, status,
// description}-like shape; "secure" status indicates no finding.
//
// Sub-check keys (Phase 0): nx, pie, stack_canary, relocation_readonly,
// rpath, runpath, fortify, symbol.
var binarySubChecks = []string{
	"nx", "pie", "stack_canary", "relocation_readonly",
	"rpath", "runpath", "fortify", "symbol",
}

// adaptBinaryAnalysis — V14 adaptor. binary_analysis is list-of-objects;
// each entry's sub-checks are emitted as separate findings only when
// the sub-check's status is NOT "secure" (or equivalent positive
// marker). Uses json.RawMessage decoding for v4.x schema resilience.
func adaptBinaryAnalysis(raw json.RawMessage, platform string) []events.RawFinding {
	if len(raw) == 0 {
		return nil
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil // defensive — schema drift surfaces as empty rather than panic
	}
	var out []events.RawFinding
	for _, entry := range entries {
		fileName, _ := entry["name"].(string)
		for _, key := range binarySubChecks {
			sub, ok := entry[key].(map[string]any)
			if !ok {
				continue
			}
			status, _ := sub["status"].(string)
			severityRaw, _ := sub["severity"].(string)
			desc, _ := sub["description"].(string)
			if strings.ToLower(status) == "secure" || strings.ToLower(status) == "" {
				continue
			}
			sev, drop := mapMobSFSeverity(severityRaw)
			if drop {
				sev = "info" // status non-secure but no severity field
			}
			out = append(out, events.RawFinding{
				Title:       "Binary check: " + key + " (" + status + ")",
				Severity:    sev,
				Description: desc,
				MobileOS:    platform,
				CodeFile:    fileName,
				Metadata: map[string]string{
					"section":     "binary_analysis",
					"check":       key,
					"status":      status,
					"binary_name": fileName,
				},
			})
		}
	}
	return out
}

// adaptSecrets — V15 list-of-strings adaptor. Each secret-excerpt
// string surfaces as a separate finding so downstream dedup operates
// at the secret-substring level.
func adaptSecrets(secrets []string, platform string) []events.RawFinding {
	if len(secrets) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(secrets))
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, events.RawFinding{
			Title:       "Hardcoded Secret",
			Severity:    "medium", // V5 warning→medium
			Description: s,
			MobileOS:    platform,
			Metadata: map[string]string{
				"section": "secrets",
			},
		})
	}
	return out
}

// certAnalysisSection — V17 list-of-3-element-lists adaptor.
// Per Phase 0: certificate_findings entries are [severity, title,
// description] triples (positional, NOT keyed).
type certAnalysisSection struct {
	CertificateFindings [][]string `json:"certificate_findings"`
}

// adaptCertificateFindings — V17 adaptor. Iterates triples; severity
// per V5 mapping; defensive against arity drift.
func adaptCertificateFindings(section certAnalysisSection, platform string) []events.RawFinding {
	if len(section.CertificateFindings) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(section.CertificateFindings))
	for _, triple := range section.CertificateFindings {
		if len(triple) < 3 {
			continue
		}
		severity, drop := mapMobSFSeverity(triple[0])
		if drop {
			continue
		}
		out = append(out, events.RawFinding{
			Title:       triple[1],
			Severity:    severity,
			Description: triple[2],
			MobileOS:    platform,
			Metadata: map[string]string{
				"section": "certificate_analysis",
			},
		})
	}
	return out
}

// trackersSection — V16: schema verified at Phase 0 v2 against
// MobSF v4.4.6 reality (shieldscan-docs cd933c5). Per-tracker shape:
// {name: string, categories: string, url: string}. No per-tracker
// severity; section-level hardcoded "info" preserved.
type trackersSection struct {
	Trackers []map[string]any `json:"trackers"`
}

// adaptTrackers — V16 adaptor. Per Phase 0 v2 empirical verification
// (IBv2 /tmp/ibv2-scan.json; 3 populated trackers: Google AdMob +
// Google Analytics + Google Tag Manager): categories ("Advertisement"
// / "Analytics") + url (Exodus Privacy report link) promoted to
// dedicated Metadata keys (ADR-027 snake_case + omit-when-empty).
func adaptTrackers(section trackersSection, platform string) []events.RawFinding {
	if len(section.Trackers) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(section.Trackers))
	for _, t := range section.Trackers {
		raw, _ := json.Marshal(t)
		name, _ := t["name"].(string)
		if name == "" {
			name = "Tracker"
		}
		meta := map[string]string{
			"section":         "trackers",
			"raw_entry":       string(raw),
			"forward_pin_v16": "verified against v4.4.6 reality (Phase 0 v2; shieldscan-docs cd933c5)",
		}
		if cats, _ := t["categories"].(string); cats != "" {
			meta["tracker_categories"] = cats
		}
		if url, _ := t["url"].(string); url != "" {
			meta["tracker_url"] = url
		}
		out = append(out, events.RawFinding{
			Title:    "Tracker detected: " + name,
			Severity: "info",
			MobileOS: platform,
			Metadata: meta,
		})
	}
	return out
}

// stringsSortInPlace is a tiny shim avoiding direct sort.Strings
// import in this file (kept import block clean).
func stringsSortInPlace(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// ─── iOS adaptors (Task 7.4 V10; Phase 0 v2 v2 empirically grounded) ──
//
// Per V10 design doc shieldscan-docs commit 0347a79 §4 + implementation
// plan 7c4fe75 §3.3. 5 mandatory iOS adaptors per Q2 (a) lock; 3
// empty-section adaptors (macho_analysis + framework_analysis +
// ios_api) forward-pinned per Q2 (a) to populated-state testbed task.

// ── adaptInfoPlist (Y-PLIST-PARSE a lock; Go stdlib pattern-scan) ──

// iOS info_plist arrives as raw XML string (~4856 chars empirical in
// DVIA-v2-swift v2.0). Per Y-PLIST-PARSE (a) execution-time lock:
// use pattern-scan over the XML text to extract known-risky keys per
// OWASP MASVS-PLATFORM-3 + MASVS-NETWORK-1; avoids dependency-add
// (github.com/howett/plist; Y-PLIST-PARSE b alternative rejected at
// execution per dependency-add overhead vs known-key extraction
// simplicity).
//
// Known-risky keys checked v1:
//   - NSAllowsArbitraryLoads (boolean; true → high severity ATS bypass)
//   - UIFileSharingEnabled (boolean; true → medium severity)
//   - ITSAppUsesNonExemptEncryption (boolean/absent; informational)
//   - NSAppTransportSecurity (parent dict presence; informational)
//
// Forward-pinned: NSExceptionDomains per-domain ATS exceptions;
// UIBackgroundModes per-mode security implications; CFBundleURLTypes
// (covered separately by adaptBundleURLTypes).
func adaptInfoPlist(plistXML string, platform string) []events.RawFinding {
	if plistXML == "" {
		return nil
	}
	var out []events.RawFinding
	emitBool := func(key, title, sev, desc string) {
		out = append(out, events.RawFinding{
			Title:       title,
			Severity:    sev,
			Description: desc,
			FindingType: "info_plist_finding",
			MobileOS:    platform,
			Metadata: map[string]string{
				"section":   "info_plist",
				"plist_key": key,
			},
		})
	}
	// Pattern-scan: <key>KEY</key>\s*<true/>  → boolean true.
	hasTrueFor := func(key string) bool {
		i := strings.Index(plistXML, "<key>"+key+"</key>")
		if i < 0 {
			return false
		}
		rest := plistXML[i+len("<key>"+key+"</key>"):]
		// Skip whitespace + newlines + a possible <dict><key>...
		trimmed := strings.TrimSpace(rest)
		return strings.HasPrefix(trimmed, "<true/>")
	}
	hasKey := func(key string) bool {
		return strings.Contains(plistXML, "<key>"+key+"</key>")
	}
	if hasTrueFor("NSAllowsArbitraryLoads") {
		emitBool("NSAllowsArbitraryLoads",
			"ATS arbitrary loads enabled: NSAllowsArbitraryLoads=true",
			"high",
			"App Transport Security restrictions disabled for all network connections. "+
				"HTTP traffic is permitted; TLS minimum-version checks are bypassed. "+
				"Violates OWASP MASVS-NETWORK-1.")
	}
	if hasTrueFor("UIFileSharingEnabled") {
		emitBool("UIFileSharingEnabled",
			"iTunes file sharing enabled: UIFileSharingEnabled=true",
			"medium",
			"App documents directory is exposed via iTunes file sharing. "+
				"Sensitive data in the Documents folder is accessible to users "+
				"with physical device access. Violates OWASP MASVS-STORAGE-1.")
	}
	if hasKey("NSAppTransportSecurity") {
		emitBool("NSAppTransportSecurity",
			"App Transport Security configuration present",
			"info",
			"NSAppTransportSecurity dictionary declared in Info.plist; "+
				"review per-domain exceptions for least-privilege adherence.")
	}
	if !hasKey("ITSAppUsesNonExemptEncryption") {
		out = append(out, events.RawFinding{
			Title:       "ITSAppUsesNonExemptEncryption key absent",
			Severity:    "info",
			Description: "ITSAppUsesNonExemptEncryption key not declared; App Store submission may require export-compliance attestation.",
			FindingType: "info_plist_finding",
			MobileOS:    platform,
			Metadata: map[string]string{
				"section":   "info_plist",
				"plist_key": "ITSAppUsesNonExemptEncryption",
				"state":     "absent",
			},
		})
	}
	return out
}

// ── adaptATSFindings (mirrors adaptNetworkSecurity Android pattern) ──

type atsAnalysisSection struct {
	ATSFindings []atsFinding `json:"ats_findings"`
	ATSSummary  atsSummary   `json:"ats_summary"`
}

type atsFinding struct {
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type atsSummary struct {
	High    int `json:"high"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
	Secure  int `json:"secure"`
}

// adaptATSFindings — iOS App Transport Security findings adaptor.
// Per V4 empirical schema: {ats_findings: [{issue, severity,
// description}], ats_summary: {high, warning, info, secure}}.
// mapMobSFSeverity reusable (iOS severity values lowercase canonical
// match Android per V-CM).
func adaptATSFindings(section atsAnalysisSection, platform string) []events.RawFinding {
	if len(section.ATSFindings) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(section.ATSFindings))
	for _, af := range section.ATSFindings {
		sev, drop := mapMobSFSeverity(af.Severity)
		if drop {
			continue
		}
		out = append(out, events.RawFinding{
			Title:       af.Issue,
			Severity:    sev,
			Description: af.Description,
			FindingType: "ats_violation",
			MobileOS:    platform,
			Metadata: map[string]string{
				"section": "ats_analysis",
			},
		})
	}
	return out
}

// ── adaptDylibAnalysis (Drift #46 — separate dylibSubChecks constant) ──

// dylibSubChecks enumerates the 8 iOS .dylib protection sub-checks
// per Task 7.4 V10 Phase 0 v2 V-CL empirical capture from
// /tmp/v10-ios-report.json. DIFFERS from Android binarySubChecks
// (overlap: nx, pie, stack_canary, rpath, symbol; iOS-only: arc,
// code_signature, encrypted; Android-only: relocation_readonly,
// runpath, fortify). Drift #46 catch — plan §3.3 originally
// suggested binarySubChecks reuse; empirically incorrect.
var dylibSubChecks = []string{
	"arc", "code_signature", "encrypted", "nx",
	"pie", "rpath", "stack_canary", "symbol",
}

type dylibEntry struct {
	Name string                    `json:"name"`
	Raw  map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON preserves all sub-check fields as raw payload so
// adaptDylibAnalysis can probe dylibSubChecks dynamically.
func (e *dylibEntry) UnmarshalJSON(data []byte) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.Raw = raw
	if n, ok := raw["name"]; ok {
		_ = json.Unmarshal(n, &e.Name)
	}
	return nil
}

type dylibSubCheck struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// adaptDylibAnalysis — iOS .dylib protection adaptor. Mirrors
// adaptBinaryAnalysis Android pattern shape per V4 empirical: list ×
// 8 sub-checks per .dylib entry. Per-sub-check severity rubric:
// MobSF emits "info" by default; non-info severities surface as
// findings; positive states ("has_nx"/"has_pie" booleans inside the
// sub-check) inform Title disambiguation.
func adaptDylibAnalysis(entries []dylibEntry, platform string) []events.RawFinding {
	if len(entries) == 0 {
		return nil
	}
	var out []events.RawFinding
	for _, e := range entries {
		for _, key := range dylibSubChecks {
			rawSub, ok := e.Raw[key]
			if !ok {
				continue
			}
			var sub dylibSubCheck
			if err := json.Unmarshal(rawSub, &sub); err != nil {
				continue
			}
			sev, drop := mapMobSFSeverity(sub.Severity)
			if drop {
				continue
			}
			out = append(out, events.RawFinding{
				Title:       "dylib " + key + " check: " + e.Name,
				Severity:    sev,
				Description: sub.Description,
				FindingType: "dylib_protection_missing",
				MobileOS:    platform,
				CodeFile:    e.Name,
				Metadata: map[string]string{
					"section":    "dylib_analysis",
					"dylib_name": e.Name,
					"sub_check":  key,
				},
			})
		}
	}
	return out
}

// ── adaptIOSBinary (Q3 (a) shape-collision resolution; iOS dict) ──

type iosBinarySummary struct {
	Findings map[string]iosBinaryFinding `json:"findings"`
	Summary  iosBinaryCounts             `json:"summary"`
}

type iosBinaryFinding struct {
	DetailedDesc string  `json:"detailed_desc"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss"`
	CWE          string  `json:"cwe"`
	OWASPMobile  string  `json:"owasp-mobile"`
	MASVS        string  `json:"masvs"`
}

type iosBinaryCounts struct {
	High       int `json:"high"`
	Warning    int `json:"warning"`
	Info       int `json:"info"`
	Secure     int `json:"secure"`
	Suppressed int `json:"suppressed"`
}

// adaptIOSBinary — iOS binary_analysis dict-shape adaptor; resolves
// Q3 (a) same-key-different-shape collision with Android. Android's
// binary_analysis is list × 8 sub-checks per binary; iOS's is dict
// {findings: {<title>: {detailed_desc, severity, cvss, cwe,
// owasp-mobile, masvs}}, summary: {...}}. parseReport gates
// invocation to platform=="ios" per Q1 (γ); this adaptor unmarshals
// raw JSON into iosBinarySummary shape.
func adaptIOSBinary(raw json.RawMessage, platform string) []events.RawFinding {
	if len(raw) == 0 {
		return nil
	}
	var summary iosBinarySummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		return nil // schema drift defensive — surface as empty
	}
	if len(summary.Findings) == 0 {
		return nil
	}
	out := make([]events.RawFinding, 0, len(summary.Findings))
	for title, f := range summary.Findings {
		sev, drop := mapMobSFSeverity(f.Severity)
		if drop {
			continue
		}
		cweNumber, cweDesc := extractCWENumber(f.CWE)
		md := map[string]string{
			"section": "binary_analysis",
		}
		if f.MASVS != "" {
			md["masvs"] = f.MASVS
		}
		if cweDesc != "" {
			md["cwe_description"] = cweDesc
		}
		owasp := ""
		if f.OWASPMobile != "" {
			// Mirror extractMobSFTags D3 convention: "M7: Client Code Quality" → "OWASP-M7"
			parts := strings.SplitN(f.OWASPMobile, ":", 2)
			if len(parts) > 0 {
				owasp = "OWASP-" + strings.TrimSpace(parts[0])
			}
		}
		out = append(out, events.RawFinding{
			Title:       title,
			Severity:    sev,
			Description: f.DetailedDesc,
			FindingType: "ios_binary_finding",
			CVSSScore:   f.CVSS,
			CWEID:       cweNumber,
			OWASP:       owasp,
			MobileOS:    platform,
			Metadata:    md,
		})
	}
	return out
}

// ── adaptBundleURLTypes (URL scheme hijack detection) ──

type bundleURLTypeEntry struct {
	CFBundleURLName    string   `json:"CFBundleURLName"`
	CFBundleURLSchemes []string `json:"CFBundleURLSchemes"`
}

// wellKnownURLSchemes are the standard schemes that are typically
// safe to register (informational findings). Custom schemes raise
// medium severity per OWASP MASVS-PLATFORM-3 URL scheme hijack risk.
var wellKnownURLSchemes = map[string]bool{
	"http":   true,
	"https":  true,
	"mailto": true,
	"tel":    true,
	"sms":    true,
	"ftp":    true,
}

// adaptBundleURLTypes — iOS URL scheme registration adaptor. Per
// V4 empirical schema: list of {CFBundleURLName, CFBundleURLSchemes:
// [...]}. Each registered scheme emits a RawFinding; severity rubric
// distinguishes well-known schemes (info) from custom schemes
// (medium; URL scheme hijack risk per OWASP MASVS-PLATFORM-3).
func adaptBundleURLTypes(entries []bundleURLTypeEntry, platform string) []events.RawFinding {
	if len(entries) == 0 {
		return nil
	}
	var out []events.RawFinding
	for _, e := range entries {
		for _, scheme := range e.CFBundleURLSchemes {
			sev := "medium"
			desc := "Custom URL scheme registered; potentially vulnerable to URL scheme hijack " +
				"if another app registers the same scheme. Per OWASP MASVS-PLATFORM-3 review " +
				"caller-validation + scheme-handler logic."
			if wellKnownURLSchemes[strings.ToLower(scheme)] {
				sev = "info"
				desc = "Well-known URL scheme registered; standard platform handling."
			}
			out = append(out, events.RawFinding{
				Title:       "iOS URL scheme registered: " + scheme,
				Severity:    sev,
				Description: desc,
				FindingType: "ios_url_scheme",
				MobileOS:    platform,
				Metadata: map[string]string{
					"section":         "bundle_url_types",
					"url_scheme":      scheme,
					"bundle_url_name": e.CFBundleURLName,
				},
			})
		}
	}
	return out
}
