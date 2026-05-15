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

// networkSecuritySection — V13 forward-pin: empty in DIVA Phase 0
// sample; shape unknown for populated case. Decoded as a raw map so
// we can log presence without panicking on schema drift.
type networkSecuritySection struct {
	NetworkFindings []map[string]any `json:"network_findings"`
}

// adaptNetworkSecurity — V13 forward-pin adaptor. Emits nothing if
// empty; for populated case emits a generic finding per entry pending
// future schema discovery.
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
		title, _ := nf["scope"].(string)
		if title == "" {
			title = "Network security finding"
		}
		desc, _ := nf["description"].(string)
		out = append(out, events.RawFinding{
			Title:       title,
			Severity:    severity,
			Description: desc,
			MobileOS:    platform,
			Metadata: map[string]string{
				"section":         "network_security",
				"raw_finding":     string(raw),
				"forward_pin_v13": "shape not yet stabilized; verify against MobSF v4.x release notes",
			},
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

// trackersSection — V16 forward-pin. Trackers list empty in DIVA Phase
// 0 sample; populated case decoded as raw entries pending stabilized
// schema.
type trackersSection struct {
	Trackers []map[string]any `json:"trackers"`
}

// adaptTrackers — V16 forward-pin adaptor.
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
		out = append(out, events.RawFinding{
			Title:    "Tracker detected: " + name,
			Severity: "info",
			MobileOS: platform,
			Metadata: map[string]string{
				"section":         "trackers",
				"raw_entry":       string(raw),
				"forward_pin_v16": "shape not yet stabilized in v4.x",
			},
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
