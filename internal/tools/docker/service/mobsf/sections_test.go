package mobsf

import (
	"encoding/json"
	"testing"
)

func TestAdaptManifestFindings(t *testing.T) {
	section := manifestSection{
		Findings: []manifestFinding{
			{Rule: "r1", Title: "t1", Severity: "high", Description: "d1", Name: "N1", Component: []string{"a", "b"}},
			{Rule: "r2", Title: "", Severity: "secure", Description: "secure"},
			{Rule: "r3", Title: "", Severity: "warning", Description: "d3", Name: "N3"},
		},
	}
	out := adaptManifestFindings(section, "android")
	if len(out) != 2 {
		t.Fatalf("expected 2 findings (drop secure); got %d", len(out))
	}
	if out[0].Title != "t1" || out[0].ComponentName != "N1" {
		t.Fatalf("first: %+v", out[0])
	}
	if out[0].Metadata["manifest_component"] != "a,b" {
		t.Fatalf("expected joined components; got %v", out[0].Metadata)
	}
	if out[1].Title != "r3" { // falls back to rule when title empty
		t.Fatalf("title fallback failed: %+v", out[1])
	}
}

func TestAdaptPermissions(t *testing.T) {
	perms := map[string]permissionEntry{
		"android.permission.READ_CONTACTS": {Status: "dangerous", Info: "info1", Description: "d1"},
		"android.permission.INTERNET":      {Status: "normal", Info: "info2"},
		"android.permission.CAMERA":        {Status: "DANGEROUS", Info: "info3"}, // case-insensitive
	}
	out := adaptPermissions(perms, "android")
	if len(out) != 2 {
		t.Fatalf("expected 2 dangerous; got %d", len(out))
	}
	// Deterministic ordering — CAMERA before READ_CONTACTS alphabetically.
	if out[0].Permission != "android.permission.CAMERA" {
		t.Fatalf("expected CAMERA first; got %s", out[0].Permission)
	}
}

func TestAdaptBinaryAnalysis(t *testing.T) {
	raw, _ := json.Marshal([]map[string]any{
		{
			"name": "libx.so",
			"nx":   map[string]any{"status": "info", "severity": "info", "description": "missing"},
			"pie":  map[string]any{"status": "secure", "severity": "info"},
		},
	})
	out := adaptBinaryAnalysis(raw, "android")
	if len(out) != 1 {
		t.Fatalf("expected 1 (pie secure dropped); got %d", len(out))
	}
	if out[0].CodeFile != "libx.so" {
		t.Fatalf("CodeFile=%q; want libx.so", out[0].CodeFile)
	}
	if out[0].Metadata["check"] != "nx" {
		t.Fatalf("check=%q; want nx", out[0].Metadata["check"])
	}
}

func TestAdaptBinaryAnalysis_EmptyAndMalformed(t *testing.T) {
	if out := adaptBinaryAnalysis(nil, "android"); out != nil {
		t.Fatal("nil should return nil")
	}
	if out := adaptBinaryAnalysis([]byte(`{}`), "android"); out != nil {
		t.Fatal("non-list should return nil")
	}
}

func TestAdaptSecrets(t *testing.T) {
	out := adaptSecrets([]string{"pkey:notespin", "", "  ", "another"}, "android")
	if len(out) != 2 {
		t.Fatalf("expected 2 (trimmed); got %d", len(out))
	}
	if out[0].Title != "Hardcoded Secret" || out[0].Severity != "medium" {
		t.Fatalf("got %+v", out[0])
	}
}

func TestAdaptCertificateFindings_V17(t *testing.T) {
	section := certAnalysisSection{
		CertificateFindings: [][]string{
			{"warning", "self-signed", "desc"},
			{"info", "fp", "abc"},
			{"x"}, // arity drift — skip
		},
	}
	out := adaptCertificateFindings(section, "android")
	if len(out) != 2 {
		t.Fatalf("expected 2; got %d", len(out))
	}
	if out[0].Severity != "medium" { // warning→medium
		t.Fatalf("got severity=%q", out[0].Severity)
	}
}

func TestAdaptNetworkSecurity_EmptyForwardPin(t *testing.T) {
	if out := adaptNetworkSecurity(networkSecuritySection{}, "android"); out != nil {
		t.Fatal("V13 empty must return nil")
	}
}

func TestAdaptNetworkSecurity_PopulatedForwardPin(t *testing.T) {
	section := networkSecuritySection{
		NetworkFindings: []map[string]any{
			{"severity": "high", "scope": "http traffic", "description": "cleartext"},
			{"severity": "secure"}, // drop
		},
	}
	out := adaptNetworkSecurity(section, "android")
	if len(out) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(out))
	}
	if out[0].Metadata["forward_pin_v13"] == "" {
		t.Fatal("forward_pin_v13 marker missing")
	}
}

// TestAdaptNetworkSecurity_V4_4_6_ScopeList exercises the Phase 0 v2
// empirically-verified shape: scope arrives as []any (e.g. ["*"]) from
// MobSF v4.4.6. Pre-Phase-0-v2 parser silently type-fell-back to the
// default Title; post-refinement coerces list→string for Title and
// preserves the raw list via scope_list Metadata key. Fixture mirrors
// DDG /tmp/ddg-scan.json populated network_findings.
func TestAdaptNetworkSecurity_V4_4_6_ScopeList(t *testing.T) {
	section := networkSecuritySection{
		NetworkFindings: []map[string]any{
			{
				"scope":       []any{"*"},
				"severity":    "high",
				"description": "Base config is insecurely configured to permit clear text traffic to all domains.",
			},
			{
				"scope":       []any{"api.example.com", "cdn.example.com"},
				"severity":    "warning",
				"description": "Domain config trusts user-added CAs",
			},
		},
	}
	out := adaptNetworkSecurity(section, "android")
	if len(out) != 2 {
		t.Fatalf("expected 2 findings; got %d", len(out))
	}
	if out[0].Title != "*" {
		t.Fatalf("V13 scope-coercion: title=%q; want %q", out[0].Title, "*")
	}
	if out[0].Metadata["scope_list"] != `["*"]` {
		t.Fatalf("V13 scope_list metadata: got %q", out[0].Metadata["scope_list"])
	}
	if out[1].Title != "api.example.com,cdn.example.com" {
		t.Fatalf("V13 multi-scope join: title=%q", out[1].Title)
	}
	if out[0].Metadata["forward_pin_v13"] == "" || out[0].Metadata["forward_pin_v13"] == "shape not yet stabilized; verify against MobSF v4.x release notes" {
		t.Fatalf("V13 breadcrumb should reflect Phase 0 v2 verification; got %q", out[0].Metadata["forward_pin_v13"])
	}
}

func TestAdaptTrackers_EmptyForwardPin(t *testing.T) {
	if out := adaptTrackers(trackersSection{}, "android"); out != nil {
		t.Fatal("V16 empty must return nil")
	}
}

func TestAdaptTrackers_PopulatedForwardPin(t *testing.T) {
	section := trackersSection{
		Trackers: []map[string]any{
			{"name": "Google Ads"},
			{}, // no name
		},
	}
	out := adaptTrackers(section, "android")
	if len(out) != 2 {
		t.Fatalf("expected 2 entries; got %d", len(out))
	}
	if out[0].Title != "Tracker detected: Google Ads" {
		t.Fatalf("title=%q", out[0].Title)
	}
}

// TestAdaptTrackers_V4_4_6_Enrichment exercises the Phase 0 v2
// empirically-verified shape: per-tracker {name, categories, url} from
// MobSF v4.4.6. Fixture mirrors IBv2 /tmp/ibv2-scan.json populated
// trackers (Google AdMob + Google Analytics + Google Tag Manager).
// Asserts tracker_categories + tracker_url Metadata keys land
// per ADR-027 omit-when-empty convention.
func TestAdaptTrackers_V4_4_6_Enrichment(t *testing.T) {
	section := trackersSection{
		Trackers: []map[string]any{
			{
				"name":       "Google AdMob",
				"categories": "Advertisement",
				"url":        "https://reports.exodus-privacy.eu.org/trackers/312",
			},
			{
				"name":       "Google Analytics",
				"categories": "Analytics",
				"url":        "https://reports.exodus-privacy.eu.org/trackers/48",
			},
			{
				// Omit-when-empty: no categories/url → keys absent
				"name": "Unknown Tracker",
			},
		},
	}
	out := adaptTrackers(section, "android")
	if len(out) != 3 {
		t.Fatalf("expected 3 trackers; got %d", len(out))
	}
	if out[0].Metadata["tracker_categories"] != "Advertisement" {
		t.Fatalf("V16 tracker_categories[0]=%q", out[0].Metadata["tracker_categories"])
	}
	if out[0].Metadata["tracker_url"] != "https://reports.exodus-privacy.eu.org/trackers/312" {
		t.Fatalf("V16 tracker_url[0]=%q", out[0].Metadata["tracker_url"])
	}
	if out[1].Metadata["tracker_categories"] != "Analytics" {
		t.Fatalf("V16 tracker_categories[1]=%q", out[1].Metadata["tracker_categories"])
	}
	// Omit-when-empty: tracker_categories + tracker_url absent on entry [2]
	if _, has := out[2].Metadata["tracker_categories"]; has {
		t.Fatal("V16 omit-when-empty violated: tracker_categories present on empty entry")
	}
	if _, has := out[2].Metadata["tracker_url"]; has {
		t.Fatal("V16 omit-when-empty violated: tracker_url present on empty entry")
	}
	if out[0].Metadata["forward_pin_v16"] == "" || out[0].Metadata["forward_pin_v16"] == "shape not yet stabilized in v4.x" {
		t.Fatalf("V16 breadcrumb should reflect Phase 0 v2 verification; got %q", out[0].Metadata["forward_pin_v16"])
	}
}

// ─── Task 7.4 V10 iOS adaptor tests (Phase 0 v2 v2 grounded) ───────────

func TestAdaptInfoPlist_NSAllowsArbitraryLoads_EmitsHighSeverity(t *testing.T) {
	plistXML := `<?xml version="1.0"?>
<plist><dict>
<key>NSAppTransportSecurity</key>
<dict>
<key>NSAllowsArbitraryLoads</key>
<true/>
</dict>
</dict></plist>`
	out := adaptInfoPlist(plistXML, "ios")
	if len(out) == 0 {
		t.Fatal("expected ≥1 finding")
	}
	found := false
	for _, f := range out {
		if f.Metadata["plist_key"] == "NSAllowsArbitraryLoads" {
			if f.Severity != "high" {
				t.Fatalf("NSAllowsArbitraryLoads severity=%q; want high", f.Severity)
			}
			if f.MobileOS != "ios" {
				t.Fatalf("MobileOS=%q; want ios", f.MobileOS)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("NSAllowsArbitraryLoads finding missing")
	}
}

func TestAdaptInfoPlist_EmptyPlist_NoFindings(t *testing.T) {
	if out := adaptInfoPlist("", "ios"); out != nil {
		t.Fatalf("empty plist → expected nil; got %d", len(out))
	}
}

func TestAdaptATSFindings_PopulatedFindings_MapsSeverityCorrectly(t *testing.T) {
	section := atsAnalysisSection{
		ATSFindings: []atsFinding{
			{Issue: "ATS disabled", Severity: "high", Description: "All HTTP allowed"},
			{Issue: "Exception domain", Severity: "warning", Description: "Per-domain bypass"},
		},
	}
	out := adaptATSFindings(section, "ios")
	if len(out) != 2 {
		t.Fatalf("expected 2 findings; got %d", len(out))
	}
	if out[0].Severity != "high" {
		t.Fatalf("first severity=%q; want high", out[0].Severity)
	}
	if out[1].Severity != "medium" { // warning → medium per mapMobSFSeverity
		t.Fatalf("second severity=%q; want medium", out[1].Severity)
	}
	if out[0].FindingType != "ats_violation" {
		t.Fatalf("FindingType=%q; want ats_violation", out[0].FindingType)
	}
}

func TestAdaptATSFindings_EmptySection_NoFindings(t *testing.T) {
	if out := adaptATSFindings(atsAnalysisSection{}, "ios"); out != nil {
		t.Fatalf("empty section → expected nil; got %d", len(out))
	}
}

func TestAdaptDylibAnalysis_PerDylibPerSubcheck_EmitsFindings(t *testing.T) {
	jsonBlob := []byte(`[{
		"name": "Payload/App.app/libtest.dylib",
		"nx": {"severity": "info", "description": "NX bit set"},
		"pie": {"severity": "warning", "description": "PIE not set"},
		"arc": {"severity": "info", "description": "ARC enabled"}
	}]`)
	var entries []dylibEntry
	if err := json.Unmarshal(jsonBlob, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := adaptDylibAnalysis(entries, "ios")
	if len(out) != 3 {
		t.Fatalf("expected 3 findings (nx+pie+arc); got %d", len(out))
	}
	for _, f := range out {
		if f.MobileOS != "ios" {
			t.Fatalf("MobileOS=%q; want ios", f.MobileOS)
		}
		if f.FindingType != "dylib_protection_missing" {
			t.Fatalf("FindingType=%q; want dylib_protection_missing", f.FindingType)
		}
		if f.Metadata["dylib_name"] != "Payload/App.app/libtest.dylib" {
			t.Fatalf("dylib_name=%q", f.Metadata["dylib_name"])
		}
	}
}

func TestAdaptDylibAnalysis_EmptyList_NoFindings(t *testing.T) {
	if out := adaptDylibAnalysis(nil, "ios"); out != nil {
		t.Fatalf("nil list → expected nil; got %d", len(out))
	}
}

func TestAdaptIOSBinary_FindingsDict_EmitsRawFindings(t *testing.T) {
	raw := json.RawMessage(`{
		"findings": {
			"Binary uses WebView Component.": {
				"detailed_desc": "May use UIWebView",
				"severity": "info",
				"cvss": 0,
				"cwe": "",
				"owasp-mobile": "",
				"masvs": "MSTG-CODE-9"
			}
		},
		"summary": {"high": 0, "warning": 0, "info": 1, "secure": 0, "suppressed": 0}
	}`)
	out := adaptIOSBinary(raw, "ios")
	if len(out) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(out))
	}
	if out[0].FindingType != "ios_binary_finding" {
		t.Fatalf("FindingType=%q", out[0].FindingType)
	}
	if out[0].Metadata["masvs"] != "MSTG-CODE-9" {
		t.Fatalf("masvs=%q", out[0].Metadata["masvs"])
	}
}

func TestAdaptIOSBinary_EmptyFindings_NoFindings(t *testing.T) {
	raw := json.RawMessage(`{"findings": {}, "summary": {}}`)
	if out := adaptIOSBinary(raw, "ios"); out != nil {
		t.Fatalf("empty findings → expected nil; got %d", len(out))
	}
}

func TestAdaptBundleURLTypes_CustomScheme_MediumSeverity(t *testing.T) {
	entries := []bundleURLTypeEntry{
		{CFBundleURLName: "com.example.app", CFBundleURLSchemes: []string{"myapp"}},
	}
	out := adaptBundleURLTypes(entries, "ios")
	if len(out) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(out))
	}
	if out[0].Severity != "medium" {
		t.Fatalf("custom scheme severity=%q; want medium", out[0].Severity)
	}
	if out[0].Metadata["url_scheme"] != "myapp" {
		t.Fatalf("url_scheme=%q", out[0].Metadata["url_scheme"])
	}
}

func TestAdaptBundleURLTypes_WellKnownScheme_InfoSeverity(t *testing.T) {
	entries := []bundleURLTypeEntry{
		{CFBundleURLName: "com.example.app", CFBundleURLSchemes: []string{"https"}},
	}
	out := adaptBundleURLTypes(entries, "ios")
	if out[0].Severity != "info" {
		t.Fatalf("well-known scheme severity=%q; want info", out[0].Severity)
	}
}

func TestAdaptBundleURLTypes_EmptyList_NoFindings(t *testing.T) {
	if out := adaptBundleURLTypes(nil, "ios"); out != nil {
		t.Fatalf("nil list → expected nil; got %d", len(out))
	}
}
