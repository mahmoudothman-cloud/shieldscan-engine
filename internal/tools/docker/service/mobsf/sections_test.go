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
