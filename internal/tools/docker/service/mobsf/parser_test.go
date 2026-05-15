package mobsf

import (
	"strings"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

func TestMapMobSFSeverity_V5Lowercase(t *testing.T) {
	cases := []struct {
		in       string
		wantSev  string
		wantDrop bool
	}{
		{"high", "high", false},
		{"HIGH", "high", false}, // case-insensitive
		{"warning", "medium", false},
		{"info", "info", false},
		{"", "", true},
		{"secure", "", true},
		{"good", "", true},
		{"future-bucket", "info", false}, // forward-compat
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			sev, drop := mapMobSFSeverity(c.in)
			if sev != c.wantSev || drop != c.wantDrop {
				t.Fatalf("got (%q,%v); want (%q,%v)", sev, drop, c.wantSev, c.wantDrop)
			}
		})
	}
}

func TestExtractCWENumber(t *testing.T) {
	cases := []struct {
		in       string
		wantNum  string
		wantDesc string
	}{
		{"CWE-89: Improper Neutralization", "89", "Improper Neutralization"},
		{"CWE-532", "532", ""},
		{"cwe-1234: lower-case prefix", "1234", "lower-case prefix"},
		{"", "", ""},
		{"NotACWE", "", "NotACWE"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			num, desc := extractCWENumber(c.in)
			if num != c.wantNum || desc != c.wantDesc {
				t.Fatalf("got (%q,%q); want (%q,%q)", num, desc, c.wantNum, c.wantDesc)
			}
		})
	}
}

func TestExtractMobSFTags_D3D4(t *testing.T) {
	// D3 colon form; D4 full form.
	tags := extractMobSFTags("M7: Client Code Quality", "MSTG-STORAGE-2")
	want := []string{"MSTG-STORAGE-2", "OWASP-M7"}
	if len(tags) != len(want) {
		t.Fatalf("want %v; got %v", want, tags)
	}
	for i, v := range want {
		if tags[i] != v {
			t.Fatalf("tags[%d]=%q; want %q", i, tags[i], v)
		}
	}
}

func TestExtractMobSFTags_Empty(t *testing.T) {
	if tags := extractMobSFTags("", ""); tags != nil {
		t.Fatalf("expected nil for both empty; got %v", tags)
	}
}

func TestExtractMobSFTags_OnlyOWASP(t *testing.T) {
	tags := extractMobSFTags("M2: Insecure Data Storage", "")
	if len(tags) != 1 || tags[0] != "OWASP-M2" {
		t.Fatalf("got %v; want [OWASP-M2]", tags)
	}
}

func TestParseFilesDict_D1(t *testing.T) {
	// D1: map[path]string-of-csv-line-numbers.
	in := map[string]string{
		"a/B.java":          "10,42",
		"jakhar/X.java":     "3,21,32",
		"jakhar/Notes.java": "10,11,12,46,47",
	}
	out := parseFilesDict(in)
	if len(out) != 3 {
		t.Fatalf("want 3 entries; got %d", len(out))
	}
	// deterministic alpha order
	if out[0].Path != "a/B.java" {
		t.Fatalf("expected a/B.java first; got %s", out[0].Path)
	}
	// CSV parse
	if len(out[0].Lines) != 2 || out[0].Lines[0] != 10 || out[0].Lines[1] != 42 {
		t.Fatalf("a/B.java lines=%v; want [10 42]", out[0].Lines)
	}
}

func TestParseFilesDict_EmptyAndMalformed(t *testing.T) {
	if parseFilesDict(nil) != nil {
		t.Fatal("nil input must return nil")
	}
	if parseFilesDict(map[string]string{}) != nil {
		t.Fatal("empty map must return nil")
	}
	// Malformed tokens skipped, valid kept.
	out := parseFilesDict(map[string]string{"x.java": "1, ,abc, 5"})
	if len(out) != 1 || len(out[0].Lines) != 2 || out[0].Lines[0] != 1 || out[0].Lines[1] != 5 {
		t.Fatalf("got lines=%v; want [1 5]", out[0].Lines)
	}
}

func TestParseReport_PhaseZeroSample(t *testing.T) {
	findings, err := parseReport(phase0SampleReport(), "android")
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected non-empty findings")
	}

	// All findings carry MobileOS=android.
	for i, f := range findings {
		if f.MobileOS != "android" {
			t.Fatalf("findings[%d].MobileOS=%q; want android", i, f.MobileOS)
		}
	}

	// Title=rule_id decision-lock (V8) for code_analysis section.
	if !containsTitle(findings, "android_sql_raw_query") {
		t.Fatal("expected title 'android_sql_raw_query' (V8 rule_id-as-Title)")
	}

	// V5: warning → medium.
	loggingFinding := findFirstByTitle(findings, "android_logging")
	if loggingFinding == nil {
		t.Fatal("missing android_logging finding")
	}
	if loggingFinding.Severity != "medium" {
		t.Fatalf("android_logging severity=%q; want medium (V5 warning→medium)", loggingFinding.Severity)
	}

	// D2: 'ref' propagates into Metadata.
	if loggingFinding.Metadata["ref"] != "https://example.com/logging-ref" {
		t.Fatalf("ref metadata missing; got %v", loggingFinding.Metadata)
	}

	// D3: OWASP-M2 (colon-extracted, hyphen-prefixed).
	if !containsString(loggingFinding.Tags, "OWASP-M2") {
		t.Fatalf("tags missing OWASP-M2; got %v", loggingFinding.Tags)
	}
	// D4: MASVS full form.
	if !containsString(loggingFinding.Tags, "MSTG-STORAGE-3") {
		t.Fatalf("tags missing MSTG-STORAGE-3; got %v", loggingFinding.Tags)
	}

	// CWE extraction.
	sqlFinding := findFirstByTitle(findings, "android_sql_raw_query")
	if sqlFinding.CWEID != "89" {
		t.Fatalf("sql.CWEID=%q; want 89", sqlFinding.CWEID)
	}
	if !strings.Contains(sqlFinding.Metadata["cwe_description"], "Improper") {
		t.Fatalf("cwe_description missing; got %v", sqlFinding.Metadata)
	}

	// V5 "secure" rules dropped.
	if containsTitle(findings, "android_secure_check") {
		t.Fatal("expected android_secure_check to drop (severity=secure)")
	}

	// Permission V12 dict-keyed adaptor.
	perm := findFirstByPermission(findings, "android.permission.READ_CONTACTS")
	if perm == nil {
		t.Fatal("expected READ_CONTACTS dangerous permission finding")
	}
	if perm.Severity != "medium" {
		t.Fatalf("permission severity=%q; want medium", perm.Severity)
	}
	if findFirstByPermission(findings, "android.permission.INTERNET") != nil {
		t.Fatal("INTERNET (status=normal) should not produce a finding")
	}

	// Manifest V11 + secure-drop.
	manifest := findFirstByTitle(findings, "Exported activity")
	if manifest == nil {
		t.Fatal("expected manifest 'Exported activity' finding")
	}
	if manifest.ComponentName != "MainActivity" {
		t.Fatalf("manifest.ComponentName=%q; want MainActivity", manifest.ComponentName)
	}
	if containsTitle(findings, "Secure thing") {
		t.Fatal("manifest secure-thing should drop")
	}

	// Secrets V15.
	secret := findFirstByTitle(findings, "Hardcoded Secret")
	if secret == nil {
		t.Fatal("expected Hardcoded Secret finding")
	}
	if secret.Severity != "medium" {
		t.Fatalf("secret severity=%q; want medium", secret.Severity)
	}

	// Certificate V17 list-of-3-element-lists.
	cert := findFirstByTitle(findings, "Self-signed certificate")
	if cert == nil {
		t.Fatal("expected Self-signed certificate finding")
	}
	if cert.Severity != "medium" {
		t.Fatalf("cert severity=%q; want medium (warning→medium)", cert.Severity)
	}

	// Binary V14: stack_canary non-secure → finding.
	bin := findFirstByTitleSubstr(findings, "stack_canary")
	if bin == nil {
		t.Fatal("expected binary stack_canary finding")
	}
	if bin.Severity != "high" {
		t.Fatalf("stack_canary severity=%q; want high", bin.Severity)
	}
	// pie status=secure must NOT surface.
	if findFirstByTitleSubstr(findings, "pie") != nil {
		t.Fatal("pie (secure) must not produce finding")
	}
}

func TestParseReport_InvalidJSON(t *testing.T) {
	if _, err := parseReport([]byte(`not json`), "android"); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

// --- helpers ---

func containsTitle(fs []events.RawFinding, title string) bool {
	for _, f := range fs {
		if f.Title == title {
			return true
		}
	}
	return false
}

func findFirstByTitle(fs []events.RawFinding, title string) *events.RawFinding {
	for i := range fs {
		if fs[i].Title == title {
			return &fs[i]
		}
	}
	return nil
}

func findFirstByTitleSubstr(fs []events.RawFinding, sub string) *events.RawFinding {
	for i := range fs {
		if strings.Contains(fs[i].Title, sub) {
			return &fs[i]
		}
	}
	return nil
}

func findFirstByPermission(fs []events.RawFinding, perm string) *events.RawFinding {
	for i := range fs {
		if fs[i].Permission == perm {
			return &fs[i]
		}
	}
	return nil
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
