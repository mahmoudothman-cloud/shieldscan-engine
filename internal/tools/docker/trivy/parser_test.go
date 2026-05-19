package trivy

import (
	"os"
	"path/filepath"
	"testing"
)

// loadFixture reads a JSON file from testdata/. Fatals on error so
// missing fixtures surface as clear test failures rather than nil
// dereferences downstream.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("loadFixture %q: %v", name, err)
	}
	return data
}

// TestParseTrivyJSON_ImageMode covers Phase 0 v2 alpine:3.10 baseline
// fixture (1 vuln: CVE-2021-36159 CRITICAL severity in apk-tools).
// Verifies image-mode-specific Metadata routing (layer_digest +
// os_family + os_version) + typed-field promotions from Y3 (References
// + CVSSVector + CVSSScore via X2 vendor priority).
func TestParseTrivyJSON_ImageMode(t *testing.T) {
	findings, err := parseTrivyJSON(loadFixture(t, "image-scan.json"))
	if err != nil {
		t.Fatalf("parseTrivyJSON: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from alpine:3.10 baseline; got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("Severity=%q; want \"critical\" (mapped from UPPERCASE CRITICAL)", f.Severity)
	}
	if f.ComponentName != "apk-tools" {
		t.Errorf("ComponentName=%q; want \"apk-tools\" (Q6 PkgName reuse)", f.ComponentName)
	}
	if f.CWEID != "CWE-125" {
		t.Errorf("CWEID=%q; want \"CWE-125\" (first of CweIDs)", f.CWEID)
	}
	if f.FindingType != "vulnerability" {
		t.Errorf("FindingType=%q; want \"vulnerability\"", f.FindingType)
	}
	// CVSSScore: X2 vendor-priority chain — nvd.V3Score = 9.1
	if f.CVSSScore != 9.1 {
		t.Errorf("CVSSScore=%v; want 9.1 (nvd.V3Score per X2)", f.CVSSScore)
	}
	// Y3 typed-field expansion: CVSSVector from same vendor as score
	if f.CVSSVector == "" {
		t.Error("CVSSVector empty; want NVD V3Vector populated per Y3")
	}
	// Y3 typed-field expansion: References populated as typed slice
	if len(f.References) == 0 {
		t.Error("References empty; want vuln.References populated per Y3 typed-field expansion")
	}
	// Title falls back to VulnerabilityID only when vuln.Title empty;
	// fixture has Title set
	if f.Title == "" || f.Title == "CVE-2021-36159" {
		t.Errorf("Title=%q; want vuln.Title (not fallback to VulnerabilityID)", f.Title)
	}
	// Metadata: container-mode routing
	if f.Metadata["os_family"] != "alpine" {
		t.Errorf("os_family=%q; want \"alpine\"", f.Metadata["os_family"])
	}
	if f.Metadata["os_version"] != "3.10.9" {
		t.Errorf("os_version=%q; want \"3.10.9\"", f.Metadata["os_version"])
	}
	if f.Metadata["layer_digest"] == "" {
		t.Error("layer_digest empty; want populated (image-mode per-vuln Layer.Digest)")
	}
	if f.Metadata["vulnerability_id"] != "CVE-2021-36159" {
		t.Errorf("vulnerability_id=%q; want CVE-2021-36159", f.Metadata["vulnerability_id"])
	}
	if f.Metadata["package_manager"] != "alpine" {
		t.Errorf("package_manager=%q; want \"alpine\" (from Result.Type)", f.Metadata["package_manager"])
	}
	if f.Metadata["class"] != "os-pkgs" {
		t.Errorf("class=%q; want \"os-pkgs\"", f.Metadata["class"])
	}
	if f.Metadata["primary_url"] == "" {
		t.Error("primary_url empty; want populated per X3 NEW Metadata key")
	}
	if f.Metadata["purl"] == "" {
		t.Error("purl empty; want populated per X3 NEW Metadata key")
	}
	// Y3 typed-field promotion: references + cvss_vector REMOVED from Metadata
	if _, has := f.Metadata["references"]; has {
		t.Error("Metadata.references must be REMOVED per Y3 typed-field promotion")
	}
	if _, has := f.Metadata["cvss_vector"]; has {
		t.Error("Metadata.cvss_vector must be REMOVED per Y3 typed-field promotion")
	}
}

// TestParseTrivyJSON_FsMode covers Phase 0 v2 multi-manifest fixture
// (3 lockfiles: Gemfile.lock 12 + package-lock.json 10 + requirements.txt
// 35 = 57 total vulns; Class=lang-pkgs uniformly; Type variance).
// Verifies uniform Q7 parser shape across multi-result heterogeneity
// + fs-mode Metadata routing (no layer_digest/os_*).
func TestParseTrivyJSON_FsMode(t *testing.T) {
	findings, err := parseTrivyJSON(loadFixture(t, "fs-scan.json"))
	if err != nil {
		t.Fatalf("parseTrivyJSON: %v", err)
	}
	if len(findings) != 57 {
		t.Fatalf("expected 57 findings (Phase 0 v2 baseline); got %d", len(findings))
	}
	// Per-result Class/Type captured uniformly — first finding from
	// Gemfile.lock should have Class=lang-pkgs Type=bundler
	classCounts := map[string]int{}
	typeCounts := map[string]int{}
	for _, f := range findings {
		classCounts[f.Metadata["class"]]++
		typeCounts[f.Metadata["type"]]++
		// Fs-mode: NO image-mode keys
		if f.Metadata["layer_digest"] != "" {
			t.Errorf("fs-mode finding has layer_digest=%q; should be absent", f.Metadata["layer_digest"])
		}
		if f.Metadata["os_family"] != "" {
			t.Errorf("fs-mode finding has os_family=%q; should be absent", f.Metadata["os_family"])
		}
	}
	if classCounts["lang-pkgs"] != 57 {
		t.Errorf("expected all 57 with Class=lang-pkgs; got %v", classCounts)
	}
	if typeCounts["bundler"] != 12 || typeCounts["npm"] != 10 || typeCounts["pip"] != 35 {
		t.Errorf("type distribution drift: %v; want bundler=12,npm=10,pip=35", typeCounts)
	}
}

// TestParseTrivyJSON_Empty covers zero-vulnerability output. Must NOT
// error; must return nil/empty findings slice.
func TestParseTrivyJSON_Empty(t *testing.T) {
	findings, err := parseTrivyJSON(loadFixture(t, "empty.json"))
	if err != nil {
		t.Fatalf("parseTrivyJSON empty: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("empty fixture expected 0 findings; got %d", len(findings))
	}
}

// TestParseTrivyJSON_Malformed covers structurally-invalid JSON.
// Must return non-nil error per parser error semantics.
func TestParseTrivyJSON_Malformed(t *testing.T) {
	_, err := parseTrivyJSON(loadFixture(t, "malformed.json"))
	if err == nil {
		t.Fatal("malformed JSON expected error; got nil")
	}
}

func TestMapTrivySeverity(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"UNKNOWN", "info"},
		{"", "info"},
		{"  critical  ", "critical"},      // whitespace + lowercase tolerance
		{"FutureSeverity", "info"},        // forward-compat defensive fallback
	}
	for _, c := range cases {
		got := mapTrivySeverity(c.in)
		if got != c.want {
			t.Errorf("mapTrivySeverity(%q)=%q; want %q", c.in, got, c.want)
		}
	}
}

func TestExtractCVSSScore(t *testing.T) {
	// X2 vendor priority chain: nvd.V3 > redhat.V3 > ghsa.V3 > nvd.V2 > 0
	cases := []struct {
		name       string
		cvss       map[string]TrivyCVSS
		wantScore  float64
		wantVendor string
	}{
		{
			name: "nvd V3 wins over all",
			cvss: map[string]TrivyCVSS{
				"nvd":    {V3Score: 9.1, V2Score: 6.4},
				"redhat": {V3Score: 8.5},
				"ghsa":   {V3Score: 7.5},
			},
			wantScore:  9.1,
			wantVendor: "nvd",
		},
		{
			name: "nvd missing → redhat V3 wins",
			cvss: map[string]TrivyCVSS{
				"redhat": {V3Score: 8.5},
				"ghsa":   {V3Score: 7.5},
			},
			wantScore:  8.5,
			wantVendor: "redhat",
		},
		{
			name: "ghsa only",
			cvss: map[string]TrivyCVSS{
				"ghsa": {V3Score: 7.5},
			},
			wantScore:  7.5,
			wantVendor: "ghsa",
		},
		{
			name: "nvd V3 zero → V2 fallback",
			cvss: map[string]TrivyCVSS{
				"nvd": {V3Score: 0, V2Score: 6.4},
			},
			wantScore:  6.4,
			wantVendor: "nvd-v2",
		},
		{
			name:       "empty map → zero",
			cvss:       map[string]TrivyCVSS{},
			wantScore:  0,
			wantVendor: "",
		},
		{
			name:       "nil map → zero",
			cvss:       nil,
			wantScore:  0,
			wantVendor: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, vendor := extractCVSSScore(c.cvss)
			if score != c.wantScore || vendor != c.wantVendor {
				t.Errorf("score=%v vendor=%q; want %v %q", score, vendor, c.wantScore, c.wantVendor)
			}
		})
	}
}

func TestExtractCVSSVector(t *testing.T) {
	cvss := map[string]TrivyCVSS{
		"nvd": {
			V2Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:P",
			V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
		},
		"redhat": {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"},
	}
	cases := []struct {
		vendor, want string
	}{
		{"nvd", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"},
		{"redhat", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"},
		{"nvd-v2", "AV:N/AC:L/Au:N/C:P/I:N/A:P"},
		{"ghsa", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := extractCVSSVector(cvss, c.vendor)
		if got != c.want {
			t.Errorf("vendor=%q got=%q want=%q", c.vendor, got, c.want)
		}
	}
	if got := extractCVSSVector(nil, "nvd"); got != "" {
		t.Errorf("nil cvss got=%q want empty", got)
	}
}

func TestExtractPkgPathFromPURL(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"no subpath", "pkg:apk/alpine/apk-tools@2.10.6-r0?arch=x86_64", ""},
		{"with subpath", "pkg:maven/com.example/lib@1.0#path/to/nested.jar", "path/to/nested.jar"},
		{"percent-encoded subpath", "pkg:maven/com.example/lib@1.0#path%2Fto%2Ffile", "path/to/file"},
		{"empty subpath", "pkg:maven/x/y@1.0#", ""},
		{"empty input", "", ""},
		{"non-PURL scheme", "http://example.com#anchor", ""},
		{"malformed PURL", "pkg:malformed", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractPkgPathFromPURL(c.in)
			if got != c.want {
				t.Errorf("got=%q want=%q", got, c.want)
			}
		})
	}
}
