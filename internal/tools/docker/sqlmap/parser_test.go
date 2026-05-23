package sqlmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("loadFixture %q: %v", name, err)
	}
	return data
}

// TestParseSQLMapOutput_DVWAInjections covers Phase 0 v2 DVWA SQLi
// stdout (parameter id; 4 techniques: boolean-blind + error-based +
// time-based + UNION). Verifies per-Q3 (a) flatten-per-technique
// emission + Q6 typed-field reuse + Q5 severity rubric.
func TestParseSQLMapOutput_DVWAInjections(t *testing.T) {
	findings, err := parseSQLMapOutput(loadFixture(t, "dvwa-sqli-scan.txt"))
	if err != nil {
		t.Fatalf("parseSQLMapOutput: %v", err)
	}
	// 4 injection findings + 1 DBMS fingerprint = 5 total
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings (4 techniques + 1 DBMS); got %d", len(findings))
	}

	// Separate by FindingType
	var injections []int
	var dbmsIdx int = -1
	for i, f := range findings {
		switch f.FindingType {
		case "sql_injection":
			injections = append(injections, i)
		case "dbms_fingerprint":
			dbmsIdx = i
		}
	}
	if len(injections) != 4 {
		t.Fatalf("expected 4 sql_injection findings; got %d", len(injections))
	}
	if dbmsIdx < 0 {
		t.Fatal("expected 1 dbms_fingerprint finding; none found")
	}

	// Verify per-technique field population on first injection
	first := findings[injections[0]]
	if first.Parameter != "id" {
		t.Errorf("Parameter=%q; want \"id\"", first.Parameter)
	}
	if first.CWEID != "CWE-89" {
		t.Errorf("CWEID=%q; want \"CWE-89\"", first.CWEID)
	}
	if first.OWASP != "A03:2021 Injection" {
		t.Errorf("OWASP=%q; want \"A03:2021 Injection\"", first.OWASP)
	}
	if first.FindingType != "sql_injection" {
		t.Errorf("FindingType=%q; want \"sql_injection\"", first.FindingType)
	}
	if first.Metadata["place"] != "GET" {
		t.Errorf("place=%q; want \"GET\"", first.Metadata["place"])
	}
	if first.TargetURL == "" {
		t.Error("TargetURL empty; expected URL extracted from sqlmap log")
	}
	if first.Payload == "" {
		t.Error("Payload empty; expected per-technique payload populated")
	}

	// Verify severity rubric across techniques
	sevByTechnique := map[string]string{}
	for _, idx := range injections {
		f := findings[idx]
		sevByTechnique[f.Metadata["technique"]] = f.Severity
	}
	if sevByTechnique["boolean-based blind"] != "high" {
		t.Errorf("boolean-based blind severity=%q; want \"high\"", sevByTechnique["boolean-based blind"])
	}
	if sevByTechnique["error-based"] != "high" {
		t.Errorf("error-based severity=%q; want \"high\"", sevByTechnique["error-based"])
	}
	if sevByTechnique["time-based blind"] != "medium" {
		t.Errorf("time-based blind severity=%q; want \"medium\"", sevByTechnique["time-based blind"])
	}
	if sevByTechnique["UNION query"] != "high" {
		t.Errorf("UNION query severity=%q; want \"high\"", sevByTechnique["UNION query"])
	}
}

// TestParseSQLMapOutput_DBMSFingerprint verifies DBMS-fingerprint
// finding emission (FindingType=dbms_fingerprint + Severity=info +
// Metadata.dbms_*). Per Q4 (a) discrete-info-finding lock.
func TestParseSQLMapOutput_DBMSFingerprint(t *testing.T) {
	findings, err := parseSQLMapOutput(loadFixture(t, "dvwa-sqli-scan.txt"))
	if err != nil {
		t.Fatalf("parseSQLMapOutput: %v", err)
	}
	var dbms *struct {
		title    string
		severity string
		typ      string
		ver      string
		osStr    string
		tech     string
	}
	for _, f := range findings {
		if f.FindingType == "dbms_fingerprint" {
			dbms = &struct {
				title    string
				severity string
				typ      string
				ver      string
				osStr    string
				tech     string
			}{
				title:    f.Title,
				severity: f.Severity,
				typ:      f.Metadata["dbms_type"],
				ver:      f.Metadata["dbms_version"],
				osStr:    f.Metadata["dbms_os"],
				tech:     f.Metadata["web_app_tech"],
			}
			break
		}
	}
	if dbms == nil {
		t.Fatal("dbms_fingerprint finding not present in output")
	}
	if dbms.severity != "info" {
		t.Errorf("DBMS severity=%q; want \"info\"", dbms.severity)
	}
	if dbms.typ != "MySQL" {
		t.Errorf("dbms_type=%q; want \"MySQL\"", dbms.typ)
	}
	if !strings.Contains(dbms.ver, "5.1") {
		t.Errorf("dbms_version=%q; want substring \"5.1\"", dbms.ver)
	}
	if !strings.Contains(dbms.osStr, "Linux") {
		t.Errorf("dbms_os=%q; want substring \"Linux\"", dbms.osStr)
	}
	if !strings.Contains(dbms.tech, "Apache") {
		t.Errorf("web_app_tech=%q; want substring \"Apache\"", dbms.tech)
	}
	if !strings.Contains(dbms.title, "MySQL") {
		t.Errorf("Title=%q; want substring \"MySQL\"", dbms.title)
	}
}

// TestParseSQLMapOutput_NoInjection covers non-injectable scan output.
// Per V4 observation: no findings header → zero findings (DBMS section
// only emitted when ≥1 injection found; no-injection scans skip both).
func TestParseSQLMapOutput_NoInjection(t *testing.T) {
	findings, err := parseSQLMapOutput(loadFixture(t, "empty-no-injection.txt"))
	if err != nil {
		t.Fatalf("parseSQLMapOutput empty: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("no-injection scan expected 0 findings; got %d", len(findings))
	}
}

// TestParseSQLMapOutput_Malformed covers garbage input. Defensive
// behavior: no findings header → zero findings + no error. Crash-free
// is the contract; specific error semantics secondary.
func TestParseSQLMapOutput_Malformed(t *testing.T) {
	findings, err := parseSQLMapOutput(loadFixture(t, "malformed.txt"))
	// Either nil-error+zero-findings OR non-nil-error+nil-findings
	// acceptable; both prove non-crash
	if err != nil && findings != nil {
		t.Fatalf("malformed: error returned but findings non-nil (%d): %v", len(findings), err)
	}
	if err == nil && len(findings) > 0 {
		t.Fatalf("malformed: no error but %d findings produced", len(findings))
	}
}

// TestParseSQLMapOutput_EmptyStdout exercises the empty-bytes guard.
func TestParseSQLMapOutput_EmptyStdout(t *testing.T) {
	_, err := parseSQLMapOutput([]byte{})
	if err == nil {
		t.Fatal("empty stdout expected error; got nil")
	}
}

// TestAdaptInjectionFindings exercises the adaptor directly with an
// inline minimal-block fixture (per-Parameter block + 2 technique
// entries).
func TestAdaptInjectionFindings(t *testing.T) {
	text := `Parameter: id (GET)
    Type: boolean-based blind
    Title: Test boolean
    Payload: id=1' OR 1=1#

    Type: error-based
    Title: Test error
    Payload: id=1' AND EXTRACTVALUE(...)
`
	out := adaptInjectionFindings(text, "http://example.test/sqli?id=1")
	if len(out) != 2 {
		t.Fatalf("expected 2 findings; got %d", len(out))
	}
	if out[0].Title != "Test boolean" {
		t.Errorf("[0].Title=%q", out[0].Title)
	}
	if out[0].Payload != "id=1' OR 1=1#" {
		t.Errorf("[0].Payload=%q", out[0].Payload)
	}
	if out[0].Metadata["technique"] != "boolean-based blind" {
		t.Errorf("[0].technique=%q", out[0].Metadata["technique"])
	}
	if out[1].Title != "Test error" {
		t.Errorf("[1].Title=%q", out[1].Title)
	}
}

// TestAdaptInjectionFindings_Empty verifies empty-text → empty-slice.
func TestAdaptInjectionFindings_Empty(t *testing.T) {
	out := adaptInjectionFindings("", "http://x.test/")
	if len(out) != 0 {
		t.Fatalf("empty text expected 0 findings; got %d", len(out))
	}
}

// TestAdaptDBMSFingerprint exercises the adaptor directly + presence-
// bool semantics (returns false when DBMS section absent).
func TestAdaptDBMSFingerprint(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		text := `web server operating system: Linux Ubuntu 22.04
web application technology: Nginx 1.24
back-end DBMS: PostgreSQL >= 14`
		f, ok := adaptDBMSFingerprint(text, "http://x.test/")
		if !ok {
			t.Fatal("expected presence-bool true; got false")
		}
		if f.Metadata["dbms_type"] != "PostgreSQL" {
			t.Errorf("dbms_type=%q", f.Metadata["dbms_type"])
		}
		if f.Severity != "info" {
			t.Errorf("severity=%q; want info", f.Severity)
		}
	})
	t.Run("DBMS line absent", func(t *testing.T) {
		text := `web server operating system: Linux`
		_, ok := adaptDBMSFingerprint(text, "http://x.test/")
		if ok {
			t.Fatal("expected presence-bool false when back-end DBMS line absent")
		}
	})
	t.Run("empty text", func(t *testing.T) {
		_, ok := adaptDBMSFingerprint("", "http://x.test/")
		if ok {
			t.Fatal("expected presence-bool false for empty text")
		}
	})
	t.Run("DBMS type only (no version)", func(t *testing.T) {
		text := `back-end DBMS: SQLite`
		f, ok := adaptDBMSFingerprint(text, "")
		if !ok {
			t.Fatal("expected presence-bool true")
		}
		if f.Metadata["dbms_type"] != "SQLite" {
			t.Errorf("dbms_type=%q", f.Metadata["dbms_type"])
		}
		if _, has := f.Metadata["dbms_version"]; has {
			t.Errorf("dbms_version present on type-only fixture; should be omit-when-empty")
		}
	})
}

// TestStripLogPrefixes verifies bracketed log-prefix removal.
func TestStripLogPrefixes(t *testing.T) {
	in := `[15:32:27] [INFO] testing
keep this line
[!] disclaimer
    Type: error-based
[*] starting
`
	out := stripLogPrefixes(in)
	if strings.Contains(out, "[INFO]") || strings.Contains(out, "[!]") || strings.Contains(out, "[*]") {
		t.Errorf("log prefixes leaked through: %q", out)
	}
	if !strings.Contains(out, "keep this line") {
		t.Error("non-prefixed line dropped unexpectedly")
	}
	if !strings.Contains(out, "Type: error-based") {
		t.Error("indented block content dropped")
	}
}

// TestMapSqlmapSeverity covers technique → severity rubric per Q5 +
// canonical lowercase output per Q4 + ZAP/MobSF/Trivy precedent.
func TestMapSqlmapSeverity(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"boolean-based blind", "high"},
		{"error-based", "high"},
		{"UNION query", "high"},
		{"union query", "high"},          // case-insensitive
		{"stacked queries", "high"},
		{"time-based blind", "medium"},
		{"  time-based blind  ", "medium"}, // whitespace tolerance
		{"FutureTechnique", "high"},        // defensive forward-compat
		{"", "high"},
	}
	for _, c := range cases {
		got := mapSqlmapSeverity(c.in)
		if got != c.want {
			t.Errorf("mapSqlmapSeverity(%q)=%q; want %q", c.in, got, c.want)
		}
	}
}

// TestExtractTargetURL pulls the GET line URL extraction helper.
func TestExtractTargetURL(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{
			name: "GET URL extracted",
			text: "stuff\nGET http://example.test/sqli?id=1\nmore stuff",
			want: "http://example.test/sqli?id=1",
		},
		{
			name: "POST URL extracted",
			text: "POST https://api.test/login\n",
			want: "https://api.test/login",
		},
		{
			name: "no URL",
			text: "no method here",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractTargetURL(c.text)
			if got != c.want {
				t.Errorf("got=%q want=%q", got, c.want)
			}
		})
	}
}

// TestSplitFindingsRegion verifies the `---` delimiter-based split.
func TestSplitFindingsRegion(t *testing.T) {
	region := `sqlmap identified...
---
Parameter: id (GET)
    Type: error-based
    Title: T
    Payload: P
---
web server operating system: Linux
back-end DBMS: MySQL
`
	inj, dbms := splitFindingsRegion(region)
	if !strings.Contains(inj, "Parameter: id (GET)") {
		t.Errorf("injectionText missing Parameter line: %q", inj)
	}
	if !strings.Contains(dbms, "back-end DBMS: MySQL") {
		t.Errorf("dbmsText missing back-end DBMS line: %q", dbms)
	}
}

// TestSetIfNonEmpty verifies omit-when-empty discipline per ADR-027.
func TestSetIfNonEmpty(t *testing.T) {
	m := map[string]string{}
	setIfNonEmpty(m, "k1", "v1")
	setIfNonEmpty(m, "k2", "")
	if m["k1"] != "v1" {
		t.Errorf("k1=%q", m["k1"])
	}
	if _, has := m["k2"]; has {
		t.Error("k2 set despite empty value (omit-when-empty violated)")
	}
}
