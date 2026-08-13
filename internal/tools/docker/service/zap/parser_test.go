package zap

import (
	"context"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapZAPRisk(t *testing.T) {
	cases := []struct {
		risk     string
		wantSev  string
		wantDrop bool
	}{
		{"High", "high", false},
		{"Medium", "medium", false},
		{"Low", "low", false},
		{"Informational", "info", false},
		{"False Positive", "", true}, // V8/V9 — drop at parser
		{"", "", true},               // defensive drop
		{"Unknown", "", true},        // defensive drop
		{"high", "", true},           // case-sensitive (canonical ZAP "High")
	}
	for _, tc := range cases {
		t.Run(tc.risk, func(t *testing.T) {
			sev, drop := mapZAPRisk(tc.risk)
			assert.Equal(t, tc.wantSev, sev)
			assert.Equal(t, tc.wantDrop, drop)
		})
	}
}

func TestExtractZAPTags_Filters(t *testing.T) {
	tags := map[string]string{
		"OWASP_2021_A05": "https://owasp.org/A05",
		"OWASP_2017_A06": "https://owasp.org/A06",
		"CWE-693":        "https://cwe.mitre.org/693.html",
		"POLICY_PENTEST": "",
		"POLICY_QA_STD":  "",
		"SYSTEMIC":       "https://systemic",
	}
	out := extractZAPTags(tags)
	assert.Equal(t, []string{"CWE-693", "OWASP_2017_A06", "OWASP_2021_A05"}, out,
		"OWASP_*/CWE-* preserved + sorted; POLICY_*/SYSTEMIC dropped")
}

func TestExtractZAPTags_Empty(t *testing.T) {
	assert.Nil(t, extractZAPTags(nil))
	assert.Nil(t, extractZAPTags(map[string]string{}))
	assert.Nil(t, extractZAPTags(map[string]string{"POLICY_X": "", "SYSTEMIC": "y"}))
}

func TestSplitReferences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty → nil", "", nil},
		{"whitespace → nil", "   ", nil},
		{"single", "https://a.com", []string{"https://a.com"}},
		{"newline-separated", "https://a.com\nhttps://b.com\nhttps://c.com",
			[]string{"https://a.com", "https://b.com", "https://c.com"}},
		{"trims + skips empties", "https://a.com\n\n  https://b.com  \n",
			[]string{"https://a.com", "https://b.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitReferences(tc.in))
		})
	}
}

func TestParseAlerts_FullSampleMapping(t *testing.T) {
	// Use the canonical Phase 0 V6 sample alert (CSP).
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	alerts, err := fetchAlerts(context.Background(), c, "https://example.com/")
	require.NoError(t, err)
	require.Len(t, alerts, 3, "stub returns 3 alerts including 1 False Positive")

	findings := parseAlerts(alerts, "https://example.com/")
	require.Len(t, findings, 2, "V8/V9: False Positive must be dropped")

	// Find the CSP alert.
	csp, xss := -1, -1
	for i, f := range findings {
		switch f.Title {
		case "Content Security Policy (CSP) Header Not Set":
			csp = i
		case "Cross Site Scripting (Reflected)":
			xss = i
		}
	}
	require.NotEqual(t, -1, csp)
	require.NotEqual(t, -1, xss)

	// CSP assertions: V6 cweid string pass-through, V8 severity normalize,
	// V12 tags filter (OWASP_2021_A05 + CWE-693 only).
	cspF := findings[csp]
	assert.Equal(t, "medium", cspF.Severity)
	assert.Equal(t, "693", cspF.CWEID, "V6 cweid passed through as string (no strconv.Itoa)")
	assert.Equal(t, "https://example.com/", cspF.TargetURL)
	assert.Equal(t, []string{"https://owasp.org/csp", "https://web.dev/csp"}, cspF.References,
		"V6 reference newline-split into array")
	assert.Equal(t, []string{"CWE-693", "OWASP_2021_A05"}, cspF.Tags,
		"V12 OWASP_*/CWE-* preserved; POLICY_*/SYSTEMIC dropped")

	// Metadata snake_case keys per Q8 + Nmap precedent.
	require.NotNil(t, cspF.Metadata)
	assert.Equal(t, "https://example.com/", cspF.Metadata["target"])
	assert.Equal(t, "High", cspF.Metadata["confidence"])
	assert.Equal(t, "10038", cspF.Metadata["plugin_id"])
	assert.Equal(t, "GET", cspF.Metadata["http_method"])
	assert.Equal(t, "15", cspF.Metadata["wasc_id"])
	assert.Equal(t, "Set CSP header.", cspF.Metadata["solution"], "V11: solution into Metadata")
	assert.Equal(t, "10038-1", cspF.Metadata["alert_ref"])
	assert.Contains(t, cspF.Metadata, "tags_raw_json", "tags raw JSON preserved for audit")

	// Empty fields (param, attack, evidence, input_vector, other) omitted
	// per Nmap omit-when-empty convention.
	assert.NotContains(t, cspF.Metadata, "evidence", "V10: evidence empty for CSP — omitted")
	assert.NotContains(t, cspF.Metadata, "attack_vector")
	assert.NotContains(t, cspF.Metadata, "input_vector")

	// XSS assertions: severity high; param/attack populated.
	xssF := findings[xss]
	assert.Equal(t, "high", xssF.Severity)
	assert.Equal(t, "79", xssF.CWEID)
	assert.Equal(t, "q", xssF.Parameter)
	assert.Equal(t, "<script>alert(1)</script>", xssF.Payload)
	assert.Equal(t, "<script>alert(1)</script>", xssF.Metadata["evidence"])
	assert.Equal(t, "<script>alert(1)</script>", xssF.Metadata["attack_vector"])
	assert.Equal(t, "URL_QUERY_STRING_VALUE", xssF.Metadata["input_vector"])
}

func TestParseAlerts_EmptyInput(t *testing.T) {
	out := parseAlerts(nil, "https://example.com/")
	assert.Empty(t, out)
}

// TestParseAlerts_FingerprintDistinctByPluginID pins the fix for the
// collapsed-fingerprint bug: parseAlerts left FindingType empty, so
// alerts sharing (url, param) but from different ZAP rules hashed to the
// same fingerprint (608 findings → 121). With FindingType=pluginId, three
// alerts at the SAME url + param but different pluginId fingerprint
// distinctly.
func TestParseAlerts_FingerprintDistinctByPluginID(t *testing.T) {
	const url = "https://example.com/"
	alerts := []zapAlert{
		{Name: "Missing CSP", Risk: "Medium", PluginID: "10038", URL: url},
		{Name: "Missing X-Frame-Options", Risk: "Medium", PluginID: "10020", URL: url},
		{Name: "Cookie without SameSite", Risk: "Low", PluginID: "10054", URL: url},
	}

	findings := parseAlerts(alerts, url)
	require.Len(t, findings, 3)

	fps := make(map[string]struct{})
	for _, f := range findings {
		require.NotEmpty(t, f.FindingType, "FindingType (pluginId) must feed the fingerprint")
		assert.Empty(t, f.Parameter, "same (url, param); pluginId is the only differing input")
		f.ToolName = "zap" // mirror the service runner enrichment step
		fps[tools.ComputeFingerprint(f)] = struct{}{}
	}
	assert.Len(t, fps, 3, "distinct pluginIds must fingerprint distinctly, not collapse")
}

func TestFetchAlerts_BulkFetchSuccess(t *testing.T) {
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	alerts, err := fetchAlerts(context.Background(), c, "https://example.com/")
	require.NoError(t, err)
	assert.Len(t, alerts, 3)
	assert.Equal(t, int32(1), stub.alertsCalls.Load())
}
