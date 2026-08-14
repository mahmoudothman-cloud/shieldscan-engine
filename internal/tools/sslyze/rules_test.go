// rules_test.go covers per-plugin rule functions in rules.go +
// helpers (boolFrom, summarizeCiphers, table-completeness check).
//
// Each rule has both vulnerable AND not-vulnerable cases per Watch
// item E (symmetric coverage prevents "we only test the alarm path"
// bug).
package sslyze

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureScanResult unwraps the scan_result map from a fixture for
// per-plugin rule testing.
func fixtureScanResult(t *testing.T, fixtureName string) map[string]any {
	t.Helper()
	raw := readFixture(t, fixtureName)
	doc := mustUnmarshal(t, raw)
	results, ok := doc["server_scan_results"].([]any)
	require.True(t, ok, "server_scan_results not array")
	require.NotEmpty(t, results)
	first, _ := results[0].(map[string]any)
	sr, _ := first["scan_result"].(map[string]any)
	return sr
}

func mustUnmarshal(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// ─── ruleHeartbleed (vuln + not-vuln) ────────────────────────────────

func TestRuleHeartbleed_Vulnerable(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_heartbleed.json")
	findings := ruleHeartbleed(sr["heartbleed"].(map[string]any), "vuln.example.com:443")
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "ssl-heartbleed", f.FindingType)
	assert.Equal(t, "critical", f.Severity)
	assert.Equal(t, "CWE-119", f.CWEID)
	assert.Equal(t, "vuln.example.com:443", f.TargetURL)
	assert.Contains(t, f.Description, "Heartbleed")
}

func TestRuleHeartbleed_NotVulnerable(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_modern.json")
	findings := ruleHeartbleed(sr["heartbleed"].(map[string]any), "modern.example.com:443")
	assert.Empty(t, findings, "is_vulnerable_to_heartbleed=false → 0 findings")
}

// ─── ruleRobot (vuln + not-vuln) ─────────────────────────────────────

func TestRuleRobot_Vulnerable(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_heartbleed.json")
	findings := ruleRobot(sr["robot"].(map[string]any), "vuln.example.com:443")
	require.Len(t, findings, 1)
	assert.Equal(t, "ssl-robot", findings[0].FindingType)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, "CWE-310", findings[0].CWEID)
}

func TestRuleRobot_NotVulnerable(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_modern.json")
	findings := ruleRobot(sr["robot"].(map[string]any), "modern.example.com:443")
	assert.Empty(t, findings, "robot_result=NOT_VULNERABLE_NO_ORACLE → 0 findings")
}

// TestRuleRobot_AllNotVulnerableResultsProduceNoFinding pins the fix for a
// live-scan bug: only NOT_VULNERABLE_NO_ORACLE was excluded, so a clean
// NOT_VULNERABLE_RSA_NOT_SUPPORTED result synthesized a CRITICAL finding
// titled "ROBOT attack vulnerability (NOT_VULNERABLE_RSA_NOT_SUPPORTED)" —
// the top-severity item in every report, asserting the exact opposite of
// what SSLyze reported.
func TestRuleRobot_AllNotVulnerableResultsProduceNoFinding(t *testing.T) {
	for _, rr := range []string{
		"NOT_VULNERABLE_NO_ORACLE",
		"NOT_VULNERABLE_RSA_NOT_SUPPORTED",
	} {
		t.Run(rr, func(t *testing.T) {
			p := map[string]any{
				"result": map[string]any{"robot_result": rr},
			}
			assert.Empty(t, ruleRobot(p, "modern.example.com:443"),
				"%s asserts the server is NOT vulnerable → 0 findings", rr)
		})
	}
}

// TestRuleRobot_VulnerableResultsStillEmit guards against over-filtering:
// the prefix match must not silence genuine oracle results.
func TestRuleRobot_VulnerableResultsStillEmit(t *testing.T) {
	for _, rr := range []string{
		"VULNERABLE_WEAK_ORACLE",
		"VULNERABLE_STRONG_ORACLE",
	} {
		t.Run(rr, func(t *testing.T) {
			p := map[string]any{
				"result": map[string]any{"robot_result": rr},
			}
			findings := ruleRobot(p, "vuln.example.com:443")
			require.Len(t, findings, 1)
			assert.Equal(t, "ssl-robot", findings[0].FindingType)
			assert.Equal(t, "critical", findings[0].Severity)
		})
	}
}

// ─── ruleCCSInjection (vuln + not-vuln) ──────────────────────────────

func TestRuleCCSInjection_Vulnerable(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_heartbleed.json")
	findings := ruleCCSInjection(sr["openssl_ccs_injection"].(map[string]any), "vuln.example.com:443")
	require.Len(t, findings, 1)
	assert.Equal(t, "ssl-ccs-injection", findings[0].FindingType)
	assert.Equal(t, "high", findings[0].Severity)
}

func TestRuleCCSInjection_NotVulnerable(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_modern.json")
	findings := ruleCCSInjection(sr["openssl_ccs_injection"].(map[string]any), "modern.example.com:443")
	assert.Empty(t, findings)
}

// ─── ruleProtocolSupported factory (4 protocol versions; share factory) ──

func TestRuleProtocolSupported_TLS10WithCiphers(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_weak.json")
	rule := ruleProtocolSupported("tls-1.0", "medium", "CWE-326")
	findings := rule(sr["tls_1_0_cipher_suites"].(map[string]any), "weak.example.com:443")
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "ssl-tls-1.0-supported", f.FindingType)
	assert.Equal(t, "medium", f.Severity)
	assert.Equal(t, "CWE-326", f.CWEID)
	// Cipher list folded into Description with 7 ciphers (5 + [+2 more]).
	assert.Contains(t, f.Description, "Accepted ciphers (7)")
	assert.Contains(t, f.Description, "[+2 more]",
		"7 ciphers should truncate to 5 + [+2 more]")
}

func TestRuleProtocolSupported_TLS11FewerCiphers(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_weak.json")
	rule := ruleProtocolSupported("tls-1.1", "medium", "CWE-326")
	findings := rule(sr["tls_1_1_cipher_suites"].(map[string]any), "weak.example.com:443")
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "ssl-tls-1.1-supported", f.FindingType)
	// 2 ciphers → no [+N more] truncation; list inline.
	assert.Contains(t, f.Description, "Accepted ciphers (2)")
	assert.NotContains(t, f.Description, "more]")
}

func TestRuleProtocolSupported_NotSupported(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_modern.json")
	rule := ruleProtocolSupported("tls-1.0", "medium", "CWE-326")
	findings := rule(sr["tls_1_0_cipher_suites"].(map[string]any), "modern.example.com:443")
	assert.Empty(t, findings, "is_tls_version_supported=false → 0 findings")
}

// ─── ruleCompression / ruleRenegotiation / ruleEMS (table-driven) ────

func TestRuleCompression(t *testing.T) {
	t.Run("vulnerable", func(t *testing.T) {
		sr := fixtureScanResult(t, "sslyze_heartbleed.json")
		findings := ruleCompression(sr["tls_compression"].(map[string]any), "v.example.com:443")
		require.Len(t, findings, 1)
		assert.Equal(t, "ssl-compression-supported", findings[0].FindingType)
	})
	t.Run("not-vulnerable", func(t *testing.T) {
		sr := fixtureScanResult(t, "sslyze_modern.json")
		findings := ruleCompression(sr["tls_compression"].(map[string]any), "m.example.com:443")
		assert.Empty(t, findings)
	})
}

func TestRuleRenegotiation(t *testing.T) {
	t.Run("insecure", func(t *testing.T) {
		sr := fixtureScanResult(t, "sslyze_heartbleed.json")
		findings := ruleRenegotiation(sr["session_renegotiation"].(map[string]any), "v.example.com:443")
		require.Len(t, findings, 1)
		assert.Equal(t, "ssl-insecure-renegotiation", findings[0].FindingType)
	})
	t.Run("secure", func(t *testing.T) {
		sr := fixtureScanResult(t, "sslyze_modern.json")
		findings := ruleRenegotiation(sr["session_renegotiation"].(map[string]any), "m.example.com:443")
		assert.Empty(t, findings)
	})
}

func TestRuleEMS(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		sr := fixtureScanResult(t, "sslyze_weak.json")
		findings := ruleEMS(sr["tls_extended_master_secret"].(map[string]any), "w.example.com:443")
		require.Len(t, findings, 1)
		assert.Equal(t, "ssl-no-extended-master-secret", findings[0].FindingType)
		assert.Equal(t, "low", findings[0].Severity)
	})
	t.Run("present", func(t *testing.T) {
		sr := fixtureScanResult(t, "sslyze_modern.json")
		findings := ruleEMS(sr["tls_extended_master_secret"].(map[string]any), "m.example.com:443")
		assert.Empty(t, findings)
	})
}

// ─── ruleCertificateInfo (multi-finding) ─────────────────────────────

// TestRuleCertificateInfo_MultiFindings pins Watch item C: cert plugin
// CAN return multiple findings from one deployment (hostname mismatch
// + sha1 signature in our fixture). Slice-return is structurally
// distinct from single-finding rules.
func TestRuleCertificateInfo_MultiFindings(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_cert_expired.json")
	findings := ruleCertificateInfo(sr["certificate_info"].(map[string]any), "expired.example.com:443")
	require.Len(t, findings, 2,
		"expired fixture: hostname mismatch + sha1 signature = 2 findings")

	// Verify the issue types.
	types := []string{findings[0].FindingType, findings[1].FindingType}
	assert.Contains(t, types, "ssl-cert-hostname-mismatch")
	assert.Contains(t, types, "ssl-cert-sha1-signature")

	// CertSubject populated identically across all findings from same
	// deployment. First-time-populated dormant field per DRIFT-LOG
	// entry 3.
	for _, f := range findings {
		assert.Equal(t, "CN=wrong-host.example.com,O=Example Org", f.CertSubject)
	}
}

func TestRuleCertificateInfo_NoIssues(t *testing.T) {
	sr := fixtureScanResult(t, "sslyze_modern.json")
	findings := ruleCertificateInfo(sr["certificate_info"].(map[string]any), "modern.example.com:443")
	assert.Empty(t, findings, "modern cert chain → 0 findings")
}

// ─── summarizeCiphers ────────────────────────────────────────────────

func TestSummarizeCiphers(t *testing.T) {
	mkResult := func(names ...string) map[string]any {
		ciphers := make([]any, 0, len(names))
		for _, n := range names {
			ciphers = append(ciphers, map[string]any{
				"cipher_suite": map[string]any{"name": n},
			})
		}
		return map[string]any{"accepted_cipher_suites": ciphers}
	}

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", summarizeCiphers(mkResult()))
	})
	t.Run("three-inline", func(t *testing.T) {
		got := summarizeCiphers(mkResult("A", "B", "C"))
		assert.Contains(t, got, "Accepted ciphers (3): A, B, C")
		assert.NotContains(t, got, "more]")
	})
	t.Run("twelve-truncated", func(t *testing.T) {
		got := summarizeCiphers(mkResult("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"))
		assert.Contains(t, got, "Accepted ciphers (12)")
		assert.Contains(t, got, "[+7 more]")
		// First 5 listed; rest folded into [+N more].
		for _, name := range []string{"A", "B", "C", "D", "E"} {
			assert.Contains(t, got, name)
		}
	})
	t.Run("2KiB-cap-respected", func(t *testing.T) {
		// 50 ciphers each with a 100-char name → exceeds 2 KiB; cap
		// suffix should appear from jsonx.Truncate.
		long := strings.Repeat("X", 100)
		names := make([]string, 50)
		for i := range names {
			names[i] = long
		}
		got := summarizeCiphers(mkResult(names...))
		assert.True(t, len(got) <= 2048+3, // truncate adds "..." (3 bytes)
			"summary capped near 2 KiB; got %d bytes", len(got))
	})
}

// ─── boolFrom (lenient bool extraction) ──────────────────────────────

func TestBoolFrom(t *testing.T) {
	cases := []struct {
		name string
		m    map[string]any
		key  string
		want bool
	}{
		{"true", map[string]any{"k": true}, "k", true},
		{"false", map[string]any{"k": false}, "k", false},
		{"missing", map[string]any{}, "k", false},
		{"nil-map", nil, "k", false},
		{"wrong-type-string", map[string]any{"k": "true"}, "k", false},
		{"wrong-type-int", map[string]any{"k": 1}, "k", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, boolFrom(c.m, c.key))
		})
	}
}

// ─── pluginSeverity + pluginCWE table alignment ──────────────────────

// TestPluginSeverityCWE_TablesAligned pins the invariant: every
// FindingType produced by our rules has both a severity AND a CWE
// entry. Catches "added a rule, forgot to register severity/CWE"
// regressions.
func TestPluginSeverityCWE_TablesAligned(t *testing.T) {
	for ft := range pluginSeverity {
		_, ok := pluginCWE[ft]
		assert.True(t, ok, "pluginSeverity has %q but pluginCWE doesn't", ft)
	}
	for ft := range pluginCWE {
		_, ok := pluginSeverity[ft]
		assert.True(t, ok, "pluginCWE has %q but pluginSeverity doesn't", ft)
	}
}
