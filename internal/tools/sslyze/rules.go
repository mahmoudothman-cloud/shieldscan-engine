package sslyze

import (
	"fmt"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
)

// ruleFunc inspects a single SSLyze plugin entry (the
// `{status, error_reason, error_trace, result}` object emitted under
// `scan_result[<plugin_key>]`) and synthesizes 0..N RawFindings.
//
// Each rule reads `pluginEntry["result"]` (a domain-shaped map) and
// applies plugin-specific interpretation logic. Returns an empty
// slice for "not vulnerable" / "no finding" cases so the dispatcher
// can skip silently.
//
// targetHostport is "<hostname>:<port>" derived from the per-server
// server_location; copied into every emitted finding's TargetURL.
type ruleFunc func(pluginEntry map[string]any, targetHostport string) []events.RawFinding

// codeSnippetMaxBytes caps Description (used for cipher-list folds)
// at 2 KiB. Consistent with 6.2/6.5 conventions.
const descriptionMaxBytes = 2048

// pluginRules dispatches SSLyze plugin keys to per-plugin rule
// functions. Plugins NOT in this table are silently ignored
// (forward-compat with future SSLyze versions adding plugins).
//
// First-instance "plugin-rules parser" / "synthetic-finding parser"
// pattern (engine DRIFT-LOG M6.4 entry 4). Future synthetic-finding
// tools (6.6 Wapiti, 6.7 Dep-Check) likely adopt similar dispatch
// shape; promote pattern at 3rd instance.
//
// M9 AI pipeline watch: this table is package-private at 6.4; richer
// access (e.g., per-rule severity overrides driven by org policy) is
// an M9-pipeline-extension concern.
var pluginRules = map[string]ruleFunc{
	"heartbleed":                 ruleHeartbleed,
	"robot":                      ruleRobot,
	"openssl_ccs_injection":      ruleCCSInjection,
	"tls_compression":            ruleCompression,
	"session_renegotiation":      ruleRenegotiation,
	"tls_extended_master_secret": ruleEMS,
	"ssl_2_0_cipher_suites":      ruleProtocolSupported("ssl-2.0", pluginSeverity["ssl-2.0-supported"], pluginCWE["ssl-2.0-supported"]),
	"ssl_3_0_cipher_suites":      ruleProtocolSupported("ssl-3.0", pluginSeverity["ssl-3.0-supported"], pluginCWE["ssl-3.0-supported"]),
	"tls_1_0_cipher_suites":      ruleProtocolSupported("tls-1.0", pluginSeverity["ssl-tls-1.0-supported"], pluginCWE["ssl-tls-1.0-supported"]),
	"tls_1_1_cipher_suites":      ruleProtocolSupported("tls-1.1", pluginSeverity["ssl-tls-1.1-supported"], pluginCWE["ssl-tls-1.1-supported"]),
	"certificate_info":           ruleCertificateInfo,
}

// ─── Vulnerability rules (Heartbleed / ROBOT / CCS Injection) ────────

func ruleHeartbleed(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	if !boolFrom(result, "is_vulnerable_to_heartbleed") {
		return nil
	}
	return []events.RawFinding{{
		Title:       "Heartbleed (CVE-2014-0160)",
		Description: "Server is vulnerable to OpenSSL Heartbleed memory disclosure (CVE-2014-0160).",
		Severity:    pluginSeverity["ssl-heartbleed"],
		FindingType: "ssl-heartbleed",
		CWEID:       pluginCWE["ssl-heartbleed"],
		TargetURL:   target,
	}}
}

// robotNotVulnerablePrefix marks every SSLyze robot_result that asserts
// the server is NOT vulnerable. SSLyze emits several such values —
// NOT_VULNERABLE_NO_ORACLE and NOT_VULNERABLE_RSA_NOT_SUPPORTED — and
// only NO_ORACLE was originally excluded. RSA_NOT_SUPPORTED therefore
// synthesized a CRITICAL finding whose own title read "ROBOT attack
// vulnerability (NOT_VULNERABLE_RSA_NOT_SUPPORTED)": a clean-result
// reported as the highest-severity item in the report. Match on the
// prefix so future NOT_VULNERABLE_* values stay excluded by default.
const robotNotVulnerablePrefix = "NOT_VULNERABLE"

func ruleRobot(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	rr := jsonx.ExtractString(result, "robot_result")
	// Only emit for results that ASSERT vulnerability. Every
	// NOT_VULNERABLE_* value is a clean result, not a finding.
	if rr == "" || strings.HasPrefix(rr, robotNotVulnerablePrefix) {
		return nil
	}
	return []events.RawFinding{{
		Title:       "ROBOT attack vulnerability (" + rr + ")",
		Description: "Server is vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat) RSA-key recovery attack: " + rr + ".",
		Severity:    pluginSeverity["ssl-robot"],
		FindingType: "ssl-robot",
		CWEID:       pluginCWE["ssl-robot"],
		TargetURL:   target,
	}}
}

func ruleCCSInjection(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	if !boolFrom(result, "is_vulnerable_to_ccs_injection") {
		return nil
	}
	return []events.RawFinding{{
		Title:       "OpenSSL CCS Injection (CVE-2014-0224)",
		Description: "Server is vulnerable to OpenSSL ChangeCipherSpec injection allowing MitM attacks.",
		Severity:    pluginSeverity["ssl-ccs-injection"],
		FindingType: "ssl-ccs-injection",
		CWEID:       pluginCWE["ssl-ccs-injection"],
		TargetURL:   target,
	}}
}

// ─── Protocol-version rules (factory) ────────────────────────────────

// ruleProtocolSupported returns a rule emitting one finding when the
// scanned SSL/TLS protocol version is supported by the server. The
// finding's Description folds the accepted-cipher list (truncated
// per summarizeCiphers).
//
// Used for ssl_2_0 / ssl_3_0 / tls_1_0 / tls_1_1 — protocols that
// SHOULDN'T be supported in modern deployments. TLS 1.2 / 1.3 are
// intentionally absent from pluginRules (modern protocol support
// is GOOD, not a finding).
func ruleProtocolSupported(version, severity, cwe string) ruleFunc {
	findingType := "ssl-" + version + "-supported"
	title := strings.ToUpper(strings.ReplaceAll(version, "-", " ")) + " protocol supported"
	return func(p map[string]any, target string) []events.RawFinding {
		result := jsonx.ExtractMap(p, "result")
		if !boolFrom(result, "is_tls_version_supported") {
			return nil
		}
		desc := strings.ToUpper(strings.ReplaceAll(version, "-", " ")) + " is supported. " + summarizeCiphers(result)
		desc = strings.TrimRight(desc, " .")
		desc = jsonx.Truncate(desc, descriptionMaxBytes)
		return []events.RawFinding{{
			Title:       title,
			Description: desc,
			Severity:    severity,
			FindingType: findingType,
			CWEID:       cwe,
			TargetURL:   target,
		}}
	}
}

// ─── Misc TLS-feature rules (compression / renegotiation / EMS) ──────

func ruleCompression(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	if !boolFrom(result, "supports_compression") {
		return nil
	}
	return []events.RawFinding{{
		Title:       "TLS compression enabled (CRIME)",
		Description: "Server supports TLS compression, exposing it to the CRIME attack (CVE-2012-4929).",
		Severity:    pluginSeverity["ssl-compression-supported"],
		FindingType: "ssl-compression-supported",
		CWEID:       pluginCWE["ssl-compression-supported"],
		TargetURL:   target,
	}}
}

func ruleRenegotiation(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	// supports_secure_renegotiation defaults to true in well-behaved
	// servers; emit finding when explicitly false.
	v, present := result["supports_secure_renegotiation"]
	if !present {
		return nil
	}
	supported, ok := v.(bool)
	if !ok || supported {
		return nil
	}
	return []events.RawFinding{{
		Title:       "Insecure TLS renegotiation",
		Description: "Server does not support secure renegotiation (CVE-2009-3555); exposed to MitM session injection.",
		Severity:    pluginSeverity["ssl-insecure-renegotiation"],
		FindingType: "ssl-insecure-renegotiation",
		CWEID:       pluginCWE["ssl-insecure-renegotiation"],
		TargetURL:   target,
	}}
}

func ruleEMS(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	v, present := result["supports_ems_extension"]
	if !present {
		return nil
	}
	supported, ok := v.(bool)
	if !ok || supported {
		return nil
	}
	return []events.RawFinding{{
		Title:       "Extended Master Secret extension missing",
		Description: "Server does not advertise the Extended Master Secret TLS extension; partial mitigation against Triple Handshake attack absent.",
		Severity:    pluginSeverity["ssl-no-extended-master-secret"],
		FindingType: "ssl-no-extended-master-secret",
		CWEID:       pluginCWE["ssl-no-extended-master-secret"],
		TargetURL:   target,
	}}
}

// ─── Certificate-info rule (multi-finding output) ────────────────────

// ruleCertificateInfo iterates certificate_deployments[] and emits
// one finding per known issue per deployment. Multi-finding return
// per Watch item C: structurally distinct from single-finding rules.
//
// Issues currently surfaced (extensible):
//   - ssl-cert-hostname-mismatch (leaf_certificate_subject_matches_hostname=false)
//   - ssl-cert-sha1-signature (verified_chain_has_sha1_signature=true)
//
// Additional issues (cert-expired, cert-weak-key, untrusted-chain)
// are deferred until SSLyze 6.x exposes them in stable shapes; the
// pluginSeverity/pluginCWE entries already cover them so they can
// be enabled here without table changes.
func ruleCertificateInfo(p map[string]any, target string) []events.RawFinding {
	result := jsonx.ExtractMap(p, "result")
	depsAny, _ := result["certificate_deployments"].([]any)
	findings := []events.RawFinding{}
	for _, depAny := range depsAny {
		dep, _ := depAny.(map[string]any)
		if dep == nil {
			continue
		}
		certSubject := extractLeafSubject(dep)

		// hostname mismatch
		if v, ok := dep["leaf_certificate_subject_matches_hostname"].(bool); ok && !v {
			findings = append(findings, events.RawFinding{
				Title:       "Certificate hostname mismatch",
				Description: "Leaf certificate subject does not match the requested hostname.",
				Severity:    pluginSeverity["ssl-cert-hostname-mismatch"],
				FindingType: "ssl-cert-hostname-mismatch",
				CWEID:       pluginCWE["ssl-cert-hostname-mismatch"],
				TargetURL:   target,
				CertSubject: certSubject,
			})
		}

		// SHA1 signature on verified chain
		if boolFrom(dep, "verified_chain_has_sha1_signature") {
			findings = append(findings, events.RawFinding{
				Title:       "Certificate chain uses SHA1 signature",
				Description: "Verified certificate chain contains a SHA1-signed certificate (collision risk).",
				Severity:    pluginSeverity["ssl-cert-sha1-signature"],
				FindingType: "ssl-cert-sha1-signature",
				CWEID:       pluginCWE["ssl-cert-sha1-signature"],
				TargetURL:   target,
				CertSubject: certSubject,
			})
		}
	}
	return findings
}

// extractLeafSubject reads the first cert in received_certificate_chain
// and returns its rfc4514_string subject. Returns "" if absent.
//
// Reduction: full chain (intermediate + root) is dropped beyond leaf
// (no multi-cert RawFinding field). Documented in DRIFT-LOG M6.4
// entry 10.
func extractLeafSubject(dep map[string]any) string {
	chain, _ := dep["received_certificate_chain"].([]any)
	if len(chain) == 0 {
		return ""
	}
	leaf, _ := chain[0].(map[string]any)
	subj := jsonx.ExtractMap(leaf, "subject")
	return jsonx.ExtractString(subj, "rfc4514_string")
}

// ─── helpers ─────────────────────────────────────────────────────────

// boolFrom is a lenient bool extractor: returns false on nil map,
// missing key, or non-bool value. Used by rules to test boolean
// plugin-result fields without panicking on unexpected shapes.
//
// Note: jsonx doesn't have ExtractBool yet (1st-instance need; YAGNI
// applies). If a 4th tool needs the same shape, promote to jsonx.
func boolFrom(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

// summarizeCiphers folds accepted_cipher_suites into a Description-
// friendly summary. Truncated at 5 ciphers with "[+N more]" marker
// per H.1; full Description capped at 2 KiB via jsonx.Truncate at
// the call site (descriptionMaxBytes constant).
//
// Format: "Accepted ciphers (N): A, B, C, D, E, [+M more]"
//
// Returns "" if accepted_cipher_suites is absent or empty.
func summarizeCiphers(result map[string]any) string {
	acceptedAny, _ := result["accepted_cipher_suites"].([]any)
	if len(acceptedAny) == 0 {
		return ""
	}
	names := make([]string, 0, len(acceptedAny))
	for _, c := range acceptedAny {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		cs := jsonx.ExtractMap(cm, "cipher_suite")
		if name := jsonx.ExtractString(cs, "name"); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	header := fmt.Sprintf("Accepted ciphers (%d): ", len(names))
	var body string
	if len(names) <= 5 {
		body = strings.Join(names, ", ")
	} else {
		body = strings.Join(names[:5], ", ") + fmt.Sprintf(", [+%d more]", len(names)-5)
	}
	return jsonx.Truncate(header+body, descriptionMaxBytes)
}
