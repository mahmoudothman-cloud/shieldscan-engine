package sslyze

// pluginSeverity maps SSLyze synthetic FindingType → canonical
// RawFinding.Severity.
//
// First multi-rule severity table in M6 beyond Semgrep's 3-level.
// "Domain-rules severity mapping" pattern (1st instance per engine
// DRIFT-LOG M6.4 entry 5; track for promotion at 3rd instance).
//
// Domain rationale per row:
//
//   - critical: confirmed-exploitable + remote (Heartbleed memory
//     disclosure, ROBOT RSA-key-recovery oracle, SSL 2.0 fundamental
//     break).
//   - high: high-impact misconfiguration with active exploitation
//     vectors (SSL 3.0 → POODLE, CCS Injection MitM, expired/
//     mismatched cert breaking trust chain).
//   - medium: deprecated-but-not-trivially-exploitable, or
//     attack-conditions-required (TLS 1.0/1.1 deprecated; CRIME
//     compression; insecure renegotiation; SHA1 cert collision risk;
//     <2048-bit keys).
//   - low: defense-in-depth absences (no EMS extension, no fallback
//     SCSV) — important to fix but exploit class limited.
var pluginSeverity = map[string]string{
	"ssl-heartbleed":                "critical",
	"ssl-robot":                     "critical",
	"ssl-2.0-supported":             "critical",
	"ssl-3.0-supported":             "high",
	"ssl-ccs-injection":             "high",
	"ssl-cert-hostname-mismatch":    "high",
	"ssl-cert-expired":              "high",
	"ssl-tls-1.0-supported":         "medium",
	"ssl-tls-1.1-supported":         "medium",
	"ssl-compression-supported":     "medium",
	"ssl-insecure-renegotiation":    "medium",
	"ssl-cert-sha1-signature":       "medium",
	"ssl-cert-weak-key":             "medium",
	"ssl-no-extended-master-secret": "low",
	"ssl-no-fallback-scsv":          "low",
}

// pluginCWE maps SSLyze synthetic FindingType → canonical CWEID.
// Aligned with pluginSeverity (TestPluginSeverityCWE_TablesAligned
// regression-guards).
//
// Common CWEs:
//
//   - CWE-119 (Improper Restriction of Operations within the Bounds
//     of a Memory Buffer): Heartbleed memory disclosure.
//   - CWE-295 (Improper Certificate Validation): hostname-mismatch,
//     expired, untrusted-chain.
//   - CWE-310 (Cryptographic Issues): protocol-level vulnerabilities
//     (CCS Injection, CRIME, insecure renegotiation, fallback
//     attacks, EMS missing).
//   - CWE-326 (Inadequate Encryption Strength): weak protocol
//     versions (SSL 2.0/3.0, TLS 1.0/1.1), weak key sizes.
//   - CWE-327 (Use of a Broken or Risky Cryptographic Algorithm):
//     SHA1 signature on cert chain.
var pluginCWE = map[string]string{
	"ssl-heartbleed":                "CWE-119",
	"ssl-robot":                     "CWE-310",
	"ssl-ccs-injection":             "CWE-310",
	"ssl-2.0-supported":             "CWE-326",
	"ssl-3.0-supported":             "CWE-326",
	"ssl-tls-1.0-supported":         "CWE-326",
	"ssl-tls-1.1-supported":         "CWE-326",
	"ssl-compression-supported":     "CWE-310",
	"ssl-insecure-renegotiation":    "CWE-310",
	"ssl-no-extended-master-secret": "CWE-310",
	"ssl-no-fallback-scsv":          "CWE-310",
	"ssl-cert-hostname-mismatch":    "CWE-295",
	"ssl-cert-expired":              "CWE-295",
	"ssl-cert-sha1-signature":       "CWE-327",
	"ssl-cert-weak-key":             "CWE-326",
}
