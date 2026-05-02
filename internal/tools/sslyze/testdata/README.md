# SSLyze testdata fixtures

Plugin-diagnostics fixtures for `internal/tools/sslyze` parser tests.
Convention inheritance: 5.1's `internal/events/testdata/README.md` +
6.1's `nuclei/testdata/README.md` + 6.5's `gitleaks/testdata/README.md`.

## Schema (SSLyze 6.1.0 `--json_out`)

**Single-doc JSON, NOT a findings list.** SSLyze emits structured
plugin diagnostics; our parser SYNTHESIZES findings via per-plugin
domain rules (see `../rules.go`).

```
{
  "sslyze_version": "6.1.0",
  "server_scan_results": [
    {
      "server_location": {"hostname": "...", "port": 443},
      "scan_status": "COMPLETED" | "ERROR_NO_CONNECTIVITY" | ...,
      "scan_result": {
        "heartbleed":              {"status": "...", "result": {...}},
        "robot":                   {"status": "...", "result": {...}},
        "openssl_ccs_injection":   {...},
        "ssl_2_0_cipher_suites":   {...},
        "ssl_3_0_cipher_suites":   {...},
        "tls_1_0_cipher_suites":   {...},
        "tls_1_1_cipher_suites":   {...},
        "tls_compression":         {...},
        "session_renegotiation":   {...},
        "tls_extended_master_secret": {...},
        "tls_fallback_scsv":       {...},
        "certificate_info":        {...},
        ...
      }
    }
  ]
}
```

Per-plugin `result` shape varies; see real outputs (we've trimmed to
minimal shapes for fixture readability).

## Anonymization rules applied

SSL cert data is privacy-sensitive even for public test sites.
Apply consistently:

1. **Hostnames** → `*.example.com` variants (`modern.example.com`,
   `weak.example.com`, `expired.example.com`, etc.)
2. **IPs** → RFC 5737 reserved (`192.0.2.x`)
3. **Cert subjects (rfc4514_string)** → generic `CN=<host>` or
   `CN=<host>,O=Example Org`
4. **Issuers** → `CN=Example CA, O=Example CA Org` (when present)
5. **Email addresses** → `admin@example.com` (when present)
6. **SANs** → `*.example.com` variants (when present)
7. **UUIDs** → deterministic placeholders (`00000000-0000-0000-0000-00000000000N`)
8. **Timestamps** → deterministic (`2026-01-15T12:00:00.000000`)
9. **`_synthetic*` markers** prefixed with underscore in fields the
   parser shouldn't read; document the synthesis in the value
   (e.g., `"_synthetic_expired": true`).

## Reductions documented in DRIFT-LOG (M6.4 entry 10)

The fixtures intentionally omit fields the parser drops:
- `cipher_suite.openssl_name` and `key_size` for cipher entries
  not relevant to a given test
- `path_validation_results`, `ocsp_response`,
  `signed_certificate_timestamps_count` (cert plugin)
- `ephemeral_key` populated only as `null` (full struct dropped)
- `network_configuration`, `connectivity_error_trace` for
  successful scans
- `tls_1_2_cipher_suites` / `tls_1_3_cipher_suites` (modern
  protocols — supported is GOOD, not a finding; rule table
  intentionally has no entry for them)

## Fixtures

| File | Synthesized findings | Coverage |
|---|---|---|
| `sslyze_modern.json` | 0 | TLS 1.2/1.3 only, EMS supported, valid cert. Happy path. |
| `sslyze_weak.json` | 4 | TLS 1.0 supported (with 7 ciphers folded), TLS 1.1 supported (2 ciphers), no Extended Master Secret. Multi-finding. |
| `sslyze_heartbleed.json` | 7 | Synthesized vulnerable: Heartbleed + ROBOT + CCS Injection + compression + insecure renegotiation + no EMS + no fallback SCSV. No real Heartbleed-vuln server in 2026. |
| `sslyze_cert_expired.json` | 2 | Cert hostname mismatch + SHA1 signature on chain. Multi-finding from `certificate_info` plugin. |
| `sslyze_empty.json` | 0 | `server_scan_results: []`. Happy-path-no-targets. |
| `sslyze_connectivity_failed.json` | 0 | `scan_status: "ERROR_NO_CONNECTIVITY"`. Per-server skipped with WARN; not an error. |

## Adding fixtures

When a new edge case surfaces in production:

1. If from a real SSLyze run: anonymize per rules 1-9 above. Strip
   `path_validation_results` / `ocsp_response` etc. for readability
   unless the test specifically needs them.
2. If synthesized: hand-craft minimal valid SSLyze JSON; use existing
   fixtures as the schema reference (real SSLyze 6.1.0 `--json_out`
   output).
3. Add a row to the table above.
4. Add a test in `sslyze_test.go` or `rules_test.go` that loads +
   asserts behavior.
