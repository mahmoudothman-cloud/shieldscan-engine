# Nuclei testdata fixtures

JSONL fixtures for `internal/tools/nuclei` parser tests. Conventions
inherited from `internal/events/testdata/README.md` (5.1) and applied
to tool-output (vs wire-format) shape per M6.1 landscape decision.

## Anonymization rules applied

1. **Public IPs** → RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`,
   `203.0.113.0/24`). The `nuclei_ssl_multi.jsonl` fixture's IPs were
   remapped from a real `nuclei -t ssl/` run against `example.com`.
2. **Hostnames** stay as `example.com` / `*.example.com` (IETF reserved
   for documentation).
3. **`template-encoded` base64 blobs** stripped from real outputs —
   massive (often >1KB per record) and not parser-relevant.
4. **`template-path`** made repo-portable (drops `/home/...` prefix).
5. **Timestamps** normalized to deterministic values
   (`2026-01-15T12:00:NN.000000000Z`) so test assertions are stable.

## Fixtures

| File | Records | Coverage |
|---|---|---|
| `nuclei_ssl_multi.jsonl` | 11 | Real-anonymized `nuclei -t ssl/` run. Severity mix `{info: 9, low: 2}`. No `info.classification` (SSL templates ship without CVE/CWE). Exercises multi-finding parse, both `matcher-name` and `extractor-name` shapes, no-classification path. |
| `nuclei_xss_basic.jsonl` | 1 | Synthesized CVE-bearing finding. `info.classification.{cve-id, cwe-id, cvss-metrics, cvss-score}` populated (CVE-2024-1234 / CWE-79 / 7.4). Exercises severity mapping (high), CWE extraction, request/response/curl-command preservation. |
| `nuclei_empty.jsonl` | 0 | Empty file. Nuclei exits 0 with no output when nothing matches. Exercises empty-output happy path → `([], nil)`. |
| `nuclei_malformed_line.jsonl` | 4 valid + 1 garbage | Line 3 is `{"template": MALFORMED]` (truncated JSON, wrong bracket). Exercises lenient parse-line resilience: drop the bad line with a warning, continue with the other 4. Realistic shape: subprocess killed mid-write would produce something similar. |

## Adding fixtures

When a new edge case surfaces in production:

1. If derived from a real Nuclei run: anonymize per rules 1-5 above.
2. If synthesized: hand-craft minimal valid Nuclei JSONL. Use existing
   fixtures as the schema reference (real Nuclei v3.7.1 output).
3. Add a row to the table above.
4. Add a test in `nuclei_test.go` that loads + asserts behavior.
