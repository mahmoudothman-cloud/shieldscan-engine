# Wapiti testdata fixtures

JSON fixtures for `internal/tools/wapiti` parser tests. Wapiti uses
NativeRunner OutputFile mode (ADR-023 2nd consumer) due to a Wapiti
bug that corrupts JSON when `-o /dev/stdout` is used.

## Schema (Wapiti 3.2.4 `-f json -o <path>`)

Single-doc JSON, **category-keyed iteration** shape (distinct from
SSLyze plugin-rules per DRIFT-LOG M6.6 entry 6):

```json
{
  "classifications": {<class_name>: {"desc": "...", "sol": "...", "ref": {...}, "wstg": [...]}, ...},
  "vulnerabilities": {<class_name>: [<vuln_instance>, ...], ...},
  "anomalies":       {<class_name>: [...], ...},
  "additionals":     {<class_name>: [...], ...},
  "infos": {"target": "https://example.com/", "date": "...", "version": "3.2.4", ...}
}
```

Per-vuln-instance fields (uniform across all classes):

```json
{
  "method":       "GET",
  "path":         "/",
  "info":         "X-Frame-Options is not set",
  "level":        1,                        // 1=info, 2=low, 3=medium, 4=high, 5=critical
  "parameter":    "",
  "referer":      "",
  "module":       "http_headers",
  "http_request": "GET / HTTP/1.1\n...",
  "curl_command": "curl ...",
  "wstg":         ["OSHP-X-Frame-Options"]
}
```

## Bug workaround pinned in DRIFT-LOG M6.6 entry 5

Wapiti 3.2.4 with `-o /dev/stdout` corrupts JSON output by injecting
the message *"A report has been generated in the file /dev/stdout"*
INTO the JSON stream. **Workaround: use ADR-023 OutputFile mode** —
Wapiti writes to a real tempfile, NativeRunner cleans up.

## Anonymization rules applied

1. **Hostnames** → `*.example.com` variants
2. **Timestamps** → deterministic (`2026-01-15T12:00:00Z`)
3. **`http_request`** → keep verbatim from real anonymized scans (no
   PII; example.com headers only)
4. **`classifications`** top-level metadata → STRIPPED for fixture
   readability (parser ignores it; large prose blocks add noise)

## Reductions documented in DRIFT-LOG (M6.6 entry 12)

- `curl_command` → DROP (reproducibility-only; not finding attribute)
- `referer` (when empty) → DROP
- `wstg[]` (OWASP WSTG references) → DROP (no References field)
- `classifications.{class}.{desc, sol, ref, wstg}` → DROP (top-level
  metadata; not per-instance)
- `module` → DROP (tool internals)

## Severity mapping (domain-rules 2nd instance after SSLyze)

Wapiti `level` integer → canonical severity:

| Wapiti level | Canonical |
|---|---|
| 1 | info |
| 2 | low |
| 3 | medium |
| 4 | high |
| 5 | critical |

## Fixtures

| File | Findings | Coverage |
|---|---|---|
| `wapiti_basic.json` | 1 | Single Clickjacking finding (level=1 → info). Happy-path single-finding parse. |
| `wapiti_multi.json` | 3 | Real-anonymized scan: Clickjacking + HSTS + MIME Type Confusion. 3 distinct vuln classes; demonstrates category-keyed iteration. |
| `wapiti_empty.json` | 0 | All class arrays empty. Happy-path-no-findings. |
| `wapiti_severity_mix.json` | 3 | Synthetic: 1 medium (level 3) + 1 high (level 4) + 1 critical (level 5) across XSS + SQLi classes. Exercises full severity-mapping table. |

## Adding fixtures

1. Real Wapiti scan: anonymize per rules 1-4 above. Strip
   `classifications` block for readability.
2. Synthetic: hand-craft minimal JSON; existing fixtures show schema.
3. Add a row to the table.
4. Add a test in `wapiti_test.go`.
