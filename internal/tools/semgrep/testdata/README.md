# Semgrep testdata fixtures

JSON fixtures for `internal/tools/semgrep` parser tests. Convention
inheritance: `internal/events/testdata/README.md` (5.1, wire format)
+ `internal/tools/nuclei/testdata/README.md` (6.1, tool output).

## Schema (Semgrep 1.95.0 `--json`)

Single-doc, NOT JSONL (contrast with Nuclei). Top level:

```
{
  "version": "1.95.0",
  "results": [...],         // array of findings
  "errors": [...],          // array of tool errors (often empty)
  "paths": {                // scanned/skipped path lists
    "scanned": [...],
    "skipped": [...]
  },
  "skipped_rules": [...],
  "interfile_languages_used": [...]
}
```

Per-result:

```
{
  "check_id": "python.lang.security...",   // rule id (dotted path)
  "path": "repo/app.py",                   // file (pre-anonymization
                                           //   was "vuln-target/...")
  "start": { "line": 10, "col": 5, "offset": 100 },
  "end":   { "line": 10, "col": 50 },
  "extra": {
    "message": "...",
    "severity": "ERROR" | "WARNING" | "INFO",
    "metadata": {
      "cwe":   ["CWE-78: human-readable description..."],
      "owasp": ["A01:2017 - Injection", "A03:2021 - Injection", ...],
      "category", "confidence", "impact", "likelihood", ...
    },
    "lines":       "matched source code",
    "fingerprint": "...",                   // Semgrep's own; we drop
    "fix":         "...",                   // optional
    "engine_kind": "OSS"
  }
}
```

## Anonymization rules applied

1. **Paths** — `vuln-target/` → `repo/` (generic synthetic root).
2. **`extra.fingerprint`** — replaced with `anonymized-<rule-suffix>`
   (Semgrep's own dedup id; we compute our own via
   `tools.ComputeFingerprint` so the upstream value is purely
   illustrative).
3. **No real secrets** — synthetic source files contain bait
   patterns (subprocess shell=True, MD5, SQLi via concat,
   placeholder API keys); none are operational secrets.
4. **No timestamps in Semgrep output** — nothing to normalize on
   that axis (contrast with Nuclei's per-record `timestamp` field).

## Fixtures

| File | Records | Coverage |
|---|---|---|
| `semgrep_basic.json` | 1 | Single `ERROR` finding (subprocess-shell-true, CWE-78). Happy-path single-finding parse. |
| `semgrep_multi.json` | 6 | Real-anonymized scan output: **4 ERROR + 1 WARNING + 1 INFO**. CWEs covered: 78, 89, 798, 352, 601. Exercises severity distribution + OWASP first-element extraction (multi-year arrays). |
| `semgrep_empty.json` | 0 | Clean run, `results: []`, `errors: []`. Happy-path-no-findings. |
| `semgrep_error.json` | 0 results, 1 error | Tool-error case: `errors[]` populated with a synthetic syntax-parse failure (exit 2 territory). Exercises log-and-continue posture (Option A from M6.2 H.1). |
| `semgrep_unknown_fields.json` | 1 | Synthetic. Top-level + `start.*` + `extra.*` + `extra.metadata.*` all carry forward-compat unknown fields. Asserts lenient-decode invariant: unknown fields MUST NOT cause parse error. |
| `semgrep_missing_fields.json` | 4 records (2 valid + 2 invalid) | Synthetic. Records lacking required `check_id` / `path` are dropped with WARN; valid records flow through. Exercises required-fields gate. |

## Adding fixtures

When a new edge case surfaces in production:

1. If from a real Semgrep run: anonymize per rules 1-4 above.
2. If synthesized: hand-craft minimal valid Semgrep JSON. Use existing
   fixtures as the schema reference (real Semgrep 1.95.0 `--json`
   output).
3. Add a row to the table above.
4. Add a test in `semgrep_test.go` that loads + asserts behavior.
