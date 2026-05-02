# CORStest testdata fixtures

Text-with-ANSI fixtures for `internal/tools/corstest` parser tests.
**First text-with-ANSI parser shape in M6** (5th format after JSONL,
single-doc JSON, JSON-array, XML).

## Output format (CORStest git-pinned, verbose mode `-v`)

CORStest is a Python research tool emitting human-readable text with
ANSI color codes. Per-host record (verbose mode):

```
------------------------------------------------------------------------
Resource: <URL>
Origin:   <URL>
ACAO:     <header value>      (or "-" if absent)
ACAC:     <header value>      (or "-" if absent)
<ANSI>{host} - {status}: {description}<ANSI-reset>
```

Where `<status>` is one of:
- `"Vulnerable"` (with various sub-descriptions)
- `"Not vulnerable"` (no finding emitted; line filtered)

ANSI escape sequences match `\x1b\[[0-9;]*m` and are stripped before
parsing.

## Reductions documented in DRIFT-LOG (M6.6 entry 12)

- `Resource` + `Origin` → folded into Description
- `ACAO` + `ACAC` (Access-Control headers) → folded into Description

## Constants applied (Pattern 4)

Every CORStest finding gets:
- `Severity = corstest.SeverityMedium` (`"medium"` per industry-
  standard CORS misconfig severity)
- `CWEID = "CWE-942"` (Permissive Cross-domain Policy with Untrusted
  Domains)

## Anonymization rules applied

1. **Hostnames** → `*.example.com` / `*.example.org` variants
2. **No real PII**; verbose-mode field values are URL-shaped
3. **ANSI codes** preserved verbatim (parser strips them; fixtures
   exercise the strip)

## Fixtures

| File | Findings | Coverage |
|---|---|---|
| `corstest_basic.txt` | 1 | Single vulnerable host (any-origin-with-credentials). Happy-path. |
| `corstest_multi.txt` | 3 | 5 hosts: 3 vulnerable + 2 not-vulnerable. Mix of vuln types (any-origin-with-credentials, null-origin, origin-reflection). Exercises filter-out invariant. |
| `corstest_empty.txt` | 0 | Empty file. Happy-path-no-findings. |
| `corstest_malformed.txt` | 2 | Synthetic. Mix of complete records + orphan status lines + missing-status records + valid-after-bad. Exercises state-machine resilience: 2 valid findings survive (complete + valid-after-bad); orphan + no-status records dropped with WARN. |

## Adding fixtures

1. If real CORStest run: anonymize hostnames per rule 1.
2. If synthesized: hand-craft minimal text shape; ANSI codes optional
   but should be present for at least one fixture's coverage.
3. Add a row to the table.
4. Add a test in `corstest_test.go`.
