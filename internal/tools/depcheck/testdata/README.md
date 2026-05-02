# Dep-Check testdata fixtures

JSON fixtures for `internal/tools/depcheck` parser tests. Convention
inheritance: 5.1's `internal/events/testdata/README.md` + per-tool
README pattern from 6.1/6.5.

## Synthesis methodology (per Watch item G)

**These fixtures are SYNTHESIZED from the documented OWASP Dep-Check
9.2.0 JSON schema, NOT captured from real scans.**

Reason: Dep-Check requires an NVD API key for fresh scans (NVD's
unauthenticated endpoint returns 403/404 as of 2026). M6.7 pre-prep
verified the binary works (`dependency-check.sh --version` returned
9.2.0) but couldn't run a real scan without an API key. Fixtures
follow the documented schema published in the Dep-Check repo
(`jeremylong/DependencyCheck`).

**Trigger to replace with real captures:** OPS milestone (M11)
configures `DEPCHECK_NVD_API_KEY` env var; first real scan output
should anonymize per the rules below and replace the synthesized
fixtures (preserving schema invariants the tests rely on).

## Schema (Dep-Check 9.2.0 `--format JSON`)

**File-output mode** (`--out <path>`) — Dep-Check writes findings to
the file, NOT stdout. Stdout is logging chatter. Per ADR-023,
NativeRunner's OutputFile mode handles the file lifecycle.

Top-level shape:

```
{
  "reportSchema": "1.1",
  "scanInfo": {"engineVersion": "9.2.0"},
  "projectInfo": {...},
  "dependencies": [
    {
      "fileName": "log4j-core-2.14.0.jar",
      "filePath": "/path/to/lib/log4j-core-2.14.0.jar",
      "md5": "...", "sha1": "...", "sha256": "...",
      "vulnerabilities": [
        {
          "name": "CVE-2021-44228",
          "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
          "cvssv3": {"baseScore": 10.0, ...},
          "cwes": ["CWE-502", "CWE-20"],
          "description": "...",
          "references": [...],
          "vulnerableSoftware": [...]
        }
      ],
      "evidenceCollected": {...}
    }
  ]
}
```

**Per-CVE findings** (per Watch item C): one `vulnerabilities[i]` →
one RawFinding. A dep with 5 CVEs produces 5 findings, each with the
same `CodeFile` (the dep file path) but distinct `FindingType` (the
CVE id).

## Reductions documented in DRIFT-LOG (M6.7 entry 10)

The fixtures intentionally include or omit fields per the parser's
reductions:

- `vulnerabilities[i].references[]` → DROP (no field; deeply nested URLs)
- `vulnerabilities[i].vulnerableSoftware[]` → DROP (CPE version ranges)
- `dependencies[j].md5/sha1/sha256` → DROP (file hashes; not actionable)
- `dependencies[j].evidenceCollected` → DROP (tool internals)
- Multi-CWE beyond `[0]` → DROP (first-only convention from 6.1/6.2)

## Anonymization rules

For real-captured fixtures (when M11 OPS milestone enables NVD scans):

1. **File paths** → `repo/lib/<jar-name>` (generic root)
2. **Project name** → `example-project`
3. **CVE descriptions** → keep verbatim (CVE descriptions are public)
4. **CVE ids + CVSS scores** → keep real (the value is in the data)
5. **Hashes** → `anonymized-md5` / `anonymized-sha1` / `anonymized-sha256`
6. **References URLs** → keep verbatim (public CVE references)
7. **Timestamps** → deterministic (`2026-01-15T12:00:00.000000Z`)

## Fixtures

| File | Findings | Coverage |
|---|---|---|
| `depcheck_basic.json` | 1 | Single CVE (CVE-2021-44228, Log4Shell, critical). Happy-path single-finding parse. |
| `depcheck_multi_cve.json` | 8 | 3 deps × variable CVE counts. Severity mix: 3 Critical + 1 High + 1 Medium + 1 Low + ... Exercises per-CVE granularity convention; same dep appearing across multiple findings. |
| `depcheck_empty.json` | 0 | `dependencies: []`. Happy-path-no-vulns. |
| `depcheck_missing_fields.json` | 2 | Synthetic. 4 deps: valid + clean (no vulnerabilities array) + missing filePath (entire dep dropped) + partial (CVE without name dropped, valid CVE survives). Net: 2 findings (one from "good.jar", one from "partial.jar"). |

## Adding fixtures

When NVD API key lands at OPS milestone:

1. Anonymize per rules 1-7 above.
2. Strip large `references[]` and `vulnerableSoftware[]` arrays for
   readability; the parser drops them anyway.
3. Add a row to the table above.
4. Add a test in `depcheck_test.go` that loads + asserts behavior.
