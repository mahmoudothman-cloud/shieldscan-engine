# Checkov testdata fixtures

Single-doc JSON fixtures for `internal/tools/checkov` parser tests.
Convention inheritance: 5.1's `internal/events/testdata/README.md` +
6.5's `gitleaks/testdata/README.md`.

## Schema (Checkov 3.2.340 `-o json`)

Single-doc JSON; one invocation = one framework's output. Top-level:

```
{
  "check_type": "terraform" | "kubernetes" | "cloudformation" | ...,
  "results": {
    "failed_checks": [
      {
        "check_id":         "CKV_AWS_23",
        "bc_check_id":      "BC_AWS_NETWORKING_31",
        "check_name":       "Ensure ...",
        "file_path":        "/main.tf",
        "file_line_range":  [5, 13],
        "resource":         "aws_security_group.web",
        "severity":         null,           // OSS Checkov: ALWAYS null
        "code_block":       [[lineNum, "code line\n"], ...],
        "guideline":        "https://...",
        ...
      }
    ]
  },
  "summary": {"passed": ..., "failed": ..., "checkov_version": "3.2.340", ...}
}
```

## Critical OSS-Checkov behavior (per M6.7 pre-prep)

**`severity` is universally `null`** in the OSS edition. Severity is a
Bridgecrew Cloud commercial feature; M6.7 applies a **constant default
`"medium"`** to every Checkov RawFinding (per H.NEW.1). Constants-only
mapping pattern, **2nd instance** after Gitleaks (M6.5).

Similarly, **`CWEID` is set to constant `"CWE-1032"`** (OWASP IaC
Misconfiguration) per H.NEW.2. Every Checkov finding maps to this CWE
since OSS Checkov has no per-check CWE field.

## Reductions documented in DRIFT-LOG (M6.7 entry 10)

- `bc_check_id` → DROP (Bridgecrew-internal)
- `guideline` → DROP (external doc URL)
- `evaluations`, `caller_file_*`, `entity_tags`, `connected_node`,
  `definition_context_file_path` → DROP (tool internals)
- `code_block` 2-D `[[lineNum, codeText]]` array → flattened to
  source string via `flattenCodeBlock` helper

## Anonymization rules

For real-captured fixtures (synthesized targets at M6.7 contained no
PII, but real customer scans may):

1. **Resource names** → `example-resource` / `example-bucket` / etc.
2. **AWS account IDs** → `123456789012` (test placeholder)
3. **Bucket names** → `example-data-bucket`
4. **File paths** → `/main.tf` / `/deployment.yaml` (generic root)
5. **Guidelines** → keep verbatim (public Bridgecrew docs)
6. **`bc_check_id`** → keep verbatim (public Bridgecrew identifiers; parser drops anyway)

## Fixtures

| File | Findings | Coverage |
|---|---|---|
| `checkov_basic.json` | 1 | Single AWS terraform finding from real scan. Happy-path single-finding parse. |
| `checkov_multi.json` | 10 | Real scan output against synthetic-vulnerable terraform target (security-group + S3 misconfigs). All 10 have `severity: null` → mapped to `"medium"`; all CWE-1032. |
| `checkov_empty.json` | 0 | `failed_checks: []`. Happy-path-no-findings. |
| `checkov_kubernetes.json` | 2 | Synthesized k8s framework output (`check_type: "kubernetes"`). Different framework → same parser shape. Verifies framework-agnostic parsing. |

## Adding fixtures

When a new edge case surfaces in production:

1. If real Checkov scan: anonymize per rules 1-6 above. Strip
   `evaluations`, `caller_file_*`, `entity_tags` for readability;
   parser drops them anyway.
2. If synthesized: hand-craft minimal valid Checkov JSON; use
   existing fixtures as schema reference (real Checkov 3.2.340
   `-o json` output).
3. Add a row to the table above.
4. Add a test in `checkov_test.go`.
