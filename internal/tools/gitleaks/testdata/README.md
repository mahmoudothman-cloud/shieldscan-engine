# Gitleaks testdata fixtures

JSON-array fixtures for `internal/tools/gitleaks` parser tests.
Convention inheritance: 5.1's `internal/events/testdata/README.md`
+ 6.1's `nuclei/testdata/README.md` + 6.2's `semgrep/testdata/README.md`.

## Schema (Gitleaks 8.21.2 `--report-format=json`)

**JSON array of finding objects** (third format observed in M6,
after Nuclei JSONL + Semgrep single-doc):

```json
[
  { /* finding 1 */ },
  { /* finding 2 */ }
]
```

Per-finding fields (from `gitleaks detect --source ... --report-format=json`):

| Field | Type | Notes |
|---|---|---|
| `RuleID` | string | rule id, e.g., `"aws-access-token"` |
| `Description` | string | rule description |
| `File` | string | file path |
| `StartLine` / `EndLine` | int | line range |
| `StartColumn` / `EndColumn` | int | column range (DROPPED at M6.5 — RawFinding has no column) |
| `Match` | string | matched substring (truncated to 2 KiB on RawFinding.CodeSnippet) |
| `Secret` | string | redactable secret (DROPPED — duplicates Match) |
| `Commit` | string | full SHA (only in `git` mode; folded into Description if all of Commit+Author+Date present) |
| `Author` | string | from `git log` (only in `git` mode; folded as above) |
| `Email` | string | from `git log` (DROPPED — Author covers attribution) |
| `Date` | string | RFC3339 timestamp (only in `git` mode; trimmed to YYYY-MM-DD in fold) |
| `Message` | string | commit message (DROPPED — too noisy for Description) |
| `Entropy` | float64 | Shannon entropy (DROPPED — diagnostic, not actionable) |
| `Tags` | []string | rule tags (DROPPED — tool-specific) |
| `SymlinkFile` | string | (DROPPED) |
| `Fingerprint` | string | Gitleaks's own dedup id (DROPPED — we compute via tools.ComputeFingerprint) |

**5 reductions applied** (commit-metadata folded, entropy dropped,
columns dropped, endline dropped, tags dropped). Tracked in engine
DRIFT-LOG M6.5 entries 4 + 9 (counter for SPEC §7.3 schema-extension
trigger: 2 of 3+ tools have reductions).

## Anonymization rules applied

1. **Match + Secret** → `"[REDACTED]"` (real fixtures captured against
   synthetic-bait targets; redacted regardless to avoid any ambiguity).
2. **File paths** → `"repo/..."` (generic synthetic root).
3. **Author** → `"Anonymous Developer"`.
4. **Email** → `"developer@example.com"`.
5. **Commit SHA** → deterministic placeholder `a1b2c3d4e5f6...`
   (length preserved).
6. **Date** → `"2026-01-15T12:00:00Z"` (deterministic).
7. **Message** → `"anonymized commit message"`.
8. **Fingerprint** → rebuilt from anonymized File + RuleID + StartLine
   for internal consistency; the parser drops this field anyway.

## Fixtures

| File | Records | Coverage |
|---|---|---|
| `gitleaks_basic.json` | 1 | Single private-key finding from real-anonymized scan. Happy-path single-finding parse. |
| `gitleaks_multi.json` | 6 | Mix of rules: `private-key`, `slack-webhook-url`, `aws-access-token`, `github-pat`, `stripe-access-token`, `generic-api-key`. Two real-anonymized + four synthesized. **All have full commit metadata** (`git` mode). Exercises commit-fold + multi-rule diversity. |
| `gitleaks_empty.json` | 0 | Bare `[]`. Happy-path-no-findings. |
| `gitleaks_missing_fields.json` | 4 (2 valid + 2 invalid) | Synthetic. Records lacking `RuleID` or `File` are skipped with WARN; valid records flow. |

## Adding fixtures

When a new edge case surfaces in production:

1. If from a real Gitleaks run: anonymize per rules 1-8 above.
2. If synthesized: hand-craft minimal valid Gitleaks JSON; use existing
   fixtures as the schema reference (real Gitleaks 8.21.2 `--json`
   output).
3. Add a row to the table above.
4. Add a test in `gitleaks_test.go` that loads + asserts behavior.
