# testdata/

Tool-output fixtures for parser tests. Pinned conventions so M6+ task
authors don't improvise.

## File naming

```
<tool>_<scenario>.<format>
```

Examples:
- `nuclei_basic.jsonl` — straightforward Nuclei run
- `nuclei_with_cwe.jsonl` — entries carrying CWE classification
- `semgrep_python_flask.json` — Semgrep run against a Flask sample
- `subfinder_example_com.txt` — newline-delimited subdomains

One fixture per scenario; **don't multiplex** ("nuclei output covering xss
+ sqli + open-redirect" hides which assertion fails). Format extension
matches the tool's actual output format (Nuclei → JSONL, Semgrep → JSON,
Subfinder → plain text, etc.).

## Anonymization rules

Every fixture sourced from a real tool run MUST be anonymized before
checked in:

| Element | Anonymize to |
|---|---|
| Target URLs | `example.com` variants — `app.example.com`, `subdomain.example.com`, etc. |
| IPs (IPv4) | IETF reserved per RFC 5737 — `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| IPs (IPv6) | RFC 3849 — `2001:db8::/32` |
| Email addresses | `*@example.com` |
| File paths | Generic patterns — `/app/*`, `/var/log/*`, `/home/user/*` |
| API tokens / secrets | Replace with `REDACTED_*` placeholders matching the original prefix shape |
| Hostnames | `host-N.example.com` |
| Real customer data | **Never include.** If you can't fully anonymize, regenerate the fixture against an anonymized target. |

## License attribution

- **Real tool output** → top-of-file comment with source citation OR
  sibling `.LICENSE` file for binary formats:
  ```
  # Source: nuclei v3.7.1 against https://app.example.com (anonymized fixture target)
  # Generated: 2026-05-01
  # License: tool output, no upstream copyright
  ```
- **Documentation-derived fixtures** (formats hand-authored from public
  schema docs) → cite the documentation URL.
- **Modified upstream samples** → cite original source + describe modifications.

## Adding a fixture

1. Generate from real tool against anonymized target (or build synthetically
   from public schema docs).
2. Apply anonymization rules above. Search for likely PII patterns:
   ```bash
   grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z|a-z]{2,}" testdata/<file>
   ```
3. Verify zero remaining PII; spot-check against any obvious internal
   markers (account IDs, customer names, etc.).
4. Place under `testdata/` (or sub-directory if grouping makes sense —
   e.g., `testdata/mobsf/` once M7.1 grows multiple MobSF fixtures).
5. Reference from tests via `os.ReadFile("testdata/<file>")` or `//go:embed`.
   Prefer `//go:embed` for fixtures referenced multiple times.

## What goes here vs in test code

- **`testdata/`** = inputs. Tool output blobs, sample mobile artifacts,
  saved HTTP responses.
- **Test code** = expected outputs. The `[]RawFinding` your parser should
  produce from the input.

Don't put expected outputs in `testdata/` — they're tied to test logic
and should live next to the assertions that consume them.
