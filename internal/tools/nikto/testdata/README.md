# Nikto testdata fixtures

XML fixtures for `internal/tools/nikto` parser tests. **First XML
parser shape in M6** (4th format after JSONL + single-doc JSON +
JSON-array).

## Schema (Nikto 2.1.5+ `-Format xml`)

Stable across Nikto 2.x. Top-level structure:

```xml
<?xml version="1.0" ?>
<!DOCTYPE niktoscan SYSTEM "/usr/share/doc/nikto/nikto.dtd">
<niktoscan version="2.1.5" scanstart="..." scanend="...">
  <scandetails targetip="..." targethostname="..." targetport="..." sitename="..." ...>
    <item id="999976" osvdbid="0" osvdblink="..." method="GET">
      <description><![CDATA[...]]></description>
      <uri><![CDATA[/]]></uri>
      <namelink><![CDATA[...]]></namelink>
      <iplink><![CDATA[...]]></iplink>
    </item>
    ...
    <statistics elapsed="..." itemsfound="..." itemstested="..." endtime="..." />
  </scandetails>
</niktoscan>
```

Multi-host scans produce multiple `<scandetails>` elements; M6.6
invokes per-target (per Option X precedent from 6.4) so typically
one element per scan. Parser iterates defensively for forward-compat.

## Anonymization rules applied

1. **Hostnames** → `*.example.com` variants
2. **IPs** → RFC 5737 (`192.0.2.x`)
3. **`<item>` osvdbid + osvdblink** → keep `"0"` placeholder (real Nikto rarely populates these meaningfully; OSVDB defunct since 2016)
4. **Description CDATA** → keep verbatim (Nikto rule descriptions are public)
5. **Timestamps** → deterministic (`2026-01-15 12:00:00`)

## Reductions documented in DRIFT-LOG (M6.6 entry 12)

- `osvdbid` + `osvdblink` → DROP (OSVDB defunct since 2016; references stale)
- `namelink` + `iplink` → DROP (redundant with `uri` + scan target)

## Constants applied (Pattern 4)

Every Nikto finding gets:
- `Severity = nikto.SeverityLow` (`"low"`)
- `CWEID = ""` (Nikto has no per-finding CWE; rejected as constants candidate per finding-class diversity — Nikto findings span info-disclosure, missing-headers, dangerous-files)

## Fixtures

| File | Findings | Coverage |
|---|---|---|
| `nikto_basic.xml` | 1 | Single missing-header finding. Happy-path single-finding parse. |
| `nikto_multi.xml` | 5 | Real-anonymized scan output: missing-headers, uncommon banner, X-Content-Type-Options, allowed methods, admin section discovered. |
| `nikto_empty.xml` | 0 | Clean scan, no `<item>` elements (only `<statistics>`). |
| `nikto_missing_fields.xml` | 2 valid + 2 invalid | Synthetic. Records lacking `id` or with empty `description` are skipped; valid records flow. Net: 2 findings. |

## Adding fixtures

1. If real Nikto run: anonymize per rules 1-5 above. Strip
   `<statistics>` if not relevant to the test.
2. If synthesized: hand-craft minimal valid Nikto XML.
3. Add a row to the table above.
4. Add a test in `nikto_test.go`.
