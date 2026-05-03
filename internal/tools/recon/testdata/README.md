# Recon (Subfinder + httpx) testdata fixtures

JSONL fixtures for `internal/tools/recon` parser tests. Convention
inheritance: 5.1's `internal/events/testdata/README.md` + per-tool
README pattern from 6.1/6.5.

## Architectural distinction (per ADR-022)

These fixtures support **pre-scan helpers**, NOT ToolRunner-based
tools. Subfinder produces subdomain strings; httpx produces LiveHost
metadata. Neither produces `events.RawFinding`. Per ADR-022 (M6.3),
recon ships as helpers in `internal/tools/recon/`, not registered
with `worker.Registry`. M8 (Recon-First Pipeline) imports + invokes.

## Subfinder schema (v2.6.7 `-oJ`)

JSONL with one object per subdomain:

```
{"host":"api.example.com","input":"example.com","source":"crtsh"}
```

Parser extracts only `host` field → `[]string`. `input` and `source`
are operational diagnostics; dropped.

## httpx schema (v1.6.10 `-json -status-code -title -tech-detect -web-server`)

JSONL with one object per probed host. Rich metadata:

```
{"timestamp":"...","url":"https://api.example.com","title":"...",
 "scheme":"https","webserver":"nginx","content_type":"application/json",
 "tech":["Nginx","Node.js"],"status_code":200,"content_length":256,
 "failed":false, ...}
```

Parser extracts 6 fields → `LiveHost`:
- `url` → `URL`
- `status_code` → `StatusCode`
- `title` → `Title`
- `tech` → `Tech`
- `webserver` → `Webserver`
- `content_type` → `ContentType`

`failed: true` records are EXCLUDED from `LiveHost` slice (filtered
during parse). Other fields (host, port, path, method, time, a/aaaa,
cdn*, knowledgebase, resolvers, words/lines, content_length,
timestamp) are dropped per pre-prep field-map decisions.

## Anonymization rules

1. **Hostnames** → `*.example.com` variants (api/www/admin/staging/dev/test/old/vpn)
2. **IP addresses** → RFC 5737 (`192.0.2.x`)
3. **Timestamps** → deterministic (`2026-01-15T12:00:NN.000Z`)
4. **Tech stacks** → keep verbatim (publicly identifiable from any web request)
5. **Titles** → generic ("Example API", "Example Home", "403 Forbidden")
6. **Webserver headers** → keep generic values (nginx, cloudflare)

## Fixtures

| File | Records | Coverage |
|---|---|---|
| `subfinder_basic.jsonl` | 1 | Single subdomain. Happy-path single-finding parse. |
| `subfinder_multi.jsonl` | 8 | 8 subdomains across 3 sources (crtsh, anubis, shodan). Exercises multi-record parse + source diversity. |
| `subfinder_empty.jsonl` | 0 | Empty file. Happy-path-no-discovery. |
| `subfinder_malformed.jsonl` | 5 (3 valid + 2 invalid) | Synthetic. Bad JSONL line (line 3) + record missing required `host` field (line 4). Bad lines dropped per 6.1 Nuclei JSONL precedent. |
| `httpx_basic.jsonl` | 1 | Single live host with full metadata. Happy-path. |
| `httpx_multi.jsonl` | 5 (4 live + 1 failed) | Mixed status codes (200, 200, 403, 404) + 1 `failed: true` record (excluded from output). |
| `httpx_empty.jsonl` | 0 | Empty file. All targets failed (no live hosts). |
| `httpx_dead_host.jsonl` | 1 (failed) | `failed: true` only. Verifies excluded-from-output invariant. |

## Adding fixtures

When a new edge case surfaces in production:

1. If real recon scan: anonymize per rules 1-6 above.
2. If synthesized: hand-craft minimal valid JSONL; use existing
   fixtures as the schema reference (real Subfinder 2.6.7 / httpx
   1.6.10 output).
3. Add a row to the table above.
4. Add a test in `subfinder_test.go` / `httpx_test.go` /
   `recon_test.go`.
