# job_dispatch_python_v1.json

**Reference fixture for SPECIFICATION.md §7.1 queue payload.**

This file holds the canonical wire-format example for what the Python
`shieldscan-api` `ScanQueue.dispatch` (`shieldscan-api/src/app/services/scan_queue.py`)
serializes into the `shieldscan:queue:{priority}` Redis lists at job
dispatch time.

The Go consumer (`shieldscan-engine/internal/redis/JobConsumer.Pop`)
deserializes against `events.JobDispatch`. The cross-repo compatibility
test `TestJobConsumer_MatchesPythonWireFormat` LPUSHes this exact
payload and asserts every field deserializes correctly.

## Cross-repo contract

When this fixture changes:
1. **Python emit code** (`scan_queue.py`) must produce the new shape.
2. **Go consumer struct** (`internal/events/events.go::JobDispatch`)
   must deserialize the new shape — `DisallowUnknownFields` is enabled,
   so any new top-level field requires a struct addition.
3. **This fixture file** is updated to reflect the new shape.
4. **Both repos commit in lockstep** (Python first if backward-
   compatible additive change; reverse if breaking).

## Versioning

The `_v1` suffix marks the schema version. If a future migration
introduces a breaking change, ship `job_dispatch_python_v2.json`
alongside v1 (deprecate v1 only after Python emit is fully migrated).

## Notable fields

- `mobile_config` is `null` here (web scan). Mobile scans populate
  it with `{upload_ref, platform, analysis_type}` per SPEC §7.1.
- `auth` is optional but populated when authenticated scan.
- `config` is open-ended (`map[string]any` Go-side); tool-specific
  fields like `template_categories` (Nuclei) are passed through.
- `callback_channel` is a forward-pin Python sets to the per-scan
  progress stream key — currently unused by Go side; Go derives the
  key from `scan_id` directly.

## Provenance

Captured 2026-05-01 from SPECIFICATION.md §7.1 example. No real
customer data; targets use `example.com` per testdata anonymization
conventions (`testdata/README.md`).
