# job_completed_python_v1.json

**Reference fixture for SPECIFICATION.md §7.3 completion event payload (post-ADR-017).**

This file holds the canonical wire-format example for what the Go
worker (`shieldscan-engine/internal/redis/CompletionsPublisher.Publish`)
serializes into the `shieldscan:completions` Redis Pub/Sub channel
when a job finishes.

The Python consumer (`shieldscan-api/src/app/services/completions_consumer.py`)
deserializes via Pydantic into the M4-shipped `JobCompletedEvent`
schema (which 5.5 will extend per ADR-017 to handle `findings` +
`event_seq` fields landed in this fixture).

## Cross-repo contract

When this fixture changes:
1. **Go emit code** (`internal/events/events.go::JobCompletedEvent`)
   must produce the new shape.
2. **Python consumer Pydantic model** must accept the new shape.
3. **This fixture file** is updated.
4. **Both repos commit in lockstep**.

## Sequencing semantics (ADR-017)

This fixture demonstrates the **single-event** case: `event_seq.total
== 1`, all findings inline, status=`completed`.

For multi-event sequences (>1000 findings):
- Intermediate batches use `event_type: "partial_findings"`,
  `status: "partial_findings"`, omit `finding_count` and
  `duration_ms` (those are authoritative only on the terminal event).
- Terminal batch carries the canonical `status` (`completed` or
  `partial`), `finding_count` covering all batches, `duration_ms`.
- `event_seq.{index, total}` populated on every event in the
  sequence so consumers can detect gaps or re-ordering.

A future fixture `job_completed_sequenced_python_v1.json` may capture
a 3-event sequenced example when M5.5 + Python consumer extension
land. For 5.4 the single-event case is the contract pin.

## Notable fields

- `findings[]` is the inline array (ADR-017). Each element matches
  `events.RawFinding` Go-side / `RawFinding` Python-side. Empty
  optional fields are `omitempty`-stripped on emit.
- `fingerprint` values are placeholder hashes (deadbeef/feedface);
  real fingerprints are SHA-256 hex of pipe-separated finding fields
  per `tools.ComputeFingerprint`.
- `idempotency_key` matches the queued `job_dispatch_python_v1`
  example, demonstrating cross-event correlation.

## Provenance

Captured 2026-05-01 from SPECIFICATION.md §7.3 example (post-ADR-017
patch landed in commit `95d04fe`). Anonymized per
`testdata/README.md` conventions.
