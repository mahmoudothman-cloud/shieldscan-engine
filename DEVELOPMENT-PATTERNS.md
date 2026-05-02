# shieldscan-engine — Development Patterns

This document captures recurring patterns in the engine codebase that
have appeared in 3+ instances and earned formal documentation per the
project's "third-instance promotion" discipline.

The API repo has its own `DEVELOPMENT-PATTERNS.md` in `shieldscan-docs/`
covering Python-specific patterns (`select_fresh`, `session_factory`
DI for long-lived background tasks, API-key audit attribution). This
file is the engine-side counterpart per the Q3 two-repo docs split
decision (Task 5.1).

---

## When to add a pattern here

**Three-instance threshold.** A pattern earns documentation when 3 or
more independent instances apply it. Promotion prevents premature
abstraction (single use ≠ pattern) while ensuring established patterns
are visible to future contributors.

For instances < 3, document in DRIFT-LOG with cross-references; the
pattern earns promotion organically when the third instance lands.

---

## 1. Trigger-based deferral

**Promoted at Task 5.5 with 8+ cited instances.** Deferrals without
triggers become permanent. Deferrals with triggers stay actionable.

### The pattern

When deferring a decision or migration to "later," specify the
**explicit conditions that should reactivate the decision** rather
than vague time references.

| Bad | Good |
|---|---|
| "We'll add R2 staging later" | "We'll add R2 staging when sustained `job_completed` payloads exceed 5MB OR Pub/Sub message size approaches 16MB sustained OR M9 ingest-time problems with batches >5000 findings" |
| "Defer to OPS milestone" | "Defer to OPS milestone — trigger: 5+ tools using the same cleanup pattern, OR sustained operational pain from missing cleanup" |
| "Maybe revisit if needed" | "Revisit when concurrency climbs to 50+ jobs simultaneously OR Redis Pub/Sub connection limits hit in production" |

### The principle

Future engineers reading "deferred to M6.3" don't know if the trigger
fired or not — they have to re-derive whether the deferral is still
valid. Future engineers reading "trigger: any M6+ tool with meaningful
intermediate state" can check current code and make an informed
decision.

The trigger language also works as a forcing function on the deciding
engineer: writing "trigger conditions are X and Y" forces clarity
about *why* we're deferring vs deciding now. If you can't articulate
the trigger, the deferral might be premature ("solve when needed"
without "needed = ?").

### How to apply

When you find yourself writing "later" or "deferred," ask:
- **What signal would make this actionable?** (Production metric,
  threshold, count, occurrence type, operational pain shape.)
- **Who would notice the signal?** (Observability surface,
  ops-runbook entry, code-review checklist, etc.)
- **What's the action when triggered?** (Specific task or PR shape,
  not "consider migration.")

If you can answer all three, write them into the deferral. If you
can't, the deferral might not be the right move.

### Cited instances (8+ in M4-M5)

Browse these for examples of the pattern in practice:

- **ADR-014** (M4 Task 4.1, `shieldscan-docs/SPECIFICATION.md` §13):
  Hybrid Streams+PubSub trigger — defer until sustained-load profiling
  shows fan-out is hot.
- **ADR-016** (Task 5.1, SPECIFICATION §13): Asynq scheduled-scan
  trigger — revisit if/when scheduled-scan use case lands and
  cron-equivalent build cost exceeds Asynq adoption cost.
- **ADR-017** (Task 5.1, SPECIFICATION §13): R2 staging triggers — 4
  conditions including "any production occurrence of mid-sequence
  crash" (the "once is the trigger, not sustained" framing).
- **ADR-021** (Task 5.1, SPECIFICATION §13): errgroup adoption trigger
  — defer to M8 if recon parallel-tool fan-out shows error-collection
  complexity that errgroup solves cleanly.
- **5.2 H.4** (`shieldscan-engine/DRIFT-LOG.md` Task 5.2 entry):
  ProgressEmitter trigger — defer until M6+ tool produces meaningful
  intermediate state worth surfacing to customer.
- **5.3 H.5** (DRIFT-LOG Task 5.3 entry): per-tool retry trigger —
  retry deferred to per-tool Execute closures based on idempotency
  profile.
- **5.4 H.6** (DRIFT-LOG Task 5.4 entry): Pub/Sub auto-reconnect
  trigger — surface disconnect via channel close; orchestration
  decides recovery.
- **Checkpoint 2 H.1** (`shieldscan-docs/DRIFT-LOG.md`): SSE DB-session
  trigger — 15+ concurrent SSE connections per uvicorn worker OR new
  long-lived streaming endpoint.

The list will grow. When the third-instance threshold is met for a
new pattern, add it as section 2, etc.

---

## 2. Env-var-binary resolution for native tools

**Promoted at Task 6.5** with 3 instances (M6.1 Nuclei, M6.2 Semgrep,
M6.5 Gitleaks). Every M6+ native-tool runner that resolves a binary
path follows this pattern.

### The pattern

Each native-tool runner config takes a `BinaryPath` resolved at
startup as:

1. **Env var first:** `os.Getenv("SHIELDSCAN_<TOOL_UPPER>_BINARY")`.
2. **`exec.LookPath` fallback:** `exec.LookPath("<tool>")`.
3. **Fail-fast** at startup Phase 1 if both empty (no usable path).

The `Config` struct in each tool package exposes `BinaryPath` as a
single string field; resolution happens in `cmd/worker/run.go` (at
M6.8 wiring), not inside the tool package — keeps tool packages
testable without env-var mutation.

### Why

Operators install tools via different mechanisms:

| Mechanism | Typical path |
|---|---|
| `go install …@version` | `~/go/bin/<tool>` |
| `pipx install <tool>==<version>` | `~/.local/bin/<tool>` |
| `apt install <tool>` | `/usr/bin/<tool>` |
| OPS `provision-worker.sh` symlink | `/usr/local/bin/<tool>` |

Hardcoding any one path breaks the others. Env-var override +
LookPath fallback handles every realistic case.

**Fail-fast diagnostic at Phase 1 startup:** the worker emits a
specific message naming both override paths so the operator can
pick whichever is operationally cleaner. Example:

```
gitleaks binary not found; set SHIELDSCAN_GITLEAKS_BINARY env var
or ensure gitleaks is on $PATH
```

The message names *both* override paths so operators don't have to
guess which is preferred. Phase 1 wiring lands at M6.8 (per M6.5
watch item E — 6.5 ships only the resolution interface).

### Instances

- **`SHIELDSCAN_NUCLEI_BINARY`** (M6.1 Nuclei,
  `internal/tools/nuclei/nuclei.go`)
- **`SHIELDSCAN_SEMGREP_BINARY`** (M6.2 Semgrep,
  `internal/tools/semgrep/semgrep.go`)
- **`SHIELDSCAN_GITLEAKS_BINARY`** (M6.5 Gitleaks,
  `internal/tools/gitleaks/gitleaks.go`)

### When to use

Every native-tool runner that takes `BinaryPath` in its `Config`
struct — i.e., every M6 task by the time the wiring lands at 6.8.
M7 Docker-service runners use a different shape (HTTP endpoints, not
binaries) and are out of scope for this pattern.

### Trigger to revisit

A native tool with a fundamentally different launch mechanism
(e.g., Java jar via `java -jar <path>`, or a wrapped Python module
via `python -m <module>`). At that point, the pattern likely
extends to a launcher abstraction rather than fragmenting per-tool.

Pattern promoted at M6.5 per project's third-instance threshold
convention (see preamble); cross-referenced explicitly to M6.1,
M6.2, M6.5 instances above.

---

*Last updated: 2026-05-02 at Task 6.5.*
