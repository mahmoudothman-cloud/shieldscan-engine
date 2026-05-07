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

## 3. PYTHONWARNINGS=ignore Env for pipx-installed Python tool runners

**Promoted at Task 6.7** with 3 instances (M6.2 Semgrep, M6.4 SSLyze,
M6.7 Checkov). Every native-tool runner backed by a pipx-installed
Python CLI sets `Env: []string{"PYTHONWARNINGS=ignore"}` regardless of
whether warnings are currently observed.

### Shape

In the runner factory:

```go
return &tools.NativeRunner{
    ToolName:    "...",
    // ... other fields ...
    Env:         []string{"PYTHONWARNINGS=ignore"},
}
```

NativeRunner appends `Env` to inherited environment (per `cmd.Environ()`
in 5.2's `native.go`), so PATH/HOME/etc. survive. The
`PYTHONWARNINGS=ignore` setting suppresses Python `UserWarning` /
`DeprecationWarning` lines on stderr.

### Why defense-in-depth (not just observed-warning fix)

Semgrep 1.95.0 on Python 3.12 emits `pkg_resources is deprecated`
UserWarning at every invocation (verified at 6.2 pre-prep). SSLyze
6.1.0 + Checkov 3.2.340 emit no observed warnings — but Python's
deprecation cycle is continuous, and the `Env` setting is forward-
compat at zero ongoing cost. Future versions of any pipx-installed
tool may begin emitting deprecation noise; the pattern preempts the
cleanup work.

The cost-asymmetry mirrors the reasoning that justified ADR-023's
NativeRunner OutputFile mode at 1st instance: when the cost of NOT
applying a small abstraction (debugging mid-incident, triaging
operationally noisy stderr) exceeds the cost of applying it
preemptively (~3 lines per runner factory), preempt.

### Why not a global engine-wide PYTHONWARNINGS setting

NativeRunner's `Env` is per-runner; non-Python tools (Nuclei Go binary,
Gitleaks Go binary, Dep-Check JVM) don't need it. Per-runner Env keeps
the surface narrow.

### Instances

- `internal/tools/semgrep/semgrep.go` (M6.2; observed warning suppression)
- `internal/tools/sslyze/sslyze.go` (M6.4; defense-in-depth)
- `internal/tools/checkov/checkov.go` (M6.7; defense-in-depth)

### When to use

Every native-tool runner whose binary is a pipx-installed Python tool:
sslyze, semgrep, wapiti, checkov, mobsf-cli, etc.

### When NOT to use

- **Go binaries:** Nuclei, Gitleaks (no Python runtime).
- **JVM tools:** Dep-Check (Java warnings via different mechanism).
- **Native binaries:** subfinder, httpx (no language runtime warnings).

### Trigger to revisit

A future Python tool emits warnings via a channel that ignores
`PYTHONWARNINGS` (e.g., direct stderr writes from C extension). At
that point, evaluate whether to extend pattern (e.g., wrap subprocess
output stripping) or accept the noise.

Pattern promoted at M6.7 per project's third-instance threshold
convention (see preamble); cross-references to ADR-023 (asymmetric-
cost reasoning that justifies threshold-overrides for the ADR-023
case) and to engine DRIFT-LOG entries at M6.2, M6.4, M6.7 for the
per-instance context.

---

## 4. Constants-only field mapping for tools with uniform finding shape

**Promoted at Task 6.6** with 4 instances (M6.5 Gitleaks, M6.7 Checkov,
M6.6 Nikto, M6.6 CORStest). Tools whose findings have a uniform
severity/CWE classification class apply package-level constants
directly rather than wiring a per-finding mapping function.

### Shape

The runner package exports constants for the values it applies
universally:

```go
// internal/tools/<tool>/<tool>.go
const (
    SeverityCritical        = "critical"     // example from Gitleaks
    CWEHardcodedCredentials = "CWE-798"      // example from Gitleaks
)
```

The parser (`parse.go`) inlines these directly when populating
`RawFinding`:

```go
return events.RawFinding{
    // ... other fields from upstream data ...
    Severity: SeverityCritical,
    CWEID:    CWEHardcodedCredentials,
}
```

No `severity.go` mapping file. No `mapSeverity()` function. No table.

Constants are **exported** so M9 AI pipeline + downstream tooling
can reference canonical values without parsing strings.

### When to use

A tool's finding class is **uniform** along severity/CWE axes — every
finding has the same severity (because the tool's domain is
uniform-severity by construction) AND no per-rule CWE diversity
(or the tool emits no per-rule CWE field).

Examples (Pattern 4 instances):

- **Gitleaks** (M6.5): every finding is a hardcoded credential →
  critical / CWE-798. No per-rule severity emitted.
- **Checkov** (M6.7): OSS Checkov emits no per-check severity; all
  IaC misconfigs → medium / CWE-1032.
- **Nikto** (M6.6): every finding is informational web-server
  misconfig → low. Nikto XML has no per-finding severity.
- **CORStest** (M6.6): every finding is a CORS misconfiguration →
  medium / CWE-942. CORStest output has no severity field.

### When NOT to use (anti-instances)

Per-finding mapping is appropriate when:

- **Tool emits per-finding severity** (Nuclei identity, Semgrep
  ERROR/WARNING/INFO, Dep-Check Critical/High/Medium/Low) → use a
  `mapSeverity()` function in `severity.go`.
- **Domain-rules table needed** (SSLyze 15-rule per-FindingType
  table; Wapiti 5-level domain mapping) → use a domain-rules table
  in `severity.go` per the "Domain-rules severity mapping" pattern
  (track-only at 2 instances; not yet promoted).

The decision is empirical: read the tool's output schema. If
severity varies per finding, map it. If it doesn't, constants-only.

### Anti-pattern: scaffolded mapping function with no input variation

A `mapSeverity()` function that always returns the same value
regardless of input is **misleading scaffolding**. It suggests
variation that doesn't exist. Constants-only is the honest
representation.

### Tools using per-finding mapping (anti-instances list)

Five tools currently use per-finding severity mapping. Reading any
of these reveals the contrast with Pattern 4:

- `internal/tools/nuclei/severity.go` — identity-passthrough (5-level)
- `internal/tools/semgrep/severity.go` — 3-level → 5-level mapping
- `internal/tools/depcheck/severity.go` — 5-level case-insensitive
  identity (with Moderate alias)
- `internal/tools/sslyze/severity.go` — 15-rule domain-rules table
  (different pattern; track-only)
- `internal/tools/wapiti/severity.go` — 5-level integer → canonical
  (different pattern; track-only)

### Trigger to revisit

A tool currently using constants-only adds per-finding severity in a
future version. At that point, replace the constants with a
`mapSeverity()` function in `severity.go`. The pattern's "When to
use" criteria become empirically false; refactor.

### Cross-pattern cross-reference

This pattern's promotion at 4 instances (one over the standard
3-instance threshold) reflects the unambiguous criteria for
applicability. By contrast, ADR-023 (NativeRunner OutputFile mode)
overrode the threshold at 1 instance via asymmetric-cost reasoning
because the alternatives were race-prone. Different cost asymmetries
yield different threshold applications; the underlying principle is
"pattern velocity should match decision-cost asymmetry," not "promote
at exactly 3 every time."

Pattern promoted at M6.6; cross-references explicit instances at
6.5 / 6.7 / 6.6 above + anti-instances list above.

---

## 5. Cleanup uses detached context

**Promoted at Task 7.2 with 3 instances.** 3rd-instance threshold met per ADR-026 §Triggers-to-revisit #3.

When `defer cleanup` runs after the parent context is cancelled
(timeout, shutdown, error propagation), using parent context for
cleanup makes cleanup fail-fast against an already-cancelled context.
The fix is a **detached context** for cleanup work.

### Shape

```go
// ANTI-PATTERN — DO NOT USE
func Run(ctx context.Context, ...) error {
    runCtx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    resource, err := acquire(runCtx)
    if err != nil { return err }
    defer release(runCtx, resource)  // ← BUG: runCtx is cancelled by the time this runs

    return doWork(runCtx, resource)
}
```

```go
// CORRECT — Option (a): in-scope cleanup with values preserved
defer func() {
    cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
    defer cancel()
    if err := release(cleanupCtx, resource); err != nil {
        log.Warn().Err(err).Msg("release failed")
    }
}()
```

```go
// CORRECT — Option (b): full lifecycle separation; suitable for shutdown paths
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
for _, resource := range resources {
    if err := resource.Shutdown(shutdownCtx); err != nil {
        log.Error().Err(err).Msg("resource shutdown failed")
    }
}
```

### Why

If `doWork` hits its timeout or returns error, `runCtx` is cancelled.
The deferred `release(runCtx, resource)` then runs against a cancelled
context — release fails fast; cleanup hook never executes; resource
lingers in stale state OR returns error that may mask the original
error. Resource leaks under load (load test that triggers context
cancellation cascades into resource exhaustion via leaked containers
/ files / connections).

The fix uses a detached cleanup context — either
`context.WithoutCancel(parent) + timeout` (preserves values like
logger context, trace IDs) or `context.Background() + timeout`
(full lifecycle separation when parent context has already cancelled
and value inheritance is unnecessary).

### Instances

| Instance | Location | Pattern Used |
|---|---|---|
| 1 (M6.7) | Wapiti file-output cleanup at `internal/tools/wapiti/` | Option (a) — first instance; established the detached-cleanup intuition |
| 2 (Task 7.5a) | DockerRunner.Run defer Pool.Return at `internal/tools/docker/dockerrunner.go` | Option (a) — `context.WithoutCancel(ctx)` + 30s timeout; preserves logger context; ADR-026 §Forcing functions documents this |
| 3 (Task 7.2) | Worker drain pool shutdown at `cmd/worker/run.go` | Option (b) — `context.Background()` + 30s grace; lifecycle boundary; parent worker ctx already cancelled |

### When to use

Apply this pattern whenever:

1. A `defer` cleanup function runs after parent context is cancelled
2. The cleanup hook needs to execute work (network calls, container
   shutdown, file writes) requiring a non-cancelled context
3. Cleanup correctness is load-bearing for resource integrity
   (not just best-effort logging)

Choice between options:

- **Option (a) `context.WithoutCancel(parent)`**: cleanup happens
  within Run/Process/Handler scope; want to inherit logger/trace/
  tenant context; cleanup is logically part of same operation
- **Option (b) `context.Background()`**: cleanup happens at lifecycle
  boundaries (shutdown, drain, restart); parent context has already
  cancelled; cleanup is independent of primary operation's scope

Pattern does NOT apply when cleanup is purely synchronous in-process
state mutation (closing a `chan` doesn't need ctx); cleanup is
best-effort logging that can fail-fast safely; parent context is
guaranteed live at defer execution.

### Anti-patterns this prevents

- **Decrement-without-cleanup:** parent-cancelled cleanup may
  decrement resource counts without actually releasing resources,
  leaking resource handles.
- **Silent partial failure:** failing cleanup masked by primary-
  context cancellation; engineer reads failed scan job + sees
  "context cancelled" without realizing cleanup hook never ran.
- **Resource leak under load:** load test that triggers context
  cancellation (timeouts, deadlines) cascades into resource
  exhaustion via leaked containers/files/connections.

### Trigger to revisit

- **4th instance lands** → pattern is well-established; further
  instances confirm rather than evolve it.
- **Cleanup-contract semantics shift** → if a future architectural
  decision requires cleanup hooks to receive parent-context
  cancellation as signal (e.g., "abort cleanup if scan is
  force-killed"), this pattern needs reconciliation.
- **`context.WithoutCancel` deprecation** → Go 1.21+ added the
  function; if Go ecosystem deprecates it, migration to
  `context.Background()` everywhere becomes the canonical choice.

### Cross-references

- ADR-021 (Context discipline; foundational ctx propagation).
- ADR-026 §Forcing functions (DockerRunner.Run usage of
  `context.WithoutCancel`).
- ADR-026 §Triggers-to-revisit #3 (3rd-instance threshold trigger
  that promoted this pattern).
- Task 7.2 commit `872b2b0` (3rd instance landed in
  `cmd/worker/run.go` drain path).
- Task 7.5a commit `f5d77c8` (2nd instance in
  `internal/tools/docker/dockerrunner.go`).
- shieldscan-docs commit `aa0d034` §10 (Task 7.2 design doc
  post-implementation acknowledgment).

---

*Last updated: 2026-05-06 at Task 7.2 Phase 5.C.*
