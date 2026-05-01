# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

### 2026-05-01 — Task 6.1: Nuclei native runner

**Files shipped:** `internal/tools/nuclei/nuclei.go` (factory + BuildArgs closure) · `internal/tools/nuclei/parse.go` (lenient JSONL parser + extraction helpers) · `internal/tools/nuclei/severity.go` (severity map) · `internal/tools/nuclei/nuclei_test.go` (17 tests with goleak TestMain) · 4 testdata fixtures (`nuclei_ssl_multi.jsonl` real-anonymized, `nuclei_xss_basic.jsonl` synthesized, `nuclei_empty.jsonl` empty, `nuclei_malformed_line.jsonl`) + testdata README.

**17 tests at 6.1 close** (vs 16 estimate; +1 from H.3 tool-failure test). Engine total: **152 tests** across 9 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Plan §6.1 thinness divergence.** Plan literal §6.1 (lines 1776-1801) is 1 test, parser-only — it predates M5 and assumes a flat `parseNucleiOutput([]byte)` signature with no construction surface. M5's `NativeRunner` inverts the contract (closure-injected behavior into a generic runner). 6.1 honors the spirit (parse Nuclei output → []RawFinding) but expands scope to match canonical-first-tool weight: 1 test → 17 tests, ~25 LoC test → ~280 LoC test + ~340 LoC src across 3 source files.

**6.1 does NOT register the runner.** `cmd/worker/run.go` registry population is deferred to 6.8 wiring task per landscape Finding 1. The empty-registry WARN at startup (5.6) continues to fire after 6.1 lands; this is acceptable and clears at 6.8. Brief reference here; full plan-staleness DRIFT entry at 6.8.

**ADR-022 candidacy: recon-as-pre-scan-helpers.** Per landscape Finding 2, recon tools (Subfinder, httpx) don't fit ToolRunner because they produce subdomain strings / LiveHosts not RawFindings. Resolution lean: ship parsers + RunRecon helper at 6.3, but don't register with worker.Registry; M8 invokes recon as pre-scan phase. Brief reference here; full DRIFT entry + ADR-022 draft at 6.3 commit time.

### 2026-05-01 — Task 6.1: tool-output lenient decode pattern (load-bearing asymmetry)

**Pin.** Tool-output parsing (`internal/tools/<tool>/parse.go`) decodes lenient `map[string]any` and extracts via type-asserted helpers (`extractString`, `extractStringSlice`, `extractFloat`, `extractMap`). This is **asymmetric** with wire-format strictness in `internal/events/`, which uses `DisallowUnknownFields` and rejects malformed payloads.

**Why the asymmetry.** Tools evolve their JSON shapes between minor releases (Nuclei v3.6 → v3.7 added fields; v3.8 will likely add more). Strict decode would break parsing on every Nuclei update. Wire format is a cross-repo contract — strictness there forces version-pin discipline. Tool output is an upstream artifact — leniency there keeps parsers stable across upstream churn.

**Per-line resilience.** Malformed JSONL lines are dropped with WARN (not fatal). A subprocess killed mid-write or a stray banner leaking into stdout shouldn't poison the whole batch. Fixture `nuclei_malformed_line.jsonl` exercises this (4 valid + 1 garbage line → 4 findings + 1 logged warning).

**Trigger to revisit (promote helpers to shared package).** Three-instance threshold: 6.1 inlines helpers in `internal/tools/nuclei/parse.go`. 6.2 (Semgrep) and 6.4 (SSLyze) likely need same shape; promote to `internal/tools/jsonx/` at the third instance. Don't pre-extract.

### 2026-05-01 — Task 6.1: bufio.Scanner MaxScanTokenSize set to 1 MiB

**Pin.** `parseOutput` allocates `bufio.Scanner` with explicit 1 MiB buffer cap (`maxScanLineBytes = 1 * 1024 * 1024`).

**Why not the default 64 KiB.** Nuclei JSONL records embed full HTTP request + response when a finding matches. Request payloads can be a few KiB; response payloads (full HTML body) can be tens of KiB. Default 64 KiB is regularly insufficient — observed on the SSL fixture's larger records (~3-4 KiB) and easily exceeded on real DAST findings.

**Lines exceeding 1 MiB are dropped with WARN** (`bufio.ErrTooLong` path). Same fail-soft posture as malformed-line handling — the runner returns successfully-parsed findings, doesn't poison the batch.

**Trigger to revisit.** Customer report of "finding visible in `nuclei` stdout but not in our DB" → check warning logs for too-long drops; if present, switch from `bufio.Scanner` to streaming `json.Decoder` over `io.Reader` (no per-line buffer cap, but more code to manage).

### 2026-05-01 — Task 6.1: severity mapping table (Nuclei → canonical)

**Pin.** `mapSeverity()` is identity for all five Nuclei-emitted levels (info, low, medium, high, critical). Empty / unknown / unrecognized inputs default to `"info"` (defensive minimum) rather than dropping the finding.

| Nuclei `info.severity` | RawFinding `Severity` |
|---|---|
| `info` | `info` |
| `low` | `low` |
| `medium` | `medium` |
| `high` | `high` |
| `critical` | `critical` |
| (empty / unknown) | `info` |

**Why pin an identity table.** Code review without it leaves "is severity validated?" ambiguous. The table-as-DRIFT-entry creates the audit trail. Other M6 tools (Semgrep at 6.2 emits `ERROR/WARNING/INFO`; SSLyze at 6.4 has its own scheme) will need genuine non-identity tables and document them in their per-task DRIFT entries.

**Case-insensitive.** `mapSeverity("HIGH")` == `"high"`. Defense in depth; Nuclei is consistent about lowercase, but case-folding costs nothing.

### 2026-05-01 — Task 6.1: CWE extraction path (first-only convention)

**Pin.** CWE extracted from `info.classification.cwe-id[0]` — first element only. If the array is absent or empty, `RawFinding.CWEID = ""`.

**Why first-only.** Nuclei's classification.cwe-id is conventionally a single-element array. Multi-CWE templates exist but are rare; selecting [0] handles the majority case without forcing a "primary CWE" decision into the parser. If a finding genuinely needs multiple CWEs surfaced, it's a SPEC schema extension (CWEs as `[]string`) — not a parser concern.

**SSL templates ship without classification.** `nuclei_ssl_multi.jsonl` fixture has 11 findings, zero have `info.classification`. CWEID is empty for all of them; pinned by `TestParseOutput_NoClassification`.

**CVE id has no dedicated RawFinding field.** SPEC §7's RawFinding schema (events.go:111+) defines CWEID, OWASP, CVSSScore but not CVEID. M6.1 folds the CVE id into Description (`"original description (CVE-2024-1234)"`) so the semantic is preserved without losing data. **Reversible:** if SPEC schema gains a CVEID field, the fold is a one-line removal.

### 2026-05-01 — Task 6.1: Plan §6.1 + SPEC §3.3 surgical patches ("Nuclei SDK" → "Nuclei CLI")

**Pin.** Two one-word doc patches landed at 6.1 docs commit:
- `shieldscan-docs/SPECIFICATION.md:45` — "Nuclei SDK" → "Nuclei CLI"
- `shieldscan-docs/IMPLEMENTATION-PLAN.md:9` — "Nuclei SDK" → "Nuclei CLI"

**Why.** Engine never integrated a Nuclei Go SDK. From M5 design through M6.1 implementation, Nuclei is invoked as a subprocess via `tools.NativeRunner` (5.2 chassis). The doc references to "Nuclei SDK" were stale from an early architecture sketch. M6.1 is the canonical-first-tool task; correcting the references at this point keeps future readers from chasing a non-existent integration.

**No other prose changes.** Surgical: just "SDK" → "CLI" in the two locations. Other Nuclei references in SPEC (e.g., line 230 tree diagram showing `nuclei.go`, line 731 example payload `"engine": "nuclei"`) are correct as-is.

### 2026-05-01 — Task 6.1: Registry redefinition reference (full entry at 6.8)

**Pin (brief).** Plan §6.8 currently says "Create `internal/tools/registry.go`" — but `internal/worker/registry.go` already exists at 5.5 (frozen-at-construction Registry shipped as part of the worker chassis). Per landscape Finding 1, plan §6.8 becomes the *wiring* task: invoking each M6 task's `NewXRunner` factory in `cmd/worker/run.go` and constructing `worker.NewRegistry(map[string]tools.ToolRunner{...})` from the results.

**Full plan-staleness DRIFT entry lands at 6.8** when the wiring is implemented and the redefinition is fully resolved. This entry is the brief reference for searchability.

---

### 2026-05-01 — Task 5.6: worker startup + heartbeat + main.go integration

**Files shipped:** `internal/worker/heartbeat.go` + test (5 tests) · `internal/worker/startup.go` + test (6 tests) · `cmd/worker/main.go` (refactored — Phase 0 ping + signal handling) · `cmd/worker/run.go` (NEW — `runMain(ctx, deps)` extraction per H.12) + test (6 tests) · `deploy/docker-compose.services.yml` + `deploy/docker_compose_test.go` (5 tests) · `internal/worker/processor.go` extension (`NewProcessorFromRedis` convenience constructor) · `internal/config/config.go` extension (`DrainGraceSeconds` field) + test.

**25 net-new tests at 5.6 close** (vs planned 17 — extras: NonExecutableBinaryWarns, NativeBinaryFoundLogsSuccess, RawDoesNotContainSecrets, ShortUUID_Distinct, GenerateWorkerID_Format, DrainGraceDefault). Engine total: **135 tests** across 8 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues. Worker binary builds cleanly.

**Worker-lifetime services pattern: 2 instances now (Worker, Heartbeat)**, not yet promoted to DEVELOPMENT-PATTERNS.md per user's H.4 nuance. ADR-021 Rule 3 carve-out covers the pattern; explicit DEVELOPMENT-PATTERNS.md entry awaits a third instance (potential candidates: M6+ metrics emitter, M7.5 warm pool manager, idempotency-cleanup service).

**Force-cancel grace period via select on runDone vs time.After.** Default 60s via `SHIELDSCAN_DRAIN_GRACE_SECONDS` env var (per H.9). Pattern: SIGTERM → workerCtx cancels → main observes → race Worker.Run completion vs grace timer; `os.Exit(2)` if timer wins.

**No forcing-function self-catch on this task specifically.** The 5.5 discrimination semantics retrospective was the M5 highlight; 5.6 is integration-heavy and the patterns are established.

### 2026-05-01 — Task 5.6: Heartbeat as worker-lifetime service

**Pin.** `internal/worker.Heartbeat` is a standalone type implementing the ADR-021 Rule 3 worker-lifetime services carve-out. Receives `workerRootCtx` from `main()` (via `runMain(ctx, deps)`); never constructs `context.Background()` itself.

**Two ctx-aware exit paths** in `Run` loop: `<-ctx.Done()` returns `ctx.Err()`; `<-ticker.C` with write-failure logs at WARN and continues. goleak in `cmd/worker/run_test.go` TestMain verifies leak-clean across tests.

**Currently the second worker-lifetime service after Worker itself.** Pattern not yet promoted to DEVELOPMENT-PATTERNS.md pending third instance. Documented in Heartbeat godoc + this entry. ADR-021 Rule 3 already covers the pattern; explicit DEVELOPMENT-PATTERNS.md entry can wait.

### 2026-05-01 — Task 5.6: TTL-only worker expiry (no Del on shutdown)

**Decision.** `Heartbeat.Run` does NOT `DEL` the worker key on shutdown. Symmetric handling: clean shutdown and crash both rely on TTL expiry (60s default).

**Trade-off acknowledged.** 60s "ghost worker" entries appear in ops dashboards after restart. Operationally low-noise — orchestrator logic should already tolerate the case where a worker key exists but no jobs are being claimed (the orchestrator's worker-routing layer reads the key to decide where to dispatch; a ghost worker briefly looks "available" but jobs queued to it stall and re-dispatch via the ghost-queued janitor).

**Trigger to revisit:** ops dashboards genuinely confused by ghost entries causing incorrect operational decisions (not just the entries' existence). At MVP scale with single-digit workers, the trigger almost certainly never fires. Acceptable.

### 2026-05-01 — Task 5.6: Phase 2 fail-soft at 5.6 (forward-pin to M7)

**Pin.** Startup Phase 2 (Docker services healthcheck) is fail-soft at 5.6 because empty registry means no services to check. Pattern documented in `Startup.checkDockerServices` godoc.

**Trigger to switch from fail-soft to fail-fast:** M7 task constructors register `*DockerServiceRunner` instances with `HealthPath` set, AND the corresponding tool is operationally required (not optional). Each M7 task scope-proposal decides per-tool whether the service warrants fail-fast on health check.

**Same pattern applies to Phase 1** (native binaries). Fail-soft until M6 task constructors register tools that are required vs optional.

**5.6 ships the 4-phase scaffolding;** M6/M7 task scope proposals decide phase semantics per their tool's operational requirements.

### 2026-05-01 — Task 5.6: /health HTTP endpoint deferred to OPS milestone

**Pin.** Worker `/health` HTTP endpoint deferred to OPS milestone. Plan literal §5.6 mentioned `health.go` as a separate file; 5.6 implementation does NOT include it.

**Trigger to revisit:** ops needs runtime worker health observable from outside the worker process. Concrete signals:
- Kubernetes liveness/readiness probes need an HTTP endpoint (when M5+ deploys to K8s).
- Pull-based monitoring infrastructure (Prometheus scraping) needs an exposition endpoint.
- Orchestrator-side worker-routing logic needs a runtime health signal beyond TTL expiry.

**Current 5.6 health surface:**
- Phase 0 Redis ping at startup (fail-fast if Redis unreachable).
- Heartbeat key TTL (orchestrator infers worker liveness from TTL refresh).

These cover MVP without an HTTP `/health` endpoint.

### 2026-05-01 — Task 5.6: empty-registry startup behavior

**Pin.** 5.6 ships with empty `Registry`; M6+ task constructors populate engines via the `worker.NewRegistry(map[string]tools.ToolRunner{...})` call site in `cmd/worker/run.go`.

**Startup logs an explicit WARN** when `Registry.Engines()` returns empty so operators don't silently run a no-op worker. The warning message:

> "worker started with empty registry; no jobs will be processed until tool runners are registered. Tool runners are registered by M6+ task constructors (e.g., NativeRunner for Nuclei in M6.1). If this is unexpected, check that your worker binary was built with the desired M6+ task code."

**Without this warning,** an operator running the 5.6 binary in production would see jobs queue up and never process, with no clear diagnostic. The warning makes the no-tools state actionable.

### 2026-05-01 — Task 5.6: runMain extraction for testability

**Pattern.** `cmd/worker/main.go` delegates the bulk of its assembly + lifecycle to `cmd/worker/run.go`'s `runMain(ctx, deps) int`. main() loads config + builds Redis client + sets up signal-derived ctx; runMain handles dependency wiring, startup phases, Worker spawning, and shutdown drain.

**Why.** Integration tests (`cmd/worker/run_test.go`) exercise the full assembly without invoking signal handling. Test fixtures construct `runMainDeps` directly; tests call `runMain(ctx, deps)` and verify exit codes + Redis-side state.

**main() is small** (under 60 lines after refactor). Responsibilities: config load, log setup, signal context, Redis client + Phase 0 ping, call runMain, exit with returned code. All assembly lives in runMain.

**Side benefit.** runMain serves as documentation of the worker's full dependency graph; reading it shows the entire engine integration in one function.

### 2026-05-01 — Task 5.6: NewProcessorFromRedis convenience constructor

**Pin.** `internal/worker.NewProcessorFromRedis(registry, *redis.Client, log)` added at 5.6 to avoid main package needing to construct values of `worker`'s unexported interface types (`progressPublisher`, `cancelSubscriber`).

**Why this exists.** `ProcessorDeps`'s factory fields take unexported interface types so tests in the worker package can inject mocks. main.go can't construct values of those unexported types from outside the package, so this convenience constructor handles the wiring inside the package.

**Trade-off.** Two constructors (`NewProcessor` for tests, `NewProcessorFromRedis` for production) is mild duplication. Considered alternatives: (a) export the interfaces (renaming would conflict with `redis` package's concrete types of the same names), (b) provide a public DepsBuilder type (over-engineered). Two-constructor approach has the smallest API surface.

### 2026-05-01 — Task 5.6: miniredis BRPOP-ctx-cancel limitation re-encountered in cmd/worker tests

**Repeat occurrence of 5.4's documented limitation.** miniredis's BRPOP runs synchronously and does NOT honor ctx-cancel mid-flight (5.4 DRIFT-LOG entry). cmd/worker integration tests that cancel ctx wait up to `Worker.brpopTimeout = 5s` for the BRPOP to time out naturally before runMain's drain logic activates.

**Effect on test runtime.** Three of six cmd/worker tests run in ~5s each; total cmd/worker test package runtime ~16s. Acceptable for CI; documented here so future eyes don't optimize away the test latency without understanding why it exists.

**Real Redis behavior unchanged.** Worker.Run's ctx-cancel path is correct — go-redis aborts in-flight BRPOP via connection close on real Redis. The test slowness is purely a miniredis artifact.

### 2026-05-01 — M5 milestone-boundary close

**M5 — Go Worker Foundation — closes after Task 5.6.**

| Item | Detail |
|---|---|
| Tasks shipped | 5.1 scaffold + ADRs · 5.2 ToolRunner + NativeRunner · 5.3 DockerServiceRunner · 5.4 Redis primitives · 5.5 worker processor · 5.6 startup + heartbeat + main.go integration |
| Task ordering followed | 5.1 → 5.2 → 5.3 → 5.4 → 5.5 → 5.6 (linear; no reordering) |
| Engine commits | 6 (one per task) |
| Docs commits (shieldscan-docs) | 4 (Checkpoint 2 §6.2 recount · Checkpoint 4 VERSIONS sync · Task 5.1 docs sweep + ADRs · post-5.1 VERSIONS adjustments) |
| Test count | 0 (M5 open) → 16 (5.1) → 35 (5.2) → 59 (5.3) → 88 (5.4) → 110 (5.5) → **135 (5.6 / M5 close)** |
| Engine packages | 8: cmd/worker · deploy · internal/{buildguard, config, events, redis, tools, worker} |
| ADRs added | ADR-016 (raw Redis, not Asynq) · ADR-017 (findings inline + sequencing) · ADR-018 (Streams correction in plan §5.4) · ADR-021 (ctx discipline) |
| ADRs reserved | 019 (cancel Pub/Sub confirmation) · 020 (worker concurrency model) — both promotable from DRIFT-LOG on trigger |
| DEVELOPMENT-PATTERNS.md (engine-side) | 1 pattern: trigger-based deferral (8+ cited instances at promotion time) |
| Cross-repo wire-format fixtures | 2: `internal/events/testdata/job_dispatch_python_v1.json` + `job_completed_python_v1.json` (with .md provenance) |

**Self-catches across M5** (validating forcing-function discipline):

| Task | Catch | Mechanism |
|---|---|---|
| 5.1 | `exec.Command` in own buildguard test | `noctx` linter |
| 5.2 | `ExitCodeIsError` zero-value semantic inverted | TDD writing surfaced design bug |
| 5.4 | ctx-cancel-vs-BRPOP-redis.Nil race losing cancel signal | Debugging miniredis ctx-cancel test |
| 5.5 | discrimination semantics conflation (worker-shutdown vs user-cancel) | Articulating the decision table BEFORE writing conditionals |

The 5.5 retrospective: when conditional logic has 4+ outcomes with different semantic meanings, force-articulate the decision table BEFORE writing the conditionals. The table catches conflations that conditionals silently allow.

**Carry-forwards to M6** (Native Tool Runners):
- Each M6.1-6.7 task constructs a `NativeRunner` instance + registers it via the `worker.NewRegistry(map[string]tools.ToolRunner{...})` map literal in `cmd/worker/run.go`.
- testdata conventions established in 5.1 (`testdata/README.md`); M6.1 Nuclei is the first real consumer with synthetic JSONL fixtures.
- Phase 1 fail-soft → fail-fast trigger lands per-tool at M6 task scope-proposal time.
- ProgressEmitter interface extension trigger fires at M6.3 Recon (per 5.2 H.4 deferral).

**Carry-forwards to M7** (Persistent Docker Service Runners):
- Each M7.1-7.6 task constructs a `*DockerServiceRunner` + populates Registry + adds entry to Startup.DockerSvcs.
- Phase 2 fail-soft → fail-fast trigger lands per-tool.
- M7.5 Nmap warm pool is the trigger for shipping Phase 3 (warm pool init).

**Carry-forwards to M8** (Recon-First Pipeline + Scan Type → Tool Matrix):
- WorkerConcurrency env-var configurability ready for fan-out tuning.
- errgroup adoption trigger evaluated at M8.1 scope proposal (per ADR-021 deferral).

**Carry-forwards to M9** (AI Pipeline):
- ADR-017 Option-C R2 staging trigger evaluated when ingest-time problems surface with deep-scan batches.

**Carry-forwards to OPS milestone:**
- Worker `/health` HTTP endpoint (deferred per 5.6 H.6).
- Runtime `HealthCheckLoop` per TOOL-ARCH §11.2.
- Worker-degraded marking + orchestrator-side worker-routing logic.
- Stream-key cleanup TTL (carry-forward from ADR-014).
- Per-request DB session checkout for SSE (carry-forward from M4 Task 4.4).
- Ghost-queued janitor (M4 Task 4.2 carry-forward; needed for ADR-017 sequenced-event recovery).

**Patterns established in M5** (now part of project DNA):

1. **Architectural-commitments preamble** before scope proposal — preempts integration surprise.
2. **Decision tables before conditionals** when ≥4 outcomes have distinct semantics (5.5 self-catch).
3. **Trigger-based deferral** (DEVELOPMENT-PATTERNS.md section 1).
4. **Cross-repo wire-format fixtures** (5.4 — `testdata/*.json` + `.md` provenance).
5. **Two-layer timeout** (worker shutdown + runner-internal timeout; never three).
6. **Per-job CancelSubscriber** (vs per-worker fan-out) at MVP scale.
7. **Frozen Registry** (defensive copy at construction; no mutex).
8. **Full-orchestration Execute closure** for HTTP-based runners (5.3) — asymmetric with NativeRunner's BuildArgs+ParseOutput is correct because HTTP is multi-step.
9. **Worker-lifetime services** with workerRootCtx from main (Worker, Heartbeat — 2 instances; pattern not yet promoted).
10. **runMain extraction** for testability of process-entry assembly.

**M5 health:** clean execution. Six commits, six self-catches captured, test count grew 0 → 135 with no rework or test deletion. Architectural decisions surfaced at scope-proposal time; design bugs caught by forcing functions before commit. The pattern-density of M5 (4 ADRs + DEVELOPMENT-PATTERNS.md creation + 4 self-catches across 6 tasks) reflects that this milestone built foundational infrastructure for all M6+ tool integration work.

**Ready for M6.** First task: M6.1 Nuclei. The full integration path is alive — JobConsumer.Pop → IdempotencyClaim.Claim → Registry.Get → NativeRunner.Run → CompletionsPublisher.Publish — and M6.1 is the first task that exercises it end-to-end with a real tool.

### 2026-05-01 — Task 5.5: worker processor + concurrency + cancel-watcher

**Files shipped:** `internal/worker/registry.go` (Registry, frozen at construction) · `internal/worker/processor.go` (Processor + Process method + cancel-watcher + JobDispatch translation helpers) · `internal/worker/worker.go` (Worker BRPOP loop + concurrency semaphore + WaitGroup-based graceful drain) · `internal/worker/{registry,processor,worker}_test.go` (3+13+8 = 24 tests + goleak TestMain).

**24 tests at 5.5 close** (vs planned 22 — extras were `TestProcessor_JobDispatchToTarget` + `TestProcessor_JobDispatchToScanConfig` + `TestWorker_PanicsOnInvalidConcurrency`; right-sized expansion on contract surfaces). Engine total: 110 tests across 6 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Discrimination semantics decision table** pinned in `processor.go` Process() docstring covering the 5 outcomes from `(runErr, jobCtx.Err, ctx.Err)`. User-cancel emits `job_canceled`; worker-shutdown emits `job_completed` if Run finished cleanly before cancel arrived; tool-internal-timeout emits `job_failed` (timeout reason); other tool errors emit `job_failed` (error message). The table is the contract; the conditionals are the implementation.

**Cancel-watcher 3 exit paths verified.** `TestProcessor_CancelWatcherExitsOnJobDone` (path 1: job finished), `TestProcessor_CancelMidRun` (path 2: cancel event received), `TestProcessor_CancelWatcherExitsOnSubClose` (path 3: subscriber closed via Process's defer). goleak in TestMain verifies no leak across all paths.

**Forcing-function self-catch pattern continues.** No catch on this commit specifically — but the design surface is dense (3 files composing every prior task surface) and the discrimination semantics table forced explicit thinking that surfaced the worker-shutdown-vs-user-cancel distinction. Without articulating the table, the conditional ordering would have collapsed worker-shutdown into "cancel" semantically — which would emit `job_canceled` to Python on every worker restart, contaminating ScanJob.status semantics.

### 2026-05-01 — Task 5.5: ADR-013 retry semantics — plan §5.5 "retry up to 3x" plan-staleness

**Plan-staleness pin.** IMPLEMENTATION-PLAN.md §5.5 step 1 (line 1690) describes the test as: _"duplicate idempotency_key is silently dropped, canceled jobs don't retry, **failed jobs retry up to 3x**."_ This is stale.

**ADR-013** (Python is the sole writer for scan state) places retry/state-machine ownership on the Python re-dispatch path: when a `job_failed` event lands, M4 Python `CompletionsConsumer` updates `ScanJob.status = 'failed'`; the M5+ ghost-queued janitor (Task 4.2 carry-forward) is the canonical retry mechanism, and re-dispatch re-creates a fresh job with a new `idempotency_key`. Go-side worker has nothing to retry — it doesn't own state.

**5.5 emits `job_failed` events on tool error** and lets Python decide re-dispatch policy. No Go-side retry counter; no `max_retries` field; no exponential backoff inside Process(). The plan literal stays as written per state-at-time discipline; 5.5 implementation derives retry-ownership from ADR-013, not from plan §5.5's test description.

**Future readers** opening §5.5 expecting Go-side retry should read this DRIFT-LOG entry first.

### 2026-05-01 — Task 5.5: per-job CancelSubscriber (vs per-worker)

**Decision.** Each `Process` call spawns its own `CancelSubscriber` bound to the job's `scan_id`. N concurrent jobs = N Pub/Sub subscriptions on the engine.

**Why not per-worker.** A single worker-lifetime subscriber would need fan-out routing logic: "this `cancel_requested` event is for scan_X; which active job is processing scan_X?" That requires a registry of active jobs keyed by scan_id, with concurrent-mutation safety (job-start adds, job-end removes), with race protection against late-arriving cancel events for jobs that just completed. Per-job subscriber sidesteps all of this — each subscriber is bound to exactly one scan, lifecycle matches the job's, no fan-out needed.

**At MVP scale (5 concurrent jobs per worker)**, 5 Pub/Sub subscriptions is fine. go-redis pools connections; subscription overhead is one connection-pool slot per active subscriber.

**Trigger to revisit:** concurrency climbing to 50+ jobs simultaneously OR Redis Pub/Sub connection limits being hit in production. At that point, per-worker subscriber + fan-out routing earns its complexity.

### 2026-05-01 — Task 5.5: frozen Registry pattern

**Decision.** `internal/worker.Registry` is constructed once at worker startup (5.6 territory) with a defensive copy of the runner map. No `Set` method exposed; safe concurrent reads without mutex.

**Trade-off.** M6.8 task may extend with `Register(engine, runner)` + mutex if dynamic registration becomes needed. For M5+M6 sequential tool registration at startup, frozen-at-startup is sufficient.

**Pinned by `TestRegistry_FrozenAtConstruction`** — mutating the input map after `NewRegistry` returns does NOT affect the registry. Without this defensive copy, M6 task constructors that build the runner map and then continue to populate it would race with worker reads.

### 2026-05-01 — Task 5.5: cancel-watcher 3 exit paths

**Per-job cancel-watcher goroutine has 3 ctx-aware exit paths:**

1. `jobCtx.Done()` — job finished or canceled by another path. Watcher exits without taking action.
2. Cancel event received via `sub.Events()` — call `cancel()` on jobCtx → runner sees ctx cancel → Process emits `job_canceled`.
3. Subscriber `Events()` channel closed — Redis disconnect (per ADR-021 H.6 from 5.4: surface, don't auto-recover) OR explicit `Close()` call from Process's defer when job completes normally.

**ADR-021 Rule 2 enforced via `goleak.VerifyTestMain`** in `internal/worker` test packages. Tests `TestProcessor_CancelWatcherExitsOnJobDone` + `TestProcessor_CancelMidRun` + `TestProcessor_CancelWatcherExitsOnSubClose` collectively pin all 3 exit paths.

**Process() blocks on `<-cancelExited` in defer** before returning — synchronizes goroutine cleanup with Process return. Without this, a Process call that returns "successfully" could leave the watcher goroutine alive briefly, racing with goleak's snapshot at TestMain exit.

### 2026-05-01 — Task 5.5: discrimination semantics for runner return

**Pin.** Process() discriminates 5 outcomes from the `(runErr, jobCtx.Err, ctx.Err)` tuple. The decision table lives in code comments above Process()'s discrimination logic, exactly as drafted in the scope-proposal review.

**Why the table matters operationally.** Each emission shape maps to distinct Python-side behavior:

- **User-cancel** → `ScanJob.status = "canceled"` in Python (clear signal of user intent; UI shows "Canceled by user").
- **Worker-shutdown-cancel** → `ScanJob.status` stays "running" until Python ghost-queued janitor sweeps (signal that worker died, not user intent — re-dispatch should retry).
- **Tool-internal-timeout** → `ScanJob.status = "failed"` with timeout reason (signal that the tool ran out of time; re-dispatch with longer timeout if customer pays for it).
- **Other tool errors** → `ScanJob.status = "failed"` with error message (signal that the tool itself failed; re-dispatch may not help if it's a permanent failure).
- **Worker-shutdown-after-clean-Run** → `ScanJob.status = "completed"` (preserves the work; the cancel arrived after Run finished but before publish, and we publish anyway because the job logically succeeded).

**Future engineers** should find the decision table in the docstring and extend it when adding new outcome types, rather than reverse-engineering from conditionals.

### 2026-05-01 — Task 5.5: two-layer timeout (worker + runner)

**Pin.** Processor's `jobCtx` is just `WithCancel(workerCtx)`; runners enforce their own timeout via internal `WithTimeout(jobCtx, effective)` (5.2 NativeRunner / 5.3 DockerServiceRunner).

**Two layers** cover all real cases: worker-level shutdown propagates through `workerCtx` cancel; tool-level timeout uses runner's own `effectiveTimeout` precedence (`cfg.Timeout > runner.Timeout > default`). A third layer ("processor-internal job timeout") would add complexity without benefit — the runner already enforces the right limit.

**`cfg.Timeout` from JobDispatch** flows to `tools.ScanConfig` via `jobDispatchToScanConfig` helper. Runner respects override per its own precedence rules. Pinned by `TestProcessor_JobDispatchToScanConfig`.

### 2026-05-01 — Task 5.5: DEVELOPMENT-PATTERNS.md created (engine-side)

**Engine-side `DEVELOPMENT-PATTERNS.md`** created at 5.5. First pattern: **trigger-based deferral**.

**8+ instances cited** from across M4-M5: ADR-014 hybrid Streams+PubSub, ADR-016 Asynq scheduled scans, ADR-017 R2 staging triggers, ADR-021 errgroup adoption, 5.2 H.4 ProgressEmitter, 5.3 H.5 per-tool retry, 5.4 H.6 Pub/Sub auto-reconnect, Checkpoint 2 H.1 SSE DB-session. Triple-pin precedent satisfied many times over; promotion overdue. Landed at 5.5.

**Engine-side vs API-side.** API repo has its own `DEVELOPMENT-PATTERNS.md` in `shieldscan-docs/` (created earlier in M3 for `select_fresh` + `session_factory` DI patterns + API-key audit attribution). The two-repo docs split (Q3 Option B at Task 5.1) means each repo accumulates its own patterns; cross-cutting patterns (like trigger-based deferral, which spans both repos) are documented in whichever repo introduces the pattern's first three instances.

### 2026-05-01 — Task 5.4: Redis primitives (queue + streams + pubsub + idem)

**Files shipped:** `internal/redis/queue.go` (JobConsumer) · `internal/redis/stream.go` (ProgressPublisher per ADR-018) · `internal/redis/pubsub.go` (CancelSubscriber + CompletionsPublisher) · `internal/redis/idem.go` (IdempotencyClaim) · `internal/redis/{queue,stream,pubsub,idem}_test.go` (4+6+5+8 = 23 tests). Plus `internal/events/events.go` extended with `JobDispatch`/`JobTarget`/`JobAuth`/`JobMobileConfig`/`ProgressEvent`/`SplitForCompletion`/`DecodeJobDispatch` and `internal/events/events_test.go` extended with 6 SplitForCompletion + fixture tests. Plus 4 fixture artifacts in `internal/events/testdata/`.

**29 net-new tests at 5.4 close** (23 redis + 6 events extension). Engine total: 88 tests across 5 packages. Race-clean, vet-clean, lint-clean.

**ADR-018 file-layout discipline implemented.** Progress XADD lives in `stream.go`; cancel + completions in `pubsub.go`. Engineer adding progress logic looks at `stream.go` first; cancel/completions logic in `pubsub.go`. Plan §5.4 literal had progress in `pubsub.go` — that's the stale Pub/Sub-for-progress shape that ADR-018 corrects.

**Self-catch during TDD: caller-cancellation-vs-BRPOP-redis.Nil race.** Initial JobConsumer.Pop checked `ctx.Err()` only in the `err != nil` path, not in the `redis.Nil` (timeout) path. On real Redis where ctx-cancel mid-BRPOP can result in the BRPOP returning `redis.Nil` first (timeout) with the cancel landing right after, the cancel signal would be lost — Pop would return `(nil, nil)` instead of `(nil, ctx.Canceled)`. Caught while debugging the miniredis ctx-cancel test; restructured to check `ctx.Err()` BEFORE interpreting BRPOP's return, so the cancel signal wins regardless of BRPOP's race behavior. Pattern: ctx-error precedence over Redis-success-or-error.

### 2026-05-01 — Task 5.4: cross-repo wire-format fixtures introduced

`internal/events/testdata/` established as cross-repo contract fixture location.

**Fixtures shipped:**
- `job_dispatch_python_v1.json` — canonical SPEC §7.1 queue payload matching M4 Python `ScanQueue.dispatch` wire format.
- `job_dispatch_python_v1.md` — provenance + cross-repo update protocol.
- `job_completed_python_v1.json` — canonical SPEC §7.3 (post-ADR-017) completion event.
- `job_completed_python_v1.md` — provenance + sequencing semantics.

**Embedded via `//go:embed`** in `internal/events/events.go` as `FixtureJobDispatchPythonV1` and `FixtureJobCompletedPythonV1` byte slices. Tests in `internal/redis/` and `internal/events/` consume the embed without filesystem-relative path fragility.

**Cross-repo update protocol** (in fixture .md files): when Python emit shape changes legitimately, both fixture files AND Python emit code AND Go consumer struct must update in lockstep. The `_v1` suffix sets up versioning for future schema migrations (e.g., `_v2.json` if a breaking change ships).

**Pinned by `TestJobConsumer_MatchesPythonWireFormat`** (cross-repo wire-format test #6). DisallowUnknownFields enforces strictness — Python emit drift breaks Go decode loudly at CI time. This is the load-bearing cross-repo contract pin of Task 5.4.

### 2026-05-01 — Task 5.4: SplitForCompletion location in events package

**Decision.** ADR-017 sequencing logic placed in `internal/events/events.go::SplitForCompletion`, NOT in `internal/redis/`.

**Why.** Sequencing is contract-shaped per ADR-017 (the multi-event protocol Python's CompletionsConsumer must understand). It belongs with the type definitions for the same reason `EventSeq.Validate` does — single source of truth for what's a valid sequenced batch. Both 5.4 `CompletionsPublisher` and 5.5 processor reference `SplitForCompletion`; placing it in events package means one canonical implementation.

Future readers asking "how do JobCompletedEvents get split for sequencing?" find the answer with the type, not by tracing publisher code. Symmetry: `EventSeq` lives in events package; `SplitForCompletion` consumes/produces `EventSeq` and `JobCompletedEvent`; co-location is correct.

**Pinned by 4 SplitForCompletion tests** covering single-event boundary cases (0/1/1000 findings), multi-event sequencing (1001/2000/2500), intermediate-status override (ADR-017 partial_findings type), and authoritative-fields-on-terminal-only invariant.

### 2026-05-01 — Task 5.4: ProgressEvent as map[string]any (loose typing)

**Decision.** `events.ProgressEvent` is a type-aliased `map[string]any`, not a typed struct.

**Trade-off acknowledged.** SPEC §7.2 has 7+ event variants (`job_started`, `recon_started`, `subdomains_discovered`, `job_progress`, `finding_discovered`, `job_canceled`, `job_failed`) with payloads varying by event_type. A strict typed struct per variant would require N Go types and Go-side schema work every time Python adds a variant. Python is map-based; SPEC is the contract surface, not the Go type.

**ProgressPublisher injects** `event_type` / `scan_id` / `timestamp` headers; payload is open-ended for everything else. Symmetric with Python's `ProgressPublisher.publish(event: dict)` shape.

**Promotion path.** If type-safety pressure surfaces (specific variants need validation — e.g., `subdomains_discovered.subdomains` must be `[]string`, `job_progress.progress` must be `0-100`), promote those variants to typed structs in events package; the `ProgressEvent` map remains as fallback for variants not yet promoted. Most variants will probably never need promotion at MVP scale.

### 2026-05-01 — Task 5.4: Pub/Sub disconnect handling for CancelSubscriber

**Decision.** go-redis v9 `Subscribe` does NOT auto-reconnect on transient drops. CancelSubscriber surfaces disconnect via Events() channel close — when the underlying `pubsub.Channel()` closes (transient drop OR explicit `Close()`), the converter goroutine exits and Events() closes. Caller (M5.5 processor) detects via closed-channel receive (`_, ok := <-sub.Events(); !ok`) and decides recovery.

**Why not auto-reconnect inside the primitive.** Primitives surface failure; orchestration decides recovery. Same shape as 5.3's "retry deferred to per-tool Execute" — for CancelSubscriber, the recovery decision depends on operational context the primitive can't know (is this transient blip recoverable? Or is Redis genuinely down and we should fail-the-job?). 5.5 processor knows; 5.4 primitive doesn't.

**Subscription confirmation pattern.** `NewCancelSubscriber` calls `pubsub.Receive(ctx)` to wait for Redis's subscribe-ack before returning. Without this, a Publish emitted between `Subscribe()` and the first `Channel()` read could be lost. miniredis honors the Receive-handshake; verified by `TestCancelSubscriber_ReceivesPublishedEvent`.

### 2026-05-01 — Task 5.4: malformed-payload poison-pill protection (queue + cancel)

**Pattern applied to both JobConsumer and CancelSubscriber.** Malformed JSON payloads are dropped (queue: returns error to caller; cancel: silent skip in converter goroutine). Underlying messages are consumed (BRPOP popped; Pub/Sub delivered) so the malformed entry doesn't loop forever.

**Trade-off acknowledged.** Malformed jobs are silently lost from the customer's perspective. M4 Python orchestrator emits well-formed JSON; malformed implies upstream bug or Redis corruption. Recovery for genuine customer-impact: M5+ ghost-queued janitor (Task 4.2 carry-forward) sweeps stuck `ScanJob.status = 'running'` rows.

Alternatives rejected:
- **Re-LPUSH for retry**: risks infinite loop on persistent malformed entry.
- **Move to dead-letter list**: requires cross-repo coordination + new primitive; M4 Python doesn't have one.

Pinned by `TestJobConsumer_MalformedJSONReturnsError` (consumed-then-empty assertion) and `TestCancelSubscriber_MalformedPayloadDropped` (subscriber continues delivering valid events after garbage).

### 2026-05-01 — Task 5.4: miniredis Streams + Pub/Sub compat verified (Checkpoint 4 closure)

**Checkpoint 4 documented-confidence pin** (miniredis/v2 v2.33.0 vs go-redis/v9.7.0) verified at Task 5.4 across both Streams and Pub/Sub primitives.

**Streams** (XADD, XRANGE, XLEN, MAXLEN approximate trim) all behave per Redis spec. `TestProgressPublisher_MaxLenApplied` (publish 1500, expect `<= 1200` retained) and `TestProgressPublisher_RoundTripWithXRange` (publish then XRANGE retrieves the same payload) collectively verify.

**Pub/Sub** (Subscribe + handshake via Receive + Channel + Publish) works correctly. `TestCancelSubscriber_ReceivesPublishedEvent` verifies subscribe-handshake + per-channel routing; `TestCompletionsPublisher_RoundTripJSON` verifies cross-process event round-trip with full JSON shape preservation.

**One miniredis limitation surfaced + worked around.** miniredis's BRPOP runs synchronously and does NOT honor ctx-cancel mid-flight (real Redis cancels BRPOP via connection close + go-redis aborts). `TestJobConsumer_CtxCancelExits` works around with a short BRPOP timeout (200ms) so miniredis returns `redis.Nil` naturally; Pop's post-BRPOP `ctx.Err()` check then returns Canceled. The implementation is correct on real Redis (where mid-flight cancel IS interrupted); the test uses the short-timeout shape because miniredis can't reproduce real-Redis cancel semantics. Documented in test docstring + this DRIFT-LOG entry.

**goleak coverage** added in `internal/redis/pubsub_test.go`'s `TestMain` with `IgnoreTopFunction` for go-redis pool reaper + miniredis serve goroutine. CancelSubscriber's converter-goroutine teardown verified leak-clean across all 8 pubsub tests.

**Compat-confidence is now compat-verified.** Both engine-test deps (httpmock @ 5.3, miniredis @ 5.4) closed.

### 2026-05-01 — Task 5.3: DockerServiceRunner for HTTP-based services

**Files shipped:** `internal/tools/docker_service.go` (DockerServiceRunner + Get/Post/PollUntil/HealthCheck helpers + compile-time interface assertion) · `internal/tools/docker_service_test.go` (24 tests using httpmock v1.3.1).

**24 tests at 5.3 close** (vs planned 17). Expansion earned weight: helper-method coverage, edge cases on PollUntil (default interval, error propagation), HealthCheck variants (happy, 5xx, missing path), and the H.4-pinning ClientReusedAcrossCalls. Race-clean, vet-clean, lint-clean.

**httpmock v1.3.1 compat verified.** First real-world test of the dep that Checkpoint 4 documented as "documented-confidence, not test-verified." `httpmock.ActivateNonDefault(client)` binds correctly to per-runner HTTP clients; `t.Cleanup(httpmock.DeactivateAndReset)` provides per-test isolation. Convention `newMockClient(t)` helper in docker_service_test.go encapsulates the setup; M7 task tests reuse the same fixture pattern.

**gosec G704 suppression precedent.** Same shape as 5.2's G204 NativeRunner suppression. `HTTPClient.Do(req)` is flagged as SSRF-taint-suspicious; suppressed with explanatory `//nolint:gosec` comment because the HTTP-to-localhost-Docker-services pattern is exactly the runner's purpose. BaseURL is operator-config; paths are M7-task in-repo code; query params are Python-orchestrator-validated before dispatch.

### 2026-05-01 — Task 5.3: full-orchestration closure pattern (vs request/response split)

**Decision.** `DockerServiceRunner.Execute` is a full-orchestration closure receiving `(ctx, *DockerServiceRunner, target, cfg)`. The runner provides primitives (Get, Post, PollUntil, HealthCheck); closures compose them.

**Why not BuildRequest+ParseResponse split** (parallel to NativeRunner's BuildArgs+ParseOutput): multi-step HTTP dances cannot be expressed as a single request/response pair. ZAP's flow per TOOL-ARCH §7.2 is 5 calls (POST spider start → POLL spider status → POST active scan → POLL active scan status → GET alerts). MobSF: upload → analyze → poll → fetch report. Trivy varies by mode. SQLMap: confirm-only mode is multi-step.

**Asymmetric with NativeRunner** — and that's correct. The asymmetry reflects the underlying difference: subprocess invocation is one round-trip (args in, output out); HTTP API integration is N round-trips with per-call state. Forcing the same shape on both would either over-constrain HTTP (single-call only) or under-constrain native (multi-step orchestration that doesn't apply).

**Convention.** Execute closures treat `*DockerServiceRunner` as read-only. Mutating runner state from within Execute breaks runner reuse across jobs. Documented in DockerServiceRunner godoc.

### 2026-05-01 — Task 5.3: HTTP retry policy deferred to per-tool Execute

**Decision.** DockerServiceRunner does NOT implement HTTP retry. Each M7 tool's `Execute` closure handles retry per its own idempotency profile.

**Why generic retry would be wrong half the time:**
- **MobSF upload:** NOT retryable (re-upload creates duplicate task with new UUID).
- **MobSF status poll:** retryable (idempotent GET).
- **ZAP spider start:** NOT retryable (creates new spider job).
- **ZAP status poll:** retryable.
- **Trivy SCA:** server-side idempotent on same target; retry safe.
- **SQLMap confirm:** task creation NOT retryable; status polling retryable.

A blanket retry on `HTTPClient.Do` would either silently double-create tasks (idempotency bugs) or silently fail to retry transient errors on idempotent calls. Closure-level retry lets each M7 task ship correct semantics for its tool.

**M7 task authors** writing retry should use the existing PollUntil pattern with retry-aware predicate (treat transient 5xx as "not done yet, try again") rather than reinventing.

### 2026-05-01 — Task 5.3: HTTP client per-runner-instance for connection reuse

**Decision.** DockerServiceRunner constructs HTTP client once per runner instance (lazy via `ensureClient` on first use); reused across all Run calls and helper-method calls.

**M6.8 registry** (future) constructs each tool's runner once at worker startup; that single runner instance handles every job hitting that tool throughout the worker's lifetime. Connection pooling kicks in for repeat calls — significant for polling-heavy tools (MobSF: ~30 polls per scan; ZAP: ~100+ polls per scan; SQLMap: ~20 polls per scan). Per-call client allocation would mean N TCP handshakes + TLS negotiations per scan.

**HTTPClient.Timeout = 0.** All timeout enforcement flows through ctx (`req.WithContext(runCtx)`). Single source of truth = ctx; logical-operation timeouts don't race with client-level timeouts.

**Pinned by `TestDockerServiceRunner_ClientReusedAcrossCalls`.**

### 2026-05-01 — Task 5.3: PollUntil enforces ADR-021 Rule 2 centrally

**Decision.** `PollUntil(ctx, interval, poll)` centralizes the ctx-aware sleep pattern (`select` on `ctx.Done()` vs `time.After(interval)`). M7 closures using PollUntil inherit Rule 2 compliance automatically.

**Why this matters.** The `noctx` linter from 5.1 catches HTTP and exec violations but **not bare `time.Sleep` in polling loops**. A naive M7 task author writing `for { check(); time.Sleep(2*time.Second) }` would pass lint while silently violating ADR-021 Rule 1 (sleep ignores ctx; cancellation hangs until sleep elapses). Centralizing the pattern in PollUntil prevents M7 authors from reinventing incorrectly.

**Default interval.** When caller passes `interval <= 0`, `DefaultPollInterval = 1 * time.Second` applies. Pinned by `TestDockerServiceRunner_PollUntilDefaultInterval` (verifies interval=0 doesn't busy-loop: ~1 call in 100ms, not hundreds).

**ADR-021 Rule 2 forcing function** — first centralized helper that enforces ctx-discipline beyond the linter layer. Future M5+ patterns that would otherwise leak Rule 2 violations should follow the same "encapsulate-the-pattern" approach.

### 2026-05-01 — Task 5.2: ToolRunner interface + NativeRunner + fingerprint

**Files shipped:** `internal/tools/runner.go` (interface + Target + ScanConfig + AuthConfig types) · `internal/tools/native.go` (NativeRunner + compile-time interface assertion) · `internal/tools/fingerprint.go` (exported ComputeFingerprint) · `internal/tools/native_test.go` (16 tests + goleak TestMain) · `internal/tools/fingerprint_test.go` (3 tests).

**19 tests at 5.2 close** (vs planned 17). Two extras earned their weight: `TestNativeRunner_NilBuildArgs` and `TestNativeRunner_NilParseOutput` pin contract surface (M6 task constructors that forget to set the closures get a clear error rather than an obscure subprocess crash). All race-clean, vet-clean, lint-clean.

**Self-catch during implementation: `ExitCodeIsError` → `ExitCodeLenient` rename.** Initial design used `ExitCodeIsError bool` with the (incorrect) docstring claiming "Default (zero value, true): non-zero exit aborts Run with an error." Go's `bool` zero value is `false`, not `true` — so the field's actual default was the OPPOSITE of the documented behavior. Caught while writing tests. Renamed to `ExitCodeLenient` (zero-value=false=strict, opt-in true=lenient) so the field name + zero-value matches the dominant pattern (most native tools follow exit-zero-on-clean; gitleaks/semgrep are the minority that opt in). Cleaner shape; the user's mental model from scope-proposal review preserved.

**Pattern: forcing functions catch their own authors.** Following the 5.1 self-catch (noctx caught my own `exec.Command` violation), 5.2 added another to the pattern: **writing the test surfaced a semantic bug in the field name**. Test-first discipline isn't just for behavior — it surfaces design bugs the docstring alone wouldn't catch. Future similar moments are positive signals worth acknowledging (per user feedback after 5.1 close).

### 2026-05-01 — Task 5.2: ComputeFingerprint exported as cross-package contract

**Decision.** `ComputeFingerprint` is an exported package function in `internal/tools/`, not the lowercase `computeFingerprint` referenced in plan literal §5.2.

**Why.** M5.5 processor + future M9 AI pipeline both consume the algorithm; package-private with wrappers risks drift across consumers. The fingerprint is a contract surface (M9's primary-pass dedup key per `../shieldscan-docs/CLAUDE.md` gotcha 4); single canonical implementation is correct.

**Cross-language parity.** Any future Python computation of the same fingerprint MUST use the byte-equivalent algorithm: pipe-separated SHA-256 of `(tool_name | finding_type | target_url | parameter | code_file | code_line)` in this order. If `RawFinding.TargetURL` ever contains a literal pipe character (technically allowed in URLs but rare), collisions become possible — at that point the algorithm gets versioned and migrated, not changed in place.

### 2026-05-01 — Task 5.2: per-tool timeouts as tool-internal constants

**Decision.** `NativeRunner.Timeout` field carries per-tool default per `../shieldscan-docs/TOOL-ARCHITECTURE.md` §6 (Nuclei 30min, Subfinder 60s, etc.). `internal/config/Config` is reserved for cross-cutting tunables (worker concurrency, log level, Redis URL).

**Override path.** Job-dispatch time via `cfg.Timeout` (in `ScanConfig`) when ops tuning is needed. Effective timeout precedence: `cfg.Timeout > 0` overrides `NativeRunner.Timeout > 0` overrides `DefaultNativeTimeout` (30 min).

**Why not centralized in `Config`.** Eleven+ env vars (one per native tool) would sprawl the config struct. Most timeouts are static defaults that never need ops tuning; the few that do are exposed via `cfg.Timeout` at the job-dispatch layer.

**Pinned by `TestNativeRunner_CfgTimeoutOverride`.**

### 2026-05-01 — Task 5.2: progress emission deferred from runner interface (with explicit trigger)

**Decision.** `ToolRunner.Run(ctx, target, cfg) ([]events.RawFinding, error)` is pure compute — no progress callback. Processor (Task 5.5) emits `job_started` / `job_completed`. Mid-run progress events deferred until trigger fires.

**Trigger to add `ProgressEmitter func(EventType, map[string]any)` field to `ScanConfig`:**
- Any M6+ tool that produces meaningful intermediate state worth surfacing to the customer (e.g., Subfinder's "discovered 47 subdomains, scanning each" mid-run signal).
- Specifically NOT: tools that just take a long time silently (Nuclei's 30-minute template runs). Those don't need progress; they need a longer-status indicator on the dashboard side.

**Lean: M6.3 Recon is the likely first trigger** — Subfinder + httpx have a natural mid-pipeline boundary (subdomains discovered → httpx checks each), and TOOL-ARCH §6.3 already has `RunRecon(...publisher *ProgressPublisher)` in the plan literal.

**When trigger fires.** Add `ProgressEmitter` as an optional field in `ScanConfig`. Non-breaking — nil emitter is no-op default; production injects a real emitter via 5.5 processor; tests pass nil. This is the H.4 Option B path; deferring it now keeps 5.2's interface minimal.

### 2026-05-01 — Task 5.2: events.RawFinding supersedes plan-literal local definition

**Pin.** Plan §5.2 (lines 1577-1604) references `RawFinding` as if local to `internal/tools/`. 5.1 shipped `events.RawFinding` as part of the wire-schema package owning all SPEC §7 contract surfaces.

**5.2 imports `events.RawFinding`** rather than redefining. Single source of truth: tool runners and processor (5.5) share the exact type the wire encodes. Avoids the M6 task tax of "do I import the events one or the tools one?" — there is only one.

**Plan literal stays as written** per state-at-time discipline. M6 task authors reading §5.2 should treat the unqualified `RawFinding` as a notational shorthand for `events.RawFinding`.

### 2026-05-01 — Task 5.1: engine repo bootstrap (M5 milestone-boundary open)

**M5 — Go Worker Foundation — opens with Task 5.1 engine bootstrap.**

| Item | Detail |
|---|---|
| Repo created | `shieldscan-engine/` greenfield Go module |
| Go version | 1.26.2 (matches `../shieldscan-docs/VERSIONS.md` §2.1) |
| golangci-lint version | v2.11.4 (see entry below for v1→v2 schema choice) |
| Files in 5.1 commit | `cmd/worker/main.go` · `internal/{buildguard,config,events}/` · `.github/workflows/engine.yml` · `.golangci.yml` · README · CLAUDE.md · DRIFT-LOG.md · `.env.example` · `.gitignore` · `testdata/README.md` · go.mod / go.sum |
| Tests at 5.1 close | 16 (4 buildguard + 4 config + 8 events) — all green |
| Forcing functions wired | ADR-013 (build-graph + reflective DB-fields check) · ADR-016 (asynq exclusion) · ADR-017 (`MaxFindingsPerEvent = 1000` constant + `EventSeq` validation) · ADR-021 (goleak + go vet lostcancel + golangci-lint containedctx/noctx) |
| ADRs landed (in `../shieldscan-docs/SPECIFICATION.md` §13) | ADR-016, ADR-017, ADR-018, ADR-021 |
| Patterns established | Two-repo docs split (engine local CLAUDE/DRIFT/PATTERNS; cross-cutting in `shieldscan-docs`) · `internal/events/` as single source of wire-schema truth · `internal/buildguard/` for cross-cutting forcing-function tests |
| Carry-forwards to 5.2-5.6 | Tool runner package · Redis primitives package (split: `stream.go` for progress, `pubsub.go` for cancel/completions per ADR-018) · processor + idempotency · startup health checks · docker-compose for Layer-2 services |

**M5 health:** clean bootstrap. Linter caught one self-inflicted ADR-021 violation in the buildguard tests (`exec.Command` instead of `exec.CommandContext`) before the first commit — exactly what `noctx` is for. Refactored to `exec.CommandContext(t.Context(), ...)` and re-pinned. The ctx-discipline forcing function works.

### 2026-05-01 — Task 5.1: golangci-lint v2 schema choice

**Decision.** Engine ships with golangci-lint **v2.11.4**, not the v1.62.0 referenced in the Task 5.1 scope proposal.

**Why.** v2.x is the current upstream-stable release line as of 2026-04 (released 2025); v1.62.0 would be sticking to a stale version with no security backport guarantee. v2 has breaking config-schema changes from v1 (`version: "2"` directive, `linters.default + linters.enable` block instead of v1's enable/disable lists, `exclusions.rules` instead of `issues.exclude-rules`), so the choice is structural — `.golangci.yml` is authored against v2 schema.

**Compatibility.** All five planned linters (containedctx, noctx, errcheck, staticcheck, gosec) are available in v2. v2's `default: standard` includes errcheck + staticcheck + govet + ineffassign + unused, so we explicitly enable only the three not in standard (containedctx, noctx, gosec).

**Pinned in `../shieldscan-docs/VERSIONS.md` §2.4** alongside other engine-test deps (miniredis, httpmock, goleak).

**Carry-forward:** if golangci-lint v3 ships before M5 close, evaluate via the standard upgrade decision matrix in VERSIONS.md §4.4. v2 → v3 would likely be another schema break.

### 2026-05-01 — Task 5.1: aws-sdk-go-v2 patch bump v1.32.0 → v1.32.2

**Resolver-driven correction.** VERSIONS.md §2.4 pins `aws-sdk-go-v2 v1.32.0` and `aws-sdk-go-v2/service/s3 v1.66.0`. At engine bootstrap, `go get ...service/s3@v1.66.0` failed because s3 v1.66.0 has a hard requirement on aws-sdk-go-v2 v1.32.2. Bumped to v1.32.2.

**This is a patch-level bump within the same minor** (v1.32.0 → v1.32.2). Per VERSIONS.md §4.4, patch releases auto-upgrade. Documenting here so the bump isn't mysterious in `go.mod` vs §2.4.

**Action item:** when next refreshing VERSIONS.md §2.4, sync the aws-sdk-go-v2 pin to whatever the s3 dep requires. Or pre-resolve at update time so internal consistency holds. Low priority; the buildguard tests remain green either way.

---

*Newest first. Add entries above this line when shipping engine changes.*
