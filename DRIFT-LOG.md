# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

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
