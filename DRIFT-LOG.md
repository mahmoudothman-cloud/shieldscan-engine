# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

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
