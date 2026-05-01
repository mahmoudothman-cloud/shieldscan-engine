# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

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
