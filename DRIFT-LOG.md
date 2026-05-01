# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

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
