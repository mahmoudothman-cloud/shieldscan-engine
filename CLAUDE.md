# CLAUDE.md — shieldscan-engine

**Engine-specific operating manual.** Delta from `../shieldscan-docs/CLAUDE.md`.
This file covers Go-specific rules, build commands, and the engine-side
PR checklist. For cross-cutting rules (TDD, document hierarchy, version
pinning, etc.), the parent CLAUDE.md still applies.

---

## Cross-cutting docs (`../shieldscan-docs/`)

**Always read first:**
- `../shieldscan-docs/CLAUDE.md` — parent operating manual (TDD, hierarchy, etc.)
- `../shieldscan-docs/VERSIONS.md` §2.1 + §2.4 — Go runtime + lib pins
- `../shieldscan-docs/SPECIFICATION.md` §7 — Redis wire contracts (read before
  touching `internal/events/` or `internal/redis/`)
- `../shieldscan-docs/SPECIFICATION.md` §13 ADRs:
  - **ADR-013** — DB-credentials forcing function (workers MUST NOT have PG access)
  - **ADR-014** — Streams (not Pub/Sub) for progress events
  - **ADR-016** — Raw Redis (not Asynq) for queue protocol
  - **ADR-017** — Findings inline in completions events with sequencing
  - **ADR-018** — Plan §5.4 Pub/Sub→Streams correction
  - **ADR-021** — ctx discipline (goleak as forcing function)

**Read on demand:**
- `../shieldscan-docs/SPECIFICATION.md` §3 — system architecture
- `../shieldscan-docs/TOOL-ARCHITECTURE.md` — when working on `internal/tools/`
- `../shieldscan-docs/OPERATIONS-RUNBOOK.md` — when touching `deploy/`

---

## Session startup checklist (engine-specific deltas)

Beyond the parent checklist:

```
[ ] Verify Go version: go version → expect go1.26.2
[ ] Verify lint version: golangci-lint --version → expect v2.11.4
[ ] go mod tidy && go test -race ./... — confirm clean baseline
[ ] Read the ADRs above for any task touching state-bearing code
```

---

## Go gotchas — ADR-021 ctx-discipline (mandatory)

Three rules. Code review and CI (lostcancel + golangci-lint
containedctx/noctx) enforce them; the rules below are what to consult
before writing.

### Rule 1: Every blocking call takes ctx

```go
// ❌ Bare time.Sleep ignores ctx; cancellation hangs.
time.Sleep(5 * time.Second)

// ✅ ctx-aware sleep.
select {
case <-ctx.Done():
    return ctx.Err()
case <-time.After(5 * time.Second):
}

// ❌ exec.Command — subprocess survives ctx cancel.
cmd := exec.Command("nuclei", args...)

// ✅ exec.CommandContext — ctx cancel SIGKILLs the subprocess.
cmd := exec.CommandContext(ctx, "nuclei", args...)
```

### Rule 2: Every goroutine has a ctx-aware exit

```go
// ❌ Fire-and-forget; survives shutdown.
go func() {
    for {
        emitMetric()
        time.Sleep(time.Second)
    }
}()

// ✅ ctx parameter + Done() in the loop.
go func(ctx context.Context) {
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            emitMetric()
        }
    }
}(workerCtx)
```

### Rule 3: ctx flows down, never back up

```go
// ❌ Severs cancel chain inside a request handler.
func handleScan(ctx context.Context) {
    go func() {
        bgCtx := context.Background()  // wrong — ctx-detached goroutine
        doLongRunningThing(bgCtx)
    }()
}

// ✅ Hand work to a worker-lifetime service via channel.
//    The service holds workerRootCtx (derived once in main()).
func handleScan(ctx context.Context, jobs chan<- Job) {
    select {
    case jobs <- Job{...}:
    case <-ctx.Done():
        return
    }
}
```

**Legitimate `context.Background()` locations** (Rule 3 carve-out):
- `main()` — process entry
- Top-level test functions — fresh ctx per test
- Worker-lifetime services constructed in `main()` and passed
  workerRootCtx — they don't construct `Background()` themselves

If you find yourself reaching for `context.Background()` outside these
three places, you're violating Rule 3. Re-architect the call site.

### `goleak.VerifyTestMain(m)` is mandatory

Every test package that spawns goroutines includes:

```go
func TestMain(m *testing.M) {
    goleak.VerifyTestMain(m,
        // goleak.IgnoreTopFunction(...) entries for known-OK background
        // goroutines (go-redis pool reaper, etc.) as discovered.
    )
}
```

Template lives in `internal/buildguard/buildguard_test.go`. Copy and
adjust the IgnoreTopFunction list as your test package's imports
require.

---

## Build / test commands

```bash
# Standard test cycle
go vet ./...
go test -race -count=1 ./...
golangci-lint run

# Single package, verbose
go test -v -race ./internal/events/...

# Single test
go test -v -run TestEvents_DisallowUnknownFields ./internal/events/

# Build worker
go build -o bin/worker ./cmd/worker/

# Verify build-graph forcing functions explicitly (ADR-013/016)
go test ./internal/buildguard/ -v
```

CI runs the same sequence (see `.github/workflows/engine.yml`).

---

## PR checklist (subsumes CONTRIBUTING.md)

Before opening a PR, confirm:

- [ ] **Tests** — `go test -race -count=1 ./...` passes locally
- [ ] **Vet** — `go vet ./...` clean (lostcancel guards Rule 1)
- [ ] **Lint** — `golangci-lint run` clean (containedctx + noctx guard
      Rules 1+3)
- [ ] **Format** — `gofmt -w internal/ cmd/` applied
- [ ] **No new bare `time.Sleep`** — search the diff
- [ ] **No new `exec.Command`** without `Context` — search the diff
- [ ] **Every new `go func()`** answers two questions: (1) what ctx
      cancels it? (2) what waits for it before declaring shutdown clean?
- [ ] **No `context.Background()` outside main/tests/worker-services** —
      see Rule 3
- [ ] **Dependencies** — any new module pinned in `../shieldscan-docs/VERSIONS.md`?
      If not, escalate before adding.
- [ ] **ADR-013 forcing function** — diff doesn't introduce `lib/pq`,
      `pgx`, or `database/sql` into `cmd/worker/`'s closure (buildguard
      test catches it; pre-empt at PR time)
- [ ] **ADR-016 forcing function** — diff doesn't reintroduce `asynq`
- [ ] **Wire schemas** — changes to `internal/events/` cross-checked
      against `../shieldscan-docs/SPECIFICATION.md` §7

---

## Pointer to parent

For everything not covered here — TDD discipline, document hierarchy,
commit message format, the broader Gotchas (Mobile Scans, Recon-First,
RLS, Fingerprint, AI Costs, Two Repositories, Idempotency Keys, Worker
Drain, etc.), refer to:

```
../shieldscan-docs/CLAUDE.md
```

The parent file is your operating manual. This file is the engine-
specific delta.
