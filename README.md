# shieldscan-engine

Go workers for the ShieldScan security scanning platform. Companion to
the Python API in [`shieldscan-api`](../shieldscan-api/).

## Architecture in 30 seconds

- **Python API** (in `shieldscan-api/`) is the sole writer of scan state
  to PostgreSQL (ADR-013). It dispatches scan jobs via Redis queues.
- **Go workers** (this repo) consume jobs, run scan tools, emit progress
  events and findings via Redis. They never touch PostgreSQL.
- **Communication** happens over Redis exclusively — see
  `../shieldscan-docs/SPECIFICATION.md` §7 for the wire contracts.

## Repository tour

```
shieldscan-engine/
├── cmd/
│   └── worker/main.go         # process entry — signal ctx, config load, run loop
├── internal/
│   ├── buildguard/            # cross-cutting forcing-function tests (ADR-013/016/021)
│   ├── config/                # env-driven config (NO PostgreSQL credentials)
│   └── events/                # SPEC §7 wire schemas + MaxFindingsPerEvent (ADR-017)
├── testdata/                  # tool-output fixtures (M6+); see testdata/README.md
├── go.mod                     # VERSIONS.md-derived; NO asynq (ADR-016)
└── .github/workflows/         # CI: vet + test -race + lint + build
```

Future packages (lazy-created):
- `internal/tools/` (Task 5.2) — `ToolRunner` interface + `NativeRunner` + `DockerServiceRunner`
- `internal/redis/` (Task 5.4) — queue consumer (`pubsub.go`) + progress publisher (`stream.go`)
- `internal/worker/` (Task 5.5) — processor + startup + health
- `deploy/docker-compose.services.yml` (Task 5.6) — MobSF/ZAP/Trivy/SQLMap

## Development

Prerequisites: Go 1.26.2, golangci-lint v2.11.4. See VERSIONS.md §C in
`shieldscan-docs/` for installation on Ubuntu 24.04.

```bash
# Install + tidy
go mod download
go mod tidy

# Test (matches CI)
go vet ./...
go test -race -count=1 ./...
golangci-lint run

# Build
go build -o bin/worker ./cmd/worker/

# Run locally (requires Redis at localhost:6379 — see .env.example)
cp .env.example .env  # edit values
SHIELDSCAN_REDIS_URL=redis://:<password>@localhost:6379/0 ./bin/worker
```

## Contributing

See [CLAUDE.md](./CLAUDE.md) — engine-specific operating manual + the
PR checklist for goroutine lifecycle, ctx propagation, and dependency
discipline.

For cross-cutting docs (CONSTITUTION, SPECIFICATION, VERSIONS, plan,
tool architecture, ops), see [`../shieldscan-docs/`](../shieldscan-docs/).

## ADRs

The four engine-shaping ADRs live in `../shieldscan-docs/SPECIFICATION.md` §13:

- **ADR-013** — Python sole writer for scan state (forcing function:
  workers MUST NOT have PG credentials)
- **ADR-016** — Raw Redis (not Asynq) for queue protocol
- **ADR-017** — Findings inline in `job_completed` events, 1000-finding
  soft cap with `event_seq` sequencing
- **ADR-018** — Streams (not Pub/Sub) for progress events
- **ADR-021** — ctx-discipline (3 rules)

Forcing-function tests for these live in `internal/buildguard/`.
