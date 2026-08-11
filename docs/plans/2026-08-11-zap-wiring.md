# ZAP Engine Wiring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. **Do NOT start until this plan is approved.**

**Goal:** Wire the already-built OWASP ZAP DAST runner into the worker so `full_web` dispatches to `engine="zap"` successfully, taking `full_web` from 5/6 engines (PARTIAL) to 6/6 (COMPLETED).

**Architecture:** ZAP's runner already exists (`internal/tools/docker/service/zap`) and already satisfies `tools.ToolRunner` via the `DockerServiceRunner` framework — so it needs **no adapter**; it drops straight into the worker's flat registry map alongside native + one-shot docker runners. The work is (1) a small framework addition so the service container can be launched with the ZAP daemon's `-config api.key=…` args, (2) constructing zap with an env-sourced API key that feeds both the client and the container from one place, and (3) merging it into the registry under key `"zap"`. This is the **first-ever activation of a `DockerServiceRunner`** — everything unit-testable is cheap; the container/readiness/scan behaviour is only verifiable live and will need iteration on the box.

**Tech Stack:** Go 1.26, Docker SDK (`github.com/docker/docker`), the in-repo `internal/tools/docker/service` framework (service.go / spinup.go / client.go / readiness.go), zerolog, testify + a fake `docker.DockerClient` for unit tests.

---

## Ground-Truth Findings (verified in-repo at HEAD `27fcd37`)

The task listed 7 things the plan must cover. Answers first, since they drive the design:

1. **Does `DockerServiceRunner` need an adapter to live in the registry?** → **NO.** `internal/tools/docker/service/service.go:114` has `var _ tools.ToolRunner = (*DockerServiceRunner)(nil)` and implements `Name()` / `Category()` / `Run()` (service.go:117/120/131). `zap.NewRunner(...)` returns `*service.DockerServiceRunner` (zap.go:175). It is a `tools.ToolRunner` by construction — it goes into the `map[string]tools.ToolRunner` unchanged. **This is the load-bearing answer; no adapter task exists.**

2. **Where zap is constructed + merged.** `cmd/worker/docker_wiring.go:buildDockerRegistry` already owns the Docker client (`cli`) and returns `(runners map[string]tools.ToolRunner, pools []*docker.WarmPool, err)`. Add `"zap": zap.NewRunner(cli, zap.Config{APIKey: key}, log)` to the `runners` map (docker_wiring.go:88-93). `cmd/worker/run.go:82-88` already merges `dockerRunners` into `allRunners` → `NewRegistry`. **No run.go registry-merge change needed.** zap is `EphemeralContainer: true` (zap.go:183) → it has **no warm pool**, so it is NOT added to `pools`.

3. **`DockerSvcs` in run.go.** `StartupDeps.DockerSvcs []dockerHealthChecker` (startup.go:56) is a **real** Phase-2 startup health-check hook (warn-not-fail at MVP), not vestigial — but it targets *persistent* services with a long-lived container to probe. zap is **ephemeral-per-scan** (a fresh container per `Run`, no daemon alive at startup), so there is nothing for Phase 2 to probe. → **Leave `DockerSvcs` empty; zap is reached via the registry, not `DockerSvcs`.** The run.go:115 comment ("DockerSvcs remains empty until M7 … populates it via DockerServiceRunner instances") is now **stale/misleading** and must be updated to say: service runners are wired via the registry map; `DockerSvcs` stays empty because zap is ephemeral (a future *persistent* service — e.g. MobSF — may use it).

4. **The API key (the zap-specific infrastructure).** Two sides must carry the *same* key:
   - **(a) client side** — already handled inside `zap.NewRunner`: `ServiceConfig.ReadinessEndpoint = "/JSON/core/view/version/?apikey=" + cfg.APIKey` and `AuthFunc = zapQueryParamAuth(cfg.APIKey)` (zap.go:184-186). `NewBuildScan` rejects an empty key (zap.go:99).
   - **(b) container side** — the ZAP daemon must be launched with `-config api.key=<same key>`. **GAP CONFIRMED:** `ServiceContainerFactory` starts the container **without overriding Cmd** — `container.Config` is only `{Image, ExposedPorts}` (spinup.go:39, spinup.go:74-77). There is currently **no way to inject daemon args**, so the container comes up with the image's default key handling and the client's `?apikey=` will not match. → **This requires a framework sub-task (Task 1): add a `Cmd []string` to `ServiceContainerOpts` + `ServiceConfig`, thread it into `container.Config.Cmd`, and have `zap.NewRunner` populate it with the ZAP daemon command including `-config api.key=<APIKey>`.** Because both (a) and (b) derive from the single `cfg.APIKey` inside `zap.NewRunner`, they **match by construction** (single source of truth). Key **source:** env var `SHIELDSCAN_ZAP_API_KEY`, read in `buildDockerRegistry` (mirrors the `SHIELDSCAN_*_BINARY` env convention for the other docker tools); operator-set, required.

5. **Preflight/registration.** `registry.Engines()` returns sorted keys, so `"zap"` automatically appears in `registered_engines` (startup.go:126/136) and the heartbeat `engines` list (run.go:110) once it's in the map. Preflight: Phase 1 stat-checks **native** binaries (zap is not native → N/A); Phase 3 inits **warm pools** (zap is ephemeral → no pool → N/A). **zap needs no startup preflight.** The ZAP image is pulled **lazily on the first scan** (`ServiceContainerFactory` step 1), not at startup — so a bad image ref / no network fails the *first scan*, not worker startup. An optional startup image-pull preflight is explicitly **out of scope (YAGNI)**.

6. **Testing split.** Unit-testable: the `Cmd`-injection framework change (fake `docker.DockerClient` asserts `ContainerCreate` received the expected `Cmd`); zap's key wiring matches on both sides (assert the same `APIKey` reaches `ServiceConfig` client fields *and* `ServiceConfig.Cmd`); the registry contains `"zap"`. Live-only (cannot be unit-tested): the container actually spins up, the readiness poll succeeds, the `api.key` handshake is accepted, and a real active scan against a live target returns findings. See "Live Verification" + "Reality Check".

7. **Reality check** — see the dedicated section at the end (first service-runner ever; list of likely first-run breakages).

**DRY/YAGNI scope:** wire **zap only**. The `Cmd`-injection field is the minimum the framework needs for zap; MobSF (a future 2nd `DockerServiceRunner` consumer) will reuse the same field — **note it, do not build for it.** No generic multi-service machinery.

---

## Task 1: Framework — inject a launch `Cmd` into the service container

**Why:** ZAP's daemon needs `-config api.key=…` (and likely `-host 0.0.0.0` + `api.addrs` allow-list) at launch. The factory currently sets no `Cmd`. This is the only framework change; it is generic (a future persistent service reuses it) but minimal.

**Files:**
- Modify: `internal/tools/docker/service/spinup.go` (add `Cmd` to `ServiceContainerOpts` ~line 20-26; set `container.Config.Cmd` ~line 74-77)
- Modify: `internal/tools/docker/service/service.go` (add `Cmd []string` to `ServiceConfig` struct; pass it through `acquireEphemeral` ~line 176-183)
- Test: `internal/tools/docker/service/spinup_test.go` (fake `docker.DockerClient` capturing `ContainerCreate`'s `container.Config`)

**Step 1 — Write the failing test.** In `spinup_test.go`, using the existing fake-docker-client test infra (mirror how spinup/readiness are already tested), assert that `ServiceContainerFactory(ServiceContainerOpts{ContainerPort: 8080, Cmd: []string{"zap.sh","-daemon"}})` passes `Cmd == []string{"zap.sh","-daemon"}` into `ContainerCreate`'s `*container.Config`, and that an empty `Cmd` leaves `Config.Cmd` nil (image default preserved — the existing tools must be unchanged).

**Step 2 — Run it, verify it fails** (`go test ./internal/tools/docker/service/ -run TestServiceContainerFactory_Cmd -v`) → FAIL (field doesn't exist / Cmd not set).

**Step 3 — Minimal implementation.**
- `ServiceContainerOpts`: add `Cmd []string`.
- In the factory: `cfg := &container.Config{Image: imageRef, ExposedPorts: …}` then `if len(opts.Cmd) > 0 { cfg.Cmd = opts.Cmd }`.
- `ServiceConfig`: add `Cmd []string` (doc: "daemon launch command; empty = image default").
- `acquireEphemeral`: add `Cmd: r.ServiceConfig.Cmd` to the `ServiceContainerOpts{…}` literal.

**Step 4 — Run tests, verify pass** (the new test + the whole `service` package + `go build ./...`).

**Step 5 — Commit:** `test(service): inject launch Cmd into service container factory` / `feat(service): support Cmd override in ServiceConfig (first needed by ZAP api.key)`.

**Note:** whether the ZAP image needs `container.Config.Cmd` (args after the image ENTRYPOINT) vs a full command depends on the image's `ENTRYPOINT`. Start with `Cmd` only; `docker inspect ghcr.io/zaproxy/zaproxy` on the box decides if an `Entrypoint []string` override is also needed — if so, that's a tiny follow-up field, **flagged as a reality-check item, not built speculatively.**

---

## Task 2: zap.NewRunner sets the daemon `Cmd` with the API key

**Files:**
- Modify: `internal/tools/docker/service/zap/zap.go:175-190` (`NewRunner` — add `Cmd` to the `ServiceConfig`)
- Test: `internal/tools/docker/service/zap/zap_test.go`

**Step 1 — Failing test:** `TestNewRunner_ApiKeyReachesBothSides` — build `zap.NewRunner(fakeCli, zap.Config{APIKey: "K123"}, log)` and assert: (a) `r.ServiceConfig.ReadinessEndpoint` contains `apikey=K123` (already true — pins it), and (b) `strings.Join(r.ServiceConfig.Cmd, " ")` contains `api.key=K123`. This is the "both sides match" guard.

**Step 2 — Run, verify fail** (Cmd is empty today) → FAIL.

**Step 3 — Implement:** in `NewRunner`'s `ServiceConfig{…}`, add:
```go
Cmd: []string{
    "zap.sh", "-daemon",
    "-host", "0.0.0.0",
    "-port", strconv.Itoa(ContainerPort),
    "-config", "api.key=" + cfg.APIKey,
    // Allow API access from the mapped host port (non-localhost from ZAP's view).
    "-config", "api.addrs.addr.name=.*",
    "-config", "api.addrs.addr.regex=true",
},
```
(exact daemon flags are a live-verification item — see Reality Check; the test only pins that the key is present, so flag tuning won't break the unit test).

**Step 4 — Run tests, verify pass** (zap package).

**Step 5 — Commit:** `feat(zap): launch daemon with -config api.key so the client key matches the container`.

---

## Task 3: Read the API key from env + register zap in the worker

**Files:**
- Modify: `cmd/worker/docker_wiring.go` (import `.../service/zap`; read `SHIELDSCAN_ZAP_API_KEY`; add `"zap"` to the `runners` map at line 88-93)
- Test: `cmd/worker/docker_wiring_test.go` (or `run_test.go` where `buildDockerRegistry`/`buildRegistry` are already tested — the "9 engines" test lives in `run_test.go`)

**Step 1 — Failing test:** extend the registry-construction test to assert `runners["zap"] != nil` and `runners["zap"].Name() == "zap"` and `.Category() == "dast"`. (The engine-count assertion in `run_test.go` — currently "9 engines" for native — is separate; docker runners are a different map. Confirm which test enumerates the docker map and update its expected set to include `zap`.)

**Step 2 — Run, verify fail** → FAIL (no "zap" key).

**Step 3 — Implement in `buildDockerRegistry`:**
```go
zapAPIKey := os.Getenv("SHIELDSCAN_ZAP_API_KEY")
// (empty key is rejected at scan time by NewBuildScan; a startup guard/log is
//  optional — decide in review. Do NOT hard-fail startup for other tools' sake.)
runners := map[string]tools.ToolRunner{
    "nmap":            nmap.NewRunner(nmapPool, log),
    "trivy-container": trivy.NewContainerRunner(trivyPool, log),
    "trivy-fs":        trivyFsRunner,
    "sqlmap":          sqlmap.NewRunner(sqlmapPool, log),
    "zap":             zap.NewRunner(cli, zap.Config{APIKey: zapAPIKey}, log),
}
```
zap uses the **same `cli`** already created at the top of `buildDockerRegistry`; it is **not** added to `pools` (ephemeral, no warm pool).

**Step 4 — Run tests, verify pass**; `go build ./cmd/worker/`.

**Step 5 — Commit:** `feat(worker): wire the ZAP DAST service runner into the registry (full_web 6/6)`.

**Decision for review:** should an empty `SHIELDSCAN_ZAP_API_KEY` (a) fail worker startup, (b) warn-and-register (zap then fails per-scan with the existing clear error), or (c) skip registering zap (full_web stays 5/6 but doesn't error differently)? Recommendation: **(b) warn + register** — keeps startup resilient, and the per-scan error message is already explicit; document the env var in the runbook.

---

## Task 4: Fix the stale `DockerSvcs` comment in run.go

**Files:** Modify `cmd/worker/run.go:112-116`.

Replace the "DockerSvcs remains empty until M7 (Docker service tools) populates it via DockerServiceRunner instances" comment with an accurate one: service runners are wired into the **registry map** (like native + one-shot docker runners) and reached via `registry.Get`; `DockerSvcs` (Phase-2 startup health checks) stays **empty** because ZAP is ephemeral-per-scan (no persistent container to probe at startup). A future *persistent* service (e.g. MobSF) may populate `DockerSvcs`.

**Commit:** `docs(worker): correct the stale DockerSvcs/service-runner wiring comment`.

---

## Task 5: Live verification + iteration (NOT unit-coverable)

Cannot be done in tests — needs real Docker + the ZAP image + a live target. On the box, at HEAD with the commits above:
1. `export SHIELDSCAN_ZAP_API_KEY=<random 32+ char>`; rebuild `go build -o bin/worker ./cmd/worker/`; restart the worker.
2. Confirm `zap` appears in `registered_engines` (worker startup log) + the heartbeat `engines` list.
3. Trigger a `full_web` scan against the live target; watch the worker log for: image pull → container create/start → readiness poll (`/JSON/core/view/version`) → spider → (standard/deep) active scan → alerts → findings.
4. Confirm the scan reaches **COMPLETED (6/6)** and ZAP RawFindings persist.

Expect **iteration** here (see Reality Check). Do **not** hand-patch the box — fix in repo, rebuild, redeploy.

---

## Testing Summary

**Unit (this plan writes these):**
- `ServiceContainerFactory` sets `container.Config.Cmd` from `opts.Cmd`; empty `Cmd` ⇒ nil (existing tools unchanged). *(Task 1)*
- `zap.NewRunner` puts the **same** `APIKey` on both the client side (`ReadinessEndpoint`/`AuthFunc`) and the container side (`ServiceConfig.Cmd`). *(Task 2)*
- `buildDockerRegistry` returns a runner under `"zap"` with `Name()=="zap"`, `Category()=="dast"`. *(Task 3)*
- No adapter test — none needed (Q1).

**Live-only (Task 5, iterative, cannot be fully covered by tests):** container spin-up, readiness success, the `api.key` handshake being accepted by the daemon, active-scan duration under load, and a real scan returning findings.

---

## Reality Check — first-ever `DockerServiceRunner` activation

This is the first time any service runner runs in the worker. Most-likely first-run breakages, and what to watch:

1. **The `api.key` handshake (highest risk).** Three things must align: the client's `?apikey=` (set), the container's `-config api.key=` (Task 1+2), and ZAP's `api.addrs` allow-list. ZAP by default only accepts API calls from `localhost`; the client reaches it via the **mapped host port**, which ZAP sees as a non-local address → `API access denied` (403) unless `-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true` is set. Watch for 403s on the readiness probe.
2. **Whether it's `Cmd` vs `Entrypoint`.** The `ghcr.io/zaproxy/zaproxy` image's `ENTRYPOINT` determines if our `Cmd` should be `zap.sh -daemon …` (full) or just `-daemon …` (args). `docker inspect` the pinned image first; if the entrypoint already invokes `zap.sh`, our `Cmd` must be args-only. (Handle by adjusting Task 2's `Cmd`, or add a tiny `Entrypoint` field to Task 1 if truly required.)
3. **Readiness timing.** ZAP daemon boot can take 10-40s+ (longer on first pull). Framework default readiness timeout is **120s / 2s poll** (readiness.go:32-35) — probably enough, but if the probe times out the container is killed + removed and the scan errors. Watch the readiness loop; tune `ServiceConfig.ReadinessTimeout` if needed.
4. **Image pull on first scan.** The ZAP image is large and pulled lazily at the first scan → the first `full_web` is slow and network-sensitive; a bad ref / no registry access fails that scan. (Startup pre-pull is out of scope.)
5. **Active-scan duration vs timeouts.** A `standard`/`deep` active scan can run many minutes. Check that `ascanDuration(depth)` (zap.go:144), the framework `RequestTimeout`, and the outer processor/job timeout are all long enough — otherwise the scan is cancelled mid-active-scan.
6. **ZAP API version vs code assumptions.** The pinned image's ZAP API must match the endpoint paths/alert schema the runner assumes (`/JSON/core/view/version`, spider/ascan/alert endpoints, alert fields). A ZAP major-version mismatch surfaces as 404s or parse gaps.
7. **Ephemeral cleanup.** Each scan creates + stops a container (`acquireEphemeral` release, 30s stop ctx). Watch for container/port leaks if stop fails under load.

---

## Out of Scope (explicit)

- **MobSF** — a future 2nd `DockerServiceRunner` consumer. It will reuse the Task-1 `Cmd` field. **Noted, not built.**
- Generic multi-service registry machinery, startup image pre-pull, warm-pooling ZAP, and form-based ZAP auth (already forward-pinned in-code) — all out of scope.
- No changes on the deployed box beyond rebuild + redeploy of the worker.
