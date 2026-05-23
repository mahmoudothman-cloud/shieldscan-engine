package sqlmap

import (
	"errors"
	"fmt"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/rs/zerolog"
)

// Image is the canonical SQLMap container image with digest pin.
// Per Task 7.6 V1 Phase 0 v2 verification (parrotsec/sqlmap:latest;
// SQLMap 1.10.4#stable; image published 5 days before pin; actively
// maintained; ENTRYPOINT=[sqlmap]).
//
// Rejected candidates per Phase 0 v2 V1.a: paoloo/sqlmap (stale; v1
// manifest schema; containerd v2.1+ pull fails); sqlmapproject/sqlmap
// + sqlmap/sqlmap (don't exist on Docker Hub).
//
// Per ADR-026 risk #14 image-pinning pattern.
const Image = "parrotsec/sqlmap:latest@sha256:740197a8356f338eeeb9875ed578643e3418acbdb4994d07ee9246d29c0d9bec"

// PoolMaxSize is the maximum concurrent SQLMap container count per
// warm pool instance. Default 4 per Q8 (a) cross-consumer convention
// matching Nmap + Trivy precedents.
const PoolMaxSize = 4

// RunnerTimeout is the per-scan timeout for SQLMap execution. Matches
// docker.DefaultDockerTimeout (30 min) per ADR-026 framework default.
// Accommodates Q5 (a) deep-scan duration (~3–5min) with substantial
// margin; aggressive --level=5/--risk=3 scans against complex targets
// may benefit from cfg.Timeout override at job-dispatch time.
const RunnerTimeout = 30 * time.Minute

// NewPool constructs the WarmPool for SQLMap with Q8 (a)-locked
// configuration: digest-pinned image, MaxSize 4, NoCleanup (stateless),
// nil HealthCheck. Mirrors Task 7.2 Nmap precedent shape exactly.
//
// Per Q1 (a) stdout-parsing lock: NO Mounts capability used.
// Config.Mounts left unset (nil); Task 7.5e WarmPool.New() three-branch
// decision tree routes to DefaultContainerFactory path (branch 3 —
// pre-7.5e behavior preserved; no host filesystem access required for
// SQLMap stdout-driven parsing strategy).
//
// Task 7.5e D-PLAN-7.5e-Phase2-Entrypoint universal fix (Entrypoint:
// []string{} in container.Config) covers parrotsec/sqlmap's
// ENTRYPOINT=[sqlmap] automatically; argv[0]="sqlmap" in buildArgs
// re-establishes binary invocation cleanly post-override.
func NewPool(cli *dockerclient.Client, log zerolog.Logger) (*docker.WarmPool, error) {
	if cli == nil {
		return nil, errors.New("sqlmap: docker client required")
	}
	pool, err := docker.New(docker.Config{
		Image:       Image,
		MaxSize:     PoolMaxSize,
		Cleanup:     docker.NoCleanup,
		HealthCheck: nil,
	}, docker.NewProductionClient(cli), log)
	if err != nil {
		return nil, fmt.Errorf("sqlmap: pool init: %w", err)
	}
	return pool, nil
}

// NewRunner constructs the DockerRunner consumer for SQLMap. Single
// runner pattern (NOT dual-Name like Trivy) — SQLMap has one canonical
// scanning mode (URL-driven SQLi detection).
//
// ToolCategory "dast" per Drift #28 W1 (a) disposition resolving the
// pre-verification finding that plan §3.8 specified `ToolCategory=
// "injection"` but the ToolRunner.Category() contract enum at
// internal/tools/runner.go does NOT include "injection". Canonical
// enum values are "dast"|"sast"|"mobile"|"ssl"|"recon"|"infrastructure"
// |"secrets"|"sca"|"api"|"container"|"iac". SQLMap is Dynamic
// Application Security Testing (active SQLi scanning against running
// URL endpoints); "dast" is the canonical fit. Drift tracked as
// D-PLAN-7.6-Drift-28 for Phase 3 commit body enumeration.
//
// ExitCodeLenient: false per SQLMap canonical exit-0-on-clean behavior
// (deviates from Trivy ExitCodeLenient: true — Trivy returns 1 for
// findings present by default; SQLMap returns 0 with findings inline
// in stdout). Default-strict behavior matches framework convention.
//
// ParseOutput is parseSQLMapOutput DIRECTLY — Group 1 surface report
// confirmed parseSQLMapOutput signature exactly matches
// DockerRunner.ParseOutput contract (no adapter wrapper needed;
// mirrors Trivy precedent).
//
// BuildArgs is buildArgs (Q9 (a) Target.URL-driven; Q5 (a) Depth
// mapping internal to buildArgs).
func NewRunner(pool *docker.WarmPool, log zerolog.Logger) *docker.DockerRunner {
	return &docker.DockerRunner{
		ToolName:        "sqlmap",
		ToolCategory:    "dast",
		Pool:            pool,
		BuildArgs:       buildArgs,
		ParseOutput:     parseSQLMapOutput,
		ExitCodeLenient: false,
		Timeout:         RunnerTimeout,
		Log:             log.With().Str("tool", "sqlmap").Logger(),
	}
}
