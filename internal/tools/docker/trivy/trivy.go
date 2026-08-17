package trivy

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/docker/docker/api/types/mount"
	dockerclient "github.com/docker/docker/client"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/rs/zerolog"
)

// ScanBasePathEnv is the environment variable name controlling the
// host-side base path bind-mounted into Trivy warm-pool containers.
// Per Task 7.5e V2 lock: default "/tmp"; override via env var for
// alternate scan-target staging directories.
const ScanBasePathEnv = "TRIVY_SCAN_BASE_PATH"

// ScanContainerPath is the canonical container-side mount target for
// the host scan-base-path bind-mount. Trivy fs-mode scans address
// targets via this path (e.g. /scan/<fs-test-dir>).
const ScanContainerPath = "/scan"

// DefaultScanBasePath is the default host-side base path bind-mounted
// into Trivy warm-pool containers when TRIVY_SCAN_BASE_PATH is unset.
// Per Task 7.5e V2 + Phase 0 v2 verification (/tmp/trivy-fs-test/
// canonical testbed location).
const DefaultScanBasePath = "/tmp"

// Image is the canonical Trivy container image with digest pin.
// Per ADR-026 risk #14 image-pinning pattern + Task 7.1 Phase 0 v2 V1
// verification (shieldscan-docs commit 615e010 implementation plan
// §1 + Phase 0 v2 surface report; verified against Docker Hub
// `aquasec/trivy:0.70.0` tag).
const Image = "aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"

// PoolMaxSize is the maximum concurrent Trivy container count per
// warm pool instance. Default 4 mirroring Task 7.2 Nmap precedent
// (suitable for pre-launch SME-scale customer base). Per
// implementation plan §3.5 concretization.
const PoolMaxSize = 4

// RunnerTimeout is the per-scan timeout for Trivy execution. Matches
// docker.DefaultDockerTimeout (30 min) per ADR-026 framework default.
// Customer override available via cfg.Timeout per ADR-026 3-tier
// precedence; deep Trivy scans against giant filesystems (per ADR-026
// line 2093 anticipated framework-gap path) may require override.
const RunnerTimeout = 30 * time.Minute

// NewPool constructs the WarmPool for Trivy with implementation plan
// §3.5-locked configuration: digest-pinned image, MaxSize 4,
// NoCleanup (stateless), nil HealthCheck.
//
// Per Q2 dual-registration lock: SINGLE shared pool drives BOTH
// NewContainerRunner + NewFsRunner. Both modes consume the same Trivy
// container image; warm-pool fan-out by mode is unnecessary
// (containers exec different argv per checkout).
//
// Per Task 7.5e V1 + V2 + V4 locks (Phase 0 v2 empirical grounding):
// pool containers receive a single bind-mount from $TRIVY_SCAN_BASE_PATH
// on the host (defaults to /tmp via DefaultScanBasePath) to /scan inside
// the container, ReadOnly. fs-mode scan targets (lockfiles, dependency
// manifests) are addressed via /scan/<subpath>. ReadOnly:true sufficient
// per V4 empirical verification (Trivy fs-scan is purely read-only).
// Image-mode scans need no mount per V1.s-ii OCI-sufficient finding;
// the mount is harmless when unused.
//
// Accepts a *client.Client (the real Docker SDK client) and internally
// adapts via docker.NewProductionClient. Mirrors Task 7.2 Nmap
// precedent shape (internal/tools/docker/nmap/nmap.go) extended with
// Task 7.5e Mounts capability.
func NewPool(cli *dockerclient.Client, workerID string, log zerolog.Logger) (*docker.WarmPool, error) {
	if cli == nil {
		return nil, errors.New("trivy: docker client required")
	}

	scanBasePath := os.Getenv(ScanBasePathEnv)
	if scanBasePath == "" {
		scanBasePath = DefaultScanBasePath
	}
	mounts := []mount.Mount{
		{
			Type:     mount.TypeBind,
			Source:   scanBasePath,
			Target:   ScanContainerPath,
			ReadOnly: true,
		},
	}

	pool, err := docker.New(docker.Config{
		Image:       Image,
		MaxSize:     PoolMaxSize,
		Labels:      docker.PoolLabels(workerID, "trivy"),
		Mounts:      mounts,
		Cleanup:     docker.NoCleanup,
		HealthCheck: nil,
	}, docker.NewProductionClient(cli), log)
	if err != nil {
		return nil, fmt.Errorf("trivy: pool init: %w", err)
	}
	return pool, nil
}

// NewContainerRunner constructs the DockerRunner consumer for Trivy
// image-mode (container scanning). Per Q2 dual-registration lock:
// Name "trivy-container" + Category "container" distinguishes from
// NewFsRunner; both runners share the SAME pool returned by NewPool.
//
// Per Y1 lock (PRE-P1 verification): ExitCodeLenient: true is set on
// the runner as defense-in-depth — the buildArgs already passes
// --exit-code 0 to Trivy to force zero-exit on findings present, but
// the framework leniency catches any behavior drift if a future Trivy
// version changes default exit-code semantics. Either layer alone
// would suffice for the v0.70.0 canonical behavior; both together
// guard against version-drift surprise.
//
// Y2 routes: BuildArgs is buildArgsImage (consumes Target.URL for
// image reference).
//
// ParseOutput is parseTrivyJSON DIRECTLY (no adapter wrapper needed
// per Group 1 surface report — parseTrivyJSON signature exactly
// matches DockerRunner.ParseOutput contract).
func NewContainerRunner(pool *docker.WarmPool, log zerolog.Logger) *docker.DockerRunner {
	return &docker.DockerRunner{
		ToolName:        "trivy-container",
		ToolCategory:    "container",
		Pool:            pool,
		BuildArgs:       buildArgsImage,
		ParseOutput:     parseTrivyJSON,
		ExitCodeLenient: true,
		Timeout:         RunnerTimeout,
		Log:             log.With().Str("tool", "trivy-container").Logger(),
	}
}

// NewFsRunner constructs the DockerRunner consumer for Trivy fs-mode
// (filesystem / dependency-manifest scanning). Per Q2 dual-registration
// lock: Name "trivy-fs" + Category "sca" distinguishes from
// NewContainerRunner. Shares pool with NewContainerRunner.
//
// Per Y2 lock: BuildArgs is buildArgsFs (consumes Target.SourcePath).
// All other framework configuration (Image, ExitCodeLenient, Timeout)
// matches NewContainerRunner.
func NewFsRunner(pool *docker.WarmPool, log zerolog.Logger) *docker.DockerRunner {
	return &docker.DockerRunner{
		ToolName:        "trivy-fs",
		ToolCategory:    "sca",
		Pool:            pool,
		BuildArgs:       buildArgsFs,
		ParseOutput:     parseTrivyJSON,
		ExitCodeLenient: true,
		Timeout:         RunnerTimeout,
		Log:             log.With().Str("tool", "trivy-fs").Logger(),
	}
}
