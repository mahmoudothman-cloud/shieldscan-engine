package trivy

import (
	"context"
	"errors"
	"fmt"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/source"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/rs/zerolog"
)

// FsSourceRunner wraps the inner trivy-fs DockerRunner with host-side
// source acquisition per the Source-Ingestion Fix task (shieldscan-
// docs commits 90fc933 design + 04f44a9 plan + 9d6ab25 TOOL-ARCH §3.2
// addendum + shieldscan-api 8dbcbab orchestrator threading).
//
// Architectural rationale (Drift #57 catch-class):
// The DockerRunner framework exposes BuildArgs (target → argv; pure)
// and ParseOutput (stdout → findings) hooks but no pre-Run hook for
// state-mutating side effects like source acquisition. Rather than
// retroactively widening DockerRunner with a pre-Run hook (which
// would impact every consumer), this task introduces a thin
// ToolRunner shim that: (1) clones the source on the host before
// (2) delegating Run() to the inner DockerRunner.
//
// Trade-off acknowledged: the shim duplicates Name() + Category()
// declaration alongside the inner DockerRunner. Acceptable for the
// single-consumer case (only trivy-fs needs source-acquisition
// today); promotion to a framework-level pre-Run hook is forward-
// pinned per rule-of-three (second SAST consumer wiring).
type FsSourceRunner struct {
	inner   *docker.DockerRunner
	staging *source.StagingManager
	log     zerolog.Logger
}

// NewFsSourceRunner constructs the source-aware wrapper around the
// inner trivy-fs DockerRunner. stagingMgr owns the per-scan tempdir
// lifecycle (typically rooted at $TRIVY_SCAN_BASE_PATH so the existing
// trivy-fs warm-pool bind mount surfaces the staging tree as
// /scan/<scan-id> inside the container, ReadOnly).
func NewFsSourceRunner(
	pool *docker.WarmPool,
	stagingMgr *source.StagingManager,
	log zerolog.Logger,
) (*FsSourceRunner, error) {
	if pool == nil {
		return nil, errors.New("trivy: FsSourceRunner pool required")
	}
	if stagingMgr == nil {
		return nil, errors.New(
			"trivy: FsSourceRunner stagingMgr required",
		)
	}
	inner := NewFsRunner(pool, log)
	return &FsSourceRunner{
		inner:   inner,
		staging: stagingMgr,
		log:     log.With().Str("tool", "trivy-fs").Logger(),
	}, nil
}

// Name implements tools.ToolRunner. Delegates to the inner
// DockerRunner so the registry key + finding ToolName field stay
// canonical ("trivy-fs").
func (r *FsSourceRunner) Name() string { return r.inner.Name() }

// Category implements tools.ToolRunner. Delegates to the inner
// DockerRunner ("sca").
func (r *FsSourceRunner) Category() string { return r.inner.Category() }

// Run implements tools.ToolRunner. Source-acquisition sequence per
// design doc §3.5:
//
//  1. If target.SourceRepoURL is empty, delegate immediately to the
//     inner runner — buildArgsFs preserves the "empty SourcePath →
//     nil argv → exec error" guard. This keeps the runner functional
//     for legacy callers that pre-stage SourcePath (none exist
//     today, but the invariant matches buildArgsFs's pre-fix
//     contract).
//
//  2. Validate target.ScanID is present. Without it, the staging
//     manager cannot derive a stable, collision-free path. Hard-
//     fail per Q-FAILURE-MODE; surfaces as ScanJob FAILED via the
//     existing processor error-emission path (Q-EVENTS standard
//     lifecycle).
//
//  3. Resolve the host-side staging directory; clone HTTPS git URL
//     with --depth=1 via source.CloneRepo. Clone failure → hard-
//     fail with structured error (Q-CLONE-FAILURE-EVENT-SHAPE a).
//
//  4. Defer host-side cleanup via os.RemoveAll. ReadOnly mount
//     inside the container does NOT block this (the mount is
//     container-namespace-enforced; the host fs is read-write).
//
//  5. Populate target.SourcePath to the container-relative path
//     (/scan/<scan-id>) and delegate to the inner DockerRunner.
//
// ctx cancellation propagates through source.CloneRepo
// (exec.CommandContext) and the inner DockerRunner.Run per ADR-021
// Rule 1.
func (r *FsSourceRunner) Run(
	ctx context.Context,
	target tools.Target,
	cfg tools.ScanConfig,
) ([]events.RawFinding, error) {
	if target.SourceRepoURL == "" {
		// Legacy path: buildArgsFs guard reports exec error on
		// empty SourcePath. Source-Ingestion Fix repairs Drift #54
		// at the orchestrator + ScanCreateRequest layer; reaching
		// here with empty SourceRepoURL means a non-source-
		// requiring ScanType somehow routed to this runner OR an
		// engine-direct producer bypassed the api gate. Surface
		// rather than silently no-op.
		return r.inner.Run(ctx, target, cfg)
	}
	if target.ScanID == "" {
		return nil, fmt.Errorf(
			"trivy-fs: ScanID required when SourceRepoURL is set",
		)
	}

	stagingDir, err := r.staging.StagingDirForScan(target.ScanID)
	if err != nil {
		return nil, fmt.Errorf(
			"trivy-fs: resolve staging dir: %w", err,
		)
	}
	if err := source.CloneRepo(ctx, target.SourceRepoURL, stagingDir); err != nil {
		return nil, fmt.Errorf(
			"trivy-fs: source acquisition failed: %w", err,
		)
	}
	// Defer host-side cleanup. A Cleanup failure is logged but does
	// not mask the Run's primary outcome (mirrors DockerRunner's
	// Pool.Return discipline at dockerrunner.go).
	defer func() {
		if cleanupErr := r.staging.Cleanup(target.ScanID); cleanupErr != nil {
			r.log.Warn().
				Err(cleanupErr).
				Str("scan_id", target.ScanID).
				Msg("trivy-fs: staging cleanup failed (best-effort)")
		}
	}()

	// Container-relative path per Q-STAGING-PATH lock: the trivy-fs
	// warm-pool bind mounts $TRIVY_SCAN_BASE_PATH → /scan ReadOnly,
	// so /scan/<scan-id> inside the container resolves to the host
	// stagingDir we just populated.
	target.SourcePath = "/scan/" + target.ScanID
	return r.inner.Run(ctx, target, cfg)
}
