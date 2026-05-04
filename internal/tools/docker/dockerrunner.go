package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// DefaultDockerTimeout is the fallback per-Run timeout for
// DockerRunner when neither ScanConfig.Timeout nor DockerRunner.Timeout
// is set. Mirrors tools.DefaultNativeTimeout (30 min) — same posture as
// NativeRunner; covers the longest expected single-tool scan with
// margin (deep Trivy scan against a giant filesystem; deep Nmap port
// sweep). Per-tool runners override via DockerRunner.Timeout when
// shorter bounds apply.
const DefaultDockerTimeout = 30 * time.Minute

// DockerRunner is the framework type for CLI-shaped Docker tools
// (Trivy, Nmap, SQLMap; future M7+ CLI Docker tools). Wraps a WarmPool
// and provides a tools.ToolRunner-shaped interface so the M5
// processor can invoke Docker tools identically to native tools.
//
// Per ADR-026 (DockerRunner framework + lazy warm pool — M7 container
// lifecycle architecture, 2026-05-XX): this is the CLI-tool framework.
// HTTP-shaped persistent services (ZAP, MobSF) use DockerServiceRunner
// (separate type at internal/tools/docker_service.go; Task 7.5b) per
// ADR-006 + ADR-008.
//
// Symmetric with tools.NativeRunner (M5.2 + ADR-023 OutputFile mode):
// per-tool config (image via Pool, BuildArgs, ParseOutput, Timeout,
// ExitCodeLenient); framework lifecycle + observability + finding
// enrichment.
//
// Per ADR-013 sole-writer atomicity: findings returned to caller (not
// persisted by runner); caller (worker.Processor) handles persistence
// per ADR-017 sequencing contract.
//
// Compile-time interface assertion at the bottom of this file (var _
// tools.ToolRunner = (*DockerRunner)(nil)) forces signature drift to
// surface at `go build` time.
type DockerRunner struct {
	// ToolName is the canonical tool name; surfaces via Name() and
	// applied to every finding's ToolName field. Mirrors NativeRunner.
	ToolName string

	// ToolCategory per TOOL-ARCHITECTURE §1; surfaces via Category()
	// and applied to every finding's EngineCategory field.
	ToolCategory string

	// Pool is the WarmPool of containers backing this runner. Required.
	// Construction: caller (Phase 4 wiring; per-tool consumer tasks)
	// builds the pool with the appropriate image + cleanup hook.
	Pool *WarmPool

	// BuildArgs constructs the CLI command for the tool, given target
	// + scan config. Returns argv slice passed verbatim to
	// Container.Exec. Symmetric with NativeRunner.BuildArgs.
	BuildArgs func(target tools.Target, cfg tools.ScanConfig) []string

	// ParseOutput parses tool stdout into RawFinding structs.
	// Identical signature to tools.NativeRunner.ParseOutput.
	// ParseOutput should NOT populate ToolName, EngineCategory,
	// DiscoveredAt, or Fingerprint — Run enriches those after parsing
	// (mirrors NativeRunner enrichment pattern at native.go:284-289).
	ParseOutput func(stdout []byte) ([]events.RawFinding, error)

	// ExitCodeLenient: same semantics as NativeRunner. If true,
	// non-zero exit codes are tolerated (tool may exit non-zero on
	// findings present, e.g., Trivy returns 1 for CVEs found). When
	// true, ParseOutput is called regardless of exit code.
	//
	// Default-strict (zero value, false) matches the dominant
	// "exit-zero-on-clean" convention; tools that don't follow it
	// must opt in explicitly.
	ExitCodeLenient bool

	// Timeout is the per-tool default timeout. cfg.Timeout (if > 0)
	// overrides at job-dispatch time. If both are zero,
	// DefaultDockerTimeout applies. Mirrors NativeRunner precedence.
	Timeout time.Duration

	Log zerolog.Logger
}

// Run implements the tools.ToolRunner contract. Checks out a warmed
// container; executes tool; parses + enriches findings; returns.
//
// Container is always returned to pool (cleanup runs between
// checkouts; failures handled by pool internally). Returns happen
// even on exec / parse failure to preserve pool integrity.
//
// Per ADR-021 ctx-discipline: ctx flows through to pool.Checkout +
// container.Exec; cancellation propagates to the daemon-side exec
// process.
func (r *DockerRunner) Run(ctx context.Context, target tools.Target, cfg tools.ScanConfig) ([]events.RawFinding, error) {
	if r.Pool == nil {
		return nil, fmt.Errorf("%s: Pool required", r.ToolName)
	}
	if r.BuildArgs == nil {
		return nil, fmt.Errorf("%s: BuildArgs required", r.ToolName)
	}
	if r.ParseOutput == nil {
		return nil, fmt.Errorf("%s: ParseOutput required", r.ToolName)
	}

	runCtx, cancel := context.WithTimeout(ctx, r.effectiveTimeout(cfg))
	defer cancel()

	// 1. Checkout container from pool.
	c, err := r.Pool.Checkout(runCtx)
	if err != nil {
		return nil, fmt.Errorf("%s: pool checkout: %w", r.ToolName, err)
	}

	// 2. Always return container to pool — even on exec / parse
	//    failure. Pool's Return runs the cleanup hook + manages size
	//    accounting; a Return failure is logged but does not mask the
	//    Run's primary outcome. Use a background-detached ctx for the
	//    Return path so a runCtx-deadline-driven cancel doesn't also
	//    abort the cleanup; cleanup gets up to 30s of grace.
	defer func() {
		returnCtx, returnCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer returnCancel()
		if returnErr := r.Pool.Return(returnCtx, c); returnErr != nil {
			r.Log.Warn().
				Err(returnErr).
				Str("tool", r.ToolName).
				Str("container_id", shortID(c.ID)).
				Msg("pool return failed")
		}
	}()

	// 3. Build args + exec inside container.
	args := r.BuildArgs(target, cfg)
	stdout, exitCode, execErr := c.Exec(runCtx, args)

	// 4. Handle exec error (network, container died, ctx cancel).
	if execErr != nil {
		return nil, fmt.Errorf("%s: exec: %w", r.ToolName, execErr)
	}

	// 5. Handle non-zero exit code per leniency policy.
	if exitCode != 0 && !r.ExitCodeLenient {
		return nil, fmt.Errorf("%s: non-zero exit code %d", r.ToolName, exitCode)
	}

	// 6. Parse output.
	findings, parseErr := r.ParseOutput(stdout)
	if parseErr != nil {
		return nil, fmt.Errorf("%s: parse: %w", r.ToolName, parseErr)
	}

	// 7. Enrich findings (mirrors NativeRunner.Run native.go:284-289).
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range findings {
		findings[i].ToolName = r.ToolName
		findings[i].EngineCategory = r.ToolCategory
		findings[i].DiscoveredAt = now
		findings[i].Fingerprint = tools.ComputeFingerprint(findings[i])
	}

	return findings, nil
}

// effectiveTimeout resolves the timeout precedence:
//
//	cfg.Timeout (if > 0)  →  DockerRunner.Timeout (if > 0)  →  DefaultDockerTimeout
//
// Mirrors tools.NativeRunner.effectiveTimeout exactly so behavior
// across the two runner types is symmetric for operators tuning
// per-tool timeouts via ScanConfig.
func (r *DockerRunner) effectiveTimeout(cfg tools.ScanConfig) time.Duration {
	if cfg.Timeout > 0 {
		return time.Duration(cfg.Timeout) * time.Second
	}
	if r.Timeout > 0 {
		return r.Timeout
	}
	return DefaultDockerTimeout
}

// Name implements ToolRunner identity (matches NativeRunner pattern).
func (r *DockerRunner) Name() string { return r.ToolName }

// Category implements ToolRunner identity.
func (r *DockerRunner) Category() string { return r.ToolCategory }

// Compile-time interface assertion. If DockerRunner ever drifts from
// the tools.ToolRunner signature, `go build` fails before tests run.
// Mirrors the same assertion pattern at internal/tools/native.go:147.
var _ tools.ToolRunner = (*DockerRunner)(nil)
