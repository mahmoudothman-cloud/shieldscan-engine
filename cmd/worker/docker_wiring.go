package main

import (
	"fmt"
	"os"

	dockerclient "github.com/docker/docker/client"
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/source"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/nmap"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service/zap"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/sqlmap"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/trivy"
)

// buildDockerRegistry constructs DockerRunner consumers + their warm
// pools per ADR-026. Parallel to buildRegistry which handles native
// CLI tools.
//
// Returns runners map (keyed by tool name) + pools list (for shutdown
// lifecycle registration in run.go drain path).
//
// Per Task 7.2 D4 brainstorming lock: separate function preserves
// buildRegistry's binary-resolution loop purpose; DockerRunner
// consumers genuinely diverge in shape (no native binary; warm pool
// init via docker SDK).
//
// Failure modes:
//   - Docker client init fails → fmt.Errorf wrapped with context
//   - Per-tool pool init fails (image pull, etc.) → fmt.Errorf wrapped
//
// Caller (runMain) treats failure as exit 1 (startup failure) — same
// posture as buildRegistry.
func buildDockerRegistry(log zerolog.Logger) (map[string]tools.ToolRunner, []*docker.WarmPool, error) {
	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: docker client init: %w", err)
	}

	nmapPool, err := nmap.NewPool(cli, log)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: nmap pool init: %w", err)
	}

	// Task 7.1 Trivy: single shared pool drives both ToolRunner
	// registrations per Q2 dual-registration lock (implementation plan
	// §3.5). NewContainerRunner + NewFsRunner exec different argv per
	// scan but share image + warm pool lifecycle.
	trivyPool, err := trivy.NewPool(cli, log)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: trivy pool init: %w", err)
	}

	// Task 7.6 SQLMap: single-runner pattern (mirrors Nmap precedent;
	// NOT Trivy dual-Name). DockerRunner exec-shape; Q1 (a) stdout-
	// parsing — NO Mounts capability used (NewPool sets Config.Mounts
	// nil; framework routes to DefaultContainerFactory).
	sqlmapPool, err := sqlmap.NewPool(cli, log)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: sqlmap pool init: %w", err)
	}

	// Source-Ingestion Fix (TOOL-ARCH §3.2 addendum 9d6ab25):
	// trivy-fs gets a source-aware wrapper that clones HTTPS git
	// URLs at job-pickup time. Staging base path is resolved from
	// $TRIVY_SCAN_BASE_PATH so the existing trivy-fs warm-pool bind
	// mount surfaces the staging tree as /scan/<scan-id> ReadOnly.
	// Falls back to trivy.DefaultScanBasePath when the env var is
	// unset (mirrors trivy.NewPool's resolution).
	trivyStageBase := os.Getenv(trivy.ScanBasePathEnv)
	if trivyStageBase == "" {
		trivyStageBase = trivy.DefaultScanBasePath
	}
	trivyStaging, err := source.NewStagingManager(trivyStageBase)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: trivy staging init: %w", err)
	}
	trivyFsRunner, err := trivy.NewFsSourceRunner(trivyPool, trivyStaging, log)
	if err != nil {
		return nil, nil, fmt.Errorf("worker: trivy-fs source runner init: %w", err)
	}

	// ZAP (OWASP DAST) — the FIRST DockerServiceRunner wired into the worker.
	// Unlike the one-shot DockerRunners above, ZAP runs an ephemeral service
	// container per scan (no warm pool → not added to `pools`). The daemon and
	// the client must share an API key; source it from the env. Empty key →
	// WARN + register anyway (graceful degradation, per the wiring-plan
	// decision): dropping zap would recreate the "no runner registered"
	// confusion, and failing startup would break the other engines over one
	// optional tool. A missing key instead surfaces as the explicit per-scan
	// "zap: APIKey required" error.
	zapAPIKey := os.Getenv("SHIELDSCAN_ZAP_API_KEY")
	if zapAPIKey == "" {
		log.Warn().Msg(
			"SHIELDSCAN_ZAP_API_KEY not set; zap engine registered but scans " +
				"will fail with 'zap: APIKey required' until it is configured",
		)
	}

	runners := map[string]tools.ToolRunner{
		"nmap":            nmap.NewRunner(nmapPool, log),
		"trivy-container": trivy.NewContainerRunner(trivyPool, log),
		"trivy-fs":        trivyFsRunner,
		"sqlmap":          sqlmap.NewRunner(sqlmapPool, log),
		"zap":             zap.NewRunner(docker.NewProductionClient(cli), zap.Config{APIKey: zapAPIKey}, log),
	}
	pools := []*docker.WarmPool{nmapPool, trivyPool, sqlmapPool}

	return runners, pools, nil
}
