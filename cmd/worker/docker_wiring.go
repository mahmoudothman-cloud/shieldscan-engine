package main

import (
	"fmt"

	dockerclient "github.com/docker/docker/client"
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/nmap"
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

	runners := map[string]tools.ToolRunner{
		"nmap":            nmap.NewRunner(nmapPool, log),
		"trivy-container": trivy.NewContainerRunner(trivyPool, log),
		"trivy-fs":        trivy.NewFsRunner(trivyPool, log),
	}
	pools := []*docker.WarmPool{nmapPool, trivyPool}

	return runners, pools, nil
}
