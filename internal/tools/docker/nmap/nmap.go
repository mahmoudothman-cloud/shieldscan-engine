package nmap

import (
	"errors"
	"fmt"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/rs/zerolog"
)

// Image is the canonical Nmap container image with digest pin.
// Per ADR-026 risk #14 image-pinning pattern + Phase 0 V5 resolution.
// Updated: 2026-05-06 (Task 7.2 first landing).
const Image = "instrumentisto/nmap:7.94@sha256:59e2c0bb2e001b14e453cebdf0ad1ba2ac907f4a14492ed67393e8c5bda96539"

// PoolMaxSize is the maximum concurrent Nmap container count per warm
// pool instance. Default 4 per Q9 brainstorming lock; suitable for
// pre-launch SME-scale customer base.
const PoolMaxSize = 4

// RunnerTimeout is the per-scan timeout for Nmap execution. Matches
// docker.DefaultDockerTimeout (30 min) per ADR-026 framework default.
// Customer override available via cfg.Timeout per ADR-026 3-tier
// precedence; aggressive port ranges (e.g., 1-65535) may require
// override.
const RunnerTimeout = 30 * time.Minute

// NewPool constructs the WarmPool for Nmap with Q9-locked configuration:
// digest-pinned image, MaxSize 4, NoCleanup (stateless), nil HealthCheck.
//
// Accepts a *client.Client (the real Docker SDK client) and internally
// adapts via docker.NewProductionClient. Tests use newPoolWithClient
// (file-local) with a stub-backed dockerClient for unit-test isolation.
func NewPool(cli *dockerclient.Client, log zerolog.Logger) (*docker.WarmPool, error) {
	if cli == nil {
		return nil, errors.New("nmap: docker client required")
	}
	pool, err := docker.New(docker.Config{
		Image:       Image,
		MaxSize:     PoolMaxSize,
		Cleanup:     docker.NoCleanup,
		HealthCheck: nil,
	}, docker.NewProductionClient(cli), log)
	if err != nil {
		return nil, fmt.Errorf("nmap: pool init: %w", err)
	}
	return pool, nil
}

// NewRunner constructs the DockerRunner consumer wiring buildArgs,
// parseOutput, and the Q9-locked configuration. The pool must be
// constructed via NewPool (or with equivalent Image+config).
//
// ToolCategory "recon" per D3 brainstorming lock — aligns with Q1 lock
// (Nmap dual-purpose: standalone scanner + M8 recon helper) and ADR-022
// recon-as-pre-scan-helpers framing.
func NewRunner(pool *docker.WarmPool, log zerolog.Logger) *docker.DockerRunner {
	return &docker.DockerRunner{
		ToolName:        "nmap",
		ToolCategory:    "recon",
		Pool:            pool,
		BuildArgs:       buildArgsAdapter,
		ParseOutput:     parseOutputForDocker,
		ExitCodeLenient: false,
		Timeout:         RunnerTimeout,
		Log:             log.With().Str("tool", "nmap").Logger(),
	}
}

// parseOutputForDocker adapts package parseOutput to DockerRunner's
// ParseOutput contract (no target parameter; per dockerrunner.go
// f5d77c8). Target is empty here; DockerRunner's enrichment loop
// populates ToolName/EngineCategory/DiscoveredAt/Fingerprint per
// ToolRunner contract — the original-target field is forward-pinned
// to a future framework extension if downstream audit-logging needs it.
func parseOutputForDocker(stdout []byte) ([]events.RawFinding, error) {
	return parseOutput(stdout, "")
}

// buildArgsAdapter adapts package buildArgs (which returns error) to
// DockerRunner's BuildArgs signature `func(target, cfg) []string`
// per dockerrunner.go f5d77c8 (no error return). On validation error,
// the adapter returns nil args; DockerRunner.Run will fail at exec
// time with the empty-command error.
//
// FORWARD-PIN: if buildArgs validation errors should propagate
// pre-Pool.Checkout (current behavior swallows the specific error
// reason, leaving the operator to debug from "exec failed" alone),
// consider extending DockerRunner.BuildArgs signature to include error
// return. Small framework change; affects future Trivy + SQLMap
// consumers. Surface for direction at Phase 5 ADR-027 if relevant.
func buildArgsAdapter(target tools.Target, cfg tools.ScanConfig) []string {
	args, err := buildArgs(target, cfg)
	if err != nil {
		return nil
	}
	return args
}
