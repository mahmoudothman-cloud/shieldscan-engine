package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/config"
	rdsh "github.com/odyssey/shieldscan-engine/internal/redis"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/worker"
)

// runMainDeps wires runMain's external dependencies. main() builds
// these from env-loaded config + a Redis client; tests build them
// from miniredis-backed clients.
type runMainDeps struct {
	Cfg    *config.Config
	Redis  *redis.Client
	Logger zerolog.Logger
}

// runMain is the assembly + lifecycle of the worker. Extracted from
// main() per Task 5.6 H.12 so integration tests can exercise the
// full shape without invoking signal handling.
//
// Returns an OS exit code:
//
//	0 — clean shutdown after ctx cancel + graceful drain
//	1 — startup failure (Phase 4 or earlier)
//	2 — drain timeout exceeded (force-cancel grace period)
//	3 — Worker.Run returned non-cancel error
//
// Lifecycle:
//
//  1. Build dependencies: registry, processor, worker, heartbeat.
//  2. Run startup phases (1: native, 2: docker, 3: deferred, 4: register).
//  3. Spawn heartbeat goroutine (worker-lifetime per ADR-021 Rule 3).
//  4. Spawn Worker.Run goroutine.
//  5. Wait for ctx cancel; observe drain via select on Worker.Run
//     completion vs DrainGraceSeconds timer.
//  6. Cleanup heartbeat exit (best-effort wait).
func runMain(ctx context.Context, deps runMainDeps) int {
	cfg := deps.Cfg
	log := deps.Logger
	client := deps.Redis

	// Empty registry at 5.6; M6+ task constructors populate engines.
	registry := worker.NewRegistry(map[string]tools.ToolRunner{})

	// Build Processor + Worker via convenience constructor.
	processor := worker.NewProcessorFromRedis(registry, client, log)
	consumer := rdsh.NewJobConsumer(client)
	workerInst := worker.NewWorker(worker.WorkerDeps{
		Consumer:    consumer,
		Processor:   processor,
		Concurrency: cfg.WorkerConcurrency,
		Logger:      log,
	})

	// Worker identity + heartbeat.
	workerID := generateWorkerID()
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	heartbeat := worker.NewHeartbeat(client, workerID, map[string]any{
		"hostname":    hostname,
		"started_at":  time.Now().UTC().Format(time.RFC3339),
		"concurrency": cfg.WorkerConcurrency,
		"engines":     registry.Engines(),
	}, log)

	// Run startup sequence.
	startup := worker.NewStartup(worker.StartupDeps{
		Registry:  registry,
		Heartbeat: heartbeat,
		Logger:    log,
		// NativeTools / DockerSvcs empty at 5.6; M6+ populates
		// via these fields when task constructors register tools.
	})
	if err := startup.Run(ctx); err != nil {
		log.Error().Err(err).Msg("startup failed")
		return 1
	}

	// Spawn heartbeat refresh loop (worker-lifetime per ADR-021 Rule 3).
	heartbeatDone := make(chan error, 1)
	go func() { heartbeatDone <- heartbeat.Run(ctx) }()

	// Spawn Worker.Run.
	runDone := make(chan error, 1)
	go func() { runDone <- workerInst.Run(ctx) }()

	graceSeconds := cfg.DrainGraceSeconds
	if graceSeconds <= 0 {
		graceSeconds = 60
	}

	// Wait for shutdown trigger.
	exitCode := 0
	select {
	case err := <-runDone:
		// Worker exited before ctx cancel — unexpected.
		if !isCancelLike(err) {
			log.Error().Err(err).Msg("worker exited with unexpected error")
			exitCode = 3
		} else {
			log.Info().Msg("worker exited cleanly")
		}
	case <-ctx.Done():
		log.Info().
			Int("grace_seconds", graceSeconds).
			Msg("shutdown signal received; draining in-flight jobs")
		select {
		case err := <-runDone:
			if !isCancelLike(err) {
				log.Error().Err(err).Msg("worker drain returned unexpected error")
				exitCode = 3
			} else {
				log.Info().Msg("worker drained cleanly")
			}
		case <-time.After(time.Duration(graceSeconds) * time.Second):
			log.Error().Int("grace_seconds", graceSeconds).Msg("drain timeout exceeded; forcing exit")
			exitCode = 2
		}
	}

	// Best-effort wait for heartbeat to exit.
	select {
	case <-heartbeatDone:
	case <-time.After(2 * time.Second):
		log.Warn().Msg("heartbeat did not exit cleanly within 2s")
	}

	log.Info().Int("exit_code", exitCode).Msg("worker shutdown complete")
	return exitCode
}

// generateWorkerID returns hostname-uuid8 (e.g., "worker-01-a1b2c3d4")
// per Task 5.6 H.1. Hostname for human-readable identity; UUID for
// uniqueness on multi-worker hosts.
func generateWorkerID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "worker"
	}
	return hostname + "-" + shortUUID()
}

// shortUUID returns 8 hex chars (4 random bytes). Sufficient entropy
// for worker fleet of <millions; collision probability negligible.
//
// Fatal on rand failure: without unique worker ID we can't register
// correctly. crypto/rand failure on Linux is essentially impossible
// (would indicate severe system breakage).
func shortUUID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
