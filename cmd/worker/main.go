// Package main is the shieldscan-engine worker binary entry point.
//
// The worker subscribes to Redis priority queues (shieldscan:queue:*),
// pulls scan jobs, runs the configured tool runner, and emits progress
// events to Redis Streams + completion events to Redis Pub/Sub. It
// never connects to PostgreSQL — Python is the sole writer per ADR-013.
//
// Task 5.1 ships the entry-point skeleton only: signal handling, ctx
// propagation, config load, ready-log, block on ctx.Done(). Job
// processing lands at Tasks 5.2-5.6.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/odyssey/shieldscan-engine/internal/config"
)

// main establishes the worker-root context (ADR-021 Rule 3 legitimate
// context.Background() location), loads config, and blocks until
// SIGTERM/SIGINT cancels the root context.
//
// The Run/Startup separation that lands in Task 5.6 will hang off the
// workerCtx derived here; goroutines spawned by the worker (heartbeat,
// processor, cancel-watcher) all derive children from workerCtx.
func main() {
	cfg, err := config.Load()
	if err != nil {
		// Pre-logger error path: write to stderr directly.
		log.Fatal().Err(err).Msg("config load failed")
	}

	configureLogging(cfg.LogLevel)

	// ADR-021 Rule 3: context.Background() at process entry only.
	// Every goroutine spawned downstream receives a child of workerCtx.
	workerCtx, workerCancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM,
	)
	defer workerCancel()

	log.Info().
		Str("worker_id", cfg.WorkerID).
		Int("concurrency", cfg.WorkerConcurrency).
		Str("redis_url", cfg.RedisURL).
		Msg("worker ready")

	// Block until SIGTERM/SIGINT. Task 5.6 replaces this with the full
	// startup sequence (binary checks, docker service health, warm pool
	// init, worker registration) followed by the BRPOP loop from 5.4.
	<-workerCtx.Done()

	log.Info().Msg("worker shutting down")
}

// configureLogging sets the global zerolog level from config.
// Invalid level strings fall back to info with a warning.
func configureLogging(level string) {
	parsed, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Str("requested_level", level).Msg("invalid log level; defaulting to info")
		parsed = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(parsed)
}
