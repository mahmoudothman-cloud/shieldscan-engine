// Package main is the shieldscan-engine worker binary entry point.
//
// main() is intentionally small: it loads config, builds the Redis
// client + signal-derived context, and delegates the rest to runMain.
// The runMain extraction enables integration tests (cmd/worker/run_test.go)
// to exercise the full assembly without invoking signal handling.
//
// Per ADR-013 (Python sole writer): no PostgreSQL access anywhere
// in this binary. The buildguard test from Task 5.1 enforces.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/odyssey/shieldscan-engine/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("config load failed")
	}
	configureLogging(cfg.LogLevel)

	// ADR-021 Rule 3: context.Background() at process entry only.
	workerCtx, workerCancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM,
	)
	defer workerCancel()

	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatal().Err(err).Str("url", cfg.RedisURL).Msg("invalid SHIELDSCAN_REDIS_URL")
	}
	redisClient := redis.NewClient(redisOpts)
	defer func() { _ = redisClient.Close() }()

	// Phase 0: verify Redis connection (per Task 5.6 H.8).
	pingCtx, pingCancel := context.WithTimeout(workerCtx, 5*time.Second)
	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		pingCancel()
		log.Fatal().Err(err).Msg("Redis connection failed (phase 0)")
	}
	pingCancel()
	log.Info().Msg("phase 0 (redis ping) ok")

	exitCode := runMain(workerCtx, runMainDeps{
		Cfg:    cfg,
		Redis:  redisClient,
		Logger: log.Logger,
	})
	os.Exit(exitCode)
}

func configureLogging(level string) {
	parsed, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Warn().Str("requested_level", level).Msg("invalid log level; defaulting to info")
		parsed = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(parsed)
}

// errCancel-detection helpers — keep main()'s exit-code mapping
// simple. Treat ctx.Canceled / DeadlineExceeded as expected during
// shutdown; any other Worker.Run error is unexpected.
func isCancelLike(err error) bool {
	return err == nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}
