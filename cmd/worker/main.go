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
	"regexp"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/odyssey/shieldscan-engine/internal/config"
)

// redisCredentialRe matches the password segment of a redis:// or rediss://
// URL, including the shape the API and worker use (empty username, leading
// colon: redis://:<password>@host:port/db).
var redisCredentialRe = regexp.MustCompile(`(rediss?://[^:@/\s"]*:)[^@\s"]*(@)`)

// redactRedisCredential replaces the password in any Redis URL appearing in s.
// Applied to error strings before logging — go-redis's ParseURL wraps
// url.Parse errors that quote the full URL, so the error text itself can carry
// the credential even when the URL is never logged directly.
func redactRedisCredential(s string) string {
	return redisCredentialRe.ReplaceAllString(s, "${1}***${2}")
}

// installSIGPIPEGuard stops a dead stdout/stderr reader from killing the
// worker mid-shutdown.
//
// Go's runtime treats SIGPIPE specially: a write to a broken pipe on fd 1 or
// 2 terminates the process, while the same write on any other fd merely
// returns EPIPE. The worker is launched as `./bin/worker 2>&1 | tee ...`, so
// fd 1 and 2 ARE a pipe. Ctrl-C in the pane signals the whole foreground
// process group; `tee` has no handler and dies immediately; the worker
// catches SIGINT and its very first act is a log line (run.go's "shutdown
// signal received; draining in-flight jobs") — a write into a pipe with no
// reader. The process died there, so the drain never ran and
// WarmPool.Shutdown never reaped its containers.
//
// os/signal documents the escape: once SIGPIPE is registered via Notify, the
// signal is delivered to the channel instead of being fatal, and the write
// returns EPIPE like any other fd. Verified on go1.26.5 — without this,
// exit status is 141 (128+SIGPIPE) and cleanup never runs; with it, exit is
// 0 and cleanup completes. Pinned by TestSIGPIPEGuard* in sigpipe_test.go.
//
// The channel is buffered and deliberately never read: package signal sends
// non-blocking, so a full buffer simply drops later SIGPIPEs. Only the
// registration matters, and a reader goroutine would be one more thing to
// shut down (ADR-021 Rule 2) for no benefit.
//
// Note this makes log output best-effort once the reader is gone — writes
// fail silently rather than killing us. That is the correct trade: losing
// shutdown log lines is strictly better than losing the shutdown itself.
func installSIGPIPEGuard() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
}

func main() {
	// FIRST, before anything can write to stdout/stderr — the whole point is
	// to survive a reader that has already gone away.
	installSIGPIPEGuard()

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
		// Never log cfg.RedisURL, and never the raw error: the URL carries
		// the Redis password (redis://:<password>@host), and ParseURL
		// surfaces url.Parse errors that quote the offending URL verbatim.
		// A parse failure is exactly the case where the credential would
		// otherwise land in stdout and in the worker log file.
		log.Fatal().
			Str("error", redactRedisCredential(err.Error())).
			Msg("invalid SHIELDSCAN_REDIS_URL")
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
