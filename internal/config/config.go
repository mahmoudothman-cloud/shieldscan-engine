// Package config loads the worker process's environment-driven
// configuration.
//
// ADR-013 forcing function: this struct deliberately contains NO
// PostgreSQL credentials. Workers do not connect to PostgreSQL.
// Test TestConfig_HasNoDatabaseFields uses reflection to assert no
// field name suggests DB connectivity. If a future change adds
// DATABASE_URL or POSTGRES_* fields, that test fails and the change
// must be reverted or escalate ADR-013 for revision.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config carries every runtime parameter the worker process needs.
//
// Field naming convention:
//   - All fields are exported (camelCase Go convention).
//   - Env var binding follows SHIELDSCAN_<UPPER_SNAKE>.
//   - Defaults are applied in Load() when env var is absent.
//
// Forbidden field names (per TestConfig_HasNoDatabaseFields):
// any name containing "Database", "Postgres", "DB" (as full word), "PG".
type Config struct {
	// WorkerID is the human-readable worker identifier used for
	// Redis registration and audit logging. Defaults to "worker-<pid>"
	// when env var is unset.
	WorkerID string

	// WorkerConcurrency is the number of jobs this worker process
	// pulls from BRPOP concurrently. Per SPEC §11 default is 5.
	// Env-var configurable so M8 fan-out work can tune without touching
	// 5.5's BRPOP loop (ADR-021).
	WorkerConcurrency int

	// RedisURL points to the Redis instance carrying queues, streams,
	// pub/sub channels. Format: redis://[user:pass@]host:port[/db].
	RedisURL string

	// R2Endpoint, R2AccessKeyID, R2SecretAccessKey, R2Bucket configure
	// the S3-compatible object store used for mobile artifact downloads
	// (M7 MobSF) and future findings staging (ADR-017 Option C trigger).
	R2Endpoint        string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2Bucket          string

	// LogLevel is the zerolog level: trace|debug|info|warn|error|fatal|panic.
	LogLevel string

	// SentryDSN enables Sentry telemetry when non-empty.
	SentryDSN string
}

// Load reads environment variables and returns a populated Config.
// Defaults apply for unset variables; missing required variables
// return an error.
//
// Required (no default):
//   - SHIELDSCAN_REDIS_URL
//
// Defaulted:
//   - SHIELDSCAN_WORKER_ID            → worker-<pid>
//   - SHIELDSCAN_WORKER_CONCURRENCY   → 5
//   - SHIELDSCAN_LOG_LEVEL            → info
//
// Optional (empty string is allowed):
//   - SHIELDSCAN_R2_*
//   - SHIELDSCAN_SENTRY_DSN
func Load() (*Config, error) {
	cfg := &Config{
		WorkerID:          envOr("SHIELDSCAN_WORKER_ID", fmt.Sprintf("worker-%d", os.Getpid())),
		RedisURL:          os.Getenv("SHIELDSCAN_REDIS_URL"),
		R2Endpoint:        os.Getenv("SHIELDSCAN_R2_ENDPOINT"),
		R2AccessKeyID:     os.Getenv("SHIELDSCAN_R2_ACCESS_KEY_ID"),
		R2SecretAccessKey: os.Getenv("SHIELDSCAN_R2_SECRET_ACCESS_KEY"),
		R2Bucket:          os.Getenv("SHIELDSCAN_R2_BUCKET"),
		LogLevel:          envOr("SHIELDSCAN_LOG_LEVEL", "info"),
		SentryDSN:         os.Getenv("SHIELDSCAN_SENTRY_DSN"),
	}

	concurrency, err := envInt("SHIELDSCAN_WORKER_CONCURRENCY", 5)
	if err != nil {
		return nil, fmt.Errorf("SHIELDSCAN_WORKER_CONCURRENCY: %w", err)
	}
	if concurrency < 1 {
		return nil, fmt.Errorf("SHIELDSCAN_WORKER_CONCURRENCY must be >= 1 (got %d)", concurrency)
	}
	cfg.WorkerConcurrency = concurrency

	if cfg.RedisURL == "" {
		return nil, errors.New("SHIELDSCAN_REDIS_URL is required")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q: %w", raw, err)
	}
	return v, nil
}
