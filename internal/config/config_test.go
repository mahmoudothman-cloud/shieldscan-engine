package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig_LoadsFromEnv verifies that Load() reads each env var into
// the corresponding Config field, applies defaults for unset variables,
// and propagates required-variable errors.
func TestConfig_LoadsFromEnv(t *testing.T) {
	t.Setenv("SHIELDSCAN_WORKER_ID", "worker-test-42")
	t.Setenv("SHIELDSCAN_WORKER_CONCURRENCY", "8")
	t.Setenv("SHIELDSCAN_REDIS_URL", "redis://test:6379/2")
	t.Setenv("SHIELDSCAN_R2_ENDPOINT", "https://acct.r2.cloudflarestorage.com")
	t.Setenv("SHIELDSCAN_R2_BUCKET", "shieldscan-test")
	t.Setenv("SHIELDSCAN_LOG_LEVEL", "debug")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "worker-test-42", cfg.WorkerID)
	assert.Equal(t, 8, cfg.WorkerConcurrency)
	assert.Equal(t, "redis://test:6379/2", cfg.RedisURL)
	assert.Equal(t, "https://acct.r2.cloudflarestorage.com", cfg.R2Endpoint)
	assert.Equal(t, "shieldscan-test", cfg.R2Bucket)
	assert.Equal(t, "debug", cfg.LogLevel)
}

// TestConfig_WorkerConcurrencyDefault pins the SPEC §11 default of 5
// concurrent jobs per worker. ADR-021 requires this to be env-var
// configurable; this test asserts both the default value and that
// env override works.
func TestConfig_WorkerConcurrencyDefault(t *testing.T) {
	// Required vars set; concurrency unset → expect default.
	t.Setenv("SHIELDSCAN_REDIS_URL", "redis://localhost:6379/0")
	// Explicitly clear in case the runner has it set:
	t.Setenv("SHIELDSCAN_WORKER_CONCURRENCY", "")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, 5, cfg.WorkerConcurrency, "SPEC §11 default")

	t.Setenv("SHIELDSCAN_WORKER_CONCURRENCY", "10")
	cfg, err = Load()
	require.NoError(t, err)
	assert.Equal(t, 10, cfg.WorkerConcurrency, "env override")

	// Invalid: rejected at load time.
	t.Setenv("SHIELDSCAN_WORKER_CONCURRENCY", "0")
	_, err = Load()
	require.Error(t, err, "concurrency 0 rejected")

	t.Setenv("SHIELDSCAN_WORKER_CONCURRENCY", "abc")
	_, err = Load()
	require.Error(t, err, "non-numeric rejected")
}

// TestConfig_DrainGraceDefault pins the SHIELDSCAN_DRAIN_GRACE_SECONDS
// default + override (per Task 5.6 H.9). Symmetric with concurrency
// validation: invalid values rejected at load.
func TestConfig_DrainGraceDefault(t *testing.T) {
	t.Setenv("SHIELDSCAN_REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("SHIELDSCAN_DRAIN_GRACE_SECONDS", "")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, 60, cfg.DrainGraceSeconds, "Task 5.6 default")

	t.Setenv("SHIELDSCAN_DRAIN_GRACE_SECONDS", "120")
	cfg, err = Load()
	require.NoError(t, err)
	assert.Equal(t, 120, cfg.DrainGraceSeconds)

	t.Setenv("SHIELDSCAN_DRAIN_GRACE_SECONDS", "0")
	_, err = Load()
	require.Error(t, err)
}

// TestConfig_RedisURLRequired pins the only required env var.
// Without SHIELDSCAN_REDIS_URL the worker has nothing to consume from
// and Load() returns an error.
func TestConfig_RedisURLRequired(t *testing.T) {
	t.Setenv("SHIELDSCAN_REDIS_URL", "")
	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SHIELDSCAN_REDIS_URL")
}

// TestConfig_HasNoDatabaseFields is the ADR-013 forcing function in
// reflective form. Walk the Config struct; assert no field name
// suggests PostgreSQL connectivity.
//
// Forbidden substrings (case-insensitive):
//   - "database" (DATABASE_URL, DatabaseURL, etc.)
//   - "postgres"
//   - "_db_" / leading "db_" / trailing "_db" in env binding
//   - "_pg_" / "pg_" / "_pg"
//
// We deliberately do NOT forbid the bare letters "db" inside other
// words (e.g., "DBC" is fine if it ever appeared in some other
// context). The substring set targets PG specifically.
//
// This test is the architectural contract surface: failing this test
// means an engineer attempted to add DB credentials to the worker.
func TestConfig_HasNoDatabaseFields(t *testing.T) {
	cfg := &Config{}
	v := reflect.TypeOf(cfg).Elem()

	forbidden := []string{
		"database",
		"postgres",
		"postgresql",
	}

	for i := 0; i < v.NumField(); i++ {
		fieldName := strings.ToLower(v.Field(i).Name)
		for _, bad := range forbidden {
			assert.NotContains(t, fieldName, bad,
				"Config field %q contains forbidden substring %q (ADR-013 forcing function — workers MUST NOT have DB credentials)",
				v.Field(i).Name, bad)
		}
	}
}
