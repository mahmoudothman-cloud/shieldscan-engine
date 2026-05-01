package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/odyssey/shieldscan-engine/internal/config"
)

// TestMain wires goleak.VerifyTestMain — load-bearing because
// runMain spawns the heartbeat + Worker goroutines. Leak detection
// here is the ADR-021 Rule 2 forcing function for the full assembly.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).reaper"),
		goleak.IgnoreAnyFunction("github.com/alicebob/miniredis/v2.(*Miniredis).serve.func1"),
	)
}

// runMainFixture spins up miniredis + builds the runMainDeps. Auto-
// cleans via t.Cleanup.
func runMainFixture(t *testing.T) (runMainDeps, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	cfg := &config.Config{
		WorkerID:          "test-worker",
		WorkerConcurrency: 2,
		RedisURL:          "redis://" + mr.Addr() + "/0",
		DrainGraceSeconds: 5,
		LogLevel:          "info",
	}
	return runMainDeps{
		Cfg:    cfg,
		Redis:  client,
		Logger: zerolog.Nop(),
	}, mr, client
}

// TestRunMain_HappyPathStartsWorker pins the canonical assembly:
// runMain starts the worker; ctx cancel exits cleanly with exit code 0.
func TestRunMain_HappyPathStartsWorker(t *testing.T) {
	deps, _, _ := runMainFixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	// Let startup complete.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case code := <-exitCh:
		assert.Equal(t, 0, code, "clean shutdown returns exit code 0")
	case <-time.After(10 * time.Second):
		t.Fatal("runMain did not exit within 10s of ctx cancel")
	}
}

// TestRunMain_RegistrationVisibleInRedis pins Phase 4: after startup,
// the worker key is set and readable via the Redis client.
func TestRunMain_RegistrationVisibleInRedis(t *testing.T) {
	deps, _, client := runMainFixture(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	// Wait for startup (Phase 4) to complete.
	require.Eventually(t, func() bool {
		keys, err := client.Keys(t.Context(), "shieldscan:workers:*").Result()
		return err == nil && len(keys) > 0
	}, 2*time.Second, 50*time.Millisecond, "worker key should appear in Redis after Phase 4")

	keys, err := client.Keys(t.Context(), "shieldscan:workers:*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	val, err := client.Get(t.Context(), keys[0]).Result()
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(val), &payload))
	assert.NotEmpty(t, payload["worker_id"])
	assert.NotEmpty(t, payload["hostname"])
	assert.Equal(t, float64(2), payload["concurrency"], "matches cfg.WorkerConcurrency")

	cancel()
	<-exitCh
}

// TestRunMain_HeartbeatRefreshesTTL pins the worker-lifetime
// heartbeat: Run loop refreshes the worker key over time (registered_at
// updates).
func TestRunMain_HeartbeatRefreshesTTL(t *testing.T) {
	deps, _, client := runMainFixture(t)
	// Override default heartbeat timings via ConfigOverrides? We
	// don't have that mechanism; but the test can just verify the
	// initial write happened. Refresh-cadence is verified in
	// internal/worker/heartbeat_test.go.

	ctx, cancel := context.WithCancel(t.Context())
	exitCh := make(chan int, 1)
	go func() { exitCh <- runMain(ctx, deps) }()

	require.Eventually(t, func() bool {
		ttl, err := client.TTL(t.Context(), "shieldscan:workers:"+findWorkerKey(t, client)).Result()
		return err == nil && ttl > 0
	}, 2*time.Second, 50*time.Millisecond, "worker key should have positive TTL")

	cancel()
	<-exitCh
}

// TestRunMain_StartupFailureExitsOne pins startup-failure → exit 1.
// Achieve by closing miniredis before runMain, so Phase 4 SETEX fails.
func TestRunMain_StartupFailureExitsOne(t *testing.T) {
	deps, mr, _ := runMainFixture(t)

	mr.Close() // SETEX will fail.

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	code := runMain(ctx, deps)

	assert.Equal(t, 1, code, "startup failure returns exit code 1")
}

// TestShortUUID_Distinct pins worker ID uniqueness: two calls produce
// different strings (4 bytes random = 32 bits entropy).
func TestShortUUID_Distinct(t *testing.T) {
	a := shortUUID()
	b := shortUUID()
	assert.Len(t, a, 8, "8 hex chars (4 random bytes)")
	assert.NotEqual(t, a, b, "two calls produce distinct UUIDs")
}

// TestGenerateWorkerID_Format pins the hostname-uuid8 format.
func TestGenerateWorkerID_Format(t *testing.T) {
	id := generateWorkerID()
	parts := strings.Split(id, "-")
	require.GreaterOrEqual(t, len(parts), 2, "format hostname-uuid; got %q", id)
	// Last segment should be 8 hex chars.
	last := parts[len(parts)-1]
	assert.Len(t, last, 8, "last segment is 8-char UUID")
}

// findWorkerKey is a small helper for tests that need the worker_id
// suffix from the Redis key. Returns the suffix portion (after the
// "shieldscan:workers:" prefix).
func findWorkerKey(t *testing.T, client *redis.Client) string {
	t.Helper()
	keys, err := client.Keys(t.Context(), "shieldscan:workers:*").Result()
	require.NoError(t, err)
	require.NotEmpty(t, keys, "no worker key found")
	return strings.TrimPrefix(keys[0], "shieldscan:workers:")
}
