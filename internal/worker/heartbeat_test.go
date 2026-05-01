package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newHeartbeatFixture spins up a miniredis-backed Heartbeat with
// fast timings for test cycles. Auto-cleans via t.Cleanup.
func newHeartbeatFixture(t *testing.T, ttl, interval time.Duration) (*Heartbeat, *redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	hb := NewHeartbeatWithTimings(client, "worker-test-01", map[string]any{
		"hostname":    "test.local",
		"started_at":  "2026-05-01T12:00:00Z",
		"concurrency": 5,
		"engines":     []string{},
	}, zerolog.Nop(), ttl, interval)
	return hb, client, mr
}

// TestHeartbeat_WriteOnceCreatesKey pins the canonical Phase 4
// registration: SETEX writes the key with TTL.
func TestHeartbeat_WriteOnceCreatesKey(t *testing.T) {
	hb, client, _ := newHeartbeatFixture(t, 60*time.Second, time.Second)

	require.NoError(t, hb.WriteOnce(t.Context()))

	// Key exists.
	val, err := client.Get(t.Context(), hb.Key()).Result()
	require.NoError(t, err)
	assert.NotEmpty(t, val)

	// TTL is set (~60s).
	ttl, err := client.TTL(t.Context(), hb.Key()).Result()
	require.NoError(t, err)
	assert.InDelta(t, 60.0, ttl.Seconds(), 5, "TTL should be ~60s; got %s", ttl)
}

// TestHeartbeat_WriteOnceJSONShape pins the value's JSON shape.
// Required fields present; extra metadata preserved.
func TestHeartbeat_WriteOnceJSONShape(t *testing.T) {
	hb, client, _ := newHeartbeatFixture(t, 60*time.Second, time.Second)

	require.NoError(t, hb.WriteOnce(t.Context()))

	val, err := client.Get(t.Context(), hb.Key()).Result()
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(val), &payload))

	assert.Equal(t, "worker-test-01", payload["worker_id"])
	assert.Equal(t, "test.local", payload["hostname"], "static metadata preserved")
	assert.Equal(t, "2026-05-01T12:00:00Z", payload["started_at"])
	assert.Equal(t, float64(5), payload["concurrency"])
	assert.NotEmpty(t, payload["registered_at"], "registered_at populated per-write")
}

// TestHeartbeat_RunRefreshes pins the refresh loop: ticker fires +
// multiple WriteOnce calls happen. Verified via miniredis FastForward
// or by counting SETEX-equivalent operations through observed TTL
// resets.
func TestHeartbeat_RunRefreshes(t *testing.T) {
	hb, client, _ := newHeartbeatFixture(t, 5*time.Second, 50*time.Millisecond)

	// Initial write.
	require.NoError(t, hb.WriteOnce(t.Context()))
	val1, err := client.Get(t.Context(), hb.Key()).Result()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- hb.Run(ctx) }()

	select {
	case err := <-done:
		// Run exited because ctx timed out. That's expected.
		assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
			"Run exits with ctx error; got %v", err)
	case <-time.After(time.Second):
		t.Fatal("Run did not exit within 1s of ctx cancel")
	}

	// After Run, the value's registered_at should be different (refreshed).
	val2, err := client.Get(t.Context(), hb.Key()).Result()
	require.NoError(t, err)
	assert.NotEqual(t, val1, val2,
		"registered_at should have updated across multiple ticks")
}

// TestHeartbeat_RunExitsOnCtxCancel pins the canonical exit path:
// ctx cancel → Run returns ctx.Err() promptly. goleak (TestMain in
// processor_test.go covers the package) verifies no leak.
func TestHeartbeat_RunExitsOnCtxCancel(t *testing.T) {
	hb, _, _ := newHeartbeatFixture(t, 60*time.Second, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() { done <- hb.Run(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled),
			"Run returns context.Canceled; got %v", err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not exit within 500ms of cancel")
	}
}

// TestHeartbeat_RunContinuesOnTransientWriteError pins resilience:
// a single SETEX failure (e.g., transient Redis blip) doesn't kill
// the loop; the next tick retries.
//
// Simulates by closing the underlying miniredis mid-Run; SETEX fails;
// Run should keep ticking and eventually exit on ctx cancel (not on
// the error).
func TestHeartbeat_RunContinuesOnTransientWriteError(t *testing.T) {
	hb, _, mr := newHeartbeatFixture(t, 60*time.Second, 30*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- hb.Run(ctx) }()

	// After ~50ms (one tick), close miniredis so SETEX fails on
	// subsequent ticks. The Run loop should keep going.
	time.Sleep(50 * time.Millisecond)
	mr.Close()

	// Run still exits on ctx cancel (not on the SETEX errors).
	select {
	case err := <-done:
		assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
			"Run exits with ctx error despite write failures; got %v", err)
	case <-time.After(time.Second):
		t.Fatal("Run did not exit within 1s; should have at ctx deadline")
	}
}
