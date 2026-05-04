package docker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNoOpCleanup is a CleanupFunc that does nothing — used in most
// tests where we don't care about cleanup behavior.
func testNoOpCleanup(_ context.Context, _ *Container) error { return nil }

// newTestPool creates a WarmPool with a stub dockerClient suitable
// for unit testing. Spin-up succeeds with auto-generated unique IDs;
// no real Docker daemon required.
func newTestPool(t *testing.T, cfg Config) *WarmPool {
	t.Helper()
	if cfg.Image == "" {
		cfg.Image = "test-image:latest"
	}
	if cfg.Cleanup == nil {
		cfg.Cleanup = testNoOpCleanup
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 4
	}
	cli := newStubDockerClient(t)
	pool, err := New(cfg, cli, noopLog())
	require.NoError(t, err)
	return pool
}

// ─── Construction (5) ─────────────────────────────────────────────────

func TestWarmPool_New_RejectsEmptyImage(t *testing.T) {
	cli := newStubDockerClient(t)
	_, err := New(Config{Image: "", Cleanup: testNoOpCleanup}, cli, noopLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Image required")
}

func TestWarmPool_New_RejectsNilCleanup(t *testing.T) {
	cli := newStubDockerClient(t)
	_, err := New(Config{Image: "img", Cleanup: nil}, cli, noopLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Cleanup required")
}

func TestWarmPool_New_RejectsNilDockerClient(t *testing.T) {
	_, err := New(Config{Image: "img", Cleanup: testNoOpCleanup}, nil, noopLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dockerClient required")
}

func TestWarmPool_New_DefaultMaxSize(t *testing.T) {
	cli := newStubDockerClient(t)
	pool, err := New(Config{Image: "img", Cleanup: testNoOpCleanup, MaxSize: 0}, cli, noopLog())
	require.NoError(t, err)
	assert.Equal(t, 4, pool.maxSize)
}

func TestWarmPool_New_CustomMaxSize(t *testing.T) {
	cli := newStubDockerClient(t)
	pool, err := New(Config{Image: "img", Cleanup: testNoOpCleanup, MaxSize: 8}, cli, noopLog())
	require.NoError(t, err)
	assert.Equal(t, 8, pool.maxSize)
}

// ─── Checkout (4) ─────────────────────────────────────────────────────

func TestWarmPool_Checkout_LazySpinUpOnFirstCall(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 2})
	require.Equal(t, 0, pool.Size(), "pool empty before first checkout")

	c, err := pool.Checkout(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, 1, pool.Size(), "size=1 after first checkout")
	assert.Equal(t, 0, pool.Available(), "no available containers (one in use)")
}

func TestWarmPool_Checkout_ReusesWarmedContainer(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 2})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.Return(ctx, c1))

	c2, err := pool.Checkout(ctx)
	require.NoError(t, err)
	assert.Equal(t, c1.ID, c2.ID, "second checkout reuses first container")
	assert.Equal(t, 1, pool.Size(), "size still 1 (no new spin-up)")
}

func TestWarmPool_Checkout_BlocksAtMaxSize(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 2})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)
	c2, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.NotEqual(t, c1.ID, c2.ID)

	thirdReturned := make(chan *Container, 1)
	go func() {
		c, err := pool.Checkout(ctx)
		if err == nil {
			thirdReturned <- c
		}
	}()

	// Verify third is blocked.
	select {
	case <-thirdReturned:
		t.Fatal("third checkout should have blocked")
	case <-time.After(100 * time.Millisecond):
		// expected — still blocked
	}

	// Return one; third unblocks.
	require.NoError(t, pool.Return(ctx, c1))
	select {
	case c3 := <-thirdReturned:
		assert.Equal(t, c1.ID, c3.ID, "third checkout gets returned c1")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("third checkout should have unblocked")
	}

	require.NoError(t, pool.Return(ctx, c2))
}

func TestWarmPool_Checkout_RespectsContextCancellation(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 1})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(context.Background())
	checkoutErr := make(chan error, 1)
	go func() {
		_, err := pool.Checkout(cancelCtx)
		checkoutErr <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-checkoutErr:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("checkout should have returned ctx error")
	}

	require.NoError(t, pool.Return(ctx, c1))
}

// ─── Return (3) ───────────────────────────────────────────────────────

func TestWarmPool_Return_RunsCleanupHook(t *testing.T) {
	cleanupCalled := atomic.Bool{}
	cleanup := func(_ context.Context, _ *Container) error {
		cleanupCalled.Store(true)
		return nil
	}

	pool := newTestPool(t, Config{MaxSize: 2, Cleanup: cleanup})
	ctx := context.Background()

	c, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.Return(ctx, c))
	assert.True(t, cleanupCalled.Load(), "cleanup ran on return")
}

func TestWarmPool_Return_StopsContainerOnCleanupFailure(t *testing.T) {
	cleanup := func(_ context.Context, _ *Container) error {
		return errors.New("cleanup failed")
	}

	pool := newTestPool(t, Config{MaxSize: 2, Cleanup: cleanup})
	ctx := context.Background()

	c, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, pool.Size())

	err = pool.Return(ctx, c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cleanup")
	assert.Equal(t, 0, pool.Size(), "size decrements on cleanup failure")
}

func TestWarmPool_Return_DecrementsSizeAllowsFutureSpinUp(t *testing.T) {
	cleanupShouldFail := atomic.Bool{}
	cleanup := func(_ context.Context, _ *Container) error {
		if cleanupShouldFail.Load() {
			return errors.New("cleanup failed")
		}
		return nil
	}

	pool := newTestPool(t, Config{MaxSize: 1, Cleanup: cleanup})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)
	cleanupShouldFail.Store(true)
	_ = pool.Return(ctx, c1)
	assert.Equal(t, 0, pool.Size())

	cleanupShouldFail.Store(false)
	c2, err := pool.Checkout(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, c1.ID, c2.ID, "spin up new; not reuse stopped")
	require.NoError(t, pool.Return(ctx, c2))
}

// ─── Health check (2) ────────────────────────────────────────────────

func TestWarmPool_HealthCheck_ReplacesUnhealthyContainer(t *testing.T) {
	healthyOnce := atomic.Bool{}
	health := func(_ context.Context, _ *Container) bool {
		// First check returns unhealthy; subsequent return healthy.
		if !healthyOnce.Load() {
			healthyOnce.Store(true)
			return false
		}
		return true
	}

	pool := newTestPool(t, Config{MaxSize: 2, HealthCheck: health})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.Return(ctx, c1))

	c2, err := pool.Checkout(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, c1.ID, c2.ID, "unhealthy container replaced")
	require.NoError(t, pool.Return(ctx, c2))
}

func TestWarmPool_HealthCheck_NilSkipsCheck(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 2, HealthCheck: nil})
	ctx := context.Background()

	c, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.Return(ctx, c))

	c2, err := pool.Checkout(ctx)
	require.NoError(t, err)
	assert.Equal(t, c.ID, c2.ID, "no health check → reuse")
	require.NoError(t, pool.Return(ctx, c2))
}

// ─── Shutdown (3) ────────────────────────────────────────────────────

func TestWarmPool_Shutdown_StopsAllContainers(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 3})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)
	c2, err := pool.Checkout(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.Return(ctx, c1))
	require.NoError(t, pool.Return(ctx, c2))

	require.Equal(t, 2, pool.Available())

	require.NoError(t, pool.Shutdown(ctx))

	_, err = pool.Checkout(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, errPoolClosed)
}

func TestWarmPool_Shutdown_Idempotent(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 2})
	ctx := context.Background()
	require.NoError(t, pool.Shutdown(ctx))
	require.NoError(t, pool.Shutdown(ctx), "second shutdown is no-op")
}

// TestWarmPool_Shutdown_UnblocksWaitingCheckout pins the done-channel
// signal: a Checkout blocked at maxSize must unblock when Shutdown
// fires (rather than hanging forever or returning a nil Container).
func TestWarmPool_Shutdown_UnblocksWaitingCheckout(t *testing.T) {
	pool := newTestPool(t, Config{MaxSize: 1})
	ctx := context.Background()

	c1, err := pool.Checkout(ctx)
	require.NoError(t, err)

	checkoutResult := make(chan error, 1)
	go func() {
		_, err := pool.Checkout(context.Background())
		checkoutResult <- err
	}()

	// Let the second checkout reach the blocking select.
	time.Sleep(50 * time.Millisecond)

	// Shutdown — should release the blocked Checkout.
	require.NoError(t, pool.Shutdown(ctx))

	select {
	case err := <-checkoutResult:
		assert.ErrorIs(t, err, errPoolClosed,
			"blocked Checkout MUST receive errPoolClosed (not nil Container) on Shutdown")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked Checkout did not unblock on Shutdown — done-channel signal broken")
	}

	_ = c1 // c1 is in-flight; Return would error with errPoolClosed (acceptable)
}

// ─── Concurrent (LOAD-BEARING; race detector pin) ────────────────────

// TestWarmPool_Concurrent_NoRaceCondition exercises 10 goroutines ×
// 50 cycles of Checkout/Return under -race. Pins:
//   - No data race in size accounting
//   - No race in available channel ops (Return send vs Shutdown drain
//     not exercised here; tested in Shutdown_UnblocksWaitingCheckout)
//   - size and Available stay <= maxSize
//   - No goroutine leaks (would be caught by goleak's TestMain in
//     other packages; here we just care correctness)
func TestWarmPool_Concurrent_NoRaceCondition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent test in short mode")
	}

	pool := newTestPool(t, Config{MaxSize: 4})
	ctx := context.Background()

	const numGoroutines = 10
	const cyclesPerGoroutine = 50

	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*cyclesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < cyclesPerGoroutine; j++ {
				c, err := pool.Checkout(ctx)
				if err != nil {
					errCh <- err
					return
				}
				time.Sleep(time.Microsecond) // simulate brief work
				if err := pool.Return(ctx, c); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	require.Empty(t, errs, "no errors expected; got %d: %v", len(errs), errs)

	assert.LessOrEqual(t, pool.Size(), 4, "size must not exceed maxSize")
	assert.LessOrEqual(t, pool.Available(), 4, "available must not exceed maxSize")
}

// ─── NoCleanup helper (1) ────────────────────────────────────────────

func TestNoCleanup_AlwaysReturnsNil(t *testing.T) {
	c := &Container{ID: "test-id"}
	err := NoCleanup(context.Background(), c)
	assert.NoError(t, err)
}
