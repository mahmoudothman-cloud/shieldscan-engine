package docker

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/rs/zerolog"
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

// ─── ContainerFactory hook (Task 7.5b V2 lock) ───────────────────────

func TestWarmPool_NilContainerFactoryRoutesToDefault(t *testing.T) {
	// nil ContainerFactory → DefaultContainerFactory (preserves Task 7.2
	// Nmap consumer + Task 7.5a backward-compat). Verified by checking
	// that pool spin-up succeeds via the stub-backed default path.
	pool := newTestPool(t, Config{
		MaxSize: 1,
		Cleanup: NoCleanup,
		// ContainerFactory deliberately omitted (nil)
	})
	c, err := pool.Checkout(context.Background())
	require.NoError(t, err)
	require.NotNil(t, c, "default factory must produce a container")
	assert.NotEmpty(t, c.ID, "default factory must populate ID")
}

func TestWarmPool_CustomContainerFactoryInvoked(t *testing.T) {
	// Custom factory invoked with correct args; container returned.
	var capturedImage string
	customFactory := func(_ context.Context, _ dockerClient, image string, _ zerolog.Logger) (*Container, error) {
		capturedImage = image
		return &Container{ID: "custom-id", Image: image}, nil
	}
	pool := newTestPool(t, Config{
		Image:            "custom-image",
		MaxSize:          1,
		Cleanup:          NoCleanup,
		ContainerFactory: customFactory,
	})
	c, err := pool.Checkout(context.Background())
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "custom-id", c.ID)
	assert.Equal(t, "custom-image", capturedImage, "factory receives image from Config")
}

func TestWarmPool_FactoryErrorPropagates(t *testing.T) {
	// Custom factory returning error propagates through spinUp; pool
	// size accounting decrements on error per existing Checkout contract.
	customFactory := func(_ context.Context, _ dockerClient, _ string, _ zerolog.Logger) (*Container, error) {
		return nil, errors.New("factory boom")
	}
	pool := newTestPool(t, Config{
		MaxSize:          1,
		Cleanup:          NoCleanup,
		ContainerFactory: customFactory,
	})
	_, err := pool.Checkout(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factory boom")
	assert.Equal(t, 0, pool.Size(), "size must decrement on factory error")
}

func TestDefaultContainerFactory_DelegatesToNewContainer(t *testing.T) {
	// Sanity check that DefaultContainerFactory is the existing
	// newContainer behavior — invoking it via the stub-backed client
	// should produce a non-nil container with the expected image.
	cli := newStubDockerClient(t)
	c, err := DefaultContainerFactory(context.Background(), cli, "test-img:1", noopLog())
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "test-img:1", c.Image)
}

// ─── Task 7.5e Mounts Extension (4) ───────────────────────────────────

// newFakeClientForMountsTest constructs a fakeClient with happy-path
// responses suitable for WarmPool spin-up testing. Captures HostConfig
// (incl. Mounts) via fakeClient.lastHostConfig per container_test.go
// fakeClient extension (Task 7.5e). Used by Mounts extension tests below.
func newFakeClientForMountsTest() *fakeClient {
	return &fakeClient{
		pullResp:   io.NopCloser(strings.NewReader("")),
		createResp: container.CreateResponse{ID: "fc-stub-001"},
	}
}

// TestConfigMounts_PlumbingToHostConfig verifies Config.Mounts flows
// through to HostConfig.Mounts via WarmPool internal closure when
// cfg.ContainerFactory is nil per Task 7.5e Q1 α.ii lock branch (2).
func TestConfigMounts_PlumbingToHostConfig(t *testing.T) {
	fc := newFakeClientForMountsTest()
	mounts := []mount.Mount{
		{Type: mount.TypeBind, Source: "/tmp/test-mount", Target: "/scan", ReadOnly: true},
	}
	pool, err := New(Config{
		Image:   "test-img:1",
		MaxSize: 1,
		Cleanup: NoCleanup,
		Mounts:  mounts,
	}, fc, noopLog())
	require.NoError(t, err)
	_, err = pool.Checkout(context.Background())
	require.NoError(t, err)
	require.NotNil(t, fc.lastHostConfig, "fakeClient must have captured HostConfig from ContainerCreate")
	assert.Equal(t, mounts, fc.lastHostConfig.Mounts,
		"Config.Mounts must reach HostConfig.Mounts via WarmPool internal closure (Task 7.5e Q1 α.ii branch 2)")
}

// TestDefaultContainerFactory_MountsPassThrough verifies that
// constructing a WarmPool with cfg.Mounts non-empty + cfg.ContainerFactory
// nil uses the internal closure path (NOT DefaultContainerFactory directly)
// and that Mounts plumb through to HostConfig. Complement to
// TestConfigMounts_PlumbingToHostConfig — asserts per-field detail of
// the routed mount entry.
func TestDefaultContainerFactory_MountsPassThrough(t *testing.T) {
	fc := newFakeClientForMountsTest()
	mounts := []mount.Mount{
		{Type: mount.TypeBind, Source: "/var/test", Target: "/data"},
	}
	pool, err := New(Config{
		Image:   "test-img:2",
		MaxSize: 1,
		Cleanup: NoCleanup,
		Mounts:  mounts,
	}, fc, noopLog())
	require.NoError(t, err)
	_, err = pool.Checkout(context.Background())
	require.NoError(t, err)
	require.NotNil(t, fc.lastHostConfig)
	require.Len(t, fc.lastHostConfig.Mounts, 1)
	assert.Equal(t, mount.TypeBind, fc.lastHostConfig.Mounts[0].Type)
	assert.Equal(t, "/var/test", fc.lastHostConfig.Mounts[0].Source)
	assert.Equal(t, "/data", fc.lastHostConfig.Mounts[0].Target)
}

// TestConfigMounts_EmptyDefaultsBackwardCompat verifies pre-Task-7.5e
// behavior preserved when cfg.Mounts is nil + cfg.ContainerFactory is
// nil: DefaultContainerFactory path taken; HostConfig.Mounts empty/nil.
// Matches Q1 α.ii lock branch (3) — Nmap consumer + any current
// DockerRunner consumer without Mounts requirement stays unchanged.
func TestConfigMounts_EmptyDefaultsBackwardCompat(t *testing.T) {
	fc := newFakeClientForMountsTest()
	pool, err := New(Config{
		Image:   "test-img:3",
		MaxSize: 1,
		Cleanup: NoCleanup,
		// Mounts deliberately omitted (nil)
	}, fc, noopLog())
	require.NoError(t, err)
	_, err = pool.Checkout(context.Background())
	require.NoError(t, err)
	require.NotNil(t, fc.lastHostConfig)
	assert.Empty(t, fc.lastHostConfig.Mounts,
		"nil cfg.Mounts must leave HostConfig.Mounts empty (Task 7.5e Q1 α.ii branch 3 pre-7.5e backward-compat)")
}

// TestConfigMounts_CustomFactoryUnchanged verifies Q1 α.ii branch (1):
// when cfg.ContainerFactory is non-nil, the custom factory wins and
// Config.Mounts is NOT consumed by the framework (consumer-side
// responsibility — e.g., service-shape ServiceContainerFactory).
// Asserts no signature/behavior change for the service-shape path.
func TestConfigMounts_CustomFactoryUnchanged(t *testing.T) {
	var customInvoked bool
	customFactory := func(_ context.Context, _ dockerClient, image string, _ zerolog.Logger) (*Container, error) {
		customInvoked = true
		return &Container{ID: "custom-id", Image: image}, nil
	}
	mounts := []mount.Mount{
		{Type: mount.TypeBind, Source: "/ignored-by-framework", Target: "/x"},
	}
	pool := newTestPool(t, Config{
		Image:            "test-img:4",
		MaxSize:          1,
		Cleanup:          NoCleanup,
		ContainerFactory: customFactory,
		Mounts:           mounts, // present but framework does NOT thread to factory per branch (1)
	})
	_, err := pool.Checkout(context.Background())
	require.NoError(t, err)
	assert.True(t, customInvoked, "custom factory must be invoked (branch 1)")
	// Note: Custom factories receive only (ctx, cli, image, log) per
	// ContainerFactoryFunc signature stability per Q1 α.ii lock; mounts
	// pass-through is consumer-side responsibility.
}
