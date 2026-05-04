package docker

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
)

// WarmPool manages a lazy-warm pool of long-running Docker containers
// for a single tool image. Pool starts empty; first checkout spins up
// a container; subsequent checkouts reuse warmed containers; max-bound
// prevents runaway resource usage.
//
// Per ADR-026 (DockerRunner framework + lazy warm pool — M7 container
// lifecycle architecture, 2026-05-XX): matches the "lazy warm"
// semantics locked in brainstorming. Resource floor is zero for
// unused tools.
//
// Per ADR-006 (Hybrid Native + Persistent Docker, refined
// 2026-04-18): this primitive is for CLI-shaped tools (Trivy, Nmap,
// SQLMap). HTTP-shaped persistent services (ZAP, MobSF) use
// DockerServiceRunner (internal/tools/docker_service.go) instead.
//
// Concurrency model: WarmPool is safe for concurrent use.
//
//   - mu guards size + closed flag.
//   - available channel (buffered to maxSize) holds warmed containers.
//   - done channel (closed once on Shutdown) signals shutdown to
//     blocked Checkout callers.
//   - The available channel is NEVER closed; Shutdown drains it under
//     mu instead. Closing would race with Return's send and panic.
//   - Channel sends in Return happen under mu so the closed-flag
//     check + send are atomic vs. Shutdown's drain. Sends never block
//     because of the size <= maxSize invariant: at most maxSize
//     containers exist; channel buffer is maxSize; len(available) +
//     in_use = size <= maxSize.
type WarmPool struct {
	image   string
	maxSize int
	cleanup CleanupFunc
	health  HealthCheckFunc
	cli     dockerClient
	log     zerolog.Logger

	available chan *Container
	done      chan struct{}

	mu     sync.Mutex
	size   int // current pool size (created containers, including in-use)
	closed bool
}

// CleanupFunc runs between checkouts to ensure tenant isolation
// (no state leak between scans). Returning an error causes the
// container to be replaced rather than returned to pool.
//
// Stateless tools must use NoCleanup explicitly (no nil functions);
// statelessness is architecturally visible.
type CleanupFunc func(ctx context.Context, c *Container) error

// HealthCheckFunc runs before checkout returns to validate container
// reusability. Returning false causes the container to be replaced.
// Optional; nil HealthCheckFunc means "always healthy."
type HealthCheckFunc func(ctx context.Context, c *Container) bool

// Config configures a WarmPool. Image is required; MaxSize defaults
// to 4 if zero; Cleanup is required (use NoCleanup for stateless
// tools); HealthCheck is optional.
type Config struct {
	Image       string
	MaxSize     int
	Cleanup     CleanupFunc
	HealthCheck HealthCheckFunc
}

// New creates a WarmPool. Pool is empty; lazy spin-up on first
// Checkout.
//
// cli is the dockerClient interface (productionClient in production;
// stubs in tests).
func New(cfg Config, cli dockerClient, log zerolog.Logger) (*WarmPool, error) {
	if cfg.Image == "" {
		return nil, errors.New("warmpool: Image required")
	}
	if cfg.Cleanup == nil {
		return nil, errors.New("warmpool: Cleanup required (use NoCleanup if stateless)")
	}
	if cli == nil {
		return nil, errors.New("warmpool: dockerClient required")
	}
	maxSize := cfg.MaxSize
	if maxSize == 0 {
		maxSize = 4
	}
	if maxSize < 0 {
		return nil, errors.New("warmpool: MaxSize must be non-negative")
	}
	return &WarmPool{
		image:     cfg.Image,
		maxSize:   maxSize,
		cleanup:   cfg.Cleanup,
		health:    cfg.HealthCheck,
		cli:       cli,
		log:       log.With().Str("warmpool_image", cfg.Image).Logger(),
		available: make(chan *Container, maxSize),
		done:      make(chan struct{}),
	}, nil
}

// Checkout retrieves a container from the pool. If a warmed container
// is available, returns it (after health check, if configured).
// Otherwise spins up a new container if size < maxSize. Otherwise
// blocks until a container becomes available, ctx is canceled, or the
// pool is shut down.
//
// Per ADR-021 ctx-discipline: ctx flows through to spinUp's Docker
// SDK calls; cancellation propagates to the daemon.
func (p *WarmPool) Checkout(ctx context.Context) (*Container, error) {
	if err := p.checkClosed(); err != nil {
		return nil, err
	}

	// Fast path: warmed container available.
	select {
	case c := <-p.available:
		return p.healthCheckOrReplace(ctx, c)
	default:
	}

	// No warmed container; try to spin up if under maxSize.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errPoolClosed
	}
	if p.size < p.maxSize {
		p.size++
		p.mu.Unlock()
		c, err := p.spinUp(ctx)
		if err != nil {
			p.mu.Lock()
			p.size--
			p.mu.Unlock()
			return nil, err
		}
		return c, nil
	}
	p.mu.Unlock()

	// At max size; block until container available, ctx cancel, or
	// pool shutdown. Including p.done in the select prevents the
	// silent-nil-Container hazard from a bare receive on a channel
	// that gets closed under us (we never close available, but the
	// done channel signal lets us exit cleanly).
	select {
	case c := <-p.available:
		return p.healthCheckOrReplace(ctx, c)
	case <-p.done:
		return nil, errPoolClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// healthCheckOrReplace runs the configured HealthCheck on a checked-
// out container. If the container is unhealthy, it is stopped and
// replaced with a fresh spin-up; size accounting is preserved
// (replacement is size-neutral on success; size-- only on spinUp
// failure).
func (p *WarmPool) healthCheckOrReplace(ctx context.Context, c *Container) (*Container, error) {
	if p.health == nil || p.health(ctx, c) {
		return c, nil
	}
	p.log.Warn().Str("container_id", shortID(c.ID)).Msg("health check failed; replacing")
	_ = c.Stop(ctx)

	// size accounting: stopping decrements logically; spinUp
	// re-increments by replacing. Net zero on success. On spinUp
	// failure, the net effect IS a decrement (we stopped one and
	// failed to create a replacement) — apply the dec then.
	replacement, err := p.spinUp(ctx)
	if err != nil {
		p.mu.Lock()
		p.size--
		p.mu.Unlock()
		return nil, err
	}
	return replacement, nil
}

// Return runs cleanup hook + returns container to pool. If cleanup
// fails, container is stopped and pool size is decremented (allows
// future spin-up to replace it).
//
// Per Phase-2 concurrency model: cleanup runs OUTSIDE the lock
// (potentially slow Docker SDK calls); the channel send happens UNDER
// the lock so closed-flag check + send are atomic vs Shutdown's
// drain. Sends never block because of the size <= maxSize invariant.
//
// CRITICAL: Cleanup runs BEFORE container goes back to pool — ensures
// tenant isolation; next checkout sees clean state.
func (p *WarmPool) Return(ctx context.Context, c *Container) error {
	// Fast-path closed check. If closed, stop the container; caller's
	// in-flight container does not survive shutdown.
	if err := p.checkClosed(); err != nil {
		_ = c.Stop(ctx)
		return err
	}

	// Cleanup outside the lock — may take time and we don't want to
	// block other Returns or Checkouts.
	if err := p.cleanup(ctx, c); err != nil {
		p.log.Warn().Err(err).Str("container_id", shortID(c.ID)).Msg("cleanup failed; stopping container")
		_ = c.Stop(ctx)
		p.mu.Lock()
		p.size--
		p.mu.Unlock()
		return fmt.Errorf("warmpool: cleanup: %w", err)
	}

	// Re-check closed under lock; if closed during cleanup, stop the
	// container so it doesn't leak. Otherwise send to channel under
	// the lock to atomically check-and-send relative to Shutdown's
	// drain.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = c.Stop(ctx)
		return errPoolClosed
	}
	select {
	case p.available <- c:
		p.mu.Unlock()
		return nil
	default:
		// Defensive: channel full despite accounting. Should never
		// happen under correct invariants; treat as bug-shape and
		// stop the container.
		p.size--
		p.mu.Unlock()
		_ = c.Stop(ctx)
		return errors.New("warmpool: available channel full on return; container stopped")
	}
}

// Shutdown stops all warmed containers and prevents future Checkouts.
// Idempotent: second call is a no-op.
//
// Containers in active use (currently checked-out) are NOT stopped
// here; callers must Return them before Shutdown completes its drain,
// OR accept that their Returns will see the closed flag and stop the
// container themselves.
//
// Concurrency: closes the done channel under mu so blocked Checkout
// callers wake up; drains the available channel under mu so no
// concurrent Return can sneak a container in after the drain. The
// drained containers' Stop calls happen OUTSIDE the lock (the Stop
// calls are slow Docker SDK calls and don't need the lock — the
// containers are no longer reachable via the pool).
func (p *WarmPool) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)

	// Drain available channel under the lock so a concurrent Return
	// (which would acquire the lock first and observe closed=true,
	// then stop the container itself) cannot interleave a send.
	var toStop []*Container
drain:
	for {
		select {
		case c := <-p.available:
			toStop = append(toStop, c)
		default:
			break drain
		}
	}
	p.mu.Unlock()

	// Stop drained containers outside the lock.
	var errs []error
	for _, c := range toStop {
		if err := c.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("warmpool: shutdown stop errors: %v", errs)
	}
	return nil
}

// spinUp creates a new container of pool's image. Internal; called by
// Checkout and healthCheckOrReplace when pool needs to grow or
// replace.
//
// Caller is responsible for size accounting (increment before call;
// decrement on error per the Checkout / healthCheckOrReplace
// contracts above).
func (p *WarmPool) spinUp(ctx context.Context) (*Container, error) {
	c, err := newContainer(ctx, p.cli, p.image, p.log)
	if err != nil {
		return nil, fmt.Errorf("warmpool: spin up: %w", err)
	}
	return c, nil
}

// checkClosed acquires mu briefly to read the closed flag. Returns
// errPoolClosed if closed; nil otherwise.
func (p *WarmPool) checkClosed() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errPoolClosed
	}
	return nil
}

// errPoolClosed is the sentinel error returned by Checkout / Return
// when the pool has been Shutdown. Sentinel so callers can errors.Is
// to handle pool-shutdown distinct from other errors.
var errPoolClosed = errors.New("warmpool: pool closed")

// NoCleanup is a CleanupFunc that does nothing. Use for stateless
// tools (e.g., Nmap) where no per-scan state cleanup is needed.
//
// Explicit no-op rather than nil function: future engineers reading
// tool packages see explicit cleanup contract for every tool;
// statelessness is architecturally visible.
func NoCleanup(_ context.Context, _ *Container) error { return nil }

// Size returns current pool size (created containers, including
// currently checked-out). For observability; tests use it to verify
// max-bound behavior.
func (p *WarmPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.size
}

// Available returns count of containers currently warm and available
// for checkout. For observability.
func (p *WarmPool) Available() int {
	return len(p.available)
}
