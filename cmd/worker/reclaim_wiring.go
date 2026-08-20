package main

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	rdsh "github.com/odyssey/shieldscan-engine/internal/redis"
)

// reclaimTimeout bounds one sweep. Like the container reap, recovery is
// a courtesy the worker performs for the fleet; it must never be able to
// stall boot or to hold the worker's shutdown open.
const reclaimTimeout = 30 * time.Second

// reclaimInterval is how often the sweep repeats after startup.
//
// A startup-only sweep would leave a real hole. Worker ids are generated
// fresh per process, so a worker that crashes and is restarted inside the
// 60s heartbeat TTL still looks alive to its own successor: nothing is
// reclaimed on that boot, and if no further restart happens the jobs stay
// stranded indefinitely. That is the single-worker deployment we
// actually run. Repeating on a 60s cadence — the TTL itself — closes it
// without any new infrastructure: the sweep is one SCAN over a keyspace
// with at most WORKER_CONCURRENCY entries per worker.
const reclaimInterval = 60 * time.Second

// runReclaimLoop sweeps once immediately, then every reclaimInterval
// until ctx is canceled.
//
// ADR-021 Rule 2: the only exit is ctx.Done(); runMain waits on the
// returned channel closing before it declares shutdown clean.
func runReclaimLoop(ctx context.Context, client *redis.Client, workerID string, log zerolog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)

		reclaimJobsOnce(ctx, client, workerID, log)

		ticker := time.NewTicker(reclaimInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reclaimJobsOnce(ctx, client, workerID, log)
			}
		}
	}()
	return done
}

// reclaimJobsOnce recovers the in-flight jobs of workers that are gone.
//
// Liveness is the heartbeat keys the workers publish themselves
// (shieldscan:workers:{id}, SETEX with a 60s TTL) — the same set the
// container reaper uses. A live peer's in-flight jobs are never touched;
// a nil set (Redis unreachable) disables the sweep rather than guessing.
func reclaimJobsOnce(ctx context.Context, client *redis.Client, workerID string, log zerolog.Logger) {
	sweepCtx, cancel := context.WithTimeout(ctx, reclaimTimeout)
	defer cancel()

	live, err := liveWorkerIDs(sweepCtx, client)
	if err != nil {
		if ctx.Err() != nil {
			return // shutting down; not worth a warning
		}
		log.Warn().Err(err).Msg("job reclaim skipped: could not read live worker set")
		return
	}
	live[workerID] = struct{}{}

	result, err := rdsh.NewReclaimer(client, log).Reclaim(sweepCtx, rdsh.ReclaimPolicy{
		SelfWorkerID:  workerID,
		LiveWorkerIDs: live,
	})
	if err != nil {
		log.Warn().Err(err).Msg("job reclaim failed; in-flight jobs left where they are")
		return
	}
	if result.Requeued > 0 || result.Failed > 0 || result.Dropped > 0 {
		log.Info().
			Int("requeued", result.Requeued).
			Int("failed", result.Failed).
			Int("dropped", result.Dropped).
			Msg("reclaimed in-flight jobs from dead workers")
	}
}
