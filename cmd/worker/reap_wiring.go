package main

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	dockerclient "github.com/docker/docker/client"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/odyssey/shieldscan-engine/internal/worker"
)

// reapTimeout bounds the whole startup sweep. Reaping is a courtesy; it must
// never be able to stall boot.
const reapTimeout = 15 * time.Second

// reapOrphanContainers removes warm-pool containers left behind by workers
// that are no longer running, then logs the outcome.
//
// Deliberately non-fatal in every failure mode. The containers it cleans up
// cost ~500 KiB each; refusing to start a worker over them would trade a
// trivial problem for an outage.
//
// Liveness comes from the heartbeat keys the workers themselves publish
// (shieldscan:workers:{id}, SETEX with a 60s TTL), so a crashed worker's key
// is gone within a minute and its containers become reapable. This is the
// guard that makes the sweep safe on a host running more than one worker: a
// live peer's containers are never touched.
func reapOrphanContainers(ctx context.Context, client *redis.Client, workerID string, log zerolog.Logger) {
	sweepCtx, cancel := context.WithTimeout(ctx, reapTimeout)
	defer cancel()

	live, err := liveWorkerIDs(sweepCtx, client)
	if err != nil {
		// nil live-set → ReapOrphans declines to reap. Explicit here so the
		// fail-safe is visible at the call site, not just in the callee.
		log.Warn().Err(err).Msg("orphan reap skipped: could not read live worker set")
		return
	}
	live[workerID] = struct{}{}

	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		log.Warn().Err(err).Msg("orphan reap skipped: docker client unavailable")
		return
	}
	defer func() { _ = cli.Close() }()

	removed, err := docker.ReapOrphans(sweepCtx, cli, docker.ReapPolicy{
		SelfWorkerID:  workerID,
		LiveWorkerIDs: live,
	}, log)
	if err != nil {
		log.Warn().Err(err).Msg("orphan reap failed; continuing startup")
		return
	}
	if removed > 0 {
		log.Info().Int("removed", removed).Msg("reaped orphan containers from dead workers")
	}
}

// liveWorkerIDs returns the ids of workers currently heartbeating.
//
// SCAN rather than KEYS: KEYS blocks the Redis server for the duration, and
// this runs against the same instance serving live scan traffic.
func liveWorkerIDs(ctx context.Context, client *redis.Client) (map[string]struct{}, error) {
	live := make(map[string]struct{})
	var cursor uint64
	for {
		keys, next, err := client.Scan(ctx, cursor, worker.WorkerKeyPrefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if id := strings.TrimPrefix(k, worker.WorkerKeyPrefix); id != "" {
				live[id] = struct{}{}
			}
		}
		if next == 0 {
			return live, nil
		}
		cursor = next
	}
}
