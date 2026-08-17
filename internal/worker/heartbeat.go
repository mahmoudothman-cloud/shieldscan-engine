package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// WorkerKeyPrefix is the Redis key namespace for worker registration.
// Format: shieldscan:workers:{worker_id}.
//
// Exported because orphan-container reaping (cmd/worker/reap_wiring.go) scans
// this namespace to learn which workers are still alive before deleting any
// container labelled with a worker id. Sharing the constant keeps the two
// readers of this keyspace from drifting apart.
const WorkerKeyPrefix = "shieldscan:workers:"

// workerKeyPrefix is the original package-private spelling, retained so the
// in-package call sites below read unchanged.
const workerKeyPrefix = WorkerKeyPrefix

// DefaultHeartbeatTTL is the worker-key TTL refreshed on each
// Heartbeat tick. 60s gives orchestrator-side detection a clear
// "missing worker" signal within a minute of crash/SIGKILL while
// tolerating transient heartbeat-write failures (3x safety margin
// over the 20s refresh interval).
const DefaultHeartbeatTTL = 60 * time.Second

// DefaultHeartbeatInterval is the refresh cadence. 20s = 3x safety
// margin under DefaultHeartbeatTTL; one missed tick from a transient
// Redis blip doesn't cause the key to expire.
const DefaultHeartbeatInterval = 20 * time.Second

// Heartbeat is the worker-lifetime registration service.
//
// ADR-021 Rule 3 worker-lifetime carve-out: Heartbeat receives the
// worker-root ctx from main(); never constructs context.Background()
// itself. Run() returns when the parent ctx is canceled.
//
// Key shape: shieldscan:workers:{worker_id}
// Value:     JSON containing worker metadata (hostname, started_at,
//
//	concurrency, engines, registered_at).
//
// TTL:       60s, refreshed every 20s via SETEX.
//
// Trade-off: TTL-only expiry on shutdown (no Del). Symmetric handling
// of clean-shutdown vs crash; both rely on TTL. Operational artifact:
// 60s "ghost worker" entries in dashboards after restart. Trigger to
// revisit: ops dashboards genuinely confused by ghost entries causing
// incorrect operational decisions.
//
// Two ctx-aware exit paths in Run (both leak-clean):
//
//  1. ctx.Done() → return ctx.Err()
//  2. ticker.C with write-failure → log + continue (transient
//     write errors don't kill the loop; sustained failure
//     eventually trips orchestrator-side TTL detection).
type Heartbeat struct {
	client   *redis.Client
	workerID string
	metadata map[string]any
	ttl      time.Duration
	interval time.Duration
	log      zerolog.Logger
}

// NewHeartbeat constructs a Heartbeat with default TTL + interval.
// Use NewHeartbeatWithTimings to override.
//
// metadata is the static portion of the worker registration payload;
// dynamic fields (registered_at) are added on each write. Callers
// typically populate hostname, started_at, concurrency, engines.
func NewHeartbeat(client *redis.Client, workerID string, metadata map[string]any, log zerolog.Logger) *Heartbeat {
	return NewHeartbeatWithTimings(client, workerID, metadata, log, DefaultHeartbeatTTL, DefaultHeartbeatInterval)
}

// NewHeartbeatWithTimings constructs a Heartbeat with custom TTL +
// interval. Used by tests to exercise refresh behavior on accelerated
// timelines.
func NewHeartbeatWithTimings(client *redis.Client, workerID string, metadata map[string]any, log zerolog.Logger, ttl, interval time.Duration) *Heartbeat {
	if metadata == nil {
		metadata = map[string]any{}
	}
	return &Heartbeat{
		client:   client,
		workerID: workerID,
		metadata: metadata,
		ttl:      ttl,
		interval: interval,
		log:      log,
	}
}

// WorkerID returns the worker identifier (read-only).
func (h *Heartbeat) WorkerID() string { return h.workerID }

// Key returns the Redis key for this worker's registration entry.
func (h *Heartbeat) Key() string { return workerKeyPrefix + h.workerID }

// WriteOnce performs a single SETEX of the worker registration. Used
// by Startup Phase 4 (initial registration) and by Run on each tick.
//
// The metadata map is augmented with a fresh registered_at timestamp
// per call so consumers can observe heartbeat liveness via the
// published value, not just key existence.
func (h *Heartbeat) WriteOnce(ctx context.Context) error {
	payload := make(map[string]any, len(h.metadata)+1)
	for k, v := range h.metadata {
		payload[k] = v
	}
	payload["worker_id"] = h.workerID
	// RFC3339Nano gives sub-second precision so consumers can detect
	// heartbeat liveness even within a single wall-clock second.
	payload["registered_at"] = time.Now().UTC().Format(time.RFC3339Nano)

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal heartbeat payload: %w", err)
	}
	if err := h.client.Set(ctx, h.Key(), string(data), h.ttl).Err(); err != nil {
		return fmt.Errorf("SETEX %s: %w", h.Key(), err)
	}
	return nil
}

// Run loops on a ticker, refreshing the worker key TTL until ctx
// cancels. Returns ctx.Err() on cancel.
//
// Tick-failure policy: a single SETEX failure logs at WARN and
// continues. Sustained failure naturally trips the worker key's
// 60s TTL — orchestrator detects the worker as gone and stops
// dispatching to it. Per H.6 from 5.4 (surface, don't auto-recover):
// the heartbeat doesn't try to reconnect or retry; it just keeps
// trying on its normal cadence.
func (h *Heartbeat) Run(ctx context.Context) error {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := h.WriteOnce(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return ctx.Err()
				}
				h.log.Warn().
					Err(err).
					Str("worker_id", h.workerID).
					Msg("heartbeat refresh failed; continuing")
			}
		}
	}
}
