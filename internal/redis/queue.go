// Package redis provides the Go-side wrappers over the Redis
// primitives that compose the inter-service contract with M4 Python
// (SPECIFICATION.md §7).
//
// Four primitives split across files per ADR-018:
//
//	queue.go   — JobConsumer (BRPOP from shieldscan:queue:{priority})
//	stream.go  — ProgressPublisher (XADD to shieldscan:progress:{scan_id})
//	pubsub.go  — CancelSubscriber + CompletionsPublisher (Pub/Sub)
//	idem.go    — IdempotencyClaim (SETNX with 24h TTL)
//
// Cross-repo wire format: every primitive matches Python's
// shieldscan-api/src/app/services/scan_queue.py byte-for-byte. JSON
// schemas live in internal/events; this package consumes them. Test
// fixtures (internal/events/testdata/job_*.json) pin the format
// across repos.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// queueKeyPrefix is the Redis list-key namespace for job dispatch.
// Per priority: shieldscan:queue:{critical|high|normal|low}.
const queueKeyPrefix = "shieldscan:queue:"

// canonicalPriorities is the priority order matching Python
// ScanQueue.PRIORITIES (scan_queue.py line ~57). BRPOP across multiple
// keys returns the first non-empty in argument order, so listing
// critical → high → normal → low gives strict priority drain.
//
// Cross-repo coupling: any change to this list (new priority tier,
// renamed tier) requires Python ScanQueue + this constant to update
// in sync. Pinned to match Python.
var canonicalPriorities = []string{"critical", "high", "normal", "low"}

// JobConsumer wraps BRPOP across the per-priority job-dispatch lists.
// Used by the M5.5 worker processor to dequeue jobs in priority order.
//
// Cross-repo coupling: the JSON payload deserialized here matches the
// Python ScanQueue.dispatch wire format (SPEC §7.1). DisallowUnknownFields
// is enabled — any new top-level field on the Python emit side breaks
// decode here, forcing struct extension in events.JobDispatch.
type JobConsumer struct {
	client *redis.Client
}

// NewJobConsumer constructs a consumer bound to the given Redis client.
func NewJobConsumer(client *redis.Client) *JobConsumer {
	return &JobConsumer{client: client}
}

// Pop blocks until a job is available on any of the priority queues
// (BRPOP semantics) or timeout elapses. Returns:
//
//	(*JobDispatch, nil) — a job was popped and decoded successfully.
//	(nil, nil)          — timeout elapsed with no job available.
//	(nil, ctx.Err())    — caller canceled ctx.
//	(nil, err)          — Redis I/O error OR malformed JSON.
//
// Malformed-job poison-pill protection: a JSON decode error returns
// the error to the caller; the underlying job has already been
// removed from the queue (BRPOP popped it). M5.5's loop logs +
// continues, so a malformed entry doesn't loop forever. Trade-off:
// the malformed job is silently lost from the customer's perspective.
// Recovery via M5+ ghost-queued janitor (Task 4.2 carry-forward).
//
// Multi-priority drain: critical → high → normal → low. BRPOP returns
// the first non-empty key in argument order, so a job on the critical
// queue always wins over high+normal+low even if all four are non-
// empty.
//
// timeout=0 means block forever (Redis BRPOP convention). Callers
// SHOULD pass a finite timeout (e.g., 5s) so they can periodically
// check ctx.Done() — though ctx-cancel also propagates through
// go-redis and exits BRPOP cleanly.
func (c *JobConsumer) Pop(ctx context.Context, timeout time.Duration) (*events.JobDispatch, error) {
	keys := make([]string, len(canonicalPriorities))
	for i, p := range canonicalPriorities {
		keys[i] = queueKeyPrefix + p
	}

	result, err := c.client.BRPop(ctx, timeout, keys...).Result()

	// Check caller cancellation BEFORE interpreting BRPOP's return.
	// If the caller canceled while BRPOP was in-flight (or right
	// before/after it timed out), surface the ctx error. This is
	// load-bearing on real Redis where ctx cancellation closes the
	// connection mid-BRPOP; without this check, a concurrent cancel +
	// natural BRPOP timeout would yield (nil, nil) instead of
	// (nil, ctx.Canceled), losing the cancel signal.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if errors.Is(err, redis.Nil) {
		return nil, nil // timeout, queues empty
	}
	if err != nil {
		return nil, fmt.Errorf("BRPOP: %w", err)
	}

	// result == [key, value]. Defensive shape-check.
	if len(result) != 2 {
		return nil, fmt.Errorf("BRPOP returned unexpected shape (len=%d): %v", len(result), result)
	}

	dec := json.NewDecoder(strings.NewReader(result[1]))
	dec.DisallowUnknownFields()
	var job events.JobDispatch
	if err := dec.Decode(&job); err != nil {
		return nil, fmt.Errorf("malformed queued job (key=%s): %w", result[0], err)
	}
	return &job, nil
}
