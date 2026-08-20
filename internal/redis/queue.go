// Package redis provides the Go-side wrappers over the Redis
// primitives that compose the inter-service contract with M4 Python
// (SPECIFICATION.md §7).
//
// Five primitives split across files per ADR-018:
//
//	queue.go   — JobConsumer (LMOVE queue → per-worker processing list)
//	reclaim.go — Reclaimer (recovers a dead worker's processing list)
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

// ProcessingKeyPrefix is the namespace for per-worker, per-priority
// in-flight lists: shieldscan:processing:{worker_id}:{priority}.
//
// This list is the whole point of the reliable-queue design (Drift #70).
// The old BRPOP was destructive: the instant a job was popped, the only
// copy of its payload existed in the worker's memory, so a worker death
// mid-scan destroyed the job permanently — the row stayed `queued` in
// PostgreSQL forever and its parent scan could never aggregate. Moving
// the payload into a list the worker owns makes "in flight" a fact
// recorded in Redis rather than an inference drawn from PostgreSQL
// status plus Redis absence.
//
// Per-priority (not one list per worker) so a reclaimed job can be
// requeued onto the queue it came from: the payload itself carries no
// priority field, and inventing one would change the SPEC §7.1 wire
// contract.
const ProcessingKeyPrefix = "shieldscan:processing:"

// canonicalPriorities is the priority order matching Python
// ScanQueue.PRIORITIES (scan_queue.py line ~57). The sweep below tries
// each key in this order, so listing critical → high → normal → low
// gives strict priority drain.
//
// Cross-repo coupling: any change to this list (new priority tier,
// renamed tier) requires Python ScanQueue + this constant to update
// in sync. Pinned to match Python.
var canonicalPriorities = []string{"critical", "high", "normal", "low"}

// idlePollInterval is how long Pop waits between sweeps when every
// queue is empty.
//
// Why polling at all: Redis has no atomic blocking multi-key move.
// BRPOP takes N keys but destroys the payload; BLMOVE preserves it but
// takes exactly one source, and blocking on one key forfeits the
// priority ordering. Strict priority plus a durable hand-off therefore
// costs one non-blocking sweep per interval.
//
// 250ms keeps dispatch latency imperceptible against scans measured in
// minutes, at four LMOVEs per idle worker per interval (~16 ops/sec) —
// noise next to the progress-stream traffic on the same instance.
const idlePollInterval = 250 * time.Millisecond

// ProcessingKey returns the in-flight list key for a worker+priority.
func ProcessingKey(workerID, priority string) string {
	return ProcessingKeyPrefix + workerID + ":" + priority
}

// splitProcessingKey reverses ProcessingKey. Returns ok=false for
// anything that is not a well-formed processing key.
//
// Worker ids are hostname+"-"+8 hex chars, so they contain no colon;
// the priority is therefore everything after the LAST colon.
func splitProcessingKey(key string) (workerID, priority string, ok bool) {
	rest, found := strings.CutPrefix(key, ProcessingKeyPrefix)
	if !found {
		return "", "", false
	}
	i := strings.LastIndex(rest, ":")
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// Delivery is one job checked out of a priority queue and into this
// worker's processing list.
//
// Payload is the raw JSON exactly as it sits in Redis. It is not a
// debugging convenience: Ack removes the entry by value (LREM), and a
// re-marshalled payload would not match byte-for-byte, so the original
// bytes are load-bearing.
type Delivery struct {
	Job      *events.JobDispatch
	Payload  string
	Priority string
}

// JobConsumer moves jobs from the per-priority dispatch lists into this
// worker's processing list, and removes them again on Ack.
//
// Cross-repo coupling: the JSON payload deserialized here matches the
// Python ScanQueue.dispatch wire format (SPEC §7.1). DisallowUnknownFields
// is enabled — any new top-level field on the Python emit side breaks
// decode here, forcing struct extension in events.JobDispatch.
type JobConsumer struct {
	client   *redis.Client
	workerID string
}

// NewJobConsumer constructs a consumer bound to the given Redis client.
//
// workerID scopes the processing list. It MUST be the same id the
// heartbeat publishes (shieldscan:workers:{id}) — the reclaimer joins
// the two to tell a dead worker's in-flight jobs from a live peer's,
// exactly as the container reaper does for labelled containers.
func NewJobConsumer(client *redis.Client, workerID string) *JobConsumer {
	return &JobConsumer{client: client, workerID: workerID}
}

// Pop returns the next job, checked out into this worker's processing
// list, or nil when the timeout elapses with every queue empty.
//
//	(*Delivery, nil) — a job was checked out and decoded successfully.
//	(nil, nil)       — timeout elapsed with no job available.
//	(nil, ctx.Err()) — caller canceled ctx.
//	(nil, err)       — Redis I/O error OR malformed JSON.
//
// Malformed-job handling: the payload has already moved into the
// processing list by the time decode runs, and it can never decode on a
// later attempt, so it is removed again immediately rather than left for
// the reclaimer to retry forever. The job is still lost from the
// customer's perspective — the difference from the pre-Drift-#70
// behaviour is that it is now lost loudly, at ERROR, with the payload
// in the log.
//
// timeout=0 means "sweep once and return". Callers SHOULD pass a finite
// timeout (e.g. 5s) so they periodically re-check ctx.Done().
func (c *JobConsumer) Pop(ctx context.Context, timeout time.Duration) (*Delivery, error) {
	deadline := time.Now().Add(timeout)

	for {
		d, err := c.sweep(ctx)
		if err != nil {
			return nil, err
		}
		if d != nil {
			return d, nil
		}

		// Cancellation beats the timeout: a caller that canceled while a
		// sweep was in flight must see ctx.Err(), not a bare nil that
		// looks like an ordinary empty-queue result.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, nil
		}
		if wait > idlePollInterval {
			wait = idlePollInterval
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// sweep tries one non-blocking LMOVE per priority, highest first, and
// returns the first job it checks out. (nil, nil) means every queue was
// empty.
func (c *JobConsumer) sweep(ctx context.Context) (*Delivery, error) {
	for _, priority := range canonicalPriorities {
		src := queueKeyPrefix + priority
		dst := ProcessingKey(c.workerID, priority)

		// RIGHT out of the queue matches Python's LPUSH-in (FIFO);
		// LEFT into processing keeps the oldest in-flight job at the
		// tail, which is the end the reclaimer drains from.
		payload, err := c.client.LMove(ctx, src, dst, "RIGHT", "LEFT").Result()
		if errors.Is(err, redis.Nil) {
			continue
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("LMOVE %s -> %s: %w", src, dst, err)
		}

		job, decodeErr := decodeJobDispatch(payload)
		if decodeErr != nil {
			if remErr := c.client.LRem(ctx, dst, 1, payload).Err(); remErr != nil {
				return nil, fmt.Errorf("malformed queued job (key=%s): %w "+
					"(and failed to clear it from %s: %v)", src, decodeErr, dst, remErr)
			}
			return nil, fmt.Errorf("malformed queued job (key=%s, payload=%q): %w",
				src, payload, decodeErr)
		}

		return &Delivery{Job: job, Payload: payload, Priority: priority}, nil
	}
	return nil, nil
}

// Ack removes a finished job from the processing list.
//
// MUST be called for every terminal outcome, including a job that failed
// and a duplicate that was dropped: what stays in the processing list is
// what the reclaimer will act on, and re-failing a job that already
// reported its own failure is worse than the leak.
//
// Equally, Ack MUST NOT be called for a job that never reached a
// published terminal event — see worker.ErrJobNotTerminal.
//
// Callers should pass a context that outlives worker shutdown
// (context.WithoutCancel + a short timeout). A missed Ack on the drain
// path leaves a finished job in the processing list, where the reclaimer
// will later fail it despite it having completed.
func (c *JobConsumer) Ack(ctx context.Context, d *Delivery) error {
	if d == nil {
		return fmt.Errorf("ack: nil delivery")
	}
	key := ProcessingKey(c.workerID, d.Priority)
	removed, err := c.client.LRem(ctx, key, 1, d.Payload).Result()
	if err != nil {
		return fmt.Errorf("LREM %s: %w", key, err)
	}
	if removed == 0 {
		// Not fatal, but never expected: something else drained our
		// processing list, which means the liveness guard let a peer
		// treat this worker as dead.
		return fmt.Errorf("LREM %s removed nothing for job_id=%s; "+
			"the entry was already gone", key, d.Job.ID)
	}
	return nil
}

// decodeJobDispatch is the single decode point for a queued payload, so
// the consumer and the reclaimer read the wire the same way.
func decodeJobDispatch(payload string) (*events.JobDispatch, error) {
	dec := json.NewDecoder(strings.NewReader(payload))
	dec.DisallowUnknownFields()
	var job events.JobDispatch
	if err := dec.Decode(&job); err != nil {
		return nil, err
	}
	return &job, nil
}
