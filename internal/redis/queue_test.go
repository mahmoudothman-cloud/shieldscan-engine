package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// testWorkerID stands in for the id the heartbeat publishes. The
// consumer's processing list is scoped by it.
const testWorkerID = "worker-test-aaaa1111"

// TestJobConsumer_PopFromMiniredis is the canonical happy path:
// LPUSH a Python-shaped payload, Pop returns a Delivery carrying the
// deserialized JobDispatch. Uses a minimal payload (not the full
// fixture) to keep the test focused on the checkout+decode mechanics.
func TestJobConsumer_PopFromMiniredis(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)

	payload := `{
		"id": "job_x", "scan_id": "s1", "organization_id": "o1",
		"engine": "nuclei", "idempotency_key": "k1",
		"target": {"url":"https://x.example.com","target_type":"web","domain_verified":true},
		"auth": null, "config": {"depth":"quick"},
		"mobile_config": null, "callback_stream": "shieldscan:progress:s1",
		"created_at": "2026-04-18T14:30:00Z"
	}`
	require.NoError(t, client.LPush(t.Context(), "shieldscan:queue:high", payload).Err())

	d, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, d)
	job := d.Job
	assert.Equal(t, "high", d.Priority)
	assert.Equal(t, "job_x", job.ID)
	assert.Equal(t, "nuclei", job.Engine)
	assert.Equal(t, "https://x.example.com", job.Target.URL)
	assert.Nil(t, job.Auth)
	assert.Equal(t, "quick", job.Config["depth"])
}

// TestJobConsumer_MultiPriorityDrainOrder pins the priority order:
// critical > high > normal > low. LPUSH onto multiple queues; the
// first Pop returns the highest-priority entry.
func TestJobConsumer_MultiPriorityDrainOrder(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)
	ctx := t.Context()

	mkPayload := func(id string) string {
		return `{
			"id": "` + id + `", "scan_id": "s", "organization_id": "o",
			"engine": "nuclei", "idempotency_key": "k",
			"target": {"url":"https://x.example.com","target_type":"web","domain_verified":true},
			"auth": null, "config": {}, "mobile_config": null,
			"callback_stream": "c", "created_at": "t"
		}`
	}

	// Push to all four priorities; critical pushed last to confirm
	// priority isn't FIFO order-of-push.
	require.NoError(t, client.LPush(ctx, "shieldscan:queue:low", mkPayload("low_job")).Err())
	require.NoError(t, client.LPush(ctx, "shieldscan:queue:normal", mkPayload("normal_job")).Err())
	require.NoError(t, client.LPush(ctx, "shieldscan:queue:high", mkPayload("high_job")).Err())
	require.NoError(t, client.LPush(ctx, "shieldscan:queue:critical", mkPayload("critical_job")).Err())

	// Each Pop should return the next-highest-priority remaining.
	expected := []string{"critical_job", "high_job", "normal_job", "low_job"}
	for i, want := range expected {
		d, err := consumer.Pop(ctx, 100*time.Millisecond)
		require.NoError(t, err, "pop #%d", i)
		require.NotNil(t, d, "pop #%d should not be nil", i)
		assert.Equal(t, want, d.Job.ID, "pop #%d order", i)
	}
}

// TestJobConsumer_TimeoutReturnsNilNil pins the empty-queue case:
// no jobs available + timeout elapses → (nil, nil), not error.
func TestJobConsumer_TimeoutReturnsNilNil(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)

	d, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, d, "empty queue + timeout returns (nil, nil)")
}

// TestJobConsumer_CtxCancelExits pins ADR-021 ctx-discipline:
// when the caller cancels ctx, Pop returns the ctx error rather
// than (nil, nil) timeout-success.
//
// Pop now waits between sweeps rather than blocking inside Redis, so
// the cancel is observed by the select in the idle wait. The contract
// under test is unchanged and still load-bearing for the processor:
// a canceled Pop returns ctx.Err(), never a bare (nil, nil) that reads
// as an ordinary empty queue.
func TestJobConsumer_CtxCancelExits(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		// A timeout longer than the cancel delay, so the cancel is
		// what ends the call rather than the deadline.
		_, err := consumer.Pop(ctx, 200*time.Millisecond)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled),
			"Pop should return ctx.Err() on cancel; got %v", err)
	case <-time.After(time.Second):
		t.Fatal("Pop did not exit within 1s of ctx cancel")
	}
}

// TestJobConsumer_MalformedJSONReturnsError pins poison-pill
// protection: malformed JSON returns an error to the caller; the
// underlying job is consumed and cleared from the processing list, so
// neither the worker loop nor a later reclaim sees the same garbage
// again.
func TestJobConsumer_MalformedJSONReturnsError(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)

	require.NoError(t, client.LPush(t.Context(), "shieldscan:queue:high", "not-json{{{").Err())

	d, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.Error(t, err)
	assert.Nil(t, d)
	assert.Contains(t, err.Error(), "malformed queued job")

	// Confirm the malformed entry was consumed (queue is now empty).
	d2, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, d2, "malformed entry was consumed; queue should be empty")

	// ...and did not accumulate in the processing list, where the
	// reclaimer would retry a payload that can never decode.
	n, err := client.LLen(t.Context(), ProcessingKey(testWorkerID, "high")).Result()
	require.NoError(t, err)
	assert.Zero(t, n, "malformed payload was left in the processing list")
}

// TestJobConsumer_MatchesPythonWireFormat is the load-bearing
// cross-repo wire-format pin. LPUSH the canonical Python ScanQueue
// fixture (events.FixtureJobDispatchPythonV1) and verify every
// documented field deserializes correctly.
//
// If this fails, one of:
//   - Python emit shape drifted (rare; M4 is shipped + tested)
//   - Go struct tags wrong (most likely — JSON field name mismatch)
//   - DisallowUnknownFields rejects field present in fixture but
//     missing from JobDispatch (surface for struct extension)
//
// This test is the primary deliverable of Task 5.4's cross-repo
// contract pin: it makes any future divergence between Python emit
// and Go consumption fail loudly at CI time.
func TestJobConsumer_MatchesPythonWireFormat(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)

	require.NoError(t,
		client.LPush(t.Context(), "shieldscan:queue:high",
			string(events.FixtureJobDispatchPythonV1)).Err())

	d, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, d)
	job := d.Job

	// Top-level fields per SPEC §7.1 example.
	assert.Equal(t, "job_a1b2c3d4", job.ID)
	assert.Equal(t, "scn_x1y2z3", job.ScanID)
	assert.Equal(t, "org_m1n2o3", job.OrganizationID)
	assert.Equal(t, "nuclei", job.Engine)
	assert.Equal(t, "scn_x1y2z3:nuclei:1711720200", job.IdempotencyKey)

	// Nested target object.
	assert.Equal(t, "https://app.example.com", job.Target.URL)
	assert.Equal(t, "web", job.Target.TargetType)
	assert.True(t, job.Target.DomainVerified)

	// Nested auth object (non-null in this fixture).
	require.NotNil(t, job.Auth)
	assert.Equal(t, "cookie", job.Auth.Type)
	assert.Equal(t, "session=abc123; csrf=xyz789", job.Auth.Data)

	// Open-ended config map.
	assert.Equal(t, "standard", job.Config["depth"])
	require.IsType(t, []any{}, job.Config["template_categories"])
	cats := job.Config["template_categories"].([]any)
	assert.Len(t, cats, 2)

	// Nullable mobile_config.
	assert.Nil(t, job.MobileConfig)

	assert.Equal(t, "shieldscan:progress:scn_x1y2z3", job.CallbackStream)
	assert.Equal(t, "2026-04-18T14:30:00Z", job.CreatedAt)
}

// ---------------------------------------------------------------------
// Reliable-queue behaviour (Drift #70)
//
// The tests above pin decode + priority. These pin the property the
// whole change exists for: while a job is being worked on, its payload
// still exists somewhere in Redis.
// ---------------------------------------------------------------------

// mkJob builds a minimal SPEC §7.1 payload with a distinct id + key.
func mkJob(id string) string {
	return `{
		"id": "` + id + `", "scan_id": "s1", "organization_id": "o1",
		"engine": "nuclei", "idempotency_key": "idem_` + id + `",
		"target": {"url":"https://x.example.com","target_type":"web","domain_verified":true},
		"auth": null, "config": {}, "mobile_config": null,
		"callback_stream": "shieldscan:progress:s1",
		"created_at": "2026-04-18T14:30:00Z"
	}`
}

// The central invariant. Before this change a popped job existed only
// in the worker's memory, so a kill -9 destroyed it permanently.
func TestJobConsumer_PopLeavesThePayloadInTheProcessingList(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)
	ctx := t.Context()

	require.NoError(t, client.LPush(ctx, "shieldscan:queue:high", mkJob("job_1")).Err())

	d, err := consumer.Pop(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, d)

	// Gone from the queue...
	qn, err := client.LLen(ctx, "shieldscan:queue:high").Result()
	require.NoError(t, err)
	assert.Zero(t, qn, "job should have left the dispatch queue")

	// ...but recorded as in-flight, byte-for-byte.
	held, err := client.LRange(ctx, ProcessingKey(testWorkerID, "high"), 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, held, 1, "an in-flight job must be recoverable from Redis, "+
		"not held only in the worker's memory")
	assert.Equal(t, d.Payload, held[0])
}

// Ack is the other half: a finished job must NOT stay in the processing
// list, or a later sweep would report a completed job as failed.
func TestJobConsumer_AckRemovesTheDelivery(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)
	ctx := t.Context()

	require.NoError(t, client.LPush(ctx, "shieldscan:queue:normal", mkJob("job_1")).Err())
	d, err := consumer.Pop(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, d)

	require.NoError(t, consumer.Ack(ctx, d))

	n, err := client.LLen(ctx, ProcessingKey(testWorkerID, "normal")).Result()
	require.NoError(t, err)
	assert.Zero(t, n)
}

// Ack removes the RIGHT entry. With several jobs in flight at once
// (WORKER_CONCURRENCY > 1), acking by position instead of by value
// would clear a job that is still running.
func TestJobConsumer_AckRemovesOnlyItsOwnDelivery(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)
	ctx := t.Context()

	require.NoError(t, client.LPush(ctx, "shieldscan:queue:high", mkJob("job_a")).Err())
	require.NoError(t, client.LPush(ctx, "shieldscan:queue:high", mkJob("job_b")).Err())

	first, err := consumer.Pop(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	second, err := consumer.Pop(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, second)

	require.NoError(t, consumer.Ack(ctx, second))

	held, err := client.LRange(ctx, ProcessingKey(testWorkerID, "high"), 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, held, 1)
	assert.Equal(t, first.Payload, held[0],
		"acking one job removed a different job that was still running")
}

// Acking something that is not there is an error, not a silent success:
// it means somebody else drained our processing list, which is the
// liveness guard having failed.
func TestJobConsumer_AckReportsAMissingEntry(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client, testWorkerID)
	ctx := t.Context()

	require.NoError(t, client.LPush(ctx, "shieldscan:queue:low", mkJob("job_1")).Err())
	d, err := consumer.Pop(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	require.NoError(t, consumer.Ack(ctx, d))

	err = consumer.Ack(ctx, d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already gone")
}

// Processing lists are per worker AND per priority. Per worker so
// liveness scopes recovery; per priority so a reclaimed job can go back
// where it came from — the payload carries no priority field.
func TestJobConsumer_ProcessingKeyRoundTrips(t *testing.T) {
	key := ProcessingKey("host-01-a1b2c3d4", "critical")
	assert.Equal(t, "shieldscan:processing:host-01-a1b2c3d4:critical", key)

	workerID, priority, ok := splitProcessingKey(key)
	require.True(t, ok)
	assert.Equal(t, "host-01-a1b2c3d4", workerID)
	assert.Equal(t, "critical", priority)

	for _, bad := range []string{
		"shieldscan:workers:host-01",        // wrong namespace
		"shieldscan:processing:no-priority", // no separator
		"shieldscan:processing::high",       // empty worker id
		"shieldscan:processing:host-01:",    // empty priority
	} {
		_, _, ok := splitProcessingKey(bad)
		assert.False(t, ok, "accepted malformed key %q", bad)
	}
}
