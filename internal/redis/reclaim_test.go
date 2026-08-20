package redis

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// These tests pin what happens to the jobs a dead worker had in flight
// (Drift #70). The two failure modes worth guarding are opposite in
// direction and both customer-visible: retrying a job that already
// published findings duplicates them, and refusing to act on a job whose
// worker is genuinely gone leaves the parent scan unable to ever reach a
// terminal state.

const (
	deadWorker = "host-01-deadbeef"
	livePeer   = "host-01-11112222"
	selfWorker = "host-01-33334444"
)

func liveWorkers(ids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

// inFlight puts a payload in a worker's processing list, as Pop would.
func inFlight(t *testing.T, client *redis.Client, workerID, priority, payload string) {
	t.Helper()
	require.NoError(t, client.LPush(t.Context(),
		ProcessingKey(workerID, priority), payload).Err())
}

// subscribeCompletions returns a subscription to the completions channel
// with the handshake already done, so nothing published afterwards is
// missed.
func subscribeCompletions(t *testing.T, client *redis.Client) *redis.PubSub {
	t.Helper()
	pubsub := client.Subscribe(t.Context(), completionsChannel)
	t.Cleanup(func() { _ = pubsub.Close() })
	_, err := pubsub.Receive(t.Context())
	require.NoError(t, err)
	return pubsub
}

func awaitCompletion(t *testing.T, pubsub *redis.PubSub) events.JobCompletedEvent {
	t.Helper()
	select {
	case msg := <-pubsub.Channel():
		var ev events.JobCompletedEvent
		require.NoError(t, json.Unmarshal([]byte(msg.Payload), &ev))
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no completion event published within 2s")
		return events.JobCompletedEvent{}
	}
}

// The happy path for recovery: a worker died before publishing anything,
// so the job goes back on the queue it came from and can run again.
func TestReclaim_RequeuesAJobThatPublishedNothing(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()
	payload := mkJob("job_1")

	inFlight(t, client, deadWorker, "high", payload)
	// The dead worker had claimed the key before it started.
	require.NoError(t, client.Set(ctx, "shieldscan:idem:idem_job_1", "1", time.Hour).Err())

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker),
	})
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{Requeued: 1}, got)

	queued, err := client.LRange(ctx, "shieldscan:queue:high", 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, queued, 1, "job did not go back onto its original priority queue")
	assert.JSONEq(t, payload, queued[0])

	// The claim must be gone, or the requeued job would be popped and
	// dropped as a duplicate — losing it a second time, silently.
	exists, err := client.Exists(ctx, "shieldscan:idem:idem_job_1").Result()
	require.NoError(t, err)
	assert.Zero(t, exists, "idempotency claim was not released; the requeued job "+
		"would be dropped as a duplicate")

	n, err := client.LLen(ctx, ProcessingKey(deadWorker, "high")).Result()
	require.NoError(t, err)
	assert.Zero(t, n)
}

// The guard the whole retry-versus-fail decision turns on. ADR-017
// sequencing lets a job publish findings before dying; retrying such a
// job would duplicate rows that already landed in raw_findings.
func TestReclaim_FailsRatherThanRetriesAJobThatAlreadyPublished(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	inFlight(t, client, deadWorker, "normal", mkJob("job_1"))
	require.NoError(t, NewPublishGuard(client).MarkPublished(ctx, "idem_job_1"))

	pubsub := subscribeCompletions(t, client)

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker),
	})
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{Failed: 1}, got)

	ev := awaitCompletion(t, pubsub)
	assert.Equal(t, "failed", ev.Status)
	assert.Equal(t, "job_1", ev.JobID)
	assert.Equal(t, "idem_job_1", ev.IdempotencyKey)
	assert.Contains(t, ev.ErrorMessage, "duplicate findings")

	queued, err := client.LLen(ctx, "shieldscan:queue:normal").Result()
	require.NoError(t, err)
	assert.Zero(t, queued, "a job that had already published results was requeued")
}

// The retry bound. A job that killed its worker once is likelier poison
// than unlucky, and the second death would cost another full tool
// runtime to learn nothing.
func TestReclaim_FailsOnceTheRetryBudgetIsSpent(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	// First death: requeued.
	inFlight(t, client, deadWorker, "high", mkJob("job_1"))
	r := NewReclaimer(client, zerolog.Nop())
	policy := ReclaimPolicy{SelfWorkerID: selfWorker, LiveWorkerIDs: liveWorkers(selfWorker)}

	first, err := r.Reclaim(ctx, policy)
	require.NoError(t, err)
	require.Equal(t, 1, first.Requeued)

	// Second death, same job, same key.
	require.NoError(t, client.Del(ctx, "shieldscan:queue:high").Err())
	inFlight(t, client, deadWorker, "high", mkJob("job_1"))
	pubsub := subscribeCompletions(t, client)

	second, err := r.Reclaim(ctx, policy)
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{Failed: 1}, second)

	ev := awaitCompletion(t, pubsub)
	assert.Equal(t, "failed", ev.Status)
	assert.Contains(t, ev.ErrorMessage, "retry budget")

	queued, err := client.LLen(ctx, "shieldscan:queue:high").Result()
	require.NoError(t, err)
	assert.Zero(t, queued, "a job past its retry budget was requeued anyway")
}

// The liveness guard, and the reason it is the same 60s heartbeat the
// container reaper uses. Reclaiming a live peer's in-flight job would
// requeue a scan that is still running.
func TestReclaim_LeavesLiveWorkersAndOurselvesAlone(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	inFlight(t, client, livePeer, "high", mkJob("job_peer"))
	inFlight(t, client, selfWorker, "high", mkJob("job_self"))
	inFlight(t, client, deadWorker, "high", mkJob("job_dead"))

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker, livePeer),
	})
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{Requeued: 1}, got)

	for _, w := range []string{livePeer, selfWorker} {
		n, err := client.LLen(ctx, ProcessingKey(w, "high")).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), n, "reclaimed the in-flight job of %s", w)
	}

	queued, err := client.LRange(ctx, "shieldscan:queue:high", 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, queued, 1)
	assert.Contains(t, queued[0], "job_dead")
}

// Fail-safe, mirroring ReapPolicy: liveness unknown means do nothing.
// Guessing here would requeue a running scan.
func TestReclaim_DeclinesWhenLivenessIsUnknown(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	inFlight(t, client, deadWorker, "high", mkJob("job_1"))

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: nil,
	})
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{}, got)

	n, err := client.LLen(ctx, ProcessingKey(deadWorker, "high")).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

// Two payloads for one job — a duplicate dispatch whose drop never got
// acked — must be handled once. Counting each copy separately would push
// the second past the retry budget and fail a job the first just
// requeued.
func TestReclaim_HandlesDuplicatePayloadsForOneJobOnce(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	inFlight(t, client, deadWorker, "high", mkJob("job_1"))
	inFlight(t, client, deadWorker, "high", mkJob("job_1"))

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker),
	})
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{Requeued: 1, Dropped: 1}, got)

	queued, err := client.LLen(ctx, "shieldscan:queue:high").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), queued, "a duplicate payload was requeued as a second job")
}

// One undecodable payload must not strand the rest of the list.
func TestReclaim_ContinuesPastAnUndecodablePayload(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	// LPUSH order: the garbage is drained first (RPOP takes the tail).
	inFlight(t, client, deadWorker, "high", "not-json{{{")
	inFlight(t, client, deadWorker, "high", mkJob("job_good"))

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker),
	})
	require.NoError(t, err)
	assert.Equal(t, ReclaimResult{Requeued: 1, Dropped: 1}, got)

	queued, err := client.LRange(ctx, "shieldscan:queue:high", 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, queued, 1)
	assert.Contains(t, queued[0], "job_good")
}

// The sweep covers every priority a dead worker could have been holding,
// and each job returns to its own queue.
func TestReclaim_RequeuesEachPriorityToItsOwnQueue(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	for _, p := range canonicalPriorities {
		inFlight(t, client, deadWorker, p, mkJob("job_"+p))
	}

	got, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker),
	})
	require.NoError(t, err)
	assert.Equal(t, 4, got.Requeued)

	for _, p := range canonicalPriorities {
		queued, err := client.LRange(ctx, queueKeyPrefix+p, 0, -1).Result()
		require.NoError(t, err)
		require.Len(t, queued, 1, "priority %s", p)
		assert.Contains(t, queued[0], "job_"+p)
	}
}

// A reclaimed job goes to the head of the line, not the back of it. It
// has already waited through a worker's death; queueing it behind newer
// work would compound the delay the customer already saw.
func TestReclaim_RequeuedJobIsServedNext(t *testing.T) {
	_, client := newMiniredisClient(t)
	ctx := t.Context()

	// Newer work already waiting.
	require.NoError(t, client.LPush(ctx, "shieldscan:queue:high", mkJob("job_new")).Err())
	inFlight(t, client, deadWorker, "high", mkJob("job_old"))

	_, err := NewReclaimer(client, zerolog.Nop()).Reclaim(ctx, ReclaimPolicy{
		SelfWorkerID:  selfWorker,
		LiveWorkerIDs: liveWorkers(selfWorker),
	})
	require.NoError(t, err)

	consumer := NewJobConsumer(client, selfWorker)
	d, err := consumer.Pop(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, d)
	assert.Equal(t, "job_old", d.Job.ID, "the reclaimed job should be served next")
}
