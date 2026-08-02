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

// TestJobConsumer_PopFromMiniredis is the canonical happy path:
// LPUSH a Python-shaped payload, BRPOP returns deserialized
// JobDispatch. Uses a minimal payload (not the full fixture) to
// keep the test focused on the BRPOP+decode mechanics.
func TestJobConsumer_PopFromMiniredis(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client)

	payload := `{
		"id": "job_x", "scan_id": "s1", "organization_id": "o1",
		"engine": "nuclei", "idempotency_key": "k1",
		"target": {"url":"https://x.example.com","target_type":"web","domain_verified":true},
		"auth": null, "config": {"depth":"quick"},
		"mobile_config": null, "callback_stream": "shieldscan:progress:s1",
		"created_at": "2026-04-18T14:30:00Z"
	}`
	require.NoError(t, client.LPush(t.Context(), "shieldscan:queue:high", payload).Err())

	job, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, job)
	assert.Equal(t, "job_x", job.ID)
	assert.Equal(t, "nuclei", job.Engine)
	assert.Equal(t, "https://x.example.com", job.Target.URL)
	assert.Nil(t, job.Auth)
	assert.Equal(t, "quick", job.Config["depth"])
}

// TestJobConsumer_MultiPriorityDrainOrder pins the priority order:
// critical > high > normal > low. LPUSH onto multiple queues; the
// first BRPOP returns the highest-priority entry.
func TestJobConsumer_MultiPriorityDrainOrder(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client)
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
		job, err := consumer.Pop(ctx, 100*time.Millisecond)
		require.NoError(t, err, "pop #%d", i)
		require.NotNil(t, job, "pop #%d should not be nil", i)
		assert.Equal(t, want, job.ID, "pop #%d order", i)
	}
}

// TestJobConsumer_TimeoutReturnsNilNil pins the empty-queue case:
// no jobs available + timeout elapses → (nil, nil), not error.
func TestJobConsumer_TimeoutReturnsNilNil(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client)

	job, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, job, "empty queue + timeout returns (nil, nil)")
}

// TestJobConsumer_CtxCancelExits pins ADR-021 ctx-discipline:
// when the caller cancels ctx, Pop returns the ctx error rather
// than (nil, nil) timeout-success.
//
// miniredis limitation: miniredis's BRPOP runs synchronously and
// does NOT honor ctx-cancel mid-flight (real Redis cancels via
// connection close + go-redis aborts). To test the ctx.Err() check
// path, we use a short BRPOP timeout so the in-flight call
// completes naturally; the ctx-cancel happens during the wait, and
// Pop's post-BRPOP ctx.Err() check returns the cancellation.
//
// On real Redis the ctx cancel would interrupt BRPOP immediately
// (hundreds of ms faster). The test still pins the contract that
// Pop returns ctx.Err() when canceled, which is the load-bearing
// invariant for 5.5's processor.
func TestJobConsumer_CtxCancelExits(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client)

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		// Short BRPOP timeout: lets miniredis return redis.Nil
		// naturally; ctx-cancel-check then returns Canceled.
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
// underlying job is consumed (BRPOP popped it) so 5.5's loop won't
// see the same garbage on next iteration.
func TestJobConsumer_MalformedJSONReturnsError(t *testing.T) {
	_, client := newMiniredisClient(t)
	consumer := NewJobConsumer(client)

	require.NoError(t, client.LPush(t.Context(), "shieldscan:queue:high", "not-json{{{").Err())

	job, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.Error(t, err)
	assert.Nil(t, job)
	assert.Contains(t, err.Error(), "malformed queued job")

	// Confirm the malformed entry was consumed (queue is now empty).
	job2, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, job2, "malformed entry was consumed; queue should be empty")
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
	consumer := NewJobConsumer(client)

	require.NoError(t,
		client.LPush(t.Context(), "shieldscan:queue:high",
			string(events.FixtureJobDispatchPythonV1)).Err())

	job, err := consumer.Pop(t.Context(), 100*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, job)

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
