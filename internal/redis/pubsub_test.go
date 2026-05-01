package redis

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// TestMain wires goleak.VerifyTestMain per ADR-021 — load-bearing
// here because CancelSubscriber spawns goroutines via go-redis Pub/Sub.
//
// IgnoreTopFunction entries are for known-OK background goroutines:
//   - go-redis pool reaper: connection-pool background worker that
//     persists for client lifetime; legitimately survives test exit.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).reaper"),
		// miniredis-internal goroutines that may persist briefly
		// during test cleanup; observed during initial test runs.
		goleak.IgnoreAnyFunction("github.com/alicebob/miniredis/v2.(*Miniredis).serve.func1"),
	)
}

// publishCancel emits a CancelEvent JSON to the per-scan cancel
// channel. Test helper for round-trip verification.
func publishCancel(t *testing.T, client *redis.Client, scanID, reason string) {
	t.Helper()
	ev := events.CancelEvent{
		EventType: events.EventCancelRequested,
		ScanID:    scanID,
		Reason:    reason,
		Timestamp: "2026-04-18T14:33:00Z",
	}
	data, err := json.Marshal(ev)
	require.NoError(t, err)
	require.NoError(t, client.Publish(t.Context(), cancelKeyPrefix+scanID, string(data)).Err())
}

// TestCancelSubscriber_ReceivesPublishedEvent pins the canonical
// happy path: subscribe → another goroutine publishes → Events()
// channel yields the decoded CancelEvent.
//
// miniredis Pub/Sub support: this is part of the Checkpoint 4 compat
// verification. If miniredis Pub/Sub behaves differently than real
// Redis (e.g., subscribe handshake doesn't ack, or Publish to
// channel-with-no-subscribers gets dropped before subscribe
// completes), the test fails and we surface the limitation.
func TestCancelSubscriber_ReceivesPublishedEvent(t *testing.T) {
	_, client := newMiniredisClient(t)

	sub, err := NewCancelSubscriber(t.Context(), client, "scn_a")
	require.NoError(t, err)
	defer sub.Close()

	// Publish from another goroutine after the subscription is live.
	go publishCancel(t, client, "scn_a", "user_requested")

	select {
	case ev := <-sub.Events():
		assert.Equal(t, events.EventCancelRequested, ev.EventType)
		assert.Equal(t, "scn_a", ev.ScanID)
		assert.Equal(t, "user_requested", ev.Reason)
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive cancel event within 2s")
	}
}

// TestCancelSubscriber_PerScanIsolation pins per-scan channel
// isolation: a cancel published on scn_a's channel is NOT received
// by scn_b's subscriber.
func TestCancelSubscriber_PerScanIsolation(t *testing.T) {
	_, client := newMiniredisClient(t)

	subA, err := NewCancelSubscriber(t.Context(), client, "scn_a")
	require.NoError(t, err)
	defer subA.Close()

	subB, err := NewCancelSubscriber(t.Context(), client, "scn_b")
	require.NoError(t, err)
	defer subB.Close()

	go publishCancel(t, client, "scn_a", "user_requested")

	// subA should receive.
	select {
	case ev := <-subA.Events():
		assert.Equal(t, "scn_a", ev.ScanID)
	case <-time.After(2 * time.Second):
		t.Fatal("subA did not receive its event within 2s")
	}

	// subB should NOT receive (different channel).
	select {
	case ev := <-subB.Events():
		t.Fatalf("subB received cross-channel event: %+v", ev)
	case <-time.After(200 * time.Millisecond):
		// expected: nothing on subB
	}
}

// TestCancelSubscriber_CtxCancelExits pins ADR-021 Rule 2: the
// converter goroutine exits cleanly when the parent ctx is canceled,
// closing Events(). goleak (TestMain) verifies no leak.
func TestCancelSubscriber_CtxCancelExits(t *testing.T) {
	_, client := newMiniredisClient(t)

	ctx, cancel := context.WithCancel(t.Context())
	sub, err := NewCancelSubscriber(ctx, client, "scn_cancel")
	require.NoError(t, err)
	defer sub.Close()

	cancel()

	// Events() channel should close (drained) — receive returns
	// zero-value with ok=false.
	select {
	case _, ok := <-sub.Events():
		assert.False(t, ok, "Events() should close on ctx cancel")
	case <-time.After(time.Second):
		t.Fatal("Events() did not close within 1s of ctx cancel")
	}
}

// TestCancelSubscriber_CloseExits pins explicit-Close behavior: Close
// releases the subscription and waits for the converter goroutine to
// exit. No leak.
func TestCancelSubscriber_CloseExits(t *testing.T) {
	_, client := newMiniredisClient(t)

	sub, err := NewCancelSubscriber(t.Context(), client, "scn_close")
	require.NoError(t, err)

	// Close should return cleanly.
	require.NoError(t, sub.Close())

	// Subsequent receive on Events() must indicate closed channel.
	select {
	case _, ok := <-sub.Events():
		assert.False(t, ok, "Events() closed after Close()")
	case <-time.After(time.Second):
		t.Fatal("Events() did not close after Close()")
	}
}

// TestCancelSubscriber_MalformedPayloadDropped pins poison-pill
// protection on the cancel channel: malformed JSON is dropped; the
// subscriber continues to deliver subsequent valid events.
func TestCancelSubscriber_MalformedPayloadDropped(t *testing.T) {
	_, client := newMiniredisClient(t)

	sub, err := NewCancelSubscriber(t.Context(), client, "scn_garbage")
	require.NoError(t, err)
	defer sub.Close()

	// Publish garbage first.
	require.NoError(t, client.Publish(t.Context(), cancelKeyPrefix+"scn_garbage", "not-json{{{").Err())
	// Then a valid event.
	go func() {
		// Tiny delay to ensure ordering; both Publish calls land
		// after subscription is live (handshake done in NewCancelSubscriber).
		time.Sleep(50 * time.Millisecond)
		publishCancel(t, client, "scn_garbage", "user_requested")
	}()

	select {
	case ev := <-sub.Events():
		// The garbage event is silently dropped by the converter; we
		// only see the valid one.
		assert.Equal(t, "user_requested", ev.Reason,
			"malformed event dropped; subscriber continues to deliver valid events")
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive valid event after garbage event")
	}
}

// TestCompletionsPublisher_PublishesValidEvent pins the canonical
// happy path: Publish a valid JobCompletedEvent; a subscribing
// client (representing M4 Python CompletionsConsumer) receives it.
func TestCompletionsPublisher_PublishesValidEvent(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewCompletionsPublisher(client)

	// Subscribe representing the Python consumer.
	pubsub := client.Subscribe(t.Context(), completionsChannel)
	defer pubsub.Close()
	_, err := pubsub.Receive(t.Context())
	require.NoError(t, err)

	ev := events.JobCompletedEvent{
		EventType: events.EventJobCompleted,
		JobID:     "job_a", ScanID: "scn_x", Engine: "nuclei",
		Status: "completed", FindingCount: 0, DurationMs: 1000,
		Timestamp: "2026-04-18T14:34:27Z",
		EventSeq:  events.EventSeq{Index: 1, Total: 1},
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		require.NoError(t, pub.Publish(t.Context(), ev))
	}()

	select {
	case msg := <-pubsub.Channel():
		var got events.JobCompletedEvent
		require.NoError(t, json.Unmarshal([]byte(msg.Payload), &got))
		assert.Equal(t, ev.JobID, got.JobID)
		assert.Equal(t, ev.ScanID, got.ScanID)
		assert.Equal(t, ev.Status, got.Status)
		assert.Equal(t, ev.EventSeq, got.EventSeq)
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not receive event within 2s")
	}
}

// TestCompletionsPublisher_RejectsInvalidEvent pins Validate
// integration: Publish errors before any Redis call when the event
// fails Validate.
func TestCompletionsPublisher_RejectsInvalidEvent(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewCompletionsPublisher(client)

	bad := events.JobCompletedEvent{
		EventType: events.EventJobCompleted,
		// JobID deliberately empty → fails Validate
		ScanID: "s", Engine: "n",
		Timestamp: "t",
		EventSeq:  events.EventSeq{Index: 1, Total: 1},
	}

	err := pub.Publish(t.Context(), bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid completion event")
	assert.Contains(t, err.Error(), "job_id")
}

// TestCompletionsPublisher_RoundTripJSON pins full JSON round-trip
// preservation: Publish marshals correctly; subscribing client
// unmarshals the same shape including findings + event_seq.
func TestCompletionsPublisher_RoundTripJSON(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewCompletionsPublisher(client)

	pubsub := client.Subscribe(t.Context(), completionsChannel)
	defer pubsub.Close()
	_, err := pubsub.Receive(t.Context())
	require.NoError(t, err)

	original := events.JobCompletedEvent{
		EventType: events.EventJobCompleted,
		JobID:     "job_rt", ScanID: "scn_rt", Engine: "nuclei",
		Status: "completed", FindingCount: 1, DurationMs: 5000,
		Timestamp: "2026-04-18T14:34:27Z",
		Findings: []events.RawFinding{
			{ToolName: "nuclei", EngineCategory: "dast",
				Title: "XSS", Severity: "high", FindingType: "xss",
				CWEID: "CWE-79", TargetURL: "https://x.example.com",
				Parameter: "q", Fingerprint: "abc123"},
		},
		EventSeq: events.EventSeq{Index: 1, Total: 1},
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		require.NoError(t, pub.Publish(t.Context(), original))
	}()

	select {
	case msg := <-pubsub.Channel():
		got, err := events.DecodeJobCompletedEvent([]byte(msg.Payload))
		require.NoError(t, err)
		assert.Equal(t, original.JobID, got.JobID)
		assert.Equal(t, original.FindingCount, got.FindingCount)
		require.Len(t, got.Findings, 1)
		assert.Equal(t, "XSS", got.Findings[0].Title)
		assert.Equal(t, "abc123", got.Findings[0].Fingerprint)
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not receive event within 2s")
	}
}
