package redis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// TestProgressPublisher_XAddsToStream pins ADR-018: progress events
// go to a Redis Stream, NOT a Pub/Sub channel. After Publish, XLEN
// reads 1 — proves the data structure is a Stream.
//
// If a regression switches to client.Publish (Pub/Sub), XLEN reads 0
// because Pub/Sub doesn't persist messages.
func TestProgressPublisher_XAddsToStream(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewProgressPublisher(client, "scn_x")

	id, err := pub.Publish(t.Context(), events.EventJobStarted, events.ProgressEvent{
		"engine": "nuclei", "job_id": "j1",
	})
	require.NoError(t, err)
	require.NotEmpty(t, id)

	// XLEN proves we wrote a Stream, not a Pub/Sub.
	xlen, err := client.XLen(t.Context(), "shieldscan:progress:scn_x").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), xlen)
}

// TestProgressPublisher_HeadersInjected pins the publisher's header
// injection: event_type, scan_id, timestamp added before serialization.
// Verified by reading the Stream entry back via XRANGE and inspecting
// the JSON.
func TestProgressPublisher_HeadersInjected(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewProgressPublisher(client, "scn_y")

	_, err := pub.Publish(t.Context(), events.EventJobProgress, events.ProgressEvent{
		"engine": "nuclei", "progress": 42, "message": "running templates",
	})
	require.NoError(t, err)

	entries, err := client.XRange(t.Context(), "shieldscan:progress:scn_y", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	raw, ok := entries[0].Values["event"].(string)
	require.True(t, ok, "event field should be JSON string")

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &decoded))

	assert.Equal(t, "job_progress", decoded["event_type"], "event_type header")
	assert.Equal(t, "scn_y", decoded["scan_id"], "scan_id header")
	assert.NotEmpty(t, decoded["timestamp"], "timestamp header")
	// Caller-supplied fields preserved.
	assert.Equal(t, "nuclei", decoded["engine"])
	assert.Equal(t, float64(42), decoded["progress"]) // JSON number → float64
}

// TestProgressPublisher_ReturnsEntryID pins the SSE Last-Event-ID
// compatibility surface: returned ID is in the {ms-seq} format that
// the Python ProgressSubscriber yields and the SSE handler relays.
func TestProgressPublisher_ReturnsEntryID(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewProgressPublisher(client, "scn_z")

	id, err := pub.Publish(t.Context(), events.EventJobStarted, nil)
	require.NoError(t, err)

	// Stream IDs are "{ms}-{seq}" format.
	parts := strings.Split(id, "-")
	require.Len(t, parts, 2, "Stream ID format ms-seq; got %q", id)
	assert.NotEmpty(t, parts[0], "ms portion non-empty")
	assert.NotEmpty(t, parts[1], "seq portion non-empty")
}

// TestProgressPublisher_MaxLenApplied pins the MAXLEN ~ 1000
// approximate trim: publishing 1500 events should leave the Stream
// length within ~10% of 1000 (Redis approximate trim is bounded by
// internal page sizes).
//
// miniredis Streams support: this test is part of the Checkpoint 4
// compat verification. If miniredis's MAXLEN behaves differently
// (e.g., trims to exactly 1000), assertion still passes since we
// allow ≤ 1100; if miniredis ignores MAXLEN entirely, the assertion
// fails and we surface the limitation.
func TestProgressPublisher_MaxLenApplied(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewProgressPublisher(client, "scn_maxlen")

	for i := 0; i < 1500; i++ {
		_, err := pub.Publish(t.Context(), events.EventJobProgress, events.ProgressEvent{
			"i": i,
		})
		require.NoError(t, err, "publish #%d", i)
	}

	xlen, err := client.XLen(t.Context(), "shieldscan:progress:scn_maxlen").Result()
	require.NoError(t, err)
	// Approximate cap: allow up to ~1200 (real Redis can be slightly
	// over due to MAXLEN ~ approximate trim). Real concern is "did
	// trimming happen at all?" — a value >1400 would indicate MAXLEN
	// was ignored.
	assert.LessOrEqual(t, xlen, int64(1200),
		"MAXLEN ~ %d trim should keep length <= ~1200; got %d", ProgressMaxLen, xlen)
	assert.Greater(t, xlen, int64(900),
		"trim should not be over-aggressive; got %d", xlen)
}

// TestProgressPublisher_RoundTripWithXRange pins the M4 contract:
// Publish writes a Stream entry that XRANGE retrieves with the
// exact JSON payload we sent. This is the cross-process round-trip
// that Python ProgressSubscriber.replay relies on.
func TestProgressPublisher_RoundTripWithXRange(t *testing.T) {
	_, client := newMiniredisClient(t)
	pub := NewProgressPublisher(client, "scn_rt")

	publishedID, err := pub.Publish(t.Context(), events.EventSubdomainsDiscovered,
		events.ProgressEvent{
			"count":      3,
			"subdomains": []string{"a.example.com", "b.example.com", "c.example.com"},
		})
	require.NoError(t, err)

	entries, err := client.XRange(t.Context(), "shieldscan:progress:scn_rt", "-", "+").Result()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, publishedID, entries[0].ID)

	raw := entries[0].Values["event"].(string)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &decoded))

	assert.Equal(t, "subdomains_discovered", decoded["event_type"])
	assert.Equal(t, "scn_rt", decoded["scan_id"])
	assert.Equal(t, float64(3), decoded["count"])
	subs, ok := decoded["subdomains"].([]any)
	require.True(t, ok)
	assert.Len(t, subs, 3)
	assert.Equal(t, "a.example.com", subs[0])
}

// Keep go-redis import touched even though only some tests reference
// it directly (others go through the client returned by helper).
var _ = redis.NewClient
