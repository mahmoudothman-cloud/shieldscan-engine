package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// ProgressMaxLen is the approximate cap on per-scan progress stream
// length per ADR-014 + M4 Python ProgressPublisher (`maxlen=1000,
// approximate=True`). Cross-repo coupling: changing this value
// requires Python ScanQueue update + SPEC §6.4 amendment in sync.
//
// Approximate trim (XADD MAXLEN ~ 1000) lets Redis trim in batches
// for performance; actual length may be slightly above 1000. Tests
// assert <= 1100 (roughly +10%) to accommodate the approximation.
const ProgressMaxLen = 1000

// progressKeyPrefix is the per-scan Stream key namespace.
const progressKeyPrefix = "shieldscan:progress:"

// ProgressPublisher wraps XADD against the per-scan progress Stream
// (per ADR-018: Streams, NOT Pub/Sub). M4 Python ProgressSubscriber
// (scan_queue.py) reads this Stream via XRANGE for SSE replay +
// XREAD BLOCK for live tail.
//
// Each event is stored as a single field "event" containing the
// JSON-serialized payload. (Streams require field=value pairs at
// the XADD level; collapsing to one field avoids hand-decomposing
// the structure into top-level Stream fields and keeps the schema
// consumer-controlled.) This matches Python's `xadd(key, {"event":
// json.dumps(event)})` exactly.
//
// Cross-repo coupling: file location (stream.go vs pubsub.go) is
// ADR-018 file-layout discipline. Engineer adding progress logic
// looks at stream.go first; cancel/completions logic in pubsub.go.
type ProgressPublisher struct {
	client *redis.Client
	scanID string
	key    string
}

// NewProgressPublisher constructs a publisher bound to a specific
// scan's Stream key.
func NewProgressPublisher(client *redis.Client, scanID string) *ProgressPublisher {
	return &ProgressPublisher{
		client: client,
		scanID: scanID,
		key:    progressKeyPrefix + scanID,
	}
}

// Publish appends a progress event to the per-scan Stream. Returns
// the assigned Stream entry id (e.g., "1714521234567-0") for SSE
// Last-Event-ID compatibility — M4 Python ProgressSubscriber yields
// the same ID format.
//
// Header injection (matches Python pattern): the publisher injects
// event_type, scan_id, and timestamp into the payload before JSON-
// serialization. Callers pass only the variant-specific fields
// (e.g., progress, message, finding_count for a job_progress event;
// count, subdomains for a subdomains_discovered event).
//
// Loose typing on payload (events.ProgressEvent = map[string]any)
// is deliberate — see events package godoc.
func (p *ProgressPublisher) Publish(ctx context.Context, eventType events.EventType, payload events.ProgressEvent) (string, error) {
	if payload == nil {
		payload = events.ProgressEvent{}
	}
	payload["event_type"] = string(eventType)
	payload["scan_id"] = p.scanID
	payload["timestamp"] = time.Now().UTC().Format(time.RFC3339)

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal progress event: %w", err)
	}

	id, err := p.client.XAdd(ctx, &redis.XAddArgs{
		Stream: p.key,
		MaxLen: ProgressMaxLen,
		Approx: true,
		Values: map[string]any{"event": string(data)},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("XADD %s: %w", p.key, err)
	}
	return id, nil
}
