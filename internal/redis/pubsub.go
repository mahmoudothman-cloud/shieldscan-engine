package redis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// cancelKeyPrefix is the per-scan Pub/Sub channel for cancel signals.
const cancelKeyPrefix = "shieldscan:cancel:"

// completionsChannel is the single Pub/Sub channel for job completion
// events. M4 Python CompletionsConsumer subscribes to this channel
// and dispatches by scan_id internally.
const completionsChannel = "shieldscan:completions"

// CancelSubscriber wraps a per-scan Pub/Sub subscription. ADR-014
// keeps cancel as Pub/Sub (one-shot live-only): a worker not
// subscribed when cancel emits cannot usefully consume a stale
// cancel — replay would be misleading.
//
// Lifecycle (ADR-021 Rule 2):
//   - NewCancelSubscriber spawns a converter goroutine that reads
//     redis.Message from the underlying pubsub.Channel(), unmarshals
//     to events.CancelEvent, forwards on the Events() channel.
//   - Converter exits on ctx.Done() OR on Close() (which closes
//     the underlying pubsub).
//   - Events() channel closes when the converter exits.
//
// On Redis transient disconnect, go-redis v9 does NOT auto-reconnect;
// the underlying pubsub.Channel() closes, the converter exits, and
// Events() closes. Callers (M5.5 processor) detect the close and
// decide: re-subscribe (recoverable) or fail-the-job (unrecoverable).
// Same shape as 5.3's "retry deferred to per-tool Execute": primitives
// surface failure; orchestration decides recovery.
type CancelSubscriber struct {
	pubsub *redis.PubSub
	events chan events.CancelEvent
	done   chan struct{}
}

// NewCancelSubscriber subscribes to the per-scan cancel channel.
// Returns when the subscription is acknowledged by Redis (or returns
// an error if the subscribe handshake fails). The Events() channel
// is live for receives immediately after this constructor returns.
//
// Caller MUST call Close() to release the subscription, even if ctx
// is canceled. The Events() channel is closed by the converter
// goroutine on exit, so a closed Events() is a signal that the
// subscriber is no longer live (caller may Close to clean up the
// pubsub object as well; idempotent).
func NewCancelSubscriber(ctx context.Context, client *redis.Client, scanID string) (*CancelSubscriber, error) {
	key := cancelKeyPrefix + scanID
	pubsub := client.Subscribe(ctx, key)

	// Wait for subscription confirmation. Without this, a Publish
	// emitted before the subscription is fully established would
	// be lost. Receive blocks until Redis sends the subscribe
	// confirmation message (Kind: "subscribe").
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		return nil, fmt.Errorf("subscribe %s: %w", key, err)
	}

	s := &CancelSubscriber{
		pubsub: pubsub,
		events: make(chan events.CancelEvent, 1), // buffered: fire-and-forget
		done:   make(chan struct{}),
	}
	go s.run(ctx)
	return s, nil
}

// Events returns the receive-only channel of decoded cancel events.
// Closes when the subscriber's converter goroutine exits (on
// ctx.Done() or Close()).
func (s *CancelSubscriber) Events() <-chan events.CancelEvent {
	return s.events
}

// Close releases the subscription and waits for the converter
// goroutine to exit. Idempotent — multiple Close calls are safe.
func (s *CancelSubscriber) Close() error {
	err := s.pubsub.Close()
	<-s.done
	return err
}

// run is the converter goroutine. Three exit paths:
//
//   - ctx.Done() — caller canceled.
//   - msgCh closed — pubsub disconnected (Redis transient drop or
//     Close() called from another goroutine).
//   - Send blocked + ctx.Done() — Events channel full and ctx canceled.
//
// Each path closes Events() (via defer) so callers can detect
// subscriber-no-longer-live via a closed channel receive.
func (s *CancelSubscriber) run(ctx context.Context) {
	defer close(s.events)
	defer close(s.done)

	msgCh := s.pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgCh:
			if !ok {
				return // pubsub closed
			}
			var ev events.CancelEvent
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
				// Malformed payload — drop and continue. M4 Python
				// CancelPublisher emits well-formed JSON; malformed
				// implies upstream bug. Same poison-pill protection
				// as JobConsumer.
				continue
			}
			select {
			case s.events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// CompletionsPublisher wraps Publish against the single
// shieldscan:completions Pub/Sub channel. M4 Python CompletionsConsumer
// subscribes to this channel and dispatches by scan_id internally.
//
// One Publish call per JobCompletedEvent. For sequenced batches
// (>1000 findings per ADR-017), callers use events.SplitForCompletion
// to produce a slice of events, then loop Publish calls.
type CompletionsPublisher struct {
	client *redis.Client
}

// NewCompletionsPublisher constructs a publisher bound to the
// completions channel.
func NewCompletionsPublisher(client *redis.Client) *CompletionsPublisher {
	return &CompletionsPublisher{client: client}
}

// Publish validates the event and emits it on the completions
// channel. Returns an error if the event fails Validate (caught
// before Redis call) or if the Publish RPC fails.
func (p *CompletionsPublisher) Publish(ctx context.Context, ev events.JobCompletedEvent) error {
	if err := ev.Validate(); err != nil {
		return fmt.Errorf("invalid completion event: %w", err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal completion event: %w", err)
	}
	if err := p.client.Publish(ctx, completionsChannel, string(data)).Err(); err != nil {
		return fmt.Errorf("PUBLISH %s: %w", completionsChannel, err)
	}
	return nil
}
