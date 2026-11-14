package agent

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// The HTTPS implementations of the five ProcessorDeps surfaces
// (progress, cancel, completions, idempotency, publish marker) plus the
// recon package's two publisher interfaces. Each mirrors exactly what
// the Redis implementation writes, because the gateway forwards the
// bodies verbatim: the SSE endpoint and the completions consumer must
// not be able to tell an agent job from a worker job.

// ---------------------------------------------------------------- progress

// flushInterval bounds how often buffered progress events are posted
// (design §3 step 4: "batched, at most once a second").
const flushInterval = time.Second

// progressPublisher batches ProgressEvents for one job and posts them
// to /jobs/{id}/events. Publish never blocks on the network; a flusher
// goroutine (bound to the job ctx, waited for by Close) does the I/O.
type progressPublisher struct {
	client *Client
	jobID  string
	scanID string
	log    zerolog.Logger

	mu      sync.Mutex
	pending []events.ProgressEvent
	seq     int

	wake chan struct{}
	done chan struct{}
}

func newProgressPublisher(ctx context.Context, client *Client, jobID, scanID string, log zerolog.Logger) *progressPublisher {
	p := &progressPublisher{
		client: client,
		jobID:  jobID,
		scanID: scanID,
		log:    log,
		wake:   make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go p.loop(ctx)
	return p
}

// Publish mirrors redis.ProgressPublisher.Publish: inject event_type,
// scan_id and timestamp, then queue. The returned id is a local
// sequence number (the stream id is assigned by the gateway's XADD and
// nothing on the agent side needs it).
func (p *progressPublisher) Publish(_ context.Context, eventType events.EventType, payload events.ProgressEvent) (string, error) {
	if payload == nil {
		payload = events.ProgressEvent{}
	}
	payload["event_type"] = string(eventType)
	payload["scan_id"] = p.scanID
	payload["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	p.mu.Lock()
	p.pending = append(p.pending, payload)
	p.seq++
	id := p.seq
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
	return "agent-" + itoa(id), nil
}

func (p *progressPublisher) take() []events.ProgressEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	batch := p.pending
	p.pending = nil
	return batch
}

// loop posts batches at most once per flushInterval until ctx ends,
// then exits. Close drains whatever is left with its own bound.
func (p *progressPublisher) loop(ctx context.Context) {
	defer close(p.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
			// Coalesce: wait for the tick so bursts become one request.
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			p.flush(ctx)
		case <-ticker.C:
			p.flush(ctx)
		}
	}
}

func (p *progressPublisher) flush(ctx context.Context) {
	batch := p.take()
	if len(batch) == 0 {
		return
	}
	// Progress is best-effort: bound each flush so a dead network never
	// stalls the job it is reporting on. Client.do retries inside.
	fctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := p.client.PostEvents(fctx, p.jobID, batch); err != nil {
		p.log.Warn().Err(err).Int("events", len(batch)).Msg("progress batch dropped")
	}
}

// Close stops the loop (the job ctx is normally already done) and posts
// the final batch with parentCtx, which outlives the job — the terminal
// job_completed/job_failed progress event is what the live feed ends on.
func (p *progressPublisher) Close(parentCtx context.Context) {
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.log.Warn().Msg("progress flusher did not stop in time")
	}
	p.flush(parentCtx)
}

// ---------------------------------------------------------------- completions

// completionsPublisher posts each JobCompletedEvent (and recon's
// EventAttackSurface) to /jobs/{id}/complete. The gateway publishes it
// on shieldscan:completions with org/scan/job/engine pinned.
type completionsPublisher struct {
	client *Client
	jobID  string
}

func (c *completionsPublisher) Publish(ctx context.Context, ev events.JobCompletedEvent) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	return c.client.Complete(ctx, c.jobID, ev)
}

func (c *completionsPublisher) PublishAttackSurface(ctx context.Context, ev events.EventAttackSurface) error {
	return c.client.Complete(ctx, c.jobID, ev)
}

// ---------------------------------------------------------------- cancel

// cancelHub turns the cancel_scan_ids list in heartbeat replies into
// the per-scan CancelEvent channel the processor's cancel watcher
// expects. One subscriber per scan at a time (one job at a time).
type cancelHub struct {
	mu   sync.Mutex
	subs map[string]*cancelSub
}

type cancelSub struct {
	hub    *cancelHub
	scanID string
	ch     chan events.CancelEvent
	once   sync.Once
}

func newCancelHub() *cancelHub { return &cancelHub{subs: map[string]*cancelSub{}} }

// Subscribe registers interest in cancels for scanID. The channel is
// closed by Close (processor's path 3) so the watcher exits cleanly.
func (h *cancelHub) Subscribe(_ context.Context, scanID string) (*cancelSub, error) {
	s := &cancelSub{hub: h, scanID: scanID, ch: make(chan events.CancelEvent, 1)}
	h.mu.Lock()
	h.subs[scanID] = s
	h.mu.Unlock()
	return s, nil
}

// Deliver fans the gateway's pending cancel ids out to subscribers.
func (h *cancelHub) Deliver(scanIDs []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, id := range scanIDs {
		if s, ok := h.subs[id]; ok {
			select {
			case s.ch <- events.CancelEvent{EventType: events.EventCancelRequested, ScanID: id, Reason: "user_requested", Timestamp: now}:
			default: // already pending
			}
		}
	}
}

func (s *cancelSub) Events() <-chan events.CancelEvent { return s.ch }

func (s *cancelSub) Close() error {
	s.once.Do(func() {
		s.hub.mu.Lock()
		if cur, ok := s.hub.subs[s.scanID]; ok && cur == s {
			delete(s.hub.subs, s.scanID)
		}
		s.hub.mu.Unlock()
		close(s.ch)
	})
	return nil
}

// ---------------------------------------------------------------- idempotency

// localClaims is the SETNX stand-in. The gateway re-queues a lost lease
// with the same payload, so the same idempotency key can arrive twice:
// if this process already ran it, the second copy is dropped, exactly
// as the worker drops a duplicate. Keys expire after a day.
type localClaims struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newLocalClaims() *localClaims { return &localClaims{seen: map[string]time.Time{}} }

func (l *localClaims) Claim(_ context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-24 * time.Hour)
	for k, t := range l.seen {
		if t.Before(cutoff) {
			delete(l.seen, k)
		}
	}
	if _, dup := l.seen[key]; dup {
		return false, nil
	}
	l.seen[key] = time.Now()
	return true, nil
}

// noopMarker: the publish marker feeds the worker's Redis reclaimer,
// which agent jobs never pass through (the gateway's lease sweep is
// the equivalent, and it keys on completion, not on this record).
type noopMarker struct{}

func (noopMarker) MarkPublished(context.Context, string) error { return nil }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
