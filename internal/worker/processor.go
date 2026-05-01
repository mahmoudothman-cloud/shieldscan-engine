package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
	rdsh "github.com/odyssey/shieldscan-engine/internal/redis"
	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// progressPublisher abstracts the publisher's Publish method so the
// processor's factory injection point doesn't leak the concrete
// type. Production wires redis.ProgressPublisher; tests can wrap.
type progressPublisher interface {
	Publish(ctx context.Context, eventType events.EventType, payload events.ProgressEvent) (string, error)
}

// cancelSubscriber abstracts the subscriber surface used by the
// processor. Production wires *redis.CancelSubscriber.
type cancelSubscriber interface {
	Events() <-chan events.CancelEvent
	Close() error
}

// completionsPublisher abstracts the completion publisher.
type completionsPublisher interface {
	Publish(ctx context.Context, ev events.JobCompletedEvent) error
}

// idempotencyClaim abstracts the SETNX-based idempotency primitive.
type idempotencyClaim interface {
	Claim(ctx context.Context, key string) (bool, error)
}

// ProcessorDeps wires the processor's external dependencies.
//
// ProgressPublisherFn and CancelSubscriberFn are factories invoked
// per-job so each scan gets its own bound primitive. Production
// closures wrap redis.NewProgressPublisher / NewCancelSubscriber;
// tests inject miniredis-backed equivalents.
type ProcessorDeps struct {
	Registry             *Registry
	IdempotencyClaim     idempotencyClaim
	ProgressPublisherFn  func(scanID string) progressPublisher
	CancelSubscriberFn   func(ctx context.Context, scanID string) (cancelSubscriber, error)
	CompletionsPublisher completionsPublisher
	Logger               zerolog.Logger
}

// Processor handles a single job from JobDispatch through to
// completion-event emission. Stateless beyond its injected deps —
// safe to share across concurrent goroutines (each Process call
// uses its own jobCtx + per-call publishers/subscribers).
type Processor struct {
	registry       *Registry
	idem           idempotencyClaim
	progressPubFn  func(string) progressPublisher
	cancelSubFn    func(context.Context, string) (cancelSubscriber, error)
	completionsPub completionsPublisher
	log            zerolog.Logger
}

// NewProcessor constructs a Processor from injected deps. Required
// fields: Registry, IdempotencyClaim, CompletionsPublisher.
// ProgressPublisherFn and CancelSubscriberFn default to no-op-yielding
// closures if nil (useful for tests that don't care about those
// surfaces).
func NewProcessor(deps ProcessorDeps) *Processor {
	if deps.Registry == nil {
		panic("worker.NewProcessor: Registry is required")
	}
	if deps.IdempotencyClaim == nil {
		panic("worker.NewProcessor: IdempotencyClaim is required")
	}
	if deps.CompletionsPublisher == nil {
		panic("worker.NewProcessor: CompletionsPublisher is required")
	}
	return &Processor{
		registry:       deps.Registry,
		idem:           deps.IdempotencyClaim,
		progressPubFn:  deps.ProgressPublisherFn,
		cancelSubFn:    deps.CancelSubscriberFn,
		completionsPub: deps.CompletionsPublisher,
		log:            deps.Logger,
	}
}

// Process executes a single job's lifecycle.
//
// Lifecycle:
//
//  1. Idempotency claim — drop silently on duplicate.
//  2. Build job-scoped ctx (jobCtx = WithCancel(ctx)).
//  3. Spawn cancel-watcher goroutine (if subscriber available).
//  4. Emit job_started progress event.
//  5. Look up runner; emit job_failed if not registered.
//  6. Invoke runner.Run(jobCtx, target, cfg).
//  7. Wait for cancel-watcher to exit; close subscriber.
//  8. Discriminate cancel-vs-error-vs-success per the table below.
//  9. On success: enrich findings + SplitForCompletion + Publish each.
//
// 10. Emit final progress event.
//
// Discrimination semantics after runner.Run returns:
//
//	runErr        jobCtx.Err              ctx.Err   →  Emission
//	──────────────────────────────────────────────────────────────────
//	nil           nil                     nil       →  job_completed
//	                                                     + completion events
//	non-nil       Canceled                nil       →  job_canceled
//	                                                     (user-initiated)
//	non-nil       DeadlineExceeded        any       →  job_failed
//	                                                     (timeout reason)
//	non-nil       any (other)             any       →  job_failed
//	                                                     (error message)
//	nil           any                     Canceled  →  job_completed
//	                                                     (worker shutdown
//	                                                      after clean Run)
//
// User-cancel emits job_canceled (Python sets ScanJob.status=canceled).
// Worker-shutdown-cancel emits job_completed if Run finished cleanly
// before the cancel arrived (preserves the work). Tool-internal-
// timeout emits job_failed with timeout reason. Other tool errors
// emit job_failed with the error message.
//
// The table is the contract; the conditionals are the implementation.
// If you find yourself rewriting the conditionals, update the table
// first.
func (p *Processor) Process(ctx context.Context, job *events.JobDispatch) error {
	// Step 1: Idempotency claim.
	claimed, err := p.idem.Claim(ctx, job.IdempotencyKey)
	if err != nil {
		return fmt.Errorf("idempotency claim failed: %w", err)
	}
	if !claimed {
		p.log.Info().
			Str("idempotency_key", job.IdempotencyKey).
			Str("job_id", job.ID).
			Str("scan_id", job.ScanID).
			Msg("duplicate job dropped")
		return nil
	}

	start := time.Now()
	progressPub := p.newProgressPub(job.ScanID)

	// Step 2: Job-scoped ctx.
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Step 3: Cancel-watcher (best-effort — non-fatal if subscriber
	// construction fails).
	cancelSub, cancelExited := p.spawnCancelWatcher(jobCtx, cancel, job.ScanID)
	defer func() {
		if cancelSub != nil {
			_ = cancelSub.Close()
		}
		if cancelExited != nil {
			<-cancelExited
		}
	}()

	// Step 4: job_started.
	p.emitProgress(ctx, progressPub, events.EventJobStarted, events.ProgressEvent{
		"job_id": job.ID,
		"engine": job.Engine,
		"target": job.Target.URL,
	})

	// Step 5: Runner lookup.
	runner, err := p.registry.Get(job.Engine)
	if err != nil {
		return p.emitFailure(ctx, progressPub, job, start, err)
	}

	// Step 6: Run the tool.
	target := jobDispatchToTarget(job)
	cfg := jobDispatchToScanConfig(job)
	findings, runErr := runner.Run(jobCtx, target, cfg)

	// Step 7-8: Discriminate cancel-vs-error-vs-success per table.
	jobCancelled := errors.Is(jobCtx.Err(), context.Canceled)
	workerShutdown := errors.Is(ctx.Err(), context.Canceled)
	jobTimedOut := errors.Is(jobCtx.Err(), context.DeadlineExceeded)

	if runErr != nil {
		if jobCancelled && !workerShutdown {
			// User-initiated cancel during runner execution.
			return p.emitCancellation(ctx, progressPub, job, start)
		}
		if jobTimedOut {
			// Tool-internal timeout (shouldn't normally surface here;
			// runners typically wrap timeout into a specific error,
			// but cover the case explicitly).
			return p.emitFailure(ctx, progressPub, job, start,
				fmt.Errorf("job timed out: %w", runErr))
		}
		// Other tool errors (including worker-shutdown-during-run).
		return p.emitFailure(ctx, progressPub, job, start, runErr)
	}

	// Step 9: Successful run — enrich + split + publish.
	for i := range findings {
		findings[i].ScanID = job.ScanID
		findings[i].OrgID = job.OrganizationID
	}

	base := events.JobCompletedEvent{
		EventType:      events.EventJobCompleted,
		JobID:          job.ID,
		ScanID:         job.ScanID,
		Engine:         job.Engine,
		Status:         "completed",
		FindingCount:   len(findings),
		DurationMs:     int(time.Since(start).Milliseconds()),
		IdempotencyKey: job.IdempotencyKey,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
	completionEvents := events.SplitForCompletion(findings, base)

	// Step 11: Publish each completion event.
	//
	// On first publish error we return immediately; subsequent events
	// are not attempted. Same crash-recovery concern as ADR-017's
	// accumulator failure mode — partial sequence on the wire is
	// recoverable via M5+ ghost-queued janitor (Task 4.2 carry-forward).
	for i, ev := range completionEvents {
		if err := p.completionsPub.Publish(ctx, ev); err != nil {
			return fmt.Errorf("publish completion event %d/%d: %w",
				i+1, len(completionEvents), err)
		}
	}

	// Step 12: Final progress event.
	p.emitProgress(ctx, progressPub, events.EventJobCompleted, events.ProgressEvent{
		"job_id":        job.ID,
		"engine":        job.Engine,
		"finding_count": len(findings),
		"duration_ms":   base.DurationMs,
	})

	return nil
}

// spawnCancelWatcher starts the cancel-watcher goroutine. Returns the
// subscriber + a "watcher exited" channel that callers wait on during
// cleanup. If subscriber construction fails (transient Redis error),
// returns (nil, nil) and the job runs without cancel propagation —
// non-fatal degradation logged via warn.
//
// Cancel-watcher exit paths (3, all leak-clean):
//
//  1. jobCtx.Done() — job finished or canceled by another path.
//  2. Cancel event received → call cancel() on jobCtx.
//  3. Subscriber Events() channel closed (Redis disconnect or Close()).
//
// goleak.VerifyTestMain in test packages verifies no leak across
// any of the three paths. ADR-021 Rule 2 enforced.
func (p *Processor) spawnCancelWatcher(jobCtx context.Context, cancel context.CancelFunc, scanID string) (cancelSubscriber, <-chan struct{}) {
	if p.cancelSubFn == nil {
		return nil, nil
	}
	sub, err := p.cancelSubFn(jobCtx, scanID)
	if err != nil {
		p.log.Warn().
			Err(err).
			Str("scan_id", scanID).
			Msg("cancel subscriber construction failed; job runs without cancel propagation")
		return nil, nil
	}
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-jobCtx.Done():
			return
		case ev, ok := <-sub.Events():
			if !ok {
				// Subscriber channel closed (Redis disconnect or
				// Close called). Per ADR-021 H.6 from 5.4: surface,
				// don't auto-recover.
				return
			}
			p.log.Info().
				Str("scan_id", ev.ScanID).
				Str("reason", ev.Reason).
				Msg("cancel signal received")
			cancel()
		}
	}()
	return sub, exited
}

// emitProgress publishes a progress event; logs but does not return
// publish errors (progress emission is best-effort — a failed
// publish here should not abort the job).
func (p *Processor) emitProgress(ctx context.Context, pub progressPublisher, eventType events.EventType, payload events.ProgressEvent) {
	if pub == nil {
		return
	}
	if _, err := pub.Publish(ctx, eventType, payload); err != nil {
		p.log.Warn().
			Err(err).
			Str("event_type", string(eventType)).
			Msg("progress publish failed")
	}
}

// emitFailure publishes both a job_failed progress event and a
// failed completion event. Returns the original error so callers
// can propagate it up.
func (p *Processor) emitFailure(ctx context.Context, pub progressPublisher, job *events.JobDispatch, start time.Time, jobErr error) error {
	p.log.Error().
		Err(jobErr).
		Str("job_id", job.ID).
		Str("scan_id", job.ScanID).
		Str("engine", job.Engine).
		Msg("job failed")

	p.emitProgress(ctx, pub, events.EventJobFailed, events.ProgressEvent{
		"job_id": job.ID,
		"engine": job.Engine,
		"error":  jobErr.Error(),
	})

	completion := events.JobCompletedEvent{
		EventType:      events.EventJobCompleted,
		JobID:          job.ID,
		ScanID:         job.ScanID,
		Engine:         job.Engine,
		Status:         "failed",
		FindingCount:   0,
		DurationMs:     int(time.Since(start).Milliseconds()),
		IdempotencyKey: job.IdempotencyKey,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		EventSeq:       events.EventSeq{Index: 1, Total: 1},
		ErrorMessage:   jobErr.Error(),
	}
	if err := p.completionsPub.Publish(ctx, completion); err != nil {
		// Failed-event publish failed; best-effort. Return the
		// original error wrapped with both contexts.
		return fmt.Errorf("%w (and failed to publish failure event: %v)", jobErr, err)
	}
	return jobErr
}

// emitCancellation publishes a job_canceled progress event and a
// canceled completion event. Returns nil (cancellation is not an
// error from the processor's perspective; the user requested it).
func (p *Processor) emitCancellation(ctx context.Context, pub progressPublisher, job *events.JobDispatch, start time.Time) error {
	p.log.Info().
		Str("job_id", job.ID).
		Str("scan_id", job.ScanID).
		Str("engine", job.Engine).
		Msg("job canceled")

	p.emitProgress(ctx, pub, events.EventJobCanceled, events.ProgressEvent{
		"job_id": job.ID,
		"engine": job.Engine,
	})

	completion := events.JobCompletedEvent{
		EventType:      events.EventJobCompleted,
		JobID:          job.ID,
		ScanID:         job.ScanID,
		Engine:         job.Engine,
		Status:         "canceled",
		FindingCount:   0,
		DurationMs:     int(time.Since(start).Milliseconds()),
		IdempotencyKey: job.IdempotencyKey,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		EventSeq:       events.EventSeq{Index: 1, Total: 1},
	}
	if err := p.completionsPub.Publish(ctx, completion); err != nil {
		return fmt.Errorf("publish cancellation event: %w", err)
	}
	return nil
}

// newProgressPub returns a progress publisher for the given scan_id.
// Returns nil if no factory was injected.
func (p *Processor) newProgressPub(scanID string) progressPublisher {
	if p.progressPubFn == nil {
		return nil
	}
	return p.progressPubFn(scanID)
}

// jobDispatchToTarget translates SPEC §7.1 target shape into
// tools.Target. Mobile-specific fields are populated when present.
func jobDispatchToTarget(job *events.JobDispatch) tools.Target {
	target := tools.Target{
		URL:            job.Target.URL,
		Domain:         job.Target.URL, // recon tools may extract domain from URL
		TargetType:     job.Target.TargetType,
		DomainVerified: job.Target.DomainVerified,
	}
	if job.Auth != nil {
		target.AuthConfig = &tools.AuthConfig{
			Type: job.Auth.Type,
			Data: job.Auth.Data,
		}
	}
	if job.MobileConfig != nil {
		target.MobileUploadRef = job.MobileConfig.UploadRef
	}
	return target
}

// jobDispatchToScanConfig translates SPEC §7.1 config map into
// tools.ScanConfig. Unknown / missing keys default to zero values;
// type assertions are defensive (incorrect type → zero value).
//
// Cross-repo coupling: Python orchestrator's config block shape
// determines what keys appear here. Adding new ScanConfig fields
// requires updating this translation.
func jobDispatchToScanConfig(job *events.JobDispatch) tools.ScanConfig {
	cfg := tools.ScanConfig{
		ExtraArgs: make(map[string]string),
	}
	if depth, ok := job.Config["depth"].(string); ok {
		cfg.Depth = depth
	}
	// JSON numbers decode as float64; coerce to int.
	if to, ok := job.Config["timeout_seconds"].(float64); ok {
		cfg.Timeout = int(to)
	}
	if rps, ok := job.Config["max_requests_per_second"].(float64); ok {
		cfg.MaxRPS = int(rps)
	}
	if cats, ok := job.Config["template_categories"].([]any); ok {
		for _, c := range cats {
			if s, ok := c.(string); ok {
				cfg.TemplateCategories = append(cfg.TemplateCategories, s)
			}
		}
	}
	if extra, ok := job.Config["extra_args"].(map[string]any); ok {
		for k, v := range extra {
			if s, ok := v.(string); ok {
				cfg.ExtraArgs[k] = s
			}
		}
	}
	return cfg
}

// ensure rdsh import is referenced even if a future refactor moves
// the production wiring elsewhere; the type check is structural.
var _ = rdsh.IdempotencyTTL
