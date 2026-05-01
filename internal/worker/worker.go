package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// brpopTimeout bounds each BRPOP call so the loop periodically
// re-checks ctx. 5s is short enough that worker shutdown drains
// within ~5s (one BRPOP must complete before the next ctx check)
// and long enough to keep Pop traffic low during quiet periods.
const brpopTimeout = 5 * time.Second

// jobConsumer abstracts JobConsumer.Pop for tests. Production
// wires *redis.JobConsumer.
type jobConsumer interface {
	Pop(ctx context.Context, timeout time.Duration) (*events.JobDispatch, error)
}

// jobProcessor abstracts Processor.Process for tests. Production
// wires *Processor.
type jobProcessor interface {
	Process(ctx context.Context, job *events.JobDispatch) error
}

// WorkerDeps wires Worker's external dependencies.
type WorkerDeps struct {
	Consumer    jobConsumer
	Processor   jobProcessor
	Concurrency int
	Logger      zerolog.Logger
}

// Worker owns the BRPOP loop + concurrency semaphore + WaitGroup-
// based graceful drain.
//
// Lifecycle (Run blocks until ctx is canceled):
//
//  1. Acquire semaphore slot (blocks if N jobs already running).
//  2. BRPOP next job from priority queues.
//  3. If job available: spawn ProcessJob goroutine; release sem
//     when goroutine completes.
//  4. If no job (timeout) or transient error: release sem; loop.
//  5. On ctx cancel: stop accepting new jobs; defer wg.Wait()
//     drains in-flight goroutines before Run returns.
//
// Per H.6: 5.5 ships graceful drain only. Force-cancel after a
// grace period (e.g., SIGTERM-then-30s-SIGKILL) is 5.6's main()
// concern.
type Worker struct {
	consumer    jobConsumer
	processor   jobProcessor
	concurrency int
	log         zerolog.Logger
}

// NewWorker constructs a Worker from injected deps. Required
// fields: Consumer, Processor, Concurrency >= 1.
func NewWorker(deps WorkerDeps) *Worker {
	if deps.Consumer == nil {
		panic("worker.NewWorker: Consumer is required")
	}
	if deps.Processor == nil {
		panic("worker.NewWorker: Processor is required")
	}
	if deps.Concurrency < 1 {
		panic(fmt.Sprintf("worker.NewWorker: Concurrency must be >= 1 (got %d)", deps.Concurrency))
	}
	return &Worker{
		consumer:    deps.Consumer,
		processor:   deps.Processor,
		concurrency: deps.Concurrency,
		log:         deps.Logger,
	}
}

// Run executes the BRPOP-then-process loop until ctx is canceled.
// Returns ctx.Err() after draining in-flight jobs.
//
// Concurrency is bounded by w.concurrency via a buffered channel
// semaphore. Each in-flight job holds one slot; semaphore released
// when the ProcessJob goroutine returns.
//
// Graceful drain: defer wg.Wait() ensures all in-flight ProcessJob
// goroutines complete before Run returns. If a job is mid-runner-
// invocation when ctx cancels, the runner's ctx-aware execution
// (ADR-021) sees the cancel and exits cleanly; ProcessJob then
// emits the appropriate completion event before goroutine exit.
func (w *Worker) Run(ctx context.Context) error {
	sem := make(chan struct{}, w.concurrency)
	var wg sync.WaitGroup

	// Drain in-flight goroutines before returning.
	defer wg.Wait()

	for {
		// Acquire semaphore (ctx-aware).
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		// BRPOP for next job.
		job, err := w.consumer.Pop(ctx, brpopTimeout)
		if err != nil {
			<-sem // release; nothing to spawn
			if errors.Is(err, context.Canceled) {
				return err
			}
			// Non-cancel error: log + continue. Poison-pill
			// protection on the JobConsumer side (5.4) catches
			// malformed jobs; this catches transient Redis errors.
			w.log.Error().Err(err).Msg("Pop failed; retrying")
			continue
		}
		if job == nil {
			<-sem // release; timeout, no job
			continue
		}

		// Spawn ProcessJob goroutine.
		wg.Add(1)
		go func(j *events.JobDispatch) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := w.processor.Process(ctx, j); err != nil {
				w.log.Error().
					Err(err).
					Str("job_id", j.ID).
					Str("scan_id", j.ScanID).
					Str("engine", j.Engine).
					Msg("processor failed")
			}
		}(job)
	}
}
