package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
	rdsh "github.com/odyssey/shieldscan-engine/internal/redis"
)

// popTimeout bounds each Pop call so the loop periodically re-checks
// ctx. 5s is short enough that worker shutdown drains promptly and long
// enough to keep the loop's own bookkeeping cheap.
const popTimeout = 5 * time.Second

// ackTimeout bounds the post-job LREM that removes a finished job from
// the processing list. It runs on a context detached from the worker's
// (see the drain note in Run), so it needs its own bound.
const ackTimeout = 5 * time.Second

// jobConsumer abstracts JobConsumer's checkout/acknowledge pair for
// tests. Production wires *redis.JobConsumer.
type jobConsumer interface {
	Pop(ctx context.Context, timeout time.Duration) (*rdsh.Delivery, error)
	Ack(ctx context.Context, d *rdsh.Delivery) error
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

// Worker owns the checkout loop + concurrency semaphore + WaitGroup-
// based graceful drain.
//
// Lifecycle (Run blocks until ctx is canceled):
//
//  1. Acquire semaphore slot (blocks if N jobs already running).
//  2. Check out the next job from the priority queues into this
//     worker's processing list.
//  3. If job available: spawn ProcessJob goroutine; release sem
//     when goroutine completes, and acknowledge the delivery.
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

// Run executes the checkout-then-process loop until ctx is canceled.
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

		// Check out the next job into this worker's processing list.
		delivery, err := w.consumer.Pop(ctx, popTimeout)
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
		if delivery == nil {
			<-sem // release; timeout, no job
			continue
		}

		// Spawn ProcessJob goroutine.
		wg.Add(1)
		go func(d *rdsh.Delivery) {
			defer wg.Done()
			defer func() { <-sem }()

			err := w.processor.Process(ctx, d.Job)
			if err != nil {
				w.log.Error().
					Err(err).
					Str("job_id", d.Job.ID).
					Str("scan_id", d.Job.ScanID).
					Str("engine", d.Job.Engine).
					Msg("processor failed")
			}
			w.finish(ctx, d, err)
		}(delivery)
	}
}

// finish decides whether this delivery leaves the processing list.
//
// The rule is not "did Process succeed" but "did anyone get told". Every
// outcome the customer can observe — completed, failed, canceled, and a
// duplicate that was dropped — has published a terminal completion event
// or is already represented by one, so the delivery is acknowledged. Only
// ErrJobNotTerminal means the job vanished silently, and that is the case
// the reclaimer exists for: leaving the entry in place is what lets it be
// retried or explicitly failed later (Drift #70).
//
// The Ack runs on a context detached from the worker's. On the drain
// path ctx is already canceled by the time a job finishes, and a
// cancel-poisoned Ack would leave a job that genuinely completed sitting
// in the processing list — where the next sweep would report it failed,
// overwriting a good result with a bad one. ADR-021 Rule 3 is about not
// severing the cancel chain for work; this is cleanup that must outlive
// the cancel, and it is bounded by ackTimeout.
func (w *Worker) finish(ctx context.Context, d *rdsh.Delivery, processErr error) {
	if errors.Is(processErr, ErrJobNotTerminal) {
		w.log.Warn().
			Str("job_id", d.Job.ID).
			Str("scan_id", d.Job.ScanID).
			Str("engine", d.Job.Engine).
			Msg("job left in the processing list; no terminal event was published, " +
				"so a reclaim will retry or fail it")
		return
	}

	ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()

	if err := w.consumer.Ack(ackCtx, d); err != nil {
		w.log.Error().
			Err(err).
			Str("job_id", d.Job.ID).
			Str("scan_id", d.Job.ScanID).
			Msg("could not remove finished job from the processing list; " +
				"a later reclaim may report this job failed despite it finishing")
	}
}
