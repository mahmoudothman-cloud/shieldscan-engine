package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
	rdsh "github.com/odyssey/shieldscan-engine/internal/redis"
)

// fakeConsumer is an in-memory JobConsumer for Worker tests. Avoids
// miniredis's ctx-cancel limitations (5.4 DRIFT-LOG) by implementing
// ctx-aware Pop directly, and records Acks so tests can pin which
// deliveries leave the processing list.
type fakeConsumer struct {
	mu        sync.Mutex
	queue     []*rdsh.Delivery
	acked     []string
	ackCtxErr []error
	ackErr    error
	popError  error
	popCalls  atomic.Int32
}

// push appends a job to the queue, wrapped as a delivery.
func (f *fakeConsumer) push(job *events.JobDispatch) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, &rdsh.Delivery{
		Job:      job,
		Payload:  `{"id":"` + job.ID + `"}`,
		Priority: "normal",
	})
}

// Ack records the delivery as acknowledged.
func (f *fakeConsumer) Ack(ctx context.Context, d *rdsh.Delivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked = append(f.acked, d.Job.ID)
	// Recorded so a test can pin that Ack runs on a context detached
	// from the worker's, rather than one already poisoned by shutdown.
	f.ackCtxErr = append(f.ackCtxErr, ctx.Err())
	return nil
}

// ackedIDs returns the job ids acknowledged so far.
func (f *fakeConsumer) ackedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.acked...)
}

// setError configures Pop to return err on next call (then clears).
func (f *fakeConsumer) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.popError = err
}

// Pop dequeues the next job; returns (nil, nil) on empty queue
// after timeout; returns ctx.Err() on cancel; returns configured
// popError once.
func (f *fakeConsumer) Pop(ctx context.Context, timeout time.Duration) (*rdsh.Delivery, error) {
	f.popCalls.Add(1)

	// Drain configured error first (single-shot).
	f.mu.Lock()
	if f.popError != nil {
		err := f.popError
		f.popError = nil
		f.mu.Unlock()
		return nil, err
	}
	if len(f.queue) > 0 {
		d := f.queue[0]
		f.queue = f.queue[1:]
		f.mu.Unlock()
		return d, nil
	}
	f.mu.Unlock()

	// Empty queue — wait timeout or ctx cancel.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(timeout):
		return nil, nil
	}
}

// fakeProcessor records invocations + supports configurable behavior.
type fakeProcessor struct {
	processCalled atomic.Int32
	processed     []*events.JobDispatch
	mu            sync.Mutex
	delay         time.Duration
	processErr    error
	startedSignal chan struct{} // closed on first Process entry
	concurrency   atomic.Int32
	maxConcurrent atomic.Int32
}

func (f *fakeProcessor) Process(ctx context.Context, job *events.JobDispatch) error {
	f.processCalled.Add(1)
	current := f.concurrency.Add(1)
	defer f.concurrency.Add(-1)

	// Track peak concurrency.
	for {
		max := f.maxConcurrent.Load()
		if current <= max || f.maxConcurrent.CompareAndSwap(max, current) {
			break
		}
	}

	if f.startedSignal != nil {
		select {
		case <-f.startedSignal:
		default:
			close(f.startedSignal)
		}
	}

	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(f.delay):
		}
	}

	f.mu.Lock()
	f.processed = append(f.processed, job)
	f.mu.Unlock()

	return f.processErr
}

// makeWorkerJob is a small constructor for worker tests.
func makeWorkerJob(id, scanID string) *events.JobDispatch {
	return &events.JobDispatch{
		ID:             id,
		ScanID:         scanID,
		OrganizationID: "org_test",
		Engine:         "nuclei",
		IdempotencyKey: id + ":nuclei:1",
		Target:         events.JobTarget{URL: "https://x.example.com", TargetType: "web"},
		Config:         map[string]any{},
	}
}

// tests -----------------------------------------------------------

// TestWorker_RunProcessesJob pins the canonical happy path: queued
// job → checkout → Process called → ctx cancel → graceful exit.
func TestWorker_RunProcessesJob(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{}
	consumer.push(makeWorkerJob("j1", "s1"))

	w := NewWorker(WorkerDeps{
		Consumer:    consumer,
		Processor:   processor,
		Concurrency: 1,
		Logger:      zerolog.Nop(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	err := w.Run(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"Run returns ctx error on shutdown")

	assert.GreaterOrEqual(t, processor.processCalled.Load(), int32(1),
		"queued job processed")
	processor.mu.Lock()
	defer processor.mu.Unlock()
	require.Len(t, processor.processed, 1)
	assert.Equal(t, "j1", processor.processed[0].ID)
}

// TestWorker_CtxCancelExits pins ADR-021: parent ctx cancel exits
// Run with the ctx error.
func TestWorker_CtxCancelExits(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{}
	w := NewWorker(WorkerDeps{
		Consumer:    consumer,
		Processor:   processor,
		Concurrency: 2,
		Logger:      zerolog.Nop(),
	})

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.True(t, errors.Is(err, context.Canceled),
			"Run returns context.Canceled; got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s of ctx cancel")
	}
}

// TestWorker_DrainsInflightOnShutdown pins the graceful drain
// contract: in-flight ProcessJob goroutines complete before Run
// returns. Without this, ctx cancel would orphan jobs mid-processing.
func TestWorker_DrainsInflightOnShutdown(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{
		delay: 200 * time.Millisecond, // each job takes 200ms
	}
	for i := 0; i < 3; i++ {
		consumer.push(makeWorkerJob("j"+string(rune('1'+i)), "s"))
	}

	w := NewWorker(WorkerDeps{
		Consumer: consumer, Processor: processor,
		Concurrency: 3, Logger: zerolog.Nop(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Let all 3 jobs start.
	require.Eventually(t, func() bool {
		return processor.concurrency.Load() == 3
	}, time.Second, 10*time.Millisecond, "all 3 jobs should be in-flight")

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not drain within 2s")
	}

	assert.Equal(t, int32(3), processor.processCalled.Load(),
		"all 3 in-flight jobs completed before Run returned")
}

// TestWorker_ConcurrencyLimited pins H.6 + WorkerConcurrency
// semaphore: with concurrency=2, no more than 2 jobs run
// simultaneously even with 5 queued.
func TestWorker_ConcurrencyLimited(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{
		delay: 100 * time.Millisecond,
	}
	for i := 0; i < 5; i++ {
		consumer.push(makeWorkerJob("j"+string(rune('1'+i)), "s"))
	}

	w := NewWorker(WorkerDeps{
		Consumer: consumer, Processor: processor,
		Concurrency: 2, Logger: zerolog.Nop(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_ = w.Run(ctx)

	assert.LessOrEqual(t, processor.maxConcurrent.Load(), int32(2),
		"WorkerConcurrency=2 limits peak in-flight to 2; observed peak: %d",
		processor.maxConcurrent.Load())
	assert.Greater(t, processor.maxConcurrent.Load(), int32(1),
		"with 5 queued jobs and concurrency=2, peak should reach 2")
}

// TestWorker_PopErrorContinues pins resilience to transient consumer
// errors: a non-cancel Pop error logs + continues; subsequent jobs
// process.
func TestWorker_PopErrorContinues(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{}
	consumer.setError(errors.New("transient redis blip"))
	consumer.push(makeWorkerJob("j_after_err", "s"))

	w := NewWorker(WorkerDeps{
		Consumer: consumer, Processor: processor,
		Concurrency: 1, Logger: zerolog.Nop(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_ = w.Run(ctx)

	assert.Equal(t, int32(1), processor.processCalled.Load(),
		"job dequeued after transient error processed")
	processor.mu.Lock()
	defer processor.mu.Unlock()
	assert.Equal(t, "j_after_err", processor.processed[0].ID)
}

// TestWorker_EmptyQueueLoops pins the empty-queue case: no jobs
// available → loop continues; no spawn; Pop called multiple times.
func TestWorker_EmptyQueueLoops(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{}

	w := NewWorker(WorkerDeps{
		Consumer: consumer, Processor: processor,
		Concurrency: 1, Logger: zerolog.Nop(),
	})

	// Use a fakeConsumer with very short Pop timeout — the worker
	// uses popTimeout=5s by default, but our fakeConsumer's
	// timeout is the second parameter. We can't control that directly
	// here; instead, run for ~100ms and verify Pop was called +
	// no jobs processed.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)

	assert.GreaterOrEqual(t, consumer.popCalls.Load(), int32(1), "Pop called")
	assert.Zero(t, processor.processCalled.Load(), "no jobs to process")
}

// TestWorker_GoroutineCleanOnShutdown pins ADR-021 Rule 2 across all
// shutdown paths. Spawn jobs, cancel mid-flight, verify no goroutine
// leak. goleak (TestMain) is the actual verifier; this test exercises
// the paths.
func TestWorker_GoroutineCleanOnShutdown(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{
		delay: 50 * time.Millisecond,
	}
	for i := 0; i < 5; i++ {
		consumer.push(makeWorkerJob("j"+string(rune('1'+i)), "s"))
	}

	w := NewWorker(WorkerDeps{
		Consumer: consumer, Processor: processor,
		Concurrency: 3, Logger: zerolog.Nop(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)
	// goleak in TestMain verifies the converter goroutines + pool
	// reaper all exited cleanly.
}

// TestWorker_PanicsOnInvalidConcurrency pins the constructor
// validation: Concurrency=0 panics. Defensive check protects against
// silent misconfiguration.
func TestWorker_PanicsOnInvalidConcurrency(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{}
	assert.Panics(t, func() {
		NewWorker(WorkerDeps{
			Consumer: consumer, Processor: processor,
			Concurrency: 0,
		})
	}, "Concurrency=0 should panic")

	assert.Panics(t, func() {
		NewWorker(WorkerDeps{
			Consumer: consumer, Processor: processor,
			Concurrency: -1,
		})
	}, "Concurrency=-1 should panic")
}

// ---------------------------------------------------------------------
// Acknowledgement (Drift #70)
//
// The processing list only helps if the worker is precise about what it
// removes from it. Removing too eagerly re-creates the old bug in a new
// place: a job that vanished without publishing anything would look
// finished. Removing too reluctantly is worse still — a reclaim would
// report a job failed that had in fact completed.
// ---------------------------------------------------------------------

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// runWorkerUntil starts a worker, waits for cond, then shuts it down.
func runWorkerUntil(t *testing.T, consumer *fakeConsumer, processor *fakeProcessor, cond func() bool) {
	t.Helper()
	w := NewWorker(WorkerDeps{
		Consumer:    consumer,
		Processor:   processor,
		Concurrency: 1,
		Logger:      zerolog.Nop(),
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	ok := waitFor(t, 2*time.Second, cond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s of ctx cancel")
	}
	require.True(t, ok, "condition never held")
}

// A finished job leaves the processing list. If it did not, the next
// reclaim sweep would publish a failure for a job that succeeded.
func TestWorker_AcksACompletedJob(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{}
	consumer.push(makeWorkerJob("j1", "s1"))

	runWorkerUntil(t, consumer, processor, func() bool {
		return len(consumer.ackedIDs()) == 1
	})
	assert.Equal(t, []string{"j1"}, consumer.ackedIDs())
}

// A tool failure is a terminal outcome, not a lost job: emitFailure has
// already published job_completed(status=failed). Leaving it in the
// processing list would have a reclaim fail it a second time.
func TestWorker_AcksAJobThatFailedInTheTool(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{processErr: errors.New("nuclei exited 1")}
	consumer.push(makeWorkerJob("j1", "s1"))

	runWorkerUntil(t, consumer, processor, func() bool {
		return len(consumer.ackedIDs()) == 1
	})
	assert.Equal(t, []string{"j1"}, consumer.ackedIDs())
}

// The case the whole mechanism exists for. Nothing was published, so the
// job must stay checked out and recoverable.
func TestWorker_DoesNotAckAJobThatPublishedNothing(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{
		processErr: fmt.Errorf("%w: publish completion event 1/1: redis down", ErrJobNotTerminal),
	}
	consumer.push(makeWorkerJob("j1", "s1"))

	runWorkerUntil(t, consumer, processor, func() bool {
		return processor.processCalled.Load() >= 1
	})
	assert.Empty(t, consumer.ackedIDs(),
		"a job that never published a terminal event was acked; the reclaimer "+
			"can no longer recover it")
}

// The drain path. By the time a job finishes during shutdown the
// worker's ctx is already canceled; an Ack inheriting it would fail, and
// a completed job would be left for a reclaim to mark failed.
func TestWorker_AcksOnACtxThatSurvivesShutdown(t *testing.T) {
	consumer := &fakeConsumer{}
	processor := &fakeProcessor{delay: 150 * time.Millisecond}
	consumer.push(makeWorkerJob("j1", "s1"))

	w := NewWorker(WorkerDeps{
		Consumer:    consumer,
		Processor:   processor,
		Concurrency: 1,
		Logger:      zerolog.Nop(),
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()

	// Cancel while the job is still running, so the Ack happens after
	// the worker ctx is dead.
	require.True(t, waitFor(t, 2*time.Second, func() bool {
		return processor.processCalled.Load() >= 1
	}))
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not drain within 3s")
	}

	require.Equal(t, []string{"j1"}, consumer.ackedIDs(),
		"the job finished during drain but was never acked")

	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	require.Len(t, consumer.ackCtxErr, 1)
	assert.NoError(t, consumer.ackCtxErr[0],
		"Ack inherited the canceled worker ctx; on real Redis the LREM would "+
			"fail and a completed job would be reported failed by the next sweep")
}
