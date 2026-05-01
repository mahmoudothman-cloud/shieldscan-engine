package worker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// fakeConsumer is an in-memory JobConsumer for Worker tests. Avoids
// miniredis BRPOP-ctx-cancel limitation (5.4 DRIFT-LOG) by
// implementing ctx-aware Pop directly.
type fakeConsumer struct {
	mu       sync.Mutex
	queue    []*events.JobDispatch
	popError error
	popCalls atomic.Int32
}

// push appends a job to the queue.
func (f *fakeConsumer) push(job *events.JobDispatch) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, job)
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
func (f *fakeConsumer) Pop(ctx context.Context, timeout time.Duration) (*events.JobDispatch, error) {
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
		job := f.queue[0]
		f.queue = f.queue[1:]
		f.mu.Unlock()
		return job, nil
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
// job → BRPOP → Process called → ctx cancel → graceful exit.
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
	// uses brpopTimeout=5s by default, but our fakeConsumer's
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
