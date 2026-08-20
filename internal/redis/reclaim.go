package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// Reclaim — recovering the jobs a dead worker had in flight (Drift #70).
//
// The processing list (queue.go) records what each worker checked out.
// This file is what makes that record worth keeping: when a worker dies,
// somebody has to decide what happens to the payloads it left behind.
//
// The decision is deliberately not "always retry". A job can publish
// findings before dying (ADR-017 sequencing splits >1000 findings across
// several completion events), and a retry after a partial publish would
// duplicate findings that already landed in raw_findings. So the sweep
// retries only what demonstrably published nothing, and reports the rest
// as failed — which is still an enormous improvement on the status quo,
// where a stranded job stayed `queued` in PostgreSQL forever and its
// parent scan could never aggregate to a terminal state.
//
// Liveness is the same 60s heartbeat the container reaper uses
// (shieldscan:workers:{id}). One liveness concept, two consumers.
//
// ADR-013 is not violated here. The reclaimer publishes a normal
// job_completed event on the completions channel and lets Python's
// CompletionsConsumer do the writing; the engine never touches
// PostgreSQL. That constraint is precisely why the failure path is an
// event and not a janitor.

const (
	// reclaimCountPrefix counts how many times a job has been recovered.
	// Keyed on idempotency_key rather than job_id because that is what
	// the requeued payload carries through unchanged.
	reclaimCountPrefix = "shieldscan:reclaims:"

	// publishedKeyPrefix marks that at least one completion event for a
	// job reached Redis. Set BEFORE the first publish, so a crash during
	// publish is treated as "may have landed" — the conservative
	// direction, since a wrongly-failed job costs a re-run the operator
	// can see, and a wrongly-retried one silently duplicates findings.
	publishedKeyPrefix = "shieldscan:published:"
)

// MaxReclaims is how many times a job may be requeued before the sweep
// reports it failed instead.
//
// 1, because a job that killed its worker once is likelier to be poison
// than to have been unlucky, and the second death would cost another
// full tool runtime to learn nothing. The bound also guarantees the
// sweep terminates: without it, a job that reliably kills workers would
// be requeued forever.
const MaxReclaims = 1

// reclaimBookkeepingTTL bounds the reclaim counter and the published
// marker. Matched to IdempotencyTTL so all three per-job keys age out
// together and none can outlive the job it describes.
const reclaimBookkeepingTTL = IdempotencyTTL

// PublishGuard records that a job has published at least one completion
// event. Written by the processor, read by the Reclaimer.
type PublishGuard struct {
	client *redis.Client
}

// NewPublishGuard constructs a guard bound to the given Redis client.
func NewPublishGuard(client *redis.Client) *PublishGuard {
	return &PublishGuard{client: client}
}

// MarkPublished records that a completion event for this job is about to
// reach Redis. Idempotent.
func (g *PublishGuard) MarkPublished(ctx context.Context, idempotencyKey string) error {
	if idempotencyKey == "" {
		return fmt.Errorf("idempotency_key is empty")
	}
	key := publishedKeyPrefix + idempotencyKey
	if err := g.client.Set(ctx, key, "1", reclaimBookkeepingTTL).Err(); err != nil {
		return fmt.Errorf("SET %s: %w", key, err)
	}
	return nil
}

// ReclaimPolicy decides whose processing lists are eligible.
//
// LiveWorkerIDs mirrors ReapPolicy: a nil set means liveness is unknown
// and disables the sweep entirely. Reclaiming a live peer's in-flight
// job would requeue a scan that is still running, so the fail-safe
// direction is to do nothing.
type ReclaimPolicy struct {
	SelfWorkerID  string
	LiveWorkerIDs map[string]struct{}
}

// ReclaimResult is what one sweep did.
type ReclaimResult struct {
	// Requeued jobs went back onto their original priority queue.
	Requeued int
	// Failed jobs got a synthetic job_completed(status=failed) so
	// Python can mark them terminal and their parent scan can aggregate.
	Failed int
	// Dropped payloads could not be acted on: a duplicate of a job
	// already handled in this sweep, or a payload that does not decode.
	Dropped int
}

// Reclaimer recovers the processing lists of workers that are gone.
type Reclaimer struct {
	client *redis.Client
	comp   *CompletionsPublisher
	idem   *IdempotencyClaim
	log    zerolog.Logger
}

// NewReclaimer constructs a Reclaimer bound to the given Redis client.
func NewReclaimer(client *redis.Client, log zerolog.Logger) *Reclaimer {
	return &Reclaimer{
		client: client,
		comp:   NewCompletionsPublisher(client),
		idem:   NewIdempotencyClaim(client),
		log:    log,
	}
}

// Reclaim sweeps every processing list that belongs to neither this
// worker nor a live peer.
//
// Errors on individual jobs are logged and counted but do not abort the
// sweep — one undecodable payload must not strand the rest. A SCAN
// failure IS returned, since it means we know nothing.
//
// Callers treat any error as non-fatal: failing to reclaim leaves jobs
// where they already are, which is the status quo, whereas failing to
// boot is an outage.
func (r *Reclaimer) Reclaim(ctx context.Context, policy ReclaimPolicy) (ReclaimResult, error) {
	var result ReclaimResult

	if policy.LiveWorkerIDs == nil {
		r.log.Warn().Msg("job reclaim skipped: live-worker set unavailable; " +
			"cannot distinguish a dead worker's in-flight jobs from a live peer's")
		return result, nil
	}

	keys, err := r.orphanProcessingKeys(ctx, policy)
	if err != nil {
		return result, err
	}

	// One de-duplication set for the whole sweep. Two payloads carrying
	// the same idempotency_key are the same job dispatched twice; the
	// first is handled and the rest discarded. Without this, the second
	// copy would bump the reclaim counter past MaxReclaims and fail a job
	// the first copy had just requeued.
	handled := make(map[string]struct{})

	for _, key := range keys {
		workerID, priority, ok := splitProcessingKey(key)
		if !ok {
			continue
		}
		r.drainList(ctx, key, workerID, priority, handled, &result)
	}

	return result, nil
}

// orphanProcessingKeys returns the processing lists of dead workers.
//
// SCAN rather than KEYS: KEYS blocks the server for its duration, and
// this runs against the same instance serving live scan traffic.
func (r *Reclaimer) orphanProcessingKeys(ctx context.Context, policy ReclaimPolicy) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := r.client.Scan(ctx, cursor, ProcessingKeyPrefix+"*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("SCAN %s*: %w", ProcessingKeyPrefix, err)
		}
		for _, k := range batch {
			workerID, _, ok := splitProcessingKey(k)
			if !ok {
				r.log.Warn().Str("key", k).Msg("ignoring malformed processing key")
				continue
			}
			if workerID == policy.SelfWorkerID {
				continue
			}
			if _, alive := policy.LiveWorkerIDs[workerID]; alive {
				continue
			}
			keys = append(keys, k)
		}
		if next == 0 {
			return keys, nil
		}
		cursor = next
	}
}

// drainList empties one dead worker's processing list, oldest first.
//
// RPOP claims each payload atomically, so two reclaimers racing on the
// same list divide the work rather than duplicating it. The cost is a
// microsecond-wide window between the RPOP and the requeue in which a
// crash loses the payload outright — six orders of magnitude smaller
// than the multi-minute window this whole change exists to close.
//
// The one case where the payload matters after that point is a requeue
// whose push fails; requeue logs it whole there. On the fail branch the
// payload is discarded by design — the job is being reported failed, so
// there is nothing left to run.
func (r *Reclaimer) drainList(
	ctx context.Context,
	key, deadWorkerID, priority string,
	handled map[string]struct{},
	result *ReclaimResult,
) {
	for {
		if ctx.Err() != nil {
			return
		}
		payload, err := r.client.RPop(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return
		}
		if err != nil {
			r.log.Warn().Err(err).Str("key", key).
				Msg("job reclaim: RPOP failed; abandoning this list for now")
			return
		}

		job, decodeErr := decodeJobDispatch(payload)
		if decodeErr != nil {
			result.Dropped++
			r.log.Error().Err(decodeErr).
				Str("key", key).
				Str("payload", payload).
				Msg("job reclaim: undecodable in-flight payload dropped")
			continue
		}

		if _, seen := handled[job.IdempotencyKey]; seen {
			result.Dropped++
			r.log.Info().
				Str("idempotency_key", job.IdempotencyKey).
				Str("job_id", job.ID).
				Msg("job reclaim: duplicate in-flight payload discarded")
			continue
		}
		handled[job.IdempotencyKey] = struct{}{}

		r.reclaimOne(ctx, job, payload, deadWorkerID, priority, result)
	}
}

// reclaimOne decides retry-versus-fail for a single job and acts on it.
func (r *Reclaimer) reclaimOne(
	ctx context.Context,
	job *events.JobDispatch,
	payload, deadWorkerID, priority string,
	result *ReclaimResult,
) {
	log := r.log.With().
		Str("job_id", job.ID).
		Str("scan_id", job.ScanID).
		Str("engine", job.Engine).
		Str("idempotency_key", job.IdempotencyKey).
		Str("dead_worker_id", deadWorkerID).
		Logger()

	attempts, err := r.bumpReclaimCount(ctx, job.IdempotencyKey)
	if err != nil {
		// We cannot bound retries, so we must not retry. Fail instead of
		// risking an unbounded requeue loop.
		log.Error().Err(err).Msg("job reclaim: reclaim counter unavailable; failing rather than retrying")
		r.fail(ctx, job, deadWorkerID, "worker died mid-job and the reclaim counter was unavailable, "+
			"so the job was not retried", result)
		return
	}

	published, err := r.hasPublished(ctx, job.IdempotencyKey)
	if err != nil {
		log.Error().Err(err).Msg("job reclaim: publish marker unreadable; failing rather than retrying")
		r.fail(ctx, job, deadWorkerID, "worker died mid-job and the publish marker was unreadable, "+
			"so the job was not retried", result)
		return
	}

	switch {
	case published:
		// ADR-017 sequencing means this job may already have written
		// findings. Retrying would duplicate them. Today findings are
		// all-or-nothing per job (a scan has to exceed 1000 findings for
		// SplitForCompletion to emit more than one event, and none has),
		// so this branch is currently unreachable in practice — it
		// activates exactly when that property stops holding.
		log.Warn().Int64("attempts", attempts).
			Msg("job reclaim: job had already published results; failing rather than retrying")
		r.fail(ctx, job, deadWorkerID,
			"worker died after publishing partial results; not retried, because a "+
				"retry would duplicate findings that already landed", result)

	case attempts > MaxReclaims:
		log.Warn().Int64("attempts", attempts).
			Msg("job reclaim: retry budget exhausted; failing")
		r.fail(ctx, job, deadWorkerID, fmt.Sprintf(
			"worker died mid-job %d times; retry budget of %d exhausted, job not retried",
			attempts, MaxReclaims), result)

	default:
		r.requeue(ctx, job, payload, deadWorkerID, priority, log, result)
	}
}

// requeue releases the idempotency claim and puts the payload back.
//
// RPUSH, not LPUSH: the queue is drained from the right, so RPUSH puts
// the reclaimed job at the head of the line. It has already waited
// through a worker's death; making it queue again behind newer work
// would compound the delay the customer already saw.
func (r *Reclaimer) requeue(
	ctx context.Context,
	job *events.JobDispatch,
	payload, deadWorkerID, priority string,
	log zerolog.Logger,
	result *ReclaimResult,
) {
	// Release BEFORE the push. The claim is taken before processing and
	// never released on the normal path, so a requeued job whose claim
	// still stands would be popped and dropped as a duplicate — the
	// silent second loss of the same job.
	if err := r.idem.Release(ctx, job.IdempotencyKey); err != nil {
		log.Error().Err(err).Str("payload", payload).
			Msg("job reclaim: could not release idempotency claim; NOT requeueing " +
				"(a requeue now would be dropped as a duplicate)")
		r.fail(ctx, job, deadWorkerID, "worker died mid-job and the idempotency claim could not "+
			"be released, so the job could not be retried", result)
		return
	}

	if err := r.client.RPush(ctx, queueKeyPrefix+priority, payload).Err(); err != nil {
		// The payload is in memory and nowhere else. Log it whole so an
		// operator can put it back by hand.
		log.Error().Err(err).Str("priority", priority).Str("payload", payload).
			Msg("job reclaim: REQUEUE FAILED — payload logged above is the only remaining copy")
		return
	}

	result.Requeued++
	log.Info().Str("priority", priority).Msg("job reclaim: requeued job from dead worker")
}

// fail publishes the terminal event the dead worker never got to send.
//
// Python's CompletionsConsumer is the sole writer (ADR-013), so this is
// how a job reaches `failed` without the engine touching PostgreSQL —
// and it is why the sweeper can live on the Go side at all.
func (r *Reclaimer) fail(
	ctx context.Context,
	job *events.JobDispatch,
	deadWorkerID, reason string,
	result *ReclaimResult,
) {
	if deadWorkerID != "" {
		reason += " (worker " + deadWorkerID + ")"
	}

	// Best-effort progress event first, so a UI tailing the scan sees the
	// job leave `running` rather than sitting there until a refresh.
	progress := NewProgressPublisher(r.client, job.ScanID)
	if _, err := progress.Publish(ctx, events.EventJobFailed, events.ProgressEvent{
		"job_id": job.ID,
		"engine": job.Engine,
		"error":  reason,
	}); err != nil {
		r.log.Warn().Err(err).Str("job_id", job.ID).
			Msg("job reclaim: progress publish failed; continuing to the completion event")
	}

	completion := events.JobCompletedEvent{
		EventType:      events.EventJobCompleted,
		JobID:          job.ID,
		ScanID:         job.ScanID,
		OrganizationID: job.OrganizationID,
		Engine:         job.Engine,
		Status:         "failed",
		FindingCount:   0,
		DurationMs:     0,
		IdempotencyKey: job.IdempotencyKey,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		EventSeq:       events.EventSeq{Index: 1, Total: 1},
		ErrorMessage:   reason,
	}
	if err := r.comp.Publish(ctx, completion); err != nil {
		r.log.Error().Err(err).
			Str("job_id", job.ID).
			Str("scan_id", job.ScanID).
			Msg("job reclaim: could not publish the failure event; job stays non-terminal")
		return
	}

	result.Failed++
	r.log.Info().
		Str("job_id", job.ID).
		Str("scan_id", job.ScanID).
		Str("engine", job.Engine).
		Str("reason", reason).
		Msg("job reclaim: reported job failed")
}

// bumpReclaimCount increments and returns this job's recovery count.
func (r *Reclaimer) bumpReclaimCount(ctx context.Context, idempotencyKey string) (int64, error) {
	key := reclaimCountPrefix + idempotencyKey
	n, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("INCR %s: %w", key, err)
	}
	if err := r.client.Expire(ctx, key, reclaimBookkeepingTTL).Err(); err != nil {
		// The count is correct; only its expiry is not. Not worth
		// abandoning the reclaim over — the key is a few bytes.
		r.log.Warn().Err(err).Str("key", key).Msg("job reclaim: could not set counter TTL")
	}
	return n, nil
}

// hasPublished reports whether any completion event for this job reached
// Redis before its worker died.
func (r *Reclaimer) hasPublished(ctx context.Context, idempotencyKey string) (bool, error) {
	n, err := r.client.Exists(ctx, publishedKeyPrefix+idempotencyKey).Result()
	if err != nil {
		return false, fmt.Errorf("EXISTS %s%s: %w", publishedKeyPrefix, idempotencyKey, err)
	}
	return n > 0, nil
}
