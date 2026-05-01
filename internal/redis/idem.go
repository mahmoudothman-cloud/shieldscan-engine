package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// IdempotencyTTL is the lifetime of idempotency-claim keys per
// SPECIFICATION.md §7.5. 24 hours covers the longest expected scan
// duration with generous headroom; cross-repo coupling means
// changing this requires SPEC §7.5 amendment + Python coordination,
// not a config tweak.
const IdempotencyTTL = 24 * time.Hour

// idemKeyPrefix is the Redis key namespace for idempotency claims.
// Format: shieldscan:idem:{scan_id}:{tool}:{unix_timestamp}.
const idemKeyPrefix = "shieldscan:idem:"

// IdempotencyClaim wraps the SETNX-with-TTL idempotency primitive
// per SPEC §7.5. The claim is worker-side: ScanQueue.dispatch (M4
// Python) does NOT dedupe; workers SETNX-claim before processing
// each popped job. Duplicate dispatches result in only one of the
// claimers proceeding; others see the key already set and drop.
//
// 24h TTL ensures keys auto-expire so a crashed worker that never
// completed processing doesn't permanently block the same job from
// being re-claimed by another worker after a future redispatch.
type IdempotencyClaim struct {
	client *redis.Client
}

// NewIdempotencyClaim constructs a primitive bound to the given
// Redis client.
func NewIdempotencyClaim(client *redis.Client) *IdempotencyClaim {
	return &IdempotencyClaim{client: client}
}

// Claim attempts to claim the idempotency_key. Returns:
//
//	(true, nil)  — first claimer; caller proceeds to process the job.
//	(false, nil) — duplicate; key already claimed by another worker.
//	                Caller should drop the job silently.
//	(_, err)     — Redis I/O error (network, auth, etc.). Surface up.
//
// The key is namespaced under shieldscan:idem: so callers pass the
// raw idempotency_key (e.g., "scn_x1y2z3:nuclei:1711720200") and the
// primitive handles namespacing.
func (i *IdempotencyClaim) Claim(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, fmt.Errorf("idempotency_key is empty")
	}
	ok, err := i.client.SetNX(ctx, idemKeyPrefix+key, "1", IdempotencyTTL).Result()
	if err != nil {
		return false, fmt.Errorf("SETNX %s%s: %w", idemKeyPrefix, key, err)
	}
	return ok, nil
}
