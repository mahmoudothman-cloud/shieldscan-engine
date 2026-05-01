package redis

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMiniredisClient spins up a miniredis instance bound to the test
// and returns a go-redis client wired to it. Auto-cleans via t.Cleanup.
//
// First real-world verification of Checkpoint 4's miniredis/v2 v2.33.0
// vs go-redis/v9.7.0 compat pin. Used by every test in this package.
func newMiniredisClient(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

// TestIdempotencyClaim_FirstClaimSucceeds pins the canonical SETNX
// behavior: the first claim returns true; subsequent claims with
// the same key return false (already-claimed).
func TestIdempotencyClaim_FirstClaimSucceeds(t *testing.T) {
	_, client := newMiniredisClient(t)
	claim := NewIdempotencyClaim(client)

	first, err := claim.Claim(t.Context(), "scn_x:nuclei:1711720200")
	require.NoError(t, err)
	assert.True(t, first, "first claim succeeds")

	dup, err := claim.Claim(t.Context(), "scn_x:nuclei:1711720200")
	require.NoError(t, err)
	assert.False(t, dup, "duplicate claim returns false")
}

// TestIdempotencyClaim_24hTTL pins SPEC §7.5 TTL.
// miniredis exposes a mock clock; we read the TTL via the client.
func TestIdempotencyClaim_24hTTL(t *testing.T) {
	_, client := newMiniredisClient(t)
	claim := NewIdempotencyClaim(client)

	_, err := claim.Claim(t.Context(), "scn_y:semgrep:42")
	require.NoError(t, err)

	ttl, err := client.TTL(t.Context(), "shieldscan:idem:scn_y:semgrep:42").Result()
	require.NoError(t, err)
	// 24h ± 60s tolerance for clock-progression between Claim and TTL read.
	assert.InDelta(t, IdempotencyTTL.Seconds(), ttl.Seconds(), 60,
		"TTL should be ~24h; got %s", ttl)
}

// TestIdempotencyClaim_DistinctKeysIndependent pins the multi-key
// case: different keys claim independently.
func TestIdempotencyClaim_DistinctKeysIndependent(t *testing.T) {
	_, client := newMiniredisClient(t)
	claim := NewIdempotencyClaim(client)

	a, err := claim.Claim(t.Context(), "scn_a:nuclei:1")
	require.NoError(t, err)
	assert.True(t, a)

	b, err := claim.Claim(t.Context(), "scn_b:nuclei:1")
	require.NoError(t, err)
	assert.True(t, b, "distinct key claims independently")
}

// TestIdempotencyClaim_EmptyKeyRejected pins contract validation:
// empty idempotency_key is invalid input.
func TestIdempotencyClaim_EmptyKeyRejected(t *testing.T) {
	_, client := newMiniredisClient(t)
	claim := NewIdempotencyClaim(client)

	_, err := claim.Claim(t.Context(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// Ensure unused-import lint doesn't trip when only some test files
// reference time.
var _ = time.Second
