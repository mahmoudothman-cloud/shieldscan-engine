// Package recon orchestrator tests cover RunRecon's pipeline shape:
// happy path, failure-tolerance scenarios, limit application, and
// publisher event sequence verification via mock binaries +
// recordingPublisher.
package recon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func noopLog() zerolog.Logger {
	return zerolog.New(nil).Level(zerolog.Disabled)
}

// shScript writes a tiny POSIX shell script + makes it executable.
// Mock-binary pattern from 6.7's framework tests.
func shScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mock.sh")
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return p
}

// ─── RunRecon orchestrator (5) ───────────────────────────────────────

// TestRunRecon_HappyPath: subfinder + httpx both succeed; ReconResult
// contains both Subdomains + LiveHosts; nil error.
//
// Note: nil publisher passes (publisher nil-safety per H.6).
func TestRunRecon_HappyPath(t *testing.T) {
	subMock := shScript(t,
		`echo '{"host":"a.example.com","input":"example.com","source":"crtsh"}'`+"\n"+
			`echo '{"host":"b.example.com","input":"example.com","source":"crtsh"}'`)
	httpxMock := shScript(t,
		`echo '{"url":"https://a.example.com","status_code":200,"title":"A","tech":["Nginx"],"webserver":"nginx","content_type":"text/html","failed":false}'`+"\n"+
			`echo '{"url":"https://b.example.com","status_code":403,"title":"B","tech":[],"webserver":"nginx","content_type":"text/html","failed":false}'`)

	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxMock)

	res, err := RunRecon(t.Context(), "example.com", 100, nil, nil, "", "", noopLog())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Len(t, res.Subdomains, 2)
	assert.Len(t, res.LiveHosts, 2)
}

// TestRunRecon_SubfinderFailureStillProbesTarget: subfinder fails, but
// recon STILL probes the scan target host via httpx (single-host-scan
// fix — subfinder failure is no longer an early return before httpx).
// Failure-tolerance is preserved (nil error); the target is probed
// regardless. Subdomains empty (the target is not a "discovered"
// subdomain).
func TestRunRecon_SubfinderFailureStillProbesTarget(t *testing.T) {
	failMock := shScript(t, `exit 1`)
	httpxMock := shScript(t,
		`echo '{"url":"https://example.com","status_code":200,"failed":false}'`)
	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", failMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxMock)

	res, err := RunRecon(t.Context(), "https://example.com", 100, nil, nil, "", "", noopLog())
	require.NoError(t, err, "subfinder failure MUST NOT propagate error to caller")
	require.NotNil(t, res)
	assert.Empty(t, res.Subdomains, "no subdomains discovered")
	assert.Len(t, res.LiveHosts, 1, "target host still probed despite subfinder failure")
}

// TestRunRecon_ZeroSubdomainsStillProbesTarget is the regression guard
// for the single-host-scan bug: Subfinder succeeds but finds ZERO
// subdomains (the normal case for a host not in any public dataset).
// Recon must STILL probe the target host via httpx and yield >=1 live
// host. Previously it early-returned before httpx ("no_subdomains") so
// phase-2 engine dispatch got an empty target list and scanned nothing.
func TestRunRecon_ZeroSubdomainsStillProbesTarget(t *testing.T) {
	emptySubMock := shScript(t, `exit 0`) // succeeds, emits no subdomains
	httpxMock := shScript(t,
		`echo '{"url":"https://shieldscan.odyssey-eg.com","status_code":200,"title":"Juice Shop","failed":false}'`)
	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", emptySubMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxMock)

	// domain is the full target_url the API passes (live-scan evidence).
	res, err := RunRecon(t.Context(), "https://shieldscan.odyssey-eg.com", 100, nil, nil, "", "", noopLog())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.Subdomains, "subfinder found no subdomains")
	assert.Len(t, res.LiveHosts, 1, "target host probed even with zero subdomains")
	assert.Equal(t, "https://shieldscan.odyssey-eg.com", res.LiveHosts[0].URL)
}

// TestProbeSet covers target-host extraction + dedup: the API passes a
// URL; the target is normalized to a bare host, placed first, and
// deduped against subdomains case-insensitively.
func TestProbeSet(t *testing.T) {
	got := probeSet(
		"https://shieldscan.odyssey-eg.com",
		[]string{"api.odyssey-eg.com", "SHIELDSCAN.odyssey-eg.com"},
	)
	assert.Equal(t,
		[]string{"shieldscan.odyssey-eg.com", "api.odyssey-eg.com"},
		got,
		"target host first (bare, from URL); case-insensitive duplicate subdomain dropped")

	assert.Equal(t, []string{"example.com"}, probeSet("example.com", nil),
		"bare-host target, no subdomains → just the target")
	assert.Empty(t, probeSet("", nil), "empty target + no subs → empty probe set")
}

// TestRunRecon_HttpxFailureReturnsSubdomains: subfinder succeeds;
// httpx fails. ReconResult preserves Subdomains; LiveHosts empty.
func TestRunRecon_HttpxFailureReturnsSubdomains(t *testing.T) {
	subMock := shScript(t,
		`echo '{"host":"a.example.com","input":"example.com","source":"crtsh"}'`)
	httpxFail := shScript(t, `exit 1`)

	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxFail)

	res, err := RunRecon(t.Context(), "example.com", 100, nil, nil, "", "", noopLog())
	require.NoError(t, err, "httpx failure MUST NOT propagate error to caller")
	require.NotNil(t, res)
	assert.Len(t, res.Subdomains, 1, "subdomains preserved despite httpx failure")
	assert.Empty(t, res.LiveHosts)
}

// TestRunRecon_LimitApplied: subfinder returns N>limit subdomains;
// only first limit are passed to httpx. Verify via subdomain count.
func TestRunRecon_LimitApplied(t *testing.T) {
	// subfinder mock emits 10 subdomains.
	body := ""
	for i := 0; i < 10; i++ {
		body += `echo '{"host":"sub` + string(rune('0'+i)) + `.example.com","input":"example.com","source":"crtsh"}'` + "\n"
	}
	subMock := shScript(t, body)

	// httpx mock: emit one record per stdin line (cat-like).
	// Simpler: emit exactly 3 records (matches limit=3).
	httpxMock := shScript(t,
		`echo '{"url":"https://sub0.example.com","status_code":200,"failed":false}'`+"\n"+
			`echo '{"url":"https://sub1.example.com","status_code":200,"failed":false}'`+"\n"+
			`echo '{"url":"https://sub2.example.com","status_code":200,"failed":false}'`)

	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxMock)

	res, err := RunRecon(t.Context(), "example.com", 3, nil, nil, "", "", noopLog())
	require.NoError(t, err)
	assert.Len(t, res.Subdomains, 3, "limit=3 applied; first 3 subdomains kept")
}

// TestRunRecon_DefaultLimitWhenZero: limit==0 → defensive default
// (100 per TOOL-ARCH §8.1). 5 subdomains in subfinder output → all
// 5 pass through (under default cap).
func TestRunRecon_DefaultLimitWhenZero(t *testing.T) {
	body := ""
	for i := 0; i < 5; i++ {
		body += `echo '{"host":"sub` + string(rune('0'+i)) + `.example.com","input":"example.com","source":"crtsh"}'` + "\n"
	}
	subMock := shScript(t, body)
	httpxFail := shScript(t, `exit 1`) // simplify; httpx not the assertion

	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxFail)

	res, err := RunRecon(t.Context(), "example.com", 0, nil, nil, "", "", noopLog())
	require.NoError(t, err)
	assert.Len(t, res.Subdomains, 5,
		"limit=0 → defensive default 100 applied; 5 subdomains all pass through")
}

// ─── Context cancellation (1) ────────────────────────────────────────

// TestRunRecon_RespectsCtxCancel: caller cancels ctx; subfinder
// subprocess SIGKILLed via exec.CommandContext; RunRecon returns
// quickly (not after subfinder's natural 60s timeout).
func TestRunRecon_RespectsCtxCancel(t *testing.T) {
	// Subfinder mock that sleeps 30s — ctx cancel must SIGKILL it.
	slowMock := shScript(t, `sleep 30`)
	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", slowMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", "/bin/echo")

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // pre-cancel

	res, err := RunRecon(ctx, "example.com", 100, nil, nil, "", "", noopLog())
	// Pre-cancelled ctx → subfinder fails → recon returns empty
	// ReconResult, nil (failure-tolerant).
	require.NoError(t, err, "ctx cancel surfaces as subfinder failure → empty result")
	require.NotNil(t, res)
	assert.Empty(t, res.Subdomains)
}

// ─── Task 8.3α EventAttackSurface emission (3) ──────────────────────

// TestStatusFromStatusCode covers the SubdomainStatus mapping per
// SPEC §7.6 field semantics: positive HTTP status → "live"; zero/
// negative sentinel → "dead". Reserved "timeout" reserved for
// future explicit deadline-exceeded signaling.
func TestStatusFromStatusCode(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{200, "live"},
		{301, "live"},
		{403, "live"},
		{500, "live"},
		{0, "dead"},
		{-1, "dead"},
	}
	for _, tt := range tests {
		assert.Equalf(t, tt.want, statusFromStatusCode(tt.code),
			"statusFromStatusCode(%d)", tt.code)
	}
}

// TestPublishAttackSurfaceIfReady_NilSafetySkips verifies the
// Y-RECON-PUBLISHER-WIRING (a) nil-safety branches: emission is
// skipped when completionsPub is nil OR scanID is empty OR orgID
// is empty (test path + M8.1 forward-pinned pre-production path).
// Helper must return without panic.
func TestPublishAttackSurfaceIfReady_NilSafetySkips(t *testing.T) {
	liveHosts := []LiveHost{{URL: "https://a.example.com", StatusCode: 200, Tech: []string{"nginx"}}}

	// All three nil-safety branches: nil publisher; empty scanID; empty orgID.
	publishAttackSurfaceIfReady(t.Context(), nil, "scan-1", "org-1", "example.com", liveHosts, noopLog())
	publishAttackSurfaceIfReady(t.Context(), nil, "", "org-1", "example.com", liveHosts, noopLog())
	publishAttackSurfaceIfReady(t.Context(), nil, "scan-1", "", "example.com", liveHosts, noopLog())
	// No assertion — absence-of-panic is the contract.
}

// TestRunRecon_AttackSurfaceEmissionNilSafe verifies that RunRecon
// in the happy path with completionsPub=nil + empty scanID/orgID does
// NOT panic and successfully returns. Pairs with the unit test on
// publishAttackSurfaceIfReady to cover the Drift #58 Layer A repair
// callsite's nil-safety end-to-end through RunRecon. Real-Redis-backed
// emission coverage is forward-pinned to M8.1 production-wiring
// integration tests (publisher injection beyond unit-scope here).
func TestRunRecon_AttackSurfaceEmissionNilSafe(t *testing.T) {
	subMock := shScript(t,
		`echo '{"host":"a.example.com","input":"example.com","source":"crtsh"}'`)
	httpxMock := shScript(t,
		`echo '{"url":"https://a.example.com","status_code":200,"title":"A","tech":["Nginx"],"webserver":"nginx","content_type":"text/html","failed":false}'`)

	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxMock)

	// completionsPub=nil + scanID/orgID empty → emission skipped silently.
	res, err := RunRecon(t.Context(), "example.com", 100, nil, nil, "", "", noopLog())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Len(t, res.LiveHosts, 1)
}
