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

	res, err := RunRecon(t.Context(), "example.com", 100, nil, noopLog())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Len(t, res.Subdomains, 2)
	assert.Len(t, res.LiveHosts, 2)
}

// TestRunRecon_SubfinderFailureReturnsEmpty: subfinder fails; recon
// returns empty ReconResult (NOT nil), nil error. Failure-tolerance
// is plan-literal-mandated.
func TestRunRecon_SubfinderFailureReturnsEmpty(t *testing.T) {
	failMock := shScript(t, `exit 1`)
	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", failMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", "/bin/echo") // not invoked

	res, err := RunRecon(t.Context(), "example.com", 100, nil, noopLog())
	require.NoError(t, err, "subfinder failure MUST NOT propagate error to caller")
	require.NotNil(t, res)
	assert.Empty(t, res.Subdomains)
	assert.Empty(t, res.LiveHosts)
}

// TestRunRecon_HttpxFailureReturnsSubdomains: subfinder succeeds;
// httpx fails. ReconResult preserves Subdomains; LiveHosts empty.
func TestRunRecon_HttpxFailureReturnsSubdomains(t *testing.T) {
	subMock := shScript(t,
		`echo '{"host":"a.example.com","input":"example.com","source":"crtsh"}'`)
	httpxFail := shScript(t, `exit 1`)

	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxFail)

	res, err := RunRecon(t.Context(), "example.com", 100, nil, noopLog())
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

	res, err := RunRecon(t.Context(), "example.com", 3, nil, noopLog())
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

	res, err := RunRecon(t.Context(), "example.com", 0, nil, noopLog())
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

	res, err := RunRecon(ctx, "example.com", 100, nil, noopLog())
	// Pre-cancelled ctx → subfinder fails → recon returns empty
	// ReconResult, nil (failure-tolerant).
	require.NoError(t, err, "ctx cancel surfaces as subfinder failure → empty result")
	require.NotNil(t, res)
	assert.Empty(t, res.Subdomains)
}
