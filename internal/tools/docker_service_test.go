package tools

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// httpmock setup convention: each test that uses httpmock acquires its
// own *http.Client via newMockClient(t), which auto-cleans via t.Cleanup.
// Per-test isolation prevents response registrations from leaking
// across tests. This is the first real-world verification of httpmock
// v1.3.1 compat (Checkpoint 4 documented-confidence pin).

// newMockClient returns an http.Client with a fresh httpmock transport,
// auto-cleaned at test end.
func newMockClient(t *testing.T) *http.Client {
	t.Helper()
	client := &http.Client{}
	httpmock.ActivateNonDefault(client)
	t.Cleanup(httpmock.DeactivateAndReset)
	return client
}

// dockerServiceFixture builds a runner wired for httpmock against a
// canonical http://test.local base. The Execute closure can be
// overridden per-test; default is a no-op returning empty findings.
func dockerServiceFixture(t *testing.T, execute func(context.Context, *DockerServiceRunner, Target, ScanConfig) ([]events.RawFinding, error)) *DockerServiceRunner {
	t.Helper()
	if execute == nil {
		execute = func(context.Context, *DockerServiceRunner, Target, ScanConfig) ([]events.RawFinding, error) {
			return nil, nil
		}
	}
	return &DockerServiceRunner{
		ToolName:     "fixture",
		ToolCategory: "test",
		BaseURL:      "http://test.local",
		Timeout:      5 * time.Second,
		HTTPClient:   newMockClient(t),
		HealthPath:   "/healthz",
		Execute:      execute,
	}
}

// tests -----------------------------------------------------------

// TestDockerServiceRunner_ImplementsToolRunner pins the interface
// assertion. Compile-time `var _ ToolRunner = (*DockerServiceRunner)(nil)`
// in docker_service.go catches drift; this runtime test catches the
// case where the file's assertion was deleted but the type still
// "happens to" implement the interface.
func TestDockerServiceRunner_ImplementsToolRunner(t *testing.T) {
	var r ToolRunner = &DockerServiceRunner{ToolName: "x", ToolCategory: "y"}
	assert.Equal(t, "x", r.Name())
	assert.Equal(t, "y", r.Category())
}

// TestDockerServiceRunner_ExecuteIsCalled is the canonical happy path.
// Execute closure invoked with runner + target + cfg; returns one
// synthetic finding; runner returns it after enrichment.
func TestDockerServiceRunner_ExecuteIsCalled(t *testing.T) {
	calls := 0
	r := dockerServiceFixture(t, func(_ context.Context, runner *DockerServiceRunner, _ Target, _ ScanConfig) ([]events.RawFinding, error) {
		calls++
		assert.Equal(t, "fixture", runner.ToolName, "Execute receives the runner")
		return []events.RawFinding{
			{Title: "synthetic", FindingType: "test", Severity: "info"},
		}, nil
	})
	findings, err := r.Run(t.Context(), Target{URL: "http://app.example.com"}, ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "synthetic", findings[0].Title)
	assert.Equal(t, 1, calls, "Execute called exactly once")
}

// TestDockerServiceRunner_PopulatesIdentity verifies the same
// post-Execute enrichment as NativeRunner: ToolName, EngineCategory,
// DiscoveredAt, Fingerprint.
func TestDockerServiceRunner_PopulatesIdentity(t *testing.T) {
	r := dockerServiceFixture(t, func(context.Context, *DockerServiceRunner, Target, ScanConfig) ([]events.RawFinding, error) {
		return []events.RawFinding{
			{Title: "first", FindingType: "test"},
			{Title: "second", FindingType: "test"},
		}, nil
	})
	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for i, f := range findings {
		assert.Equal(t, "fixture", f.ToolName, "finding %d ToolName", i)
		assert.Equal(t, "test", f.EngineCategory, "finding %d Category", i)
		assert.NotEmpty(t, f.DiscoveredAt, "finding %d DiscoveredAt", i)
		assert.NotEmpty(t, f.Fingerprint, "finding %d Fingerprint", i)
		_, parseErr := time.Parse(time.RFC3339, f.DiscoveredAt)
		assert.NoError(t, parseErr, "finding %d DiscoveredAt format", i)
	}
}

// TestDockerServiceRunner_AppliesFingerprint pins canonical
// fingerprint application: same algorithm as NativeRunner; cross-
// runner equality for same logical finding.
func TestDockerServiceRunner_AppliesFingerprint(t *testing.T) {
	r := dockerServiceFixture(t, func(context.Context, *DockerServiceRunner, Target, ScanConfig) ([]events.RawFinding, error) {
		return []events.RawFinding{{
			FindingType: "xss", TargetURL: "https://app.example.com", Parameter: "q",
		}}, nil
	})
	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	independent := ComputeFingerprint(events.RawFinding{
		ToolName:    "fixture",
		FindingType: "xss",
		TargetURL:   "https://app.example.com",
		Parameter:   "q",
	})
	assert.Equal(t, independent, findings[0].Fingerprint,
		"DockerServiceRunner uses same canonical fingerprint as NativeRunner")
}

// TestDockerServiceRunner_TimeoutKillsExecute pins that
// DockerServiceRunner.Timeout fires through ctx into Execute. Execute
// hangs on its own ctx; runner's effective timeout cancels it.
func TestDockerServiceRunner_TimeoutKillsExecute(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "fixture", ToolCategory: "test",
		BaseURL: "http://test.local",
		Timeout: 100 * time.Millisecond,
		Execute: func(ctx context.Context, _ *DockerServiceRunner, _ Target, _ ScanConfig) ([]events.RawFinding, error) {
			// Block until ctx cancels (which should happen at ~100ms).
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	start := time.Now()
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Less(t, elapsed, 500*time.Millisecond, "should return promptly after Execute exits")
}

// TestDockerServiceRunner_CtxCancelKillsExecute pins caller-side
// cancellation: parent ctx cancel propagates into Execute; Run
// returns context.Canceled.
func TestDockerServiceRunner_CtxCancelKillsExecute(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "fixture", ToolCategory: "test",
		BaseURL: "http://test.local",
		Timeout: 10 * time.Second, // long; cancel should win
		Execute: func(ctx context.Context, _ *DockerServiceRunner, _ Target, _ ScanConfig) ([]events.RawFinding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
			cancel()
		}
	}()

	start := time.Now()
	_, err := r.Run(ctx, Target{}, ScanConfig{})
	elapsed := time.Since(start)
	<-done

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected Canceled, got %v", err)
	assert.Less(t, elapsed, 500*time.Millisecond)
}

// TestDockerServiceRunner_CfgTimeoutOverride pins timeout precedence:
// cfg.Timeout (when > 0) overrides runner.Timeout. Symmetric with
// NativeRunner's TestNativeRunner_CfgTimeoutOverride.
func TestDockerServiceRunner_CfgTimeoutOverride(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "fixture", ToolCategory: "test",
		BaseURL: "http://test.local",
		Timeout: 10 * time.Second, // long — should be overridden
		Execute: func(ctx context.Context, _ *DockerServiceRunner, _ Target, _ ScanConfig) ([]events.RawFinding, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	start := time.Now()
	_, err := r.Run(t.Context(), Target{}, ScanConfig{Timeout: 1}) // 1 second
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Less(t, elapsed, 2*time.Second, "cfg.Timeout=1s overrides runner.Timeout=10s")
}

// TestDockerServiceRunner_NilExecute pins contract-surface validation:
// missing Execute closure rejected at Run entry.
func TestDockerServiceRunner_NilExecute(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "fixture", ToolCategory: "test",
		BaseURL: "http://test.local",
		// Execute deliberately nil
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Execute is nil")
}

// TestDockerServiceRunner_NilBaseURL pins symmetric validation for
// missing BaseURL.
func TestDockerServiceRunner_NilBaseURL(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "fixture", ToolCategory: "test",
		// BaseURL deliberately empty
		Execute: func(context.Context, *DockerServiceRunner, Target, ScanConfig) ([]events.RawFinding, error) {
			return nil, nil
		},
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BaseURL is empty")
}

// TestDockerServiceRunner_GetHelper pins the Get convenience method:
// constructs URL, sends ctx, applies query params, returns body.
func TestDockerServiceRunner_GetHelper(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	httpmock.RegisterResponder("GET", "http://test.local/api/scan/status?id=42",
		httpmock.NewStringResponder(200, `{"status":"running"}`))

	body, err := r.Get(t.Context(), "/api/scan/status", map[string]string{"id": "42"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"status":"running"}`, string(body))
}

// TestDockerServiceRunner_PostHelper pins Post: marshals JSON body,
// sets Content-Type, returns response body.
func TestDockerServiceRunner_PostHelper(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	httpmock.RegisterResponder("POST", "http://test.local/api/scan/start",
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
			body := make([]byte, 1024)
			n, _ := req.Body.Read(body)
			assert.Contains(t, string(body[:n]), `"target":"https://x.example.com"`)
			return httpmock.NewStringResponse(202, `{"task_id":"abc123"}`), nil
		})

	body, err := r.Post(t.Context(), "/api/scan/start", map[string]string{
		"target": "https://x.example.com",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"task_id":"abc123"}`, string(body))
}

// TestDockerServiceRunner_AuthHeaderInjected pins APIKey/APIKeyHeader
// auto-injection: helpers add the configured header to every request.
func TestDockerServiceRunner_AuthHeaderInjected(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	r.APIKey = "sk_test_secret"
	r.APIKeyHeader = "X-Mobsfapi-Key"

	httpmock.RegisterResponder("GET", "http://test.local/api/v1/scans",
		func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "sk_test_secret", req.Header.Get("X-Mobsfapi-Key"))
			return httpmock.NewStringResponse(200, "[]"), nil
		})

	_, err := r.Get(t.Context(), "/api/v1/scans", nil)
	require.NoError(t, err)
}

// TestDockerServiceRunner_AuthHeaderOmittedWhenEmpty pins the
// no-auth case: APIKey empty → no header injection.
func TestDockerServiceRunner_AuthHeaderOmittedWhenEmpty(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	// APIKey deliberately empty; APIKeyHeader configured but should be ignored.
	r.APIKeyHeader = "X-Mobsfapi-Key"

	httpmock.RegisterResponder("GET", "http://test.local/api/v1/scans",
		func(req *http.Request) (*http.Response, error) {
			assert.Empty(t, req.Header.Get("X-Mobsfapi-Key"),
				"no auth header when APIKey empty")
			return httpmock.NewStringResponse(200, "[]"), nil
		})

	_, err := r.Get(t.Context(), "/api/v1/scans", nil)
	require.NoError(t, err)
}

// TestDockerServiceRunner_NonSuccessStatus pins HTTP error reporting:
// 4xx/5xx responses surface as errors with status code + truncated
// body for diagnostic context.
func TestDockerServiceRunner_NonSuccessStatus(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	httpmock.RegisterResponder("GET", "http://test.local/api/v1/scans",
		httpmock.NewStringResponder(503, `{"error":"service unavailable"}`))

	_, err := r.Get(t.Context(), "/api/v1/scans", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Contains(t, err.Error(), "service unavailable")
}

// TestDockerServiceRunner_ResponseSizeCap pins the DoS guard:
// response body exceeding MaxResponseBytes rejected via io.LimitReader.
//
// Production default is 50MB. Test uses 1KB cap with 4KB body to
// avoid slow CI; the mechanism is the same regardless of value.
// Implementation MUST stream via io.LimitReader (not buffer-then-check)
// so genuinely huge bodies don't OOM.
func TestDockerServiceRunner_ResponseSizeCap(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	r.MaxResponseBytes = 1024 // 1KB

	bigBody := strings.Repeat("x", 4096) // 4KB
	httpmock.RegisterResponder("GET", "http://test.local/big",
		httpmock.NewStringResponder(200, bigBody))

	_, err := r.Get(t.Context(), "/big", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeded cap")
}

// TestDockerServiceRunner_HealthCheckHappy pins the success path:
// 2xx response on HealthPath returns nil.
func TestDockerServiceRunner_HealthCheckHappy(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	httpmock.RegisterResponder("GET", "http://test.local/healthz",
		httpmock.NewStringResponder(200, ""))

	require.NoError(t, r.HealthCheck(t.Context()))
}

// TestDockerServiceRunner_HealthCheckFailsOn5xx pins the failure path:
// non-2xx on HealthPath wraps with the tool name for ops diagnostics.
func TestDockerServiceRunner_HealthCheckFailsOn5xx(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	httpmock.RegisterResponder("GET", "http://test.local/healthz",
		httpmock.NewStringResponder(503, "service down"))

	err := r.HealthCheck(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fixture health check failed",
		"error wrapped with tool name for ops diagnostics")
}

// TestDockerServiceRunner_HealthCheckMissingPath pins the validation:
// HealthPath empty → error before any HTTP traffic.
func TestDockerServiceRunner_HealthCheckMissingPath(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName:     "fixture",
		ToolCategory: "test",
		BaseURL:      "http://test.local",
		// HealthPath deliberately empty
	}
	err := r.HealthCheck(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HealthPath not configured")
}

// TestDockerServiceRunner_PollUntilSucceeds pins the happy path:
// poll function returning done=true exits cleanly.
func TestDockerServiceRunner_PollUntilSucceeds(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	calls := 0
	err := r.PollUntil(t.Context(), 10*time.Millisecond, func(_ context.Context) (bool, error) {
		calls++
		return calls >= 3, nil // succeed on third call
	})
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

// TestDockerServiceRunner_PollUntilExitsOnCancel pins ADR-021 Rule 2
// enforcement: ctx cancellation between poll cycles exits PollUntil
// with ctx.Err(), not with a hung goroutine. The goleak check in
// TestMain covers leak detection across the whole test package.
func TestDockerServiceRunner_PollUntilExitsOnCancel(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		done <- r.PollUntil(ctx, 50*time.Millisecond, func(_ context.Context) (bool, error) {
			return false, nil // never done
		})
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled),
			"PollUntil exits with ctx.Err() on cancel; got %v", err)
	case <-time.After(time.Second):
		t.Fatal("PollUntil did not exit within 1s of ctx cancel")
	}
}

// TestDockerServiceRunner_PollUntilDefaultInterval pins watch item C:
// interval <= 0 defaults to DefaultPollInterval (1s). We can't easily
// verify the exact 1s default without slowing the test; instead, test
// that interval=0 doesn't busy-loop (no calls in the first 100ms
// beyond the initial "check immediately" call).
func TestDockerServiceRunner_PollUntilDefaultInterval(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	calls := 0
	err := r.PollUntil(ctx, 0, func(_ context.Context) (bool, error) {
		calls++
		return false, nil
	})
	// Should exit on ctx deadline (100ms), having made the initial
	// "check immediately" call but NOT busy-looping (the default
	// 1s interval keeps calls to ~1).
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
	assert.Equal(t, 1, calls,
		"interval=0 must default to ~1s; expected 1 call in 100ms, got %d", calls)
}

// TestDockerServiceRunner_PollUntilPropagatesError pins error
// propagation: poll function errors abort PollUntil immediately,
// without further sleeps.
func TestDockerServiceRunner_PollUntilPropagatesError(t *testing.T) {
	r := dockerServiceFixture(t, nil)
	syntheticErr := errors.New("synthetic poll error")
	calls := 0
	err := r.PollUntil(t.Context(), 10*time.Millisecond, func(_ context.Context) (bool, error) {
		calls++
		return false, syntheticErr
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, syntheticErr))
	assert.Equal(t, 1, calls, "error aborts PollUntil after first call")
}

// TestDockerServiceRunner_ExecuteErrorWrapped pins error propagation
// from Execute through Run: Execute errors are wrapped with tool
// name (matching NativeRunner pattern).
func TestDockerServiceRunner_ExecuteErrorWrapped(t *testing.T) {
	syntheticErr := errors.New("synthetic execute error")
	r := dockerServiceFixture(t, func(context.Context, *DockerServiceRunner, Target, ScanConfig) ([]events.RawFinding, error) {
		return nil, syntheticErr
	})

	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fixture")
	assert.True(t, errors.Is(err, syntheticErr), "underlying error preserved via %%w")
}

// TestDockerServiceRunner_ClientReusedAcrossCalls pins H.4: HTTP
// client is allocated once per runner and reused. Subsequent calls
// to Run/Get/Post don't allocate fresh clients.
func TestDockerServiceRunner_ClientReusedAcrossCalls(t *testing.T) {
	r := dockerServiceFixture(t, nil)

	httpmock.RegisterResponder("GET", "http://test.local/a",
		httpmock.NewStringResponder(200, ""))
	httpmock.RegisterResponder("GET", "http://test.local/b",
		httpmock.NewStringResponder(200, ""))

	clientBefore := r.HTTPClient
	require.NotNil(t, clientBefore)

	_, err := r.Get(t.Context(), "/a", nil)
	require.NoError(t, err)
	_, err = r.Get(t.Context(), "/b", nil)
	require.NoError(t, err)

	assert.Same(t, clientBefore, r.HTTPClient,
		"HTTP client reused across Get calls (H.4 connection-reuse goal)")
}
