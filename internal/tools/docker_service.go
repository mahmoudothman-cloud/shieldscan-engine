package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// DefaultDockerServiceTimeout is the fallback total operation timeout
// when neither DockerServiceRunner.Timeout nor cfg.Timeout is set. 30
// minutes covers the longest expected single-tool run (deep ZAP active
// scan); shorter individual timeouts apply per TOOL-ARCHITECTURE.md
// §7 when tools opt in.
const DefaultDockerServiceTimeout = 30 * time.Minute

// DefaultMaxResponseBytes is the default cap for HTTP response body.
// 50MB covers expected ranges for every Docker service in M7 (MobSF
// reports ~5-10MB, ZAP alert dumps ~20-30MB, Trivy SBOM ~30MB) with
// generous headroom. Override per-tool via DockerServiceRunner.MaxResponseBytes
// if a specific service legitimately exceeds; see field godoc.
const DefaultMaxResponseBytes = 50 * 1024 * 1024 // 50 MiB

// DefaultPollInterval is used by PollUntil when caller passes
// interval <= 0. One second is a sensible default for most M7 polling
// patterns (MobSF status check, ZAP spider/scan progress).
const DefaultPollInterval = time.Second

// HealthCheckTimeout caps the per-call HealthCheck duration. Worker
// startup phase 2 (Task 5.6) iterates registered DockerServiceRunners
// and invokes HealthCheck on each; bounded duration prevents one
// unhealthy service from blocking startup indefinitely.
const HealthCheckTimeout = 10 * time.Second

// DockerServiceRunner wraps an HTTP API as a ToolRunner. Each M7
// persistent-Docker tool task constructs an instance with its own
// Execute closure; the lifecycle (timeout, ctx propagation, response
// capture, fingerprint enrichment) is shared.
//
// Asymmetric with NativeRunner: NativeRunner splits subprocess into
// BuildArgs + ParseOutput closures (one round-trip), while
// DockerServiceRunner uses a single full-orchestration Execute
// closure. The asymmetry reflects HTTP's multi-step reality —
// MobSF (upload → analyze → poll → fetch report) and ZAP (spider →
// wait → scan → wait → alerts) cannot be expressed as a single
// request/response pair. Helper methods (Get, Post, PollUntil)
// provide primitives; Execute closures compose them.
//
// Convention: Execute closures should treat *DockerServiceRunner as
// read-only. Mutating runner state from within Execute is an
// anti-pattern that breaks runner reuse across jobs.
type DockerServiceRunner struct {
	// Identity
	ToolName     string
	ToolCategory string

	// HTTP target
	BaseURL string // e.g., "http://localhost:8000". No trailing slash.

	// APIKey is the credential value sent under APIKeyHeader on every
	// helper-method request. Empty disables auth header injection.
	APIKey string

	// APIKeyHeader is the header name (e.g., "X-Mobsfapi-Key",
	// "X-ZAP-API-Key"). Empty disables auth header injection.
	APIKeyHeader string

	// HealthPath is the relative path for HealthCheck (e.g.,
	// "/api/v1/ping", "/healthz"). Required for HealthCheck to function.
	HealthPath string

	// Lifecycle
	Timeout time.Duration // total operation timeout; cfg.Timeout overrides

	// HTTPClient is reused across Run calls and helper-method calls.
	// Per-runner-instance lifecycle enables connection reuse for
	// polling-heavy tools (MobSF: 30+ polls per scan, ZAP: 100+).
	// Constructed at first use if nil.
	//
	// HTTPClient.Timeout SHOULD be 0; timeout enforcement flows
	// through ctx (req.WithContext) so logical-operation timeouts
	// don't race with client-level timeouts.
	HTTPClient *http.Client

	// MaxResponseBytes caps HTTP response body to prevent runaway
	// services. Default 50MB. Set to 0 to disable (not recommended
	// in production).
	//
	// Override threshold: if a service legitimately produces >50MB
	// responses (rare; observed only on Trivy comprehensive SBOM
	// dumps for monorepos), prefer streaming/chunked download over
	// raising this cap. Services producing >100MB responses approach
	// wire-payload concerns; consider fetching report URLs and
	// downloading via R2/S3 instead.
	MaxResponseBytes int64

	// Execute is the full-orchestration closure. Receives the runner
	// (for helper-method access), target, and config. Returns
	// findings; runner enriches with ToolName/Category/DiscoveredAt/
	// Fingerprint after Execute returns.
	//
	// Execute is responsible for the entire HTTP dance — single call
	// for trivial cases, multi-call orchestration with PollUntil for
	// asynchronous services (MobSF, ZAP).
	//
	// Execute SHOULD treat *DockerServiceRunner as read-only.
	Execute func(ctx context.Context, r *DockerServiceRunner, target Target, cfg ScanConfig) ([]events.RawFinding, error)
}

// Compile-time interface assertion. If DockerServiceRunner ever drifts
// from the ToolRunner signature, `go build` fails before tests run.
var _ ToolRunner = (*DockerServiceRunner)(nil)

// Name returns the configured tool name.
func (d *DockerServiceRunner) Name() string { return d.ToolName }

// Category returns the configured tool category.
func (d *DockerServiceRunner) Category() string { return d.ToolCategory }

// Run delegates to Execute, applies the standard enrichment, and wraps
// errors with the tool name. See ToolRunner.Run for error semantics.
func (d *DockerServiceRunner) Run(ctx context.Context, target Target, cfg ScanConfig) ([]events.RawFinding, error) {
	if d.Execute == nil {
		return nil, fmt.Errorf("%s: Execute is nil", d.ToolName)
	}
	if d.BaseURL == "" {
		return nil, fmt.Errorf("%s: BaseURL is empty", d.ToolName)
	}

	d.ensureClient()

	effectiveTimeout := d.effectiveTimeout(cfg)
	runCtx, cancel := context.WithTimeout(ctx, effectiveTimeout)
	defer cancel()

	findings, err := d.Execute(runCtx, d, target, cfg)

	// Caller cancellation takes precedence over our internal timeout.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%s timed out after %s", d.ToolName, effectiveTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", d.ToolName, err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range findings {
		findings[i].ToolName = d.ToolName
		findings[i].EngineCategory = d.ToolCategory
		findings[i].DiscoveredAt = now
		findings[i].Fingerprint = ComputeFingerprint(findings[i])
	}
	return findings, nil
}

// HealthCheck pings the configured HealthPath. Reaching the endpoint
// with a non-error status (2xx) is the success signal — body content
// is intentionally not parsed because services return divergent
// shapes (MobSF: {"status":"ok"}, ZAP: version JSON, Trivy: empty
// 200, SQLMap: version JSON).
//
// Bounded by HealthCheckTimeout (10s) regardless of caller ctx
// remaining; one unhealthy service should not block worker startup.
func (d *DockerServiceRunner) HealthCheck(ctx context.Context) error {
	if d.HealthPath == "" {
		return fmt.Errorf("%s: HealthPath not configured", d.ToolName)
	}
	d.ensureClient()
	healthCtx, cancel := context.WithTimeout(ctx, HealthCheckTimeout)
	defer cancel()
	if _, err := d.Get(healthCtx, d.HealthPath, nil); err != nil {
		return fmt.Errorf("%s health check failed: %w", d.ToolName, err)
	}
	return nil
}

// Get performs a GET against BaseURL+path with optional query params.
// Returns the response body (size-capped per MaxResponseBytes).
//
// Auth header injection: when APIKey and APIKeyHeader are both
// non-empty, the configured header is set on the request.
//
// Non-2xx responses are reported as errors with the status code; the
// body is captured (truncated for the error message) for diagnostic
// context.
func (d *DockerServiceRunner) Get(ctx context.Context, path string, query map[string]string) ([]byte, error) {
	d.ensureClient()
	fullURL, err := d.buildURL(path, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	d.applyAuth(req)
	return d.do(req)
}

// Post performs a POST against BaseURL+path with optional JSON body.
// Returns the response body (size-capped per MaxResponseBytes).
//
// Auth header injection: same as Get. Content-Type is set to
// application/json automatically when body is non-nil.
func (d *DockerServiceRunner) Post(ctx context.Context, path string, body any) ([]byte, error) {
	d.ensureClient()
	fullURL, err := d.buildURL(path, nil)
	if err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	d.applyAuth(req)
	return d.do(req)
}

// PollUntil repeatedly invokes poll with ctx-aware sleep between
// attempts until poll returns done=true (success) or returns an
// error. interval bounds the wait between polls; values <=0 default
// to DefaultPollInterval.
//
// ADR-021 Rule 2 enforced centrally: the inner sleep selects on
// <-ctx.Done(); ctx cancellation exits PollUntil with ctx.Err().
// M7 closures using PollUntil inherit ctx-aware sleep automatically;
// they should NOT reinvent the pattern with bare time.Sleep.
//
// poll is invoked at least once before the first sleep; this matches
// the "check immediately" expectation for status APIs.
func (d *DockerServiceRunner) PollUntil(ctx context.Context, interval time.Duration, poll func(context.Context) (bool, error)) error {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	for {
		done, err := poll(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
			// continue polling
		}
	}
}

// ensureClient lazily constructs HTTPClient if not provided. Single
// allocation per runner instance; subsequent Run calls reuse.
func (d *DockerServiceRunner) ensureClient() {
	if d.HTTPClient == nil {
		// Timeout: 0 — ctx governs, not client. See HTTPClient godoc.
		d.HTTPClient = &http.Client{}
	}
}

// effectiveTimeout resolves the timeout precedence:
//
//	cfg.Timeout (if > 0)  →  DockerServiceRunner.Timeout (if > 0)  →  DefaultDockerServiceTimeout
func (d *DockerServiceRunner) effectiveTimeout(cfg ScanConfig) time.Duration {
	if cfg.Timeout > 0 {
		return time.Duration(cfg.Timeout) * time.Second
	}
	if d.Timeout > 0 {
		return d.Timeout
	}
	return DefaultDockerServiceTimeout
}

// buildURL composes BaseURL + path with optional query string. Strips
// trailing slash from BaseURL and ensures path starts with "/" so
// composition is consistent regardless of how callers format inputs.
func (d *DockerServiceRunner) buildURL(path string, query map[string]string) (string, error) {
	base := strings.TrimRight(d.BaseURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, err := url.Parse(base + path)
	if err != nil {
		return "", fmt.Errorf("parse url %s%s: %w", base, path, err)
	}
	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// applyAuth injects APIKeyHeader: APIKey if both are configured.
// Idempotent: calling on a request with the header already set
// overwrites with the runner's APIKey.
func (d *DockerServiceRunner) applyAuth(req *http.Request) {
	if d.APIKey != "" && d.APIKeyHeader != "" {
		req.Header.Set(d.APIKeyHeader, d.APIKey)
	}
}

// do executes the request, enforces MaxResponseBytes, and returns
// the body. Non-2xx responses produce an error containing the status
// code and a truncated body excerpt for diagnostic context.
//
// gosec G704 (SSRF taint analysis) suppression: the request URL is
// composed from BaseURL (operator-controlled config, validated at
// worker startup) and a path constant chosen by the M7 task author
// (in-repo code, not user input). Query parameters from the job
// payload are validated by the Python orchestrator before dispatch.
// The HTTP-talking-to-localhost-Docker-services pattern is the
// runner's purpose; flagging Do() as taint-suspicious doesn't apply.
func (d *DockerServiceRunner) do(req *http.Request) ([]byte, error) {
	resp, err := d.HTTPClient.Do(req) //nolint:gosec // G704: see comment above
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	max := d.MaxResponseBytes
	if max == 0 {
		max = DefaultMaxResponseBytes
	}

	// Read up to max+1 bytes via io.LimitReader. If we read max+1
	// bytes, the body exceeded the cap; report and reject without
	// continuing to drain.
	limited := io.LimitReader(resp.Body, max+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response body exceeded cap of %d bytes", max)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	return body, nil
}
