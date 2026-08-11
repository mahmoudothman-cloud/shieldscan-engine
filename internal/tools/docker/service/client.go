package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
)

// AuthFunc injects authentication into an HTTP request. Consumers
// construct via WithAPIKeyHeader or WithBearerToken (typed helpers
// per Q8 lock); custom closures handle novel auth (escape hatch).
//
// nil AuthFunc disables auth header injection.
type AuthFunc func(*http.Request)

// WithAPIKeyHeader returns an AuthFunc that adds a fixed-name header
// (e.g., X-Mobsfapi-Key) carrying the API key value. Empty value or
// empty header name returns a no-op AuthFunc.
//
// Note: ZAP's documented canonical authentication method is the
// "?apikey=" URL query parameter, not a header (per zaproxy.org/docs/api/);
// Task 7.3 ZAP consumer (commit e905afe) uses an AuthFunc escape-hatch
// closure instead of this helper. Header backward-compat works empirically
// (Phase 0 V3) but is not doc-backed. Future query-param-auth tools may
// warrant a WithAPIKeyQueryParam framework helper at 2nd-instance
// threshold per Phase 5.D Task 7.5b precedent (3a17274).
func WithAPIKeyHeader(headerName, value string) AuthFunc {
	if headerName == "" || value == "" {
		return func(*http.Request) {}
	}
	return func(req *http.Request) {
		req.Header.Set(headerName, value)
	}
}

// WithBearerToken returns an AuthFunc that adds an Authorization
// header with the Bearer scheme. Empty token returns a no-op.
func WithBearerToken(token string) AuthFunc {
	if token == "" {
		return func(*http.Request) {}
	}
	return func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// Client is the framework HTTP client for service-shape Docker
// consumers. Wraps net/http.Client with consumer-friendly Get/Post/
// PollUntil helpers + auth injection.
//
// HTTPClient.Timeout MUST be 0 per V10 + design doc; per-request
// timeout is enforced via ctx (http.NewRequestWithContext). This
// pattern prevents client-level timeouts racing with logical-operation
// timeouts.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthFunc   AuthFunc
	Log        zerolog.Logger
}

// serviceAddressing computes the request base URL and HTTP transport for
// a service's addressing model, given the container's mapped host:port
// (e.g. "http://127.0.0.1:49xxx") and an optional forward-proxy magic
// host.
//
// Direct mode (apiProxyHost == ""): requests go straight to the mapped
// address. Returns (mappedAddr, nil) — a nil transport means net/http
// uses DefaultTransport, preserving the pre-existing behavior for every
// normal HTTP service (MobSF and friends).
//
// Proxy mode (apiProxyHost != ""): the mapped host:port is treated as an
// HTTP forward-proxy and requests target http://<apiProxyHost>/... routed
// THROUGH it. ZAP requires this: its control API is served on the SAME
// port as its forward proxy, so a plain GET to the mapped port is
// interpreted as a proxy-forward and returns 502 Bad Gateway. Reaching
// the API means proxying to ZAP's magic host "zap" — verified live
// against ghcr.io/zaproxy/zaproxy ZAP 2.17.0:
//
//	curl    http://127.0.0.1:P/JSON/core/view/version/?apikey=K            → 502
//	curl -x http://127.0.0.1:P http://zap/JSON/core/view/version/?apikey=K → 200
//
// The mapped port is bound to 127.0.0.1 only (spinup PortBindings), so
// the open forward-proxy is not reachable off the worker host.
func serviceAddressing(mappedAddr, apiProxyHost string) (baseURL string, transport *http.Transport, err error) {
	if apiProxyHost == "" {
		return mappedAddr, nil, nil
	}
	proxyURL, err := url.Parse(mappedAddr)
	if err != nil {
		return "", nil, fmt.Errorf("service: parse proxy address %q: %w", mappedAddr, err)
	}
	return "http://" + apiProxyHost, &http.Transport{Proxy: http.ProxyURL(proxyURL)}, nil
}

// PollPredicate decides whether polling is complete given a response
// body. Tri-state per Q4 lock: (done=true, err=nil) = success;
// (done=false, err=nil) = continue polling; (done=*, err!=nil) =
// terminal failure.
type PollPredicate func(response []byte) (done bool, err error)

// PollOpts configures PollUntil's exponential backoff + termination
// criteria per Q4 lock. Zero-value fields use framework defaults.
type PollOpts struct {
	InitialInterval time.Duration                   // default 1s
	MaxInterval     time.Duration                   // default 30s
	BackoffFactor   float64                         // default 2.0
	MaxAttempts     int                             // default 1000
	MaxDuration     time.Duration                   // default 30 minutes
	BackoffFunc     func(attempt int) time.Duration // optional override; nil = exponential
}

// Get issues an authenticated GET request to BaseURL+path and returns
// the response body. ctx cancellation propagates to the request.
// Non-2xx responses return *HTTPError (callers can errors.As to
// inspect retryability).
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	fullURL, err := c.buildURL(path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("client: build request: %w", err)
	}
	c.applyAuth(req)
	return c.do(req)
}

// Post issues an authenticated POST request with a JSON-marshaled
// body. ctx cancellation propagates. Non-2xx responses return
// *HTTPError.
func (c *Client) Post(ctx context.Context, path string, body any) ([]byte, error) {
	fullURL, err := c.buildURL(path)
	if err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("client: marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("client: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.applyAuth(req)
	return c.do(req)
}

// PollUntil repeatedly issues GET requests against path with
// exponential backoff until predicate returns done=true, predicate
// returns an error, MaxAttempts is exceeded, MaxDuration is exceeded,
// or ctx is cancelled.
//
// Per Q4 lock: belt-and-suspenders termination (BOTH MaxAttempts AND
// MaxDuration are independent guards; whichever fires first wins).
//
// Backoff: factor-based exponential growth from InitialInterval to
// MaxInterval cap. BackoffFunc override (if non-nil) replaces the
// default exponential calculation.
//
// ctx-flow: per-iteration request uses ctx; backoff sleep is
// ctx-cancellable via select on ctx.Done().
func (c *Client) PollUntil(ctx context.Context, path string, predicate PollPredicate, opts PollOpts) ([]byte, error) {
	o := normalizePollOpts(opts)

	deadline := time.Now().Add(o.MaxDuration)
	for attempt := 0; attempt < o.MaxAttempts; attempt++ {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("poll: max duration %s exceeded after %d attempts", o.MaxDuration, attempt)
		}

		body, err := c.Get(ctx, path)
		if err != nil {
			// If the error is a non-retryable HTTPError, fail fast.
			if httpErr, ok := err.(*HTTPError); ok && !httpErr.Retryable {
				return nil, fmt.Errorf("poll: non-retryable http error: %w", err)
			}
			// Retryable error: log + backoff (continue loop)
			c.Log.Debug().Err(err).Int("attempt", attempt).Msg("poll request failed; retrying")
		} else {
			done, predErr := predicate(body)
			if predErr != nil {
				return nil, fmt.Errorf("poll: predicate error: %w", predErr)
			}
			if done {
				return body, nil
			}
		}

		// Backoff before next attempt
		var interval time.Duration
		if o.BackoffFunc != nil {
			interval = o.BackoffFunc(attempt)
		} else {
			interval = exponentialInterval(o.InitialInterval, o.MaxInterval, o.BackoffFactor, attempt)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil, fmt.Errorf("poll: max attempts %d exceeded", o.MaxAttempts)
}

// buildURL joins BaseURL and path defensively.
func (c *Client) buildURL(path string) (string, error) {
	if c.BaseURL == "" {
		return "", fmt.Errorf("client: BaseURL is empty")
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", fmt.Errorf("client: parse BaseURL %q: %w", c.BaseURL, err)
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("client: parse path %q: %w", path, err)
	}
	return base.ResolveReference(rel).String(), nil
}

// applyAuth injects auth via AuthFunc when configured.
func (c *Client) applyAuth(req *http.Request) {
	if c.AuthFunc != nil {
		c.AuthFunc(req)
	}
}

// do executes the request, drains the body, and categorizes non-2xx
// responses as *HTTPError.
func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("client: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{
			StatusCode: resp.StatusCode,
			Body:       body,
			Retryable:  categorizeHTTPStatus(resp.StatusCode),
		}
	}
	return body, nil
}

// normalizePollOpts applies defaults to zero-value fields.
//
// MaxDuration default 30 minutes is the framework cap. Original
// design doc verbatim referenced ServiceConfig.ScanTimeout (which
// doesn't exist as a field); resolution adopts a flat 30-minute
// default at the framework level. Consumers may override per-call.
// Documented as DRIFT-LOG entry candidate for Phase 4.
func normalizePollOpts(opts PollOpts) PollOpts {
	if opts.InitialInterval <= 0 {
		opts.InitialInterval = time.Second
	}
	if opts.MaxInterval <= 0 {
		opts.MaxInterval = 30 * time.Second
	}
	if opts.BackoffFactor <= 1.0 {
		opts.BackoffFactor = 2.0
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 1000
	}
	if opts.MaxDuration <= 0 {
		opts.MaxDuration = 30 * time.Minute
	}
	return opts
}

// exponentialInterval calculates the backoff for a given attempt
// number (zero-indexed). Capped at MaxInterval.
func exponentialInterval(initial, max time.Duration, factor float64, attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	multiplier := math.Pow(factor, float64(attempt))
	candidate := time.Duration(float64(initial) * multiplier)
	if candidate > max || candidate < 0 { // overflow guard
		return max
	}
	return candidate
}
