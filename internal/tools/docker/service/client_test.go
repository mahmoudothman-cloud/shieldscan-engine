package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	return &Client{
		BaseURL:    server.URL,
		HTTPClient: &http.Client{Timeout: 0},
		Log:        noopLog(),
	}
}

func TestWithAPIKeyHeader_InjectsHeader(t *testing.T) {
	auth := WithAPIKeyHeader("X-API-Key", "secret")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example", nil)
	auth(req)
	assert.Equal(t, "secret", req.Header.Get("X-API-Key"))
}

func TestWithAPIKeyHeader_EmptyHeaderName_NoOp(t *testing.T) {
	auth := WithAPIKeyHeader("", "value")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example", nil)
	auth(req)
	assert.Empty(t, req.Header)
}

func TestWithBearerToken_InjectsAuthorization(t *testing.T) {
	auth := WithBearerToken("token123")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example", nil)
	auth(req)
	assert.Equal(t, "Bearer token123", req.Header.Get("Authorization"))
}

func TestWithBearerToken_EmptyToken_NoOp(t *testing.T) {
	auth := WithBearerToken("")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example", nil)
	auth(req)
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestClient_Get_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	c := newTestClient(t, server)
	body, err := c.Get(context.Background(), "/test")
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))
}

func TestClient_Get_AuthApplied(t *testing.T) {
	var seenHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("X-Auth")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server)
	c.AuthFunc = WithAPIKeyHeader("X-Auth", "abc")
	_, err := c.Get(context.Background(), "/test")
	require.NoError(t, err)
	assert.Equal(t, "abc", seenHeader)
}

func TestClient_Get_NonRetryable4xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "not found")
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.Get(context.Background(), "/missing")
	require.Error(t, err)

	var httpErr *HTTPError
	require.True(t, errors.As(err, &httpErr))
	assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
	assert.False(t, httpErr.Retryable)
}

func TestClient_Get_Retryable5xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.Get(context.Background(), "/")
	require.Error(t, err)

	var httpErr *HTTPError
	require.True(t, errors.As(err, &httpErr))
	assert.True(t, httpErr.Retryable)
}

func TestClient_Post_JSONBody(t *testing.T) {
	var receivedBody []byte
	var ct string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.Post(context.Background(), "/post", map[string]string{"k": "v"})
	require.NoError(t, err)
	assert.Equal(t, "application/json", ct)
	assert.JSONEq(t, `{"k":"v"}`, string(receivedBody))
}

func TestClient_Post_NilBody_NoContentType(t *testing.T) {
	var ct string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.Post(context.Background(), "/post", nil)
	require.NoError(t, err)
	assert.Empty(t, ct, "nil body must not set Content-Type")
}

func TestClient_BuildURL_EmptyBaseURL(t *testing.T) {
	c := &Client{}
	_, err := c.buildURL("/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BaseURL")
}

func TestClient_PollUntil_DoneOnFirstAttempt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "READY")
	}))
	defer server.Close()

	c := newTestClient(t, server)
	body, err := c.PollUntil(context.Background(), "/status",
		func(b []byte) (bool, error) { return string(b) == "READY", nil },
		PollOpts{InitialInterval: time.Millisecond, MaxInterval: 10 * time.Millisecond, MaxAttempts: 3, MaxDuration: time.Second},
	)
	require.NoError(t, err)
	assert.Equal(t, "READY", string(body))
}

func TestClient_PollUntil_PredicateError_TerminalFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "garbage")
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.PollUntil(context.Background(), "/status",
		func(_ []byte) (bool, error) { return false, errors.New("malformed") },
		PollOpts{InitialInterval: time.Millisecond, MaxInterval: 10 * time.Millisecond, MaxAttempts: 5, MaxDuration: time.Second},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "predicate error")
}

func TestClient_PollUntil_MaxAttemptsExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not yet")
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.PollUntil(context.Background(), "/status",
		func(_ []byte) (bool, error) { return false, nil },
		PollOpts{InitialInterval: time.Millisecond, MaxInterval: 10 * time.Millisecond, MaxAttempts: 3, MaxDuration: time.Second},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max attempts")
}

func TestClient_PollUntil_NonRetryableHTTPError_FailsFast(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := newTestClient(t, server)
	_, err := c.PollUntil(context.Background(), "/status",
		func(_ []byte) (bool, error) { return true, nil },
		PollOpts{InitialInterval: time.Millisecond, MaxAttempts: 5, MaxDuration: time.Second},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-retryable")
}

func TestClient_PollUntil_CtxCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "incomplete")
	}))
	defer server.Close()

	c := newTestClient(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := c.PollUntil(ctx, "/status",
		func(_ []byte) (bool, error) { return false, nil },
		PollOpts{InitialInterval: 10 * time.Millisecond, MaxInterval: 100 * time.Millisecond, MaxAttempts: 1000, MaxDuration: time.Hour},
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "ctx cancellation propagates: got %v", err)
}

func TestExponentialInterval_RespectsCap(t *testing.T) {
	// Large attempt → capped at max
	got := exponentialInterval(time.Second, 30*time.Second, 2.0, 100)
	assert.Equal(t, 30*time.Second, got)
}

func TestExponentialInterval_GrowsWithAttempt(t *testing.T) {
	a0 := exponentialInterval(time.Second, time.Hour, 2.0, 0)
	a1 := exponentialInterval(time.Second, time.Hour, 2.0, 1)
	a2 := exponentialInterval(time.Second, time.Hour, 2.0, 2)
	assert.Equal(t, time.Second, a0)
	assert.Equal(t, 2*time.Second, a1)
	assert.Equal(t, 4*time.Second, a2)
}

func TestNormalizePollOpts_Defaults(t *testing.T) {
	opts := normalizePollOpts(PollOpts{})
	assert.Equal(t, time.Second, opts.InitialInterval)
	assert.Equal(t, 30*time.Second, opts.MaxInterval)
	assert.InDelta(t, 2.0, opts.BackoffFactor, 0.001)
	assert.Equal(t, 1000, opts.MaxAttempts)
	assert.Equal(t, 30*time.Minute, opts.MaxDuration)
}

func TestNormalizePollOpts_PreservesNonZero(t *testing.T) {
	opts := normalizePollOpts(PollOpts{
		InitialInterval: 500 * time.Millisecond,
		MaxAttempts:     50,
	})
	assert.Equal(t, 500*time.Millisecond, opts.InitialInterval)
	assert.Equal(t, 50, opts.MaxAttempts)
}
