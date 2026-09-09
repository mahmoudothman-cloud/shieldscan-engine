package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForReady_ImmediateSuccess(t *testing.T) {
	server := newReadyServer(t, "/ready", nil)
	defer server.Close()

	err := waitForReady(context.Background(), server.URL, "/ready", 200, 2*time.Second, 10*time.Millisecond, "", nil)
	require.NoError(t, err)
}

func TestWaitForReady_TimeoutOnUnreachable(t *testing.T) {
	// Use a port that's almost certainly closed; readiness should
	// time out within the configured budget.
	err := waitForReady(context.Background(), "http://127.0.0.1:1", "/ready", 200, 100*time.Millisecond, 20*time.Millisecond, "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}

func TestWaitForReady_StatusMismatchKeepsPolling(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := waitForReady(context.Background(), server.URL, "/", 200, 2*time.Second, 5*time.Millisecond, "", nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, calls.Load(), int32(3), "must keep polling until 200")
}

func TestWaitForReady_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	err := waitForReady(ctx, server.URL, "/", 200, time.Hour, 10*time.Millisecond, "", nil)
	require.Error(t, err)
}

func TestWaitForReady_ZeroExpectedStatus_DefaultsTo200(t *testing.T) {
	server := newReadyServer(t, "/", nil)
	defer server.Close()
	err := waitForReady(context.Background(), server.URL, "/", 0, time.Second, 10*time.Millisecond, "", nil)
	require.NoError(t, err)
}

func TestWaitForReady_ZeroPollInterval_DefaultsApplied(t *testing.T) {
	server := newReadyServer(t, "/", nil)
	defer server.Close()
	// Default poll interval (2s) shouldn't affect immediate-200 case.
	err := waitForReady(context.Background(), server.URL, "/", 200, 5*time.Second, 0, "", nil)
	require.NoError(t, err)
}
