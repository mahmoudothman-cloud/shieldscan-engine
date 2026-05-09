package service

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// waitForReady polls baseURL+endpoint until the response status code
// matches expectedStatus (default 200) within the timeout window,
// using a fixed pollInterval. Returns nil on ready; descriptive
// error on timeout.
//
// Per Q2 lock: HTTP endpoint poll readiness with consumer-specified
// endpoint. Per Q6 lock: readiness probe runs at spin-up only;
// invoked by ServiceContainerFactory after ContainerStart +
// ContainerInspect.
//
// Uses standalone *http.Client (NOT consumer's Client) — readiness
// is pre-Client-construction; the standalone client has explicit
// per-request timeout via ctx.WithTimeout for each probe.
//
// Fixed pollInterval (not exponential) — readiness is short-window
// probing; exponential backoff would unnecessarily delay detection
// of services that come up slowly-but-uniformly.
func waitForReady(ctx context.Context, baseURL, endpoint string, expectedStatus int, timeout, pollInterval time.Duration) error {
	if expectedStatus == 0 {
		expectedStatus = http.StatusOK
	}
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	probeClient := &http.Client{Timeout: 0} // ctx provides timeout
	deadline := time.Now().Add(timeout)
	url := baseURL + endpoint

	var lastErr error
	for time.Now().Before(deadline) {
		probeCtx, cancel := context.WithTimeout(ctx, pollInterval)
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return fmt.Errorf("readiness: build request %s: %w", url, err)
		}
		resp, err := probeClient.Do(req)
		if err != nil {
			lastErr = err
			cancel()
		} else {
			status := resp.StatusCode
			_ = resp.Body.Close()
			cancel()
			if status == expectedStatus {
				return nil
			}
			lastErr = fmt.Errorf("status %d (expected %d)", status, expectedStatus)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("readiness: timed out after %s polling %s: last error: %w", timeout, url, lastErr)
	}
	return fmt.Errorf("readiness: timed out after %s polling %s", timeout, url)
}
