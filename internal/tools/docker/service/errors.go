// Package service provides the DockerServiceRunner framework for
// HTTP-API-shaped Docker tools (ZAP, MobSF, future Burp/Snyk/Wiz).
// Distinct from internal/tools/docker (DockerRunner; exec-shape tools
// like Nmap) by handling long-running service containers that expose
// REST APIs.
//
// Per ADR-026 (DockerRunner framework + lazy warm pool — M7 container
// lifecycle architecture; SPEC §13) and Task 7.5b design doc
// (plans/2026-05-09-task-7.5b-docker-service-runner-design.md +
// revision plans/2026-05-09-task-7.5b-docker-service-runner-design.md
// at commit 3067c92 in shieldscan-docs).
//
// Phase 0 resolution locks (per design doc revision 3067c92):
//   - V8 Option (c) Replace: this subpackage replaces the previous
//     internal/tools/docker_service.go (M5.3 + ADR-006; deleted in
//     Task 7.5b Phase 4 atomic commit). Zero active consumers per
//     Phase 0.5 verification.
//   - V2 Option (α) ContainerFactory hook on Task 7.5a WarmPool.Config:
//     ServiceContainerFactory in spinup.go provides service-shape
//     container creation (port mapping; no Cmd override; readiness
//     probing).
//   - V4 Option (γ) cfg.EphemeralContainer = true ZAP default v1:
//     ZAP newSession reset surfaces NOT VERIFIED in public docs;
//     fresh-container-per-scan side-steps the cleanup uncertainty.
//   - V5 Option (γ) MobSF md5-tracked cleanup: CleanupFunc closure
//     captures consumer-side lastScanMD5 state across scans.
package service

import "fmt"

// HTTPError represents an HTTP-protocol-level error from a service
// request. Distinct from network errors (returned directly by
// http.Client.Do) and parse errors (returned by Client decoders).
//
// Retryable distinguishes 5xx + 429 (transient; safe to retry) from
// 4xx-else (permanent; retry won't help). Consumers use Retryable to
// decide between immediate-fail vs PollUntil-with-backoff.
type HTTPError struct {
	StatusCode int
	Body       []byte
	Retryable  bool
}

func (e *HTTPError) Error() string {
	if len(e.Body) == 0 {
		return fmt.Sprintf("http error: status %d", e.StatusCode)
	}
	// Cap body length in error message to avoid log spam on giant
	// responses; full body preserved on the struct for debugging.
	body := string(e.Body)
	const maxLen = 200
	if len(body) > maxLen {
		body = body[:maxLen] + "..."
	}
	return fmt.Sprintf("http error: status %d: %s", e.StatusCode, body)
}

// categorizeHTTPStatus returns whether an HTTP status code is
// retry-worthy. 5xx (server errors) and 429 (rate limit) are
// retryable; all other non-2xx codes are not.
//
// Network errors (DNS, connection refused, timeout) are handled at
// the http.Client.Do level; this function is invoked only when an
// HTTP response was received.
func categorizeHTTPStatus(statusCode int) bool {
	if statusCode == 429 {
		return true
	}
	if statusCode >= 500 && statusCode < 600 {
		return true
	}
	return false
}
