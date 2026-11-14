// Package agent is the on-prem agent (M14; On-Prem Agent Design v1.0):
// the worker's Processor behind an HTTPS transport to the API's
// /v1/agent gateway instead of Redis.
//
// Everything that reaches the network goes through Client, which
// retries 5xx and transport errors with capped backoff for as long as
// the context lives (design §5: "a 5xx or network loss is retried
// indefinitely with the job held locally"), and turns a 401 into
// ErrRevoked so the run loop can exit non-zero with a clear message.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// ErrRevoked is returned when the gateway answers 401: the agent key is
// unknown or the agent was revoked. Not retried.
var ErrRevoked = errors.New("agent key rejected by the API (revoked or unknown)")

// ErrEnrolmentTokenInvalid is returned when /enroll answers 401: the
// token is unknown, expired or already used.
var ErrEnrolmentTokenInvalid = errors.New("enrolment token invalid, expired or already used")

// HostInfo is what the agent says about itself at enrolment and in
// every heartbeat.
type HostInfo struct {
	Version  string `json:"version,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Platform string `json:"platform,omitempty"`
}

// EnrolResponse is the gateway's answer to a successful enrolment. The
// key is shown to the caller exactly once; State.Save is the only
// place it should go.
type EnrolResponse struct {
	AgentID        string `json:"agent_id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	AgentKey       string `json:"agent_key"`
}

// ToolHealth is one entry of the heartbeat's tool inventory.
type ToolHealth struct {
	Status  string `json:"status"` // ok | missing | error
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
}

// HeartbeatRequest mirrors the API's HeartbeatRequest schema.
type HeartbeatRequest struct {
	HostInfo
	Tools map[string]ToolHealth `json:"tools"`
}

// HeartbeatResponse mirrors the API's HeartbeatResponse schema.
type HeartbeatResponse struct {
	AgentID        string   `json:"agent_id"`
	Name           string   `json:"name"`
	CancelScanIDs  []string `json:"cancel_scan_ids"`
	RequeuedJobIDs []string `json:"requeued_job_ids"`
	PollWaitS      int      `json:"poll_wait_s"`
}

// Client talks to one API base URL with one agent key.
type Client struct {
	base      string
	key       string
	http      *http.Client
	log       zerolog.Logger
	userAgent string

	// backoff bounds, overridable in tests.
	minBackoff time.Duration
	maxBackoff time.Duration
}

// NewClient returns a client for base (e.g. https://app.shieldscan.io;
// the /v1 prefix is added here). key may be empty for Enroll.
func NewClient(base, key, version string, log zerolog.Logger) *Client {
	return &Client{
		base:       strings.TrimRight(base, "/"),
		key:        key,
		http:       &http.Client{Timeout: 60 * time.Second},
		log:        log,
		userAgent:  "shieldscan-agent/" + version,
		minBackoff: time.Second,
		maxBackoff: 30 * time.Second,
	}
}

// Base returns the API base URL (without /v1).
func (c *Client) Base() string { return c.base }

// Enroll exchanges a one-time token for an agent key. Not retried on
// 401 (the token is burned server-side on first success, so a retry
// would never help); retried like everything else on 5xx.
func (c *Client) Enroll(ctx context.Context, token string, info HostInfo) (*EnrolResponse, error) {
	body := map[string]any{
		"token": token, "version": info.Version, "hostname": info.Hostname, "platform": info.Platform,
	}
	var out EnrolResponse
	status, err := c.do(ctx, http.MethodPost, "/v1/agent/enroll", body, &out, false)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized {
		return nil, ErrEnrolmentTokenInvalid
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("enroll: unexpected status %d", status)
	}
	return &out, nil
}

// Heartbeat posts liveness + tool inventory; the reply carries pending
// cancels and jobs the gateway re-queued after a lost lease.
func (c *Client) Heartbeat(ctx context.Context, hb HeartbeatRequest) (*HeartbeatResponse, error) {
	if hb.Tools == nil {
		hb.Tools = map[string]ToolHealth{}
	}
	var out HeartbeatResponse
	status, err := c.do(ctx, http.MethodPost, "/v1/agent/heartbeat", hb, &out, true)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("heartbeat: unexpected status %d", status)
	}
	return &out, nil
}

// NextJob long-polls for up to wait seconds. Returns (nil, nil) when
// nothing arrived (204). The raw payload is returned beside the decoded
// job so callers can keep it verbatim.
func (c *Client) NextJob(ctx context.Context, wait int) (*events.JobDispatch, []byte, error) {
	if wait < 0 {
		wait = 0
	}
	if wait > 30 {
		wait = 30
	}
	path := fmt.Sprintf("/v1/agent/jobs?wait=%d", wait)
	// The server holds the request for up to `wait` seconds; give the
	// transport that plus headroom, but only for this call.
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(wait+20)*time.Second)
	defer cancel()
	var raw json.RawMessage
	status, err := c.do(pollCtx, http.MethodGet, path, nil, &raw, true)
	if err != nil {
		// A deadline on the poll context alone is a quiet poll, not an error.
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil, nil
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("jobs: unexpected status %d", status)
	}
	job, err := events.DecodeJobDispatch(raw)
	if err != nil {
		return nil, raw, err
	}
	return job, raw, nil
}

// PostEvents sends a batch of progress events for a job (202).
func (c *Client) PostEvents(ctx context.Context, jobID string, evs []events.ProgressEvent) error {
	if len(evs) == 0 {
		return nil
	}
	status, err := c.do(ctx, http.MethodPost, "/v1/agent/jobs/"+jobID+"/events",
		map[string]any{"events": evs}, nil, true)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return fmt.Errorf("events: job %s not known to the gateway", jobID)
	}
	if status != http.StatusAccepted {
		return fmt.Errorf("events: unexpected status %d", status)
	}
	return nil
}

// Complete posts a completion event (JobCompletedEvent or
// EventAttackSurface) verbatim; the gateway pins identity fields and
// publishes it on the completions channel.
func (c *Client) Complete(ctx context.Context, jobID string, event any) error {
	status, err := c.do(ctx, http.MethodPost, "/v1/agent/jobs/"+jobID+"/complete", event, nil, true)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return fmt.Errorf("complete: job %s not known to the gateway", jobID)
	}
	if status != http.StatusAccepted {
		return fmt.Errorf("complete: unexpected status %d", status)
	}
	return nil
}

// Fail asks the gateway to publish job_completed(status=failed) for a
// job the agent could not run at all (no runner, payload rejected).
func (c *Client) Fail(ctx context.Context, jobID, message string) error {
	status, err := c.do(ctx, http.MethodPost, "/v1/agent/jobs/"+jobID+"/fail",
		map[string]any{"error_message": message}, nil, true)
	if err != nil {
		return err
	}
	if status != http.StatusAccepted && status != http.StatusNotFound {
		return fmt.Errorf("fail: unexpected status %d", status)
	}
	return nil
}

// do performs one request with retries. It returns the final HTTP
// status for 2xx/4xx answers (the caller interprets them) and an error
// only for 401 with auth (ErrRevoked), context end, or a body that did
// not decode. 5xx and transport errors are retried with capped
// exponential backoff until ctx ends.
func (c *Client) do(ctx context.Context, method, path string, in, out any, auth bool) (int, error) {
	var payload []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, fmt.Errorf("%s %s: marshal body: %w", method, path, err)
		}
		payload = b
	}
	backoff := c.minBackoff
	for attempt := 1; ; attempt++ {
		status, body, err := c.once(ctx, method, path, payload, auth)
		switch {
		case err == nil && status == http.StatusUnauthorized && auth:
			return status, ErrRevoked
		case err == nil && status < 500:
			if out != nil && len(body) > 0 && status != http.StatusNoContent {
				if derr := json.Unmarshal(body, out); derr != nil {
					return status, fmt.Errorf("%s %s: decode response: %w", method, path, derr)
				}
			}
			return status, nil
		}
		// 5xx or transport error: retry unless the context is done.
		if ctx.Err() != nil {
			if err != nil {
				return 0, err
			}
			return status, ctx.Err()
		}
		c.log.Warn().
			Str("method", method).Str("path", path).Int("attempt", attempt).
			Int("status", status).Err(err).Dur("retry_in", backoff).
			Msg("gateway call failed; retrying")
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
	}
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, auth bool) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}
