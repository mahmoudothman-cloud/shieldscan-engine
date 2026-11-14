package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/worker"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// net/http keeps idle keep-alive connections in the background;
		// httptest.Server.Close drains them but the goroutine can outlive
		// the test by a tick.
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}

// ---------------------------------------------------------------- fake gateway

// gateway is an httptest stand-in for /v1/agent/*. It records what the
// agent sent and hands out one queued job.
type gateway struct {
	t   *testing.T
	key string

	mu         sync.Mutex
	queue      [][]byte
	heartbeats []HeartbeatRequest
	cancels    []string // returned on every heartbeat
	events     map[string][]events.ProgressEvent
	completes  map[string][]map[string]any
	fails      map[string][]string
	revoked    bool
	flaky      int // first N calls answer 500

	completed chan string
	srv       *httptest.Server
}

func newGateway(t *testing.T) *gateway {
	g := &gateway{
		t: t, key: "ss_agent_testkey",
		events: map[string][]events.ProgressEvent{}, completes: map[string][]map[string]any{},
		fails: map[string][]string{}, completed: make(chan string, 16),
	}
	g.srv = httptest.NewServer(http.HandlerFunc(g.handle))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *gateway) handle(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.flaky > 0 {
		g.flaky--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/agent")
	if path == "/enroll" {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != "ss_enrol_good" {
			http.Error(w, `{"detail":"enrolment_token_invalid"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(EnrolResponse{
			AgentID: "a-1", OrganizationID: "o-1", Name: "dc1", AgentKey: g.key,
		})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+g.key || g.revoked {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case path == "/heartbeat":
		var hb HeartbeatRequest
		require.NoError(g.t, json.NewDecoder(r.Body).Decode(&hb))
		g.heartbeats = append(g.heartbeats, hb)
		_ = json.NewEncoder(w).Encode(HeartbeatResponse{
			AgentID: "a-1", Name: "dc1", CancelScanIDs: g.cancels, RequeuedJobIDs: []string{}, PollWaitS: 25,
		})
	case path == "/jobs" && r.Method == http.MethodGet:
		if len(g.queue) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		payload := g.queue[0]
		g.queue = g.queue[1:]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	case strings.HasSuffix(path, "/events"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/jobs/"), "/events")
		var body struct {
			Events []events.ProgressEvent `json:"events"`
		}
		require.NoError(g.t, json.NewDecoder(r.Body).Decode(&body))
		g.events[id] = append(g.events[id], body.Events...)
		w.WriteHeader(http.StatusAccepted)
	case strings.HasSuffix(path, "/complete"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/jobs/"), "/complete")
		var ev map[string]any
		require.NoError(g.t, json.NewDecoder(r.Body).Decode(&ev))
		g.completes[id] = append(g.completes[id], ev)
		w.WriteHeader(http.StatusAccepted)
		g.completed <- id
	case strings.HasSuffix(path, "/fail"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/jobs/"), "/fail")
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.fails[id] = append(g.fails[id], body["error_message"])
		w.WriteHeader(http.StatusAccepted)
		g.completed <- id
	default:
		http.NotFound(w, r)
	}
}

func (g *gateway) enqueue(job events.JobDispatch) {
	b, err := json.Marshal(job)
	require.NoError(g.t, err)
	g.mu.Lock()
	g.queue = append(g.queue, b)
	g.mu.Unlock()
}

func (g *gateway) client() *Client {
	c := NewClient(g.srv.URL, g.key, "test", zerolog.Nop())
	c.minBackoff, c.maxBackoff = 5*time.Millisecond, 20*time.Millisecond
	return c
}

// ---------------------------------------------------------------- fake tool

type fakeRunner struct {
	name     string
	findings []events.RawFinding
	err      error
	block    bool // wait for ctx cancel
	ran      chan struct{}
}

func (f *fakeRunner) Name() string     { return f.name }
func (f *fakeRunner) Category() string { return "dast" }
func (f *fakeRunner) Run(ctx context.Context, _ tools.Target, _ tools.ScanConfig) ([]events.RawFinding, error) {
	if f.ran != nil {
		close(f.ran)
	}
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.findings, f.err
}

func job(id, engine string) events.JobDispatch {
	return events.JobDispatch{
		ID: id, ScanID: "scan-1", OrganizationID: "o-1", Engine: engine, IdempotencyKey: "scan-1:" + engine + ":1",
		Target:    events.JobTarget{URL: "http://10.0.0.5:8080", TargetType: "web"},
		Config:    map[string]any{"depth": "quick"},
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func runUntil(t *testing.T, g *gateway, reg *worker.Registry, until func(ctx context.Context, cancel context.CancelFunc)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunConfig{
			Client: g.client(), Registry: reg, Version: "test", Log: zerolog.Nop(),
			HeartbeatInterval: 30 * time.Millisecond, PollWait: 0, DrainGrace: 3 * time.Second,
		})
	}()
	until(ctx, cancel)
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

// ---------------------------------------------------------------- tests

func TestRun_JobFlowsThroughTheGatewayInTheWorkersShape(t *testing.T) {
	g := newGateway(t)
	reg := worker.NewRegistry(map[string]tools.ToolRunner{"nuclei": &fakeRunner{
		name: "nuclei",
		findings: []events.RawFinding{{
			Title: "Exposed .git", Severity: "high", FindingType: "misconfig", TargetURL: "http://10.0.0.5:8080/.git/",
		}},
	}})
	g.enqueue(job("job-1", "nuclei"))

	err := runUntil(t, g, reg, func(ctx context.Context, cancel context.CancelFunc) {
		select {
		case <-g.completed:
		case <-ctx.Done():
		}
		// Let the terminal progress event flush, then stop.
		time.Sleep(flushInterval + 200*time.Millisecond)
		cancel()
	})
	require.NoError(t, err)

	g.mu.Lock()
	defer g.mu.Unlock()
	// Heartbeats carried the inventory shape (all seven tools named).
	require.NotEmpty(t, g.heartbeats)
	for _, name := range ToolNames() {
		_, ok := g.heartbeats[0].Tools[name]
		assert.True(t, ok, "heartbeat inventory names %s", name)
	}
	assert.Equal(t, "test", g.heartbeats[0].Version)

	// Progress: job_started first, job_completed last, scan_id + timestamp injected.
	evs := g.events["job-1"]
	require.GreaterOrEqual(t, len(evs), 2, "progress events: %v", evs)
	assert.Equal(t, "job_started", evs[0]["event_type"])
	assert.Equal(t, "scan-1", evs[0]["scan_id"])
	assert.NotEmpty(t, evs[0]["timestamp"])
	assert.Equal(t, "job_completed", evs[len(evs)-1]["event_type"])

	// Completion: a valid JobCompletedEvent with the finding, enriched.
	comps := g.completes["job-1"]
	require.Len(t, comps, 1)
	raw, _ := json.Marshal(comps[0])
	ev, derr := events.DecodeJobCompletedEvent(raw)
	require.NoError(t, derr)
	require.NoError(t, ev.Validate())
	assert.Equal(t, "completed", ev.Status)
	assert.Equal(t, 1, ev.FindingCount)
	require.Len(t, ev.Findings, 1)
	// The processor stamps scan/org on every finding (tool name and
	// fingerprint come from NativeRunner, which the fake stands in for).
	assert.Equal(t, "scan-1", ev.Findings[0].ScanID)
	assert.Equal(t, "o-1", ev.Findings[0].OrgID)
	assert.Equal(t, events.EventSeq{Index: 1, Total: 1}, ev.EventSeq)
}

func TestRun_UnknownEngineFailsTheJobVisibly(t *testing.T) {
	g := newGateway(t)
	reg := worker.NewRegistry(map[string]tools.ToolRunner{})
	g.enqueue(job("job-2", "zap"))

	err := runUntil(t, g, reg, func(ctx context.Context, cancel context.CancelFunc) {
		select {
		case <-g.completed:
		case <-ctx.Done():
		}
		cancel()
	})
	require.NoError(t, err)
	g.mu.Lock()
	defer g.mu.Unlock()
	require.Len(t, g.completes["job-2"], 1)
	assert.Equal(t, "failed", g.completes["job-2"][0]["status"])
	assert.Contains(t, g.completes["job-2"][0]["error_message"], "no runner registered")
}

func TestRun_CancelFromHeartbeatStopsTheTool(t *testing.T) {
	g := newGateway(t)
	fr := &fakeRunner{name: "nikto", block: true, ran: make(chan struct{})}
	reg := worker.NewRegistry(map[string]tools.ToolRunner{"nikto": fr})
	g.enqueue(job("job-3", "nikto"))

	err := runUntil(t, g, reg, func(ctx context.Context, cancel context.CancelFunc) {
		select {
		case <-fr.ran:
		case <-ctx.Done():
		}
		g.mu.Lock()
		g.cancels = []string{"scan-1"}
		g.mu.Unlock()
		select {
		case <-g.completed:
		case <-ctx.Done():
		}
		cancel()
	})
	require.NoError(t, err)
	g.mu.Lock()
	defer g.mu.Unlock()
	require.Len(t, g.completes["job-3"], 1)
	assert.Equal(t, "canceled", g.completes["job-3"][0]["status"])
}

func TestRun_DuplicateDeliveryIsDroppedLocally(t *testing.T) {
	g := newGateway(t)
	reg := worker.NewRegistry(map[string]tools.ToolRunner{"nuclei": &fakeRunner{name: "nuclei"}})
	g.enqueue(job("job-4", "nuclei"))
	g.enqueue(job("job-4", "nuclei")) // the gateway's lease re-queue, same idempotency key

	err := runUntil(t, g, reg, func(ctx context.Context, cancel context.CancelFunc) {
		select {
		case <-g.completed:
		case <-ctx.Done():
		}
		time.Sleep(300 * time.Millisecond)
		cancel()
	})
	require.NoError(t, err)
	g.mu.Lock()
	defer g.mu.Unlock()
	assert.Len(t, g.completes["job-4"], 1, "second copy dropped, not completed twice")
}

func TestRun_RevokedKeyEndsTheRun(t *testing.T) {
	g := newGateway(t)
	g.revoked = true
	err := runUntil(t, g, worker.NewRegistry(nil), func(ctx context.Context, cancel context.CancelFunc) {})
	require.ErrorIs(t, err, ErrRevoked)
}

func TestClient_RetriesServerErrorsAndStopsOnContext(t *testing.T) {
	g := newGateway(t)
	g.flaky = 2
	c := g.client()
	resp, err := c.Heartbeat(context.Background(), HeartbeatRequest{})
	require.NoError(t, err, "two 500s then a 200")
	assert.Equal(t, "a-1", resp.AgentID)

	g.mu.Lock()
	g.flaky = 1 << 30
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = c.Heartbeat(ctx, HeartbeatRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "gives up only when the context ends: %v", err)
}

func TestEnroll_WritesStateFileWithMode0600(t *testing.T) {
	g := newGateway(t)
	dir := filepath.Join(t.TempDir(), "state")

	_, err := Enroll(context.Background(), g.srv.URL, "ss_enrol_bad", dir, "test", zerolog.Nop())
	require.ErrorIs(t, err, ErrEnrolmentTokenInvalid)

	st, err := Enroll(context.Background(), g.srv.URL, "ss_enrol_good", dir, "test", zerolog.Nop())
	require.NoError(t, err)
	assert.Equal(t, "a-1", st.AgentID)

	info, err := os.Stat(filepath.Join(dir, "agent.json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	loaded, err := LoadState(dir)
	require.NoError(t, err)
	assert.Equal(t, g.key, loaded.AgentKey)
	assert.Equal(t, g.srv.URL, loaded.APIBase)

	require.NoError(t, RemoveState(dir))
	_, err = LoadState(dir)
	assert.ErrorIs(t, err, ErrNotEnrolled)
}

func TestInventory_ReportsMissingToolsWithoutFailing(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // nothing installed
	for _, s := range toolSpecs {
		t.Setenv(s.EnvVar, "")
	}
	inv := Inventory(context.Background())
	for _, name := range ToolNames() {
		assert.Equal(t, "missing", inv[name].Status, name)
	}
	reg, missing := BuildRegistry(zerolog.Nop())
	assert.Empty(t, reg.Engines())
	assert.ElementsMatch(t, []string{"nuclei", "sslyze", "nikto", "wapiti", "nmap"}, missing)
}

func TestFirstVersionLine(t *testing.T) {
	assert.Equal(t, "Nmap version 7.94SVN ( https://nmap.org )",
		firstVersionLine("Nmap version 7.94SVN ( https://nmap.org )\nPlatform: x86_64"))
	assert.Equal(t, "Current Version: 3.4.0",
		firstVersionLine("\x1b[34m\n   __     _\x1b[0m\n\x1b[1mCurrent Version: 3.4.0\x1b[0m\n"))
	assert.Equal(t, "", firstVersionLine("no number here"))
	assert.Equal(t, "SSLyze version 6.1.0",
		firstVersionLine("usage: sslyze [-h] [--update_trust_stores]\n  --json_out JSON_FILE\nSSLyze version 6.1.0\n"))
}
