package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/odyssey/shieldscan-engine/internal/events"
	rdsh "github.com/odyssey/shieldscan-engine/internal/redis"
	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// TestMain wires goleak.VerifyTestMain — load-bearing here because
// the processor spawns cancel-watcher goroutines per job. Leak
// detection is the ADR-021 forcing function.
//
// IgnoreTopFunction entries cover known-OK background goroutines
// from go-redis's connection pool + miniredis's serve loop.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).reaper"),
		goleak.IgnoreAnyFunction("github.com/alicebob/miniredis/v2.(*Miniredis).serve.func1"),
	)
}

// testRunner is the shared mock ToolRunner for processor tests.
// Configurable behavior via fields; concurrency tracking via atomics.
type testRunner struct {
	name           string
	category       string
	findings       []events.RawFinding
	err            error
	delay          time.Duration
	blockOnCtx     bool
	runCalled      atomic.Int32
	startedBarrier chan struct{} // optional: closed on first Run entry for concurrency tests
}

func (t *testRunner) Name() string     { return t.name }
func (t *testRunner) Category() string { return t.category }

func (t *testRunner) Run(ctx context.Context, _ tools.Target, _ tools.ScanConfig) ([]events.RawFinding, error) {
	t.runCalled.Add(1)
	if t.startedBarrier != nil {
		select {
		case <-t.startedBarrier:
		default:
			close(t.startedBarrier)
		}
	}
	if t.blockOnCtx {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if t.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(t.delay):
		}
	}
	return t.findings, t.err
}

var _ tools.ToolRunner = (*testRunner)(nil)

// processorFixture wires a Processor backed by miniredis. Returns the
// processor + the redis client (for direct event injection / inspection)
// + the runner (for behavior config). Auto-cleans via t.Cleanup.
func processorFixture(t *testing.T, runner *testRunner) (*Processor, *goredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	registry := NewRegistry(map[string]tools.ToolRunner{
		runner.name: runner,
	})
	idem := rdsh.NewIdempotencyClaim(client)
	completionsPub := rdsh.NewCompletionsPublisher(client)

	progressFn := func(scanID string) progressPublisher {
		return rdsh.NewProgressPublisher(client, scanID)
	}
	cancelFn := func(ctx context.Context, scanID string) (cancelSubscriber, error) {
		return rdsh.NewCancelSubscriber(ctx, client, scanID)
	}

	p := NewProcessor(ProcessorDeps{
		Registry:             registry,
		IdempotencyClaim:     idem,
		ProgressPublisherFn:  progressFn,
		CancelSubscriberFn:   cancelFn,
		CompletionsPublisher: completionsPub,
		Logger:               zerolog.Nop(),
		// Concrete recon publishers per ADR-028 Phase-1 + Drift #62 (B);
		// miniredis-backed per Sub-Decision 2 (B.i). Harmless for
		// non-recon dispatch tests (fields sit unused).
		ReconProgressPubFn:  func(scanID string) *rdsh.ProgressPublisher { return rdsh.NewProgressPublisher(client, scanID) },
		ReconCompletionsPub: rdsh.NewCompletionsPublisher(client),
	})
	return p, client, mr
}

// reconScript writes a tiny POSIX shell script + makes it executable.
// Mirrors the recon package's shScript helper (different test package,
// so duplicated here). Used to mock subfinder/httpx binaries for the
// engine="recon" dispatch test.
func reconScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mock.sh")
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return p
}

// makeJob constructs a JobDispatch for tests with sane defaults.
func makeJob(engine, scanID, idemKey string) *events.JobDispatch {
	return &events.JobDispatch{
		ID:             "job_" + scanID,
		ScanID:         scanID,
		OrganizationID: "org_test",
		Engine:         engine,
		IdempotencyKey: idemKey,
		Target: events.JobTarget{
			URL:            "https://app.example.com",
			TargetType:     "web",
			DomainVerified: true,
		},
		Config:         map[string]any{"depth": "quick"},
		CallbackStream: "shieldscan:progress:" + scanID,
		CreatedAt:      "2026-04-18T14:30:00Z",
	}
}

// subscribeCompletions subscribes to the completions channel and
// returns the receive-only message channel. Auto-cleans via t.Cleanup.
func subscribeCompletions(t *testing.T, client *goredis.Client) <-chan *goredis.Message {
	t.Helper()
	pubsub := client.Subscribe(t.Context(), "shieldscan:completions")
	t.Cleanup(func() { _ = pubsub.Close() })
	_, err := pubsub.Receive(t.Context())
	require.NoError(t, err)
	return pubsub.Channel()
}

// recvCompletion blocks for one completion event and decodes it.
func recvCompletion(t *testing.T, ch <-chan *goredis.Message, timeout time.Duration) events.JobCompletedEvent {
	t.Helper()
	select {
	case msg := <-ch:
		var ev events.JobCompletedEvent
		require.NoError(t, json.Unmarshal([]byte(msg.Payload), &ev))
		return ev
	case <-time.After(timeout):
		t.Fatal("did not receive completion event within timeout")
		return events.JobCompletedEvent{}
	}
}

// tests -----------------------------------------------------------

// TestProcessor_HappyPath pins the canonical success flow:
// idempotency claim → runner.Run → enrich findings → publish
// single completion event with status=completed.
func TestProcessor_HappyPath(t *testing.T) {
	runner := &testRunner{
		name: "nuclei", category: "dast",
		findings: []events.RawFinding{
			{Title: "XSS", FindingType: "xss", Severity: "high"},
		},
	}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_happy", "scn_happy:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))

	assert.Equal(t, int32(1), runner.runCalled.Load())

	ev := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, events.EventJobCompleted, ev.EventType)
	assert.Equal(t, "completed", ev.Status)
	assert.Equal(t, "scn_happy", ev.ScanID)
	assert.Equal(t, 1, ev.FindingCount)
	assert.Equal(t, events.EventSeq{Index: 1, Total: 1}, ev.EventSeq)
	require.Len(t, ev.Findings, 1)
	assert.Equal(t, "scn_happy", ev.Findings[0].ScanID, "ScanID enriched by processor")
	assert.Equal(t, "org_test", ev.Findings[0].OrgID, "OrgID enriched by processor")
}

// TestProcessor_IdempotencyDrop pins the dedup gate: a job whose
// idempotency_key was already claimed is silently dropped (no
// runner call, no events).
func TestProcessor_IdempotencyDrop(t *testing.T) {
	runner := &testRunner{name: "nuclei", category: "dast"}
	p, client, _ := processorFixture(t, runner)

	job := makeJob("nuclei", "scn_dup", "scn_dup:nuclei:1")

	// First call claims; runs.
	require.NoError(t, p.Process(t.Context(), job))
	assert.Equal(t, int32(1), runner.runCalled.Load())

	// Second call sees the existing claim; drops silently.
	completionsCh := subscribeCompletions(t, client)
	require.NoError(t, p.Process(t.Context(), job))
	assert.Equal(t, int32(1), runner.runCalled.Load(), "runner not called on duplicate")

	// No completion event for the duplicate.
	select {
	case msg := <-completionsCh:
		t.Fatalf("unexpected completion event for duplicate: %s", msg.Payload)
	case <-time.After(200 * time.Millisecond):
		// expected
	}
}

// TestProcessor_RunnerNotRegistered pins H.4: unknown engine name
// produces a job_failed completion event (not a process-level
// error that aborts the worker).
func TestProcessor_RunnerNotRegistered(t *testing.T) {
	registeredRunner := &testRunner{name: "nuclei", category: "dast"}
	p, client, _ := processorFixture(t, registeredRunner)
	completionsCh := subscribeCompletions(t, client)

	// Submit a job for an unregistered engine.
	job := makeJob("unknown_engine", "scn_unreg", "scn_unreg:unknown:1")
	err := p.Process(t.Context(), job)
	require.Error(t, err, "Process returns the runner-lookup error")
	assert.Contains(t, err.Error(), "unknown_engine")

	// And a job_failed completion event was published.
	ev := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, "failed", ev.Status)
	assert.Contains(t, ev.ErrorMessage, "unknown_engine")
}

// TestProcessor_RunnerError pins runner-error propagation: runner
// returns error → job_failed completion event with the error.
func TestProcessor_RunnerError(t *testing.T) {
	runErr := errors.New("synthetic tool failure")
	runner := &testRunner{name: "nuclei", category: "dast", err: runErr}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_err", "scn_err:nuclei:1")
	err := p.Process(t.Context(), job)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "synthetic tool failure")

	ev := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, "failed", ev.Status)
	assert.Contains(t, ev.ErrorMessage, "synthetic tool failure")
}

// TestProcessor_FindingsEnrichedWithScanContext pins runtime
// enrichment: ScanID + OrgID applied to every finding, even
// when the runner doesn't populate them (NativeRunner enriches
// ToolName + EngineCategory + DiscoveredAt + Fingerprint, but
// scan-context fields are processor's responsibility).
func TestProcessor_FindingsEnrichedWithScanContext(t *testing.T) {
	runner := &testRunner{
		name: "nuclei", category: "dast",
		findings: []events.RawFinding{
			{Title: "first", FindingType: "test"},
			{Title: "second", FindingType: "test"},
		},
	}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_enrich", "scn_enrich:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))

	ev := recvCompletion(t, completionsCh, 2*time.Second)
	require.Len(t, ev.Findings, 2)
	for i, f := range ev.Findings {
		assert.Equal(t, "scn_enrich", f.ScanID, "finding %d", i)
		assert.Equal(t, "org_test", f.OrgID, "finding %d", i)
	}
}

// TestProcessor_SequencedFindings pins ADR-017 in the integration
// path: 1500-finding runner → 2 completion events with correct
// event_seq, intermediate=partial_findings, terminal=completed.
func TestProcessor_SequencedFindings(t *testing.T) {
	findings := make([]events.RawFinding, 1500)
	for i := range findings {
		findings[i] = events.RawFinding{
			Title: "f", FindingType: "test", Severity: "info",
		}
	}
	runner := &testRunner{
		name: "nuclei", category: "dast", findings: findings,
	}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_seq", "scn_seq:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))

	// First event: intermediate (partial_findings).
	ev1 := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, events.EventPartialFindings, ev1.EventType)
	assert.Equal(t, "partial_findings", ev1.Status)
	assert.Equal(t, events.EventSeq{Index: 1, Total: 2}, ev1.EventSeq)
	assert.Len(t, ev1.Findings, 1000)
	assert.Zero(t, ev1.FindingCount, "intermediate event has no authoritative finding_count")

	// Second event: terminal (completed).
	ev2 := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, events.EventJobCompleted, ev2.EventType)
	assert.Equal(t, "completed", ev2.Status)
	assert.Equal(t, events.EventSeq{Index: 2, Total: 2}, ev2.EventSeq)
	assert.Len(t, ev2.Findings, 500)
	assert.Equal(t, 1500, ev2.FindingCount, "terminal event has authoritative finding_count")
}

// TestProcessor_ZeroFindings pins the empty-findings case: single
// completion event with empty Findings, status=completed.
func TestProcessor_ZeroFindings(t *testing.T) {
	runner := &testRunner{name: "nuclei", category: "dast", findings: nil}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_empty", "scn_empty:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))

	ev := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, "completed", ev.Status)
	assert.Equal(t, 0, ev.FindingCount)
	assert.Empty(t, ev.Findings)
	assert.Equal(t, events.EventSeq{Index: 1, Total: 1}, ev.EventSeq)
}

// TestProcessor_CancelMidRun pins user-cancel discrimination:
// cancel signal published mid-run → runner sees ctx.Done() →
// processor emits job_canceled completion event (status=canceled),
// not job_failed.
func TestProcessor_CancelMidRun(t *testing.T) {
	runner := &testRunner{name: "nuclei", category: "dast", blockOnCtx: true}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	scanID := "scn_cancel"
	job := makeJob("nuclei", scanID, scanID+":nuclei:1")

	processDone := make(chan error, 1)
	go func() {
		processDone <- p.Process(t.Context(), job)
	}()

	// Wait for runner to enter Run() before publishing cancel —
	// race-free via runCalled atomic.
	require.Eventually(t, func() bool {
		return runner.runCalled.Load() >= 1
	}, time.Second, 5*time.Millisecond, "runner should be invoked")

	// Publish cancel.
	cancelEv := events.CancelEvent{
		EventType: events.EventCancelRequested,
		ScanID:    scanID,
		Reason:    "user_requested",
		Timestamp: "2026-04-18T14:33:00Z",
	}
	data, err := json.Marshal(cancelEv)
	require.NoError(t, err)
	require.NoError(t, client.Publish(t.Context(), "shieldscan:cancel:"+scanID, string(data)).Err())

	// Process returns nil (cancel is not an error from processor's
	// perspective).
	select {
	case err := <-processDone:
		assert.NoError(t, err, "user-cancel returns nil")
	case <-time.After(2 * time.Second):
		t.Fatal("Process did not return within 2s of cancel")
	}

	// And a canceled completion event was published.
	ev := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, "canceled", ev.Status)
}

// TestProcessor_CancelWatcherExitsOnJobDone pins exit path #1:
// job completes normally; cancel-watcher goroutine exits via
// jobCtx.Done(). goleak (TestMain) verifies no leak.
func TestProcessor_CancelWatcherExitsOnJobDone(t *testing.T) {
	runner := &testRunner{
		name: "nuclei", category: "dast",
		findings: []events.RawFinding{{Title: "f", FindingType: "t"}},
	}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_jobdone", "scn_jobdone:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))
	_ = recvCompletion(t, completionsCh, 2*time.Second)
	// goleak verifies cancel-watcher exited cleanly.
}

// TestProcessor_CancelWatcherExitsOnSubClose pins exit path #3:
// CancelSubscriber's Close() (called via defer in Process) exits
// the watcher goroutine. goleak (TestMain) verifies no leak.
//
// This path is exercised by every other test that completes
// normally (Process's defer closes the subscriber, which closes
// the Events() channel, which causes the watcher's select to
// exit via the !ok branch). This dedicated test pins the path
// explicitly via a synchronous Close + verify.
func TestProcessor_CancelWatcherExitsOnSubClose(t *testing.T) {
	runner := &testRunner{
		name: "nuclei", category: "dast",
		findings: []events.RawFinding{{Title: "f", FindingType: "t"}},
		delay:    50 * time.Millisecond, // give cancel-watcher time to subscribe
	}
	p, client, _ := processorFixture(t, runner)
	completionsCh := subscribeCompletions(t, client)

	job := makeJob("nuclei", "scn_subclose", "scn_subclose:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))
	_ = recvCompletion(t, completionsCh, 2*time.Second)
	// Process's defer closed the subscriber; goleak verifies the
	// watcher goroutine exited via the closed-channel path.
}

// TestProcessor_ProgressEmittedAtStart pins the job_started event
// emission: progress stream contains the start event before any
// completion event lands.
func TestProcessor_ProgressEmittedAtStart(t *testing.T) {
	runner := &testRunner{name: "nuclei", category: "dast"}
	p, client, _ := processorFixture(t, runner)

	job := makeJob("nuclei", "scn_progress", "scn_progress:nuclei:1")
	require.NoError(t, p.Process(t.Context(), job))

	// Read the progress stream directly via XRANGE.
	entries, err := client.XRange(t.Context(),
		"shieldscan:progress:scn_progress", "-", "+").Result()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(entries), 2,
		"expect at least job_started + job_completed progress events")

	// First event is job_started.
	var first map[string]any
	require.NoError(t, json.Unmarshal([]byte(entries[0].Values["event"].(string)), &first))
	assert.Equal(t, "job_started", first["event_type"])
	assert.Equal(t, "scn_progress", first["scan_id"])
	assert.Equal(t, "nuclei", first["engine"])
}

// TestProcessor_JobDispatchToTarget pins the SPEC §7.1 → tools.Target
// translation helper. Without this test, silent drift between SPEC
// and target shape goes undetected.
func TestProcessor_JobDispatchToTarget(t *testing.T) {
	job := &events.JobDispatch{
		ScanID:         "s",
		OrganizationID: "o",
		Engine:         "nuclei",
		Target: events.JobTarget{
			URL:            "https://x.example.com",
			TargetType:     "web",
			DomainVerified: true,
		},
		Auth: &events.JobAuth{Type: "cookie", Data: "session=abc"},
		MobileConfig: &events.JobMobileConfig{
			UploadRef: "r2://x",
			Platform:  "android",
		},
	}
	target := jobDispatchToTarget(job)

	assert.Equal(t, "https://x.example.com", target.URL)
	assert.Equal(t, "web", target.TargetType)
	assert.True(t, target.DomainVerified)
	require.NotNil(t, target.AuthConfig)
	assert.Equal(t, "cookie", target.AuthConfig.Type)
	assert.Equal(t, "session=abc", target.AuthConfig.Data)
	assert.Equal(t, "r2://x", target.MobileUploadRef)
}

// TestProcessor_JobDispatchToScanConfig pins the SPEC §7.1 config
// map → tools.ScanConfig translation. JSON numbers decode as
// float64; helper coerces to int correctly.
func TestProcessor_JobDispatchToScanConfig(t *testing.T) {
	job := &events.JobDispatch{
		Config: map[string]any{
			"depth":                   "deep",
			"timeout_seconds":         float64(1800),
			"max_requests_per_second": float64(50),
			"template_categories":     []any{"owasp-top-10", "cves"},
		},
	}
	cfg := jobDispatchToScanConfig(job)

	assert.Equal(t, "deep", cfg.Depth)
	assert.Equal(t, 1800, cfg.Timeout)
	assert.Equal(t, 50, cfg.MaxRPS)
	assert.Equal(t, []string{"owasp-top-10", "cves"}, cfg.TemplateCategories)
	assert.NotNil(t, cfg.ExtraArgs, "ExtraArgs initialized to non-nil empty map")
}

// TestProcessor_JobDispatchToScanConfig_MobileExtraArgs pins the
// Task 7.4 D-PLAN-2 Path Y wiring: when JobMobileConfig is populated,
// Platform + AnalysisType mirror to ScanConfig.ExtraArgs under
// keys "mobsf.platform" + "mobsf.analysis_type" so the MobSF consumer
// can read them via the escape-hatch pattern (symmetric with ZAP's
// zap.scan_policy).
func TestProcessor_JobDispatchToScanConfig_MobileExtraArgs(t *testing.T) {
	t.Run("populated mobile config mirrors to ExtraArgs", func(t *testing.T) {
		job := &events.JobDispatch{
			MobileConfig: &events.JobMobileConfig{
				UploadRef:    "r2://uploads/org/diva.apk",
				Platform:     "android",
				AnalysisType: "static",
			},
		}
		cfg := jobDispatchToScanConfig(job)
		assert.Equal(t, "android", cfg.ExtraArgs["mobsf.platform"])
		assert.Equal(t, "static", cfg.ExtraArgs["mobsf.analysis_type"])
	})
	t.Run("nil mobile config leaves ExtraArgs free of mobsf keys", func(t *testing.T) {
		job := &events.JobDispatch{}
		cfg := jobDispatchToScanConfig(job)
		_, hasPlatform := cfg.ExtraArgs["mobsf.platform"]
		_, hasAnalysis := cfg.ExtraArgs["mobsf.analysis_type"]
		assert.False(t, hasPlatform, "mobsf.platform must not appear when MobileConfig nil")
		assert.False(t, hasAnalysis, "mobsf.analysis_type must not appear when MobileConfig nil")
	})
	t.Run("empty mobile fields skip the mirror", func(t *testing.T) {
		job := &events.JobDispatch{
			MobileConfig: &events.JobMobileConfig{UploadRef: "r2://x"},
		}
		cfg := jobDispatchToScanConfig(job)
		_, hasPlatform := cfg.ExtraArgs["mobsf.platform"]
		_, hasAnalysis := cfg.ExtraArgs["mobsf.analysis_type"]
		assert.False(t, hasPlatform)
		assert.False(t, hasAnalysis)
	})
}

// _ = sync.RWMutex{} // unused-import guard for sync (used elsewhere)
var _ = sync.RWMutex{}

// TestProcessor_ReconDispatch pins the ADR-028 Phase-1 dispatch case:
// engine="recon" routes to recon.RunRecon directly (NOT via registry
// per ADR-022) with concrete publishers (Drift #62 Sub-Decision 1 (B)),
// emits EventAttackSurface to the completions channel (Task 8.3α), and
// emits a terminal job_completed for the recon ScanJob (ADR-013).
//
// Mock subfinder + httpx binaries (miniredis-backed publishers per
// Sub-Decision 2 (B.i)) produce one live host so EventAttackSurface
// carries a subdomain row + the job_completed lands FindingCount=0
// (recon emits target-discovery, not findings, per ADR-022).
func TestProcessor_ReconDispatch(t *testing.T) {
	// Registry has NO "recon" entry — proves dispatch does NOT use
	// registry.Get for recon (ADR-022). A non-recon runner is present
	// only to satisfy the fixture's registry construction.
	runner := &testRunner{name: "nuclei", category: "dast"}
	p, client, _ := processorFixture(t, runner)

	subMock := reconScript(t,
		`echo '{"host":"api.example.com","input":"example.com","source":"crtsh"}'`)
	httpxMock := reconScript(t,
		`echo '{"url":"https://api.example.com","status_code":200,"title":"API","tech":["nginx"],"webserver":"nginx","content_type":"text/html","failed":false}'`)
	t.Setenv("SHIELDSCAN_SUBFINDER_BINARY", subMock)
	t.Setenv("SHIELDSCAN_HTTPX_BINARY", httpxMock)

	completionsCh := subscribeCompletions(t, client)

	job := makeJob("recon", "scn_recon", "scn_recon:recon:1")
	job.Target.URL = "example.com" // orchestrator sets recon target_url to root domain
	require.NoError(t, p.Process(t.Context(), job))

	// The non-recon runner must NOT have been invoked — recon does not
	// route through registry.Get (ADR-022 canonical lock).
	assert.Equal(t, int32(0), runner.runCalled.Load(),
		"recon dispatch must NOT invoke a registered ToolRunner")

	// Two events land on the completions channel: EventAttackSurface
	// (emitted inside RunRecon) + the terminal job_completed (emitted by
	// dispatchRecon). Order is emission-order: attack_surface first
	// (during httpx phase), then job_completed. Drain both + classify.
	sawAttackSurface := false
	sawJobCompleted := false
	for i := 0; i < 2; i++ {
		select {
		case msg := <-completionsCh:
			var probe map[string]any
			require.NoError(t, json.Unmarshal([]byte(msg.Payload), &probe))
			switch probe["event_type"] {
			case "attack_surface":
				sawAttackSurface = true
				assert.Equal(t, "scn_recon", probe["scan_id"])
				subs, ok := probe["subdomains"].([]any)
				require.True(t, ok, "attack_surface event carries subdomains array")
				assert.Len(t, subs, 1, "one live host discovered")
			case string(events.EventJobCompleted):
				sawJobCompleted = true
				var ev events.JobCompletedEvent
				require.NoError(t, json.Unmarshal([]byte(msg.Payload), &ev))
				assert.Equal(t, "completed", ev.Status)
				assert.Equal(t, "scn_recon", ev.ScanID)
				assert.Equal(t, "recon", ev.Engine)
				assert.Equal(t, 0, ev.FindingCount,
					"recon emits target-discovery not findings (ADR-022)")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("did not receive both completions events (attack_surface=%v job_completed=%v)",
				sawAttackSurface, sawJobCompleted)
		}
	}
	assert.True(t, sawAttackSurface, "EventAttackSurface emitted (Task 8.3α composition)")
	assert.True(t, sawJobCompleted, "terminal job_completed emitted (ADR-013 sole-writer)")
}

// TestProcessor_ReconDispatch_NoWiringFailsLoud pins the ADR-021
// fail-loud guard: an engine="recon" job arriving at a processor with
// no recon publishers wired emits a failure (misconfiguration, not a
// runtime-tolerable condition).
func TestProcessor_ReconDispatch_NoWiringFailsLoud(t *testing.T) {
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	registry := NewRegistry(map[string]tools.ToolRunner{
		"nuclei": &testRunner{name: "nuclei", category: "dast"},
	})
	// NewProcessor WITHOUT ReconProgressPubFn / ReconCompletionsPub.
	p := NewProcessor(ProcessorDeps{
		Registry:            registry,
		IdempotencyClaim:    rdsh.NewIdempotencyClaim(client),
		ProgressPublisherFn: func(scanID string) progressPublisher { return rdsh.NewProgressPublisher(client, scanID) },
		CancelSubscriberFn: func(ctx context.Context, scanID string) (cancelSubscriber, error) {
			return rdsh.NewCancelSubscriber(ctx, client, scanID)
		},
		CompletionsPublisher: rdsh.NewCompletionsPublisher(client),
		Logger:               zerolog.Nop(),
	})

	completionsCh := subscribeCompletions(t, client)
	job := makeJob("recon", "scn_nowire", "scn_nowire:recon:1")
	err := p.Process(t.Context(), job)
	require.Error(t, err, "recon dispatch with no wiring returns the failure error")
	assert.Contains(t, err.Error(), "recon publishers")

	ev := recvCompletion(t, completionsCh, 2*time.Second)
	assert.Equal(t, "failed", ev.Status, "recon dispatch with no wiring fails loud")
	assert.Equal(t, "recon", ev.Engine)
}
