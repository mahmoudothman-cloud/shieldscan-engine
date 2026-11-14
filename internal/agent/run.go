package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/recon"
	"github.com/odyssey/shieldscan-engine/internal/worker"
)

// DefaultHeartbeatInterval is the design's 30 s (§5 lifecycle).
const DefaultHeartbeatInterval = 30 * time.Second

// RunConfig is everything `run` needs. Client and Registry are
// injectable for tests; nil means build them from State / the PATH.
type RunConfig struct {
	State    *State
	Version  string
	Log      zerolog.Logger
	Client   *Client
	Registry *worker.Registry
	// Missing is the list BuildRegistry returned; logged at start.
	Missing []string

	HeartbeatInterval time.Duration
	PollWait          int // seconds, ≤ 30
	// DrainGrace bounds how long Run waits for an in-flight job after
	// ctx is canceled before returning anyway.
	DrainGrace time.Duration
}

// Run is the long-running mode: a heartbeat loop and a job loop, one
// job at a time, until ctx ends or the key is revoked (ErrRevoked).
func Run(ctx context.Context, cfg RunConfig) error {
	log := cfg.Log
	if cfg.Client == nil {
		if cfg.State == nil {
			return errors.New("agent.Run: State or Client required")
		}
		cfg.Client = NewClient(cfg.State.APIBase, cfg.State.AgentKey, cfg.Version, log)
	}
	if cfg.Registry == nil {
		cfg.Registry, cfg.Missing = BuildRegistry(log)
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.PollWait <= 0 {
		cfg.PollWait = 25
	}
	if cfg.DrainGrace <= 0 {
		cfg.DrainGrace = 60 * time.Second
	}

	r := &runner{cfg: cfg, client: cfg.Client, log: log, hub: newCancelHub(), claims: newLocalClaims()}
	r.processor = worker.NewProcessor(worker.ProcessorDeps{
		Registry:         cfg.Registry,
		IdempotencyClaim: r.claims,
		ProgressPublisherFn: func(string) worker.ProgressPublisher {
			return r.currentProgress()
		},
		CancelSubscriberFn: func(ctx context.Context, scanID string) (worker.CancelSubscriber, error) {
			return r.hub.Subscribe(ctx, scanID)
		},
		CompletionsPublisher: r, // Publish → current job's completions publisher
		PublishMarker:        noopMarker{},
		Logger:               log,
		ReconProgressPubFn: func(string) recon.ProgressPublisher {
			return r.currentProgress()
		},
		ReconCompletionsPub: r,
	})

	log.Info().
		Strs("engines", cfg.Registry.Engines()).
		Strs("missing", cfg.Missing).
		Str("api", cfg.Client.Base()).
		Msg("agent starting")

	// ADR-021 Rule 3: one ctx for both loops, derived here; a revoked
	// key cancels it from the heartbeat side.
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.heartbeatLoop(runCtx, cancel) }()
	go func() { defer wg.Done(); r.jobLoop(runCtx, cancel) }()

	<-runCtx.Done()
	cause := context.Cause(runCtx)

	// Drain: the loops observe runCtx and return; an in-flight job gets
	// DrainGrace to reach a terminal event (shutdown-cancel is one).
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(cfg.DrainGrace):
		log.Error().Dur("grace", cfg.DrainGrace).Msg("drain timeout exceeded; exiting with a job in flight")
	}

	if errors.Is(cause, ErrRevoked) {
		return ErrRevoked
	}
	return nil
}

type runner struct {
	cfg       RunConfig
	client    *Client
	log       zerolog.Logger
	hub       *cancelHub
	claims    *localClaims
	processor *worker.Processor

	mu       sync.Mutex
	progress *progressPublisher
	jobID    string
}

func (r *runner) currentProgress() *progressPublisher {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.progress
}

// Publish / PublishAttackSurface make runner the completions publisher
// for whichever job is current. One job at a time keeps this exact.
func (r *runner) Publish(ctx context.Context, ev events.JobCompletedEvent) error {
	return (&completionsPublisher{client: r.client, jobID: r.current()}).Publish(ctx, ev)
}

func (r *runner) PublishAttackSurface(ctx context.Context, ev events.EventAttackSurface) error {
	return (&completionsPublisher{client: r.client, jobID: r.current()}).PublishAttackSurface(ctx, ev)
}

func (r *runner) current() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jobID
}

func (r *runner) hostInfo() HostInfo {
	host, _ := os.Hostname()
	return HostInfo{Version: r.cfg.Version, Hostname: host, Platform: runtime.GOOS + "/" + runtime.GOARCH}
}

// heartbeatLoop: every interval, post inventory + liveness; fan out
// pending cancels; a revoked key ends the run.
func (r *runner) heartbeatLoop(ctx context.Context, cancel context.CancelCauseFunc) {
	ticker := time.NewTicker(r.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		resp, err := r.client.Heartbeat(ctx, HeartbeatRequest{HostInfo: r.hostInfo(), Tools: Inventory(ctx)})
		switch {
		case errors.Is(err, ErrRevoked):
			r.log.Error().Msg("agent key rejected by the API; this agent was revoked — exiting")
			cancel(ErrRevoked)
			return
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			r.log.Warn().Err(err).Msg("heartbeat failed")
		default:
			if len(resp.CancelScanIDs) > 0 {
				r.log.Info().Strs("scan_ids", resp.CancelScanIDs).Msg("cancel requested")
				r.hub.Deliver(resp.CancelScanIDs)
			}
			if len(resp.RequeuedJobIDs) > 0 {
				r.log.Warn().Strs("job_ids", resp.RequeuedJobIDs).Msg("gateway re-queued jobs whose lease expired")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// jobLoop: long-poll, run, repeat.
func (r *runner) jobLoop(ctx context.Context, cancel context.CancelCauseFunc) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, raw, err := r.client.NextJob(ctx, r.cfg.PollWait)
		switch {
		case errors.Is(err, ErrRevoked):
			cancel(ErrRevoked)
			return
		case err != nil && raw != nil:
			// Decoded badly: a wire-shape drift. Fail it loud so the scan
			// does not hang, then keep polling.
			r.log.Error().Err(err).Msg("job payload did not decode; failing it")
			if id := jobIDFromRaw(raw); id != "" {
				_ = r.client.Fail(ctx, id, "agent could not decode job payload: "+err.Error())
			}
			continue
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			r.log.Warn().Err(err).Msg("poll failed")
			continue
		case job == nil:
			continue
		}
		r.runJob(ctx, job)
	}
}

func (r *runner) runJob(ctx context.Context, job *events.JobDispatch) {
	start := time.Now()
	log := r.log.With().Str("job_id", job.ID).Str("scan_id", job.ScanID).Str("engine", job.Engine).Logger()
	log.Info().Str("target", job.Target.URL).Msg("job received")

	jobCtx, cancelJob := context.WithCancel(ctx)
	pub := newProgressPublisher(jobCtx, r.client, job.ID, job.ScanID, log)
	r.mu.Lock()
	r.progress, r.jobID = pub, job.ID
	r.mu.Unlock()

	err := r.processor.Process(jobCtx, job)
	cancelJob()
	// The terminal progress event must still go out after the job ctx
	// is gone; use the run ctx (shutdown keeps it alive for the drain).
	pub.Close(ctx)
	r.mu.Lock()
	r.progress, r.jobID = nil, ""
	r.mu.Unlock()

	switch {
	case err == nil:
		log.Info().Dur("took", time.Since(start)).Msg("job done")
	case errors.Is(err, worker.ErrJobNotTerminal):
		log.Error().Err(err).Msg("job ended without a terminal event; the gateway's lease sweep will re-queue or fail it")
	default:
		log.Warn().Err(err).Dur("took", time.Since(start)).Msg("job failed (reported)")
	}
}

func jobIDFromRaw(raw []byte) string {
	var probe struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return probe.ID
}

// Enroll performs the one-time token exchange and writes the state file.
func Enroll(ctx context.Context, apiBase, token, stateDir, version string, log zerolog.Logger) (*State, error) {
	host, _ := os.Hostname()
	client := NewClient(apiBase, "", version, log)
	resp, err := client.Enroll(ctx, token, HostInfo{
		Version: version, Hostname: host, Platform: runtime.GOOS + "/" + runtime.GOARCH,
	})
	if err != nil {
		return nil, err
	}
	st := State{
		APIBase: client.Base(), AgentID: resp.AgentID, OrganizationID: resp.OrganizationID,
		Name: resp.Name, AgentKey: resp.AgentKey,
	}
	if err := SaveState(stateDir, st); err != nil {
		return nil, fmt.Errorf("enrolled, but could not save the agent key: %w", err)
	}
	return &st, nil
}
