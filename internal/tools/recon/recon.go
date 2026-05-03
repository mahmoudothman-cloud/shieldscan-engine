// Package recon ships the recon-as-pre-scan-helpers implementation
// per ADR-022 (M6.3). Subfinder + httpx are NOT ToolRunners;
// they're helper functions that produce target-discovery data
// (subdomain strings + LiveHost metadata), not events.RawFinding.
//
// M8 (Recon-First Pipeline) imports this package and invokes
// RunRecon as a pre-scan phase before per-target scan jobs are
// dispatched to the standard processor. cmd/worker/run.go (M6.8
// wiring) explicitly does NOT register Subfinder or httpx with
// worker.Registry; an explicit code comment references ADR-022.
//
// First non-tool-runner package under internal/tools/. Sibling to
// internal/tools/jsonx/ (helpers) and the per-tool ToolRunner
// packages (internal/tools/nuclei/, etc.).
//
// Architectural commitments (per ADR-022):
//   - Recon does NOT fit ToolRunner contract (output is
//     target-discovery data, not findings).
//   - Direct exec.CommandContext for subprocess management (NOT
//     NativeRunner) — architectural consistency: NativeRunner
//     enrichment loop is irrelevant when output isn't RawFinding.
//   - Failure-tolerant orchestration: subfinder/httpx failures log
//     WARN + return partial data (never propagate error to caller).
//     M8 makes routing decisions based on whatever recon produced.
package recon

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/redis"
	"github.com/rs/zerolog"
)

// defaultLimit is the defensive cap when caller passes limit=0.
// Matches TOOL-ARCH §8.1 (max 100 subdomains per scan, configurable
// per tier).
const defaultLimit = 100

// ReconResult is the canonical output of RunRecon, consumed by M8
// (Recon-First Pipeline) as the basis of per-target scan job
// dispatch.
type ReconResult struct {
	// Subdomains is the deduplicated list of discovered subdomains
	// (capped at the caller-supplied `limit`). Includes only the
	// hostname strings; source/input metadata from Subfinder is
	// dropped during parse.
	Subdomains []string

	// LiveHosts is the subset of probed subdomains that responded
	// (failed:true records from httpx are excluded). Each host
	// carries 6 metadata fields useful for M8's target-list
	// construction + tool-selection routing.
	LiveHosts []LiveHost
}

// LiveHost extends plan §6.3 literal {URL, StatusCode, Tech} with
// three additional fields (per M6.3 H.NEW.1): Title, Webserver,
// ContentType. The 6-field shape covers M8's likely needs (target
// list construction, liveness signaling, UI display, tool-selection
// hints, fingerprint signals) without forcing a future-iteration
// refactor.
//
// Trigger to extend further: M8 implementation surfaces a need for
// a field currently dropped (e.g., latency, IP for network-policy
// scoping). Extend additively; existing M8 callers remain
// compatible.
type LiveHost struct {
	URL         string   // canonical URL with scheme (from httpx `url` field)
	StatusCode  int      // HTTP status; 0 if missing
	Title       string   // page title; empty if no HTML
	Tech        []string // detected tech stack (e.g., ["nginx", "Node.js"])
	Webserver   string   // server header value
	ContentType string   // content-type header value
}

// RunRecon executes the recon-first pipeline against a single root
// domain. Discovers subdomains via Subfinder, probes liveness via
// httpx, and returns a ReconResult for M8 to use as the basis of
// the per-target scan job dispatch.
//
// Per ADR-022 (M6.3): recon is pre-scan helpers, NOT registered
// with worker.Registry. M8 (Recon-First Pipeline) imports this
// package and invokes RunRecon directly.
//
// publisher MAY be nil (e.g., for tests) — RunRecon's
// publishIfNotNil helper checks before publishing each event.
// Production callers always supply a real *redis.ProgressPublisher.
//
// Failure-tolerant by design (per plan §6.3 literal):
//   - Subfinder failure → log WARN + return empty ReconResult, nil
//   - httpx failure → log WARN + return ReconResult{Subdomains: subs}, nil
//   - Errors are NEVER propagated to the caller; partial data is
//     the useful state for M8's routing decisions.
//
// 4-event recon progress sequence emitted via publisher:
//
//  1. EventReconStarted   — at entry
//  2. EventSubdomainsDiscovered — after Subfinder (count + subdomains)
//  3. EventLivenessProbed — after httpx (live count)
//  4. EventReconCompleted — at exit (status: ok / subfinder_failed /
//     httpx_failed / no_subdomains)
//
// Step 3 is skipped on subfinder failure / no subdomains. Step 4
// always fires.
func RunRecon(
	ctx context.Context,
	domain string,
	limit int,
	publisher *redis.ProgressPublisher,
	log zerolog.Logger,
) (*ReconResult, error) {
	if limit <= 0 {
		limit = defaultLimit
	}

	publishIfNotNil(ctx, publisher, events.EventReconStarted, events.ProgressEvent{
		"domain": domain,
	})

	subs, err := runSubfinder(ctx, domain, subfinderTimeout)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("subfinder failed")
		publishIfNotNil(ctx, publisher, events.EventReconCompleted, events.ProgressEvent{
			"subdomain_count": 0,
			"live_count":      0,
			"status":          "subfinder_failed",
		})
		return &ReconResult{}, nil
	}

	if len(subs) > limit {
		subs = subs[:limit]
	}

	publishIfNotNil(ctx, publisher, events.EventSubdomainsDiscovered, events.ProgressEvent{
		"count":      len(subs),
		"subdomains": subs,
	})

	if len(subs) == 0 {
		publishIfNotNil(ctx, publisher, events.EventReconCompleted, events.ProgressEvent{
			"subdomain_count": 0,
			"live_count":      0,
			"status":          "no_subdomains",
		})
		return &ReconResult{Subdomains: subs}, nil
	}

	liveHosts, err := runHttpx(ctx, subs, httpxTimeout)
	if err != nil {
		log.Warn().Err(err).Int("subdomain_count", len(subs)).Msg("httpx failed")
		publishIfNotNil(ctx, publisher, events.EventReconCompleted, events.ProgressEvent{
			"subdomain_count": len(subs),
			"live_count":      0,
			"status":          "httpx_failed",
		})
		return &ReconResult{Subdomains: subs}, nil
	}

	publishIfNotNil(ctx, publisher, events.EventLivenessProbed, events.ProgressEvent{
		"count": len(liveHosts),
	})
	publishIfNotNil(ctx, publisher, events.EventReconCompleted, events.ProgressEvent{
		"subdomain_count": len(subs),
		"live_count":      len(liveHosts),
		"status":          "ok",
	})
	return &ReconResult{Subdomains: subs, LiveHosts: liveHosts}, nil
}

// publishIfNotNil safely calls publisher.Publish when publisher is
// non-nil. Test callers pass nil; production callers always supply
// a real *redis.ProgressPublisher.
//
// Publish errors are intentionally swallowed — recon should not
// fail because progress publishing failed. Per ADR-021 fail-soft
// posture.
func publishIfNotNil(ctx context.Context, publisher *redis.ProgressPublisher, eventType events.EventType, payload events.ProgressEvent) {
	if publisher == nil {
		return
	}
	_, _ = publisher.Publish(ctx, eventType, payload)
}

// resolveBinary applies DEVELOPMENT-PATTERNS.md Pattern 2:
// SHIELDSCAN_<TOOL>_BINARY env var first; exec.LookPath fallback;
// fail-fast if both empty. 11th + 12th instances of the pattern
// (Subfinder + httpx; recon helpers also use it).
//
// Shared between runSubfinder + runHttpx; package-private.
func resolveBinary(envVar, toolName string) (string, error) {
	if path := os.Getenv(envVar); path != "" {
		return path, nil
	}
	path, err := exec.LookPath(toolName)
	if err != nil {
		return "", fmt.Errorf("%s: binary not found; set %s env var or ensure %s is on $PATH",
			toolName, envVar, toolName)
	}
	return path, nil
}
