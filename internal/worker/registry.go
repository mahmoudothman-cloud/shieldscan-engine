// Package worker composes the per-job processor + Redis primitives
// (5.4) + tool runners (5.2/5.3) into a complete worker that consumes
// from the priority queues, runs scan tools, and emits progress +
// completion events back to Python via Redis.
//
// The package is the integration point of M5; every prior task
// surface (events, tools, redis, config) is consumed here. ADR-013
// (Python sole writer) holds throughout — no PG access; findings
// flow up via CompletionsPublisher.
//
// Three primary types:
//
//	Registry  — frozen-at-construction map of engine name → ToolRunner.
//	Processor — per-job lifecycle (idempotency, cancel-watcher, runner
//	            invocation, completion-event sequencing, error
//	            discrimination).
//	Worker    — BRPOP loop + concurrency semaphore + WaitGroup-based
//	            graceful drain.
//
// Task 5.6 wires Worker into cmd/worker/main.go after the startup
// phases populate the Registry with concrete tool runners.
package worker

import (
	"fmt"
	"sort"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// Registry maps engine names to ToolRunner instances. Constructed
// once at worker startup (5.6) with a defensive copy of the input
// map; no Set method is exposed, so concurrent reads are safe
// without a mutex.
//
// Pattern: frozen-at-construction. M6.8 task may extend with
// Register(engine, runner) + mutex if dynamic registration becomes
// needed; for M5+M6 sequential tool registration at startup,
// frozen-at-startup is sufficient. Trigger to revisit: any task
// requiring runtime runner registration (e.g., dynamic plugin
// loading).
type Registry struct {
	runners map[string]tools.ToolRunner
}

// NewRegistry constructs a Registry with a defensive copy of runners.
// Mutating the input map after this call does NOT affect the registry.
func NewRegistry(runners map[string]tools.ToolRunner) *Registry {
	cp := make(map[string]tools.ToolRunner, len(runners))
	for k, v := range runners {
		cp[k] = v
	}
	return &Registry{runners: cp}
}

// Get returns the runner registered for the given engine name, or
// an error if no such runner is registered. Per H.4 / DRIFT-LOG:
// the processor surfaces this as a job_failed completion event
// rather than special-case error reporting.
func (r *Registry) Get(engine string) (tools.ToolRunner, error) {
	runner, ok := r.runners[engine]
	if !ok {
		return nil, fmt.Errorf("no runner registered for engine %q", engine)
	}
	return runner, nil
}

// Engines returns the sorted list of registered engine names.
// Used by 5.6 startup logging + diagnostics.
func (r *Registry) Engines() []string {
	names := make([]string, 0, len(r.runners))
	for name := range r.runners {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
