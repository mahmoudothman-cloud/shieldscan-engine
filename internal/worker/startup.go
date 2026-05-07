package worker

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
)

// NativeBinary describes a native scan tool whose binary should be
// verified at startup Phase 1. M6+ task constructors populate the
// list passed to Startup.
type NativeBinary struct {
	Name string // canonical tool name (e.g., "nuclei")
	Path string // absolute path (e.g., "/usr/local/bin/nuclei")
}

// dockerHealthChecker is the surface Phase 2 calls. *DockerServiceRunner
// (5.3) implements it via its HealthCheck method. Decoupled here so
// tests can inject lightweight stubs without spinning miniredis.
type dockerHealthChecker interface {
	Name() string
	HealthCheck(ctx context.Context) error
}

// StartupDeps wires the dependencies for the 4-phase startup sequence
// per TOOL-ARCHITECTURE.md §11.1.
//
// Phase 1: native binary verification (warn-not-fail at MVP — registry
//
//	is empty until M6+ populates).
//
// Phase 2: Docker services healthcheck (warn-not-fail at MVP — same
//
//	reason; M7 task scope decides per-tool fail-fast opt-in).
//
// Phase 3: warm pool init — Task 7.2 D4 lock; pools list passed by
//
//	cmd/worker/docker_wiring.go's buildDockerRegistry. Phase 3
//	logs the pool count; pool shutdown is wired into run.go's
//	drain path (not Startup) since pool shutdown happens AFTER
//	worker drain, not at startup time.
//
// Phase 4: worker registration via Heartbeat.WriteOnce (fail-fast —
//
//	registration is required for the orchestrator to route
//	jobs to this worker).
type StartupDeps struct {
	Registry    *Registry
	NativeTools []NativeBinary
	DockerSvcs  []dockerHealthChecker
	WarmPools   []*docker.WarmPool
	Heartbeat   *Heartbeat
	Logger      zerolog.Logger
}

// Startup orchestrates the 4-phase worker startup sequence.
type Startup struct {
	registry    *Registry
	nativeTools []NativeBinary
	dockerSvcs  []dockerHealthChecker
	warmPools   []*docker.WarmPool
	heartbeat   *Heartbeat
	log         zerolog.Logger
}

// NewStartup constructs a Startup. Required: Registry, Heartbeat.
// NativeTools and DockerSvcs may be empty (5.6 ships empty by
// default; M6+ populates).
func NewStartup(deps StartupDeps) *Startup {
	if deps.Registry == nil {
		panic("worker.NewStartup: Registry is required")
	}
	if deps.Heartbeat == nil {
		panic("worker.NewStartup: Heartbeat is required")
	}
	return &Startup{
		registry:    deps.Registry,
		nativeTools: deps.NativeTools,
		dockerSvcs:  deps.DockerSvcs,
		warmPools:   deps.WarmPools,
		heartbeat:   deps.Heartbeat,
		log:         deps.Logger,
	}
}

// Run executes the 4 phases. Returns error only on Phase 4 failure
// (worker registration); Phases 1+2 fail-soft at 5.6 with warnings.
func (s *Startup) Run(ctx context.Context) error {
	s.log.Info().Msg("worker startup beginning")

	// Phase 1: native binaries.
	s.checkNativeBinaries()

	// Phase 2: Docker services.
	s.checkDockerServices(ctx)

	// Phase 3: warm pool init — Task 7.2 D4 lock; pools constructed
	// lazily so spin-up is on first Checkout. Phase 3 logs the count;
	// shutdown is orchestrated by runMain alongside worker drain.
	if len(s.warmPools) == 0 {
		s.log.Debug().Msg("phase 3 (warm pool init): none configured")
	} else {
		s.log.Info().
			Int("count", len(s.warmPools)).
			Msg("phase 3 (warm pool init): pools registered (lazy spin-up on first checkout)")
	}

	// Phase 4: worker registration (fail-fast).
	if err := s.heartbeat.WriteOnce(ctx); err != nil {
		return fmt.Errorf("phase 4 worker registration: %w", err)
	}
	s.log.Info().
		Str("worker_id", s.heartbeat.WorkerID()).
		Msg("phase 4 worker registration complete")

	// Empty-registry warning. 5.6 ships empty Registry; M6+ task
	// constructors populate engines. Without this WARN, an operator
	// running the binary in production might not realize jobs queue
	// up and never process because no runners are registered.
	engines := s.registry.Engines()
	if len(engines) == 0 {
		s.log.Warn().
			Msg("worker started with empty registry; no jobs will be processed " +
				"until tool runners are registered. Tool runners are registered " +
				"by M6+ task constructors (e.g., NativeRunner for Nuclei in M6.1). " +
				"If this is unexpected, check that your worker binary was built " +
				"with the desired M6+ task code.")
	} else {
		s.log.Info().
			Strs("registered_engines", engines).
			Msg("worker startup complete")
	}
	return nil
}

// checkNativeBinaries iterates configured native tools; each missing
// binary logs a warning. Empty list at 5.6 (Registry empty); becomes
// meaningful when M6 task constructors populate.
func (s *Startup) checkNativeBinaries() {
	if len(s.nativeTools) == 0 {
		s.log.Debug().Msg("phase 1 (native binaries): no tools configured")
		return
	}
	missing := 0
	for _, t := range s.nativeTools {
		info, err := os.Stat(t.Path)
		if err != nil {
			s.log.Warn().
				Str("tool", t.Name).
				Str("path", t.Path).
				Err(err).
				Msg("native binary missing")
			missing++
			continue
		}
		// Verify executable bit.
		if info.Mode().Perm()&0111 == 0 {
			s.log.Warn().
				Str("tool", t.Name).
				Str("path", t.Path).
				Msg("native binary not executable")
			missing++
		}
	}
	if missing > 0 {
		s.log.Warn().
			Int("missing", missing).
			Int("total", len(s.nativeTools)).
			Msg("phase 1 (native binaries): some tools missing/unexecutable; continuing (fail-soft)")
	} else {
		s.log.Info().
			Int("count", len(s.nativeTools)).
			Msg("phase 1 (native binaries): all verified")
	}
}

// checkDockerServices iterates configured Docker service runners;
// each unreachable service logs a warning. Empty list at 5.6;
// becomes meaningful when M7 tasks register DockerServiceRunner
// instances.
//
// Trigger to switch from fail-soft to fail-fast: M7 task scope
// proposals decide per-tool whether the service is operationally
// required (fail-fast) or optional (fail-soft).
func (s *Startup) checkDockerServices(ctx context.Context) {
	if len(s.dockerSvcs) == 0 {
		s.log.Debug().Msg("phase 2 (docker services): none configured")
		return
	}
	failed := 0
	for _, svc := range s.dockerSvcs {
		if err := svc.HealthCheck(ctx); err != nil {
			s.log.Warn().
				Str("service", svc.Name()).
				Err(err).
				Msg("docker service unreachable")
			failed++
		}
	}
	if failed > 0 {
		s.log.Warn().
			Int("failed", failed).
			Int("total", len(s.dockerSvcs)).
			Msg("phase 2 (docker services): some services unreachable; continuing (fail-soft)")
	} else {
		s.log.Info().
			Int("count", len(s.dockerSvcs)).
			Msg("phase 2 (docker services): all healthy")
	}
}
