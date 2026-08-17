// Package docker provides warm-pool semantics for short-lived,
// CLI-shaped Docker tool containers (Trivy, Nmap, SQLMap).
//
// Per ADR-026 (DockerRunner framework + lazy warm pool — M7
// container lifecycle architecture, 2026-05-XX) and ADR-006
// (Hybrid Native + Persistent Docker, refined 2026-04-18), this
// package is the canonical M7 framework for CLI Docker tools.
//
// Distinct from internal/tools/docker/service/ (Task 7.5b
// DockerServiceRunner), which handles HTTP-shaped persistent
// Docker services (MobSF, ZAP per ADR-008). The two abstractions
// coexist + share the WarmPool primitive (extended via
// ContainerFactory hook per Task 7.5b V2 lock):
//
//   - DockerRunner (this package): exec into warmed containers;
//     CLI-shaped tools; lazy-warm pool semantics.
//   - DockerServiceRunner (internal/tools/docker/service/): HTTP
//     requests to long-lived service containers; persistent
//     service shape; ServiceContainerFactory provides port-mapped
//     spin-up + readiness probing.
//
// Container is the framework's Docker SDK abstraction. Tool
// runners do not import the Docker SDK directly; they consume
// Container via Exec/Stop methods.
package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/pkg/stdcopy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
)

// Default resource limits per SPEC §11.4 security posture. Applied
// to every warm-pool container at create time. Operators can override
// per Config (Phase 3 DockerRunner.Resources field; not exposed at
// the Container abstraction layer).
const (
	defaultMemoryBytes = 2 * 1024 * 1024 * 1024 // 2 GiB
	defaultNanoCPUs    = 2 * 1000000000         // 2 CPU
)

// dockerClient is the testable boundary between Container and the
// Docker SDK. Production code uses *client.Client (which satisfies
// this interface naturally — every method below is implemented on
// *client.Client at the same signature). Tests provide mock
// implementations to exercise Container without a live daemon.
//
// Method signatures verified against Docker SDK v28.5.2+incompatible
// (per Phase 0 dependency pin).
type dockerClient interface {
	ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error)
	ContainerCreate(
		ctx context.Context,
		config *container.Config,
		hostConfig *container.HostConfig,
		networkingConfig *network.NetworkingConfig,
		platform *ocispec.Platform,
		containerName string,
	) (container.CreateResponse, error)
	ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)
	ContainerExecCreate(ctx context.Context, containerID string, options container.ExecOptions) (container.ExecCreateResponse, error)
	ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (HijackedResponse, error)
	ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error)
	ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
}

// DockerClient is the exported alias for the package-private
// dockerClient interface. Type alias preserves identity — in-package
// code references dockerClient as before; out-of-package code
// (e.g., internal/tools/docker/service for service-shape factories
// per Task 7.5b V2 lock) references DockerClient. Single source of
// truth for the SDK abstraction surface.
type DockerClient = dockerClient

// HijackedResponse is the Container-package adapter for the Docker
// SDK's types.HijackedResponse. We model the subset we need (Reader
// + Close) so tests can construct a fake without dragging in the
// SDK's internal net.Conn assembly.
//
// Production-side: a thin wrapper around the SDK's HijackedResponse
// is created by the production dockerClient implementation; see
// productionClient.ContainerExecAttach.
type HijackedResponse struct {
	Reader io.Reader
	close  func()
}

// Close releases the underlying SDK hijacked connection (production)
// or runs the test-supplied cleanup (tests).
func (h HijackedResponse) Close() {
	if h.close != nil {
		h.close()
	}
}

// Container wraps a long-running Docker container with lifecycle
// management. Created by WarmPool's spinUp (Phase 2; not in this
// commit yet); consumed by tool runners via Exec; returned via Stop
// or WarmPool.Return.
//
// Per ADR-026: framework abstraction over Docker SDK. Tool packages
// don't import Docker SDK directly; they consume Container.
type Container struct {
	ID    string
	Image string
	// BaseURL is populated by service-shape factories (see
	// internal/tools/docker/service.ServiceContainerFactory) when the
	// container exposes an HTTP service on a host-mapped port.
	// Empty for exec-shape containers (Task 7.2 Nmap; future Trivy +
	// SQLMap). Set once at spinUp time per Q6 readiness-at-spin-up-only
	// lock; immutable thereafter.
	BaseURL string
	cli     dockerClient
	log     zerolog.Logger
}

// NewServiceContainer is the exported constructor for service-shape
// containers built by external factories (internal/tools/docker/service.
// ServiceContainerFactory per Task 7.5b V2 lock). Out-of-package code
// cannot set the unexported cli + log fields via struct literal; this
// constructor closes that gap while keeping cli + log unexported.
//
// Caller is responsible for ensuring the underlying container at id
// has been created + started + (optionally) verified ready. Caller
// passes the cli used for creation so subsequent Stop/Exec calls
// flow through the same SDK adapter.
func NewServiceContainer(id, imageRef, baseURL string, cli DockerClient, log zerolog.Logger) *Container {
	return &Container{
		ID:      id,
		Image:   imageRef,
		BaseURL: baseURL,
		cli:     cli,
		log:     log.With().Str("container_id", shortID(id)).Logger(),
	}
}

// newContainer creates a long-running container of the given image.
// The container runs `sleep infinity` to stay alive for subsequent
// Exec calls (warm-pool reuse semantics; see ADR-026).
//
// Image-pull policy: always-pull (simpler than image-list-then-pull;
// Docker handles already-pulled images cheaply by short-circuiting
// the pull). Failures during pull or container create surface as
// errors; caller (WarmPool.spinUp at Phase 2) decrements pool size
// accordingly.
//
// The function is lower-case (package-private) by design — only
// WarmPool constructs Containers; direct construction at the tool-
// runner layer would bypass pool accounting.
//
// Per Task 7.5e Mounts extension: mounts is the optional slice of
// host bind-mounts / volume mounts threaded into HostConfig.Mounts.
// Nil/empty mounts preserves pre-7.5e behavior (no host filesystem
// access; matches Task 7.2 Nmap consumer expectation). DefaultContainerFactory
// passes nil for backward-compat; WarmPool internal closure (when
// cfg.Mounts non-empty + cfg.ContainerFactory nil) passes cfg.Mounts.
// Per the orphan-reaping extension: labels is the optional set of Docker
// labels stamped onto the container at create. WarmPool populates it from
// Config.Labels (owning worker id + pool name) so a later worker can
// identify containers a dead worker left behind. Nil labels are legal and
// mean "unlabelled" — but note that an unlabelled container is invisible to
// ReapOrphans by construction, which is the point: reaping keys on OUR label,
// never on the image, so a container a human started from the same image is
// never touched.
func newContainer(ctx context.Context, cli dockerClient, image string, mounts []mount.Mount, labels map[string]string, log zerolog.Logger) (*Container, error) {
	scopedLog := log.With().Str("image", image).Logger()

	// 1. Pull image. SDK returns an io.ReadCloser carrying pull
	//    progress JSONL; draining it is required for the pull to
	//    actually complete (Docker SDK's contract).
	pullReader, err := cli.ImagePull(ctx, image, dockerImagePullOptions{}.toSDK())
	if err != nil {
		return nil, fmt.Errorf("docker: image pull %s: %w", image, err)
	}
	if _, copyErr := io.Copy(io.Discard, pullReader); copyErr != nil {
		scopedLog.Warn().Err(copyErr).Msg("draining pull stream errored; continuing")
	}
	_ = pullReader.Close()

	// 2. Create container with a sleep-infinity entrypoint so it
	//    persists across multiple Exec calls. Resource limits per
	//    SPEC §11.4. AutoRemove deliberately false — pool manages
	//    lifecycle; AutoRemove would race with Stop's explicit
	//    ContainerRemove.
	// Override ENTRYPOINT to empty so Cmd: [sleep, infinity] runs as
	// the container's command directly. Per Task 7.5e Phase 2
	// empirical finding (D-PLAN-7.5e-Phase2-Entrypoint): tool images
	// like aquasec/trivy + instrumentisto/nmap declare ENTRYPOINT
	// (e.g., ["trivy"], ["/usr/bin/nmap"]) which would otherwise be
	// prepended to Cmd, producing "trivy sleep infinity" → failure.
	// Empty []string entrypoint is the canonical Docker SDK pattern
	// for overriding image entrypoint to no-op. Warm-pool semantics
	// require sleep-infinity persistence; actual tool invocation
	// happens via subsequent Container.Exec calls per warm-pool design.
	createResp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:      image,
			Entrypoint: []string{},
			Cmd:        []string{"sleep", "infinity"},
			Tty:        false,
			Labels:     labels,
		},
		&container.HostConfig{
			Resources: container.Resources{
				Memory:   defaultMemoryBytes,
				NanoCPUs: defaultNanoCPUs,
			},
			AutoRemove:     false,
			ReadonlyRootfs: false, // some tools write to /tmp at runtime
			Mounts:         mounts,
		},
		nil, nil, "",
	)
	if err != nil {
		return nil, fmt.Errorf("docker: container create %s: %w", image, err)
	}

	// 3. Start container. On start failure, force-remove the created
	//    container so we don't leak stopped containers on retries.
	if err := cli.ContainerStart(ctx, createResp.ID, container.StartOptions{}); err != nil {
		_ = cli.ContainerRemove(ctx, createResp.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("docker: container start %s: %w", createResp.ID, err)
	}

	return &Container{
		ID:    createResp.ID,
		Image: image,
		cli:   cli,
		log:   scopedLog.With().Str("container_id", shortID(createResp.ID)).Logger(),
	}, nil
}

// Exec runs a command inside the container and captures stdout +
// exit code. Stderr is demultiplexed via stdcopy.StdCopy and logged
// at DEBUG; tools that legitimately use stderr for findings should
// be configured to write to stdout instead (most CLI tools accept
// `-o -` or equivalent flags).
//
// Equivalent to `docker exec <id> <cmd...>`.
//
// Context cancellation propagates to the SDK; partial stdout drained
// before cancellation is still returned alongside the error.
//
// Per ADR-021 ctx-discipline: ctx flows through the SDK; cancel
// reaches the daemon-side exec process.
func (c *Container) Exec(ctx context.Context, cmd []string) (stdout []byte, exitCode int, err error) {
	execResp, err := c.cli.ContainerExecCreate(ctx, c.ID, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	})
	if err != nil {
		return nil, -1, fmt.Errorf("docker: exec create: %w", err)
	}

	attachResp, err := c.cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, -1, fmt.Errorf("docker: exec attach: %w", err)
	}
	defer attachResp.Close()

	// Demux stdout / stderr. The Docker stream multiplexes both via
	// per-frame headers; stdcopy.StdCopy unpacks them.
	var stdoutBuf, stderrBuf bytes.Buffer
	if _, copyErr := stdcopy.StdCopy(&stdoutBuf, &stderrBuf, attachResp.Reader); copyErr != nil && !errors.Is(copyErr, io.EOF) {
		c.log.Warn().Err(copyErr).Msg("stdcopy non-EOF error; partial stdout returned")
	}

	inspectResp, err := c.cli.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return stdoutBuf.Bytes(), -1, fmt.Errorf("docker: exec inspect: %w", err)
	}

	if stderrBuf.Len() > 0 {
		c.log.Debug().Int("stderr_bytes", stderrBuf.Len()).Msg("tool wrote to stderr")
	}

	return stdoutBuf.Bytes(), inspectResp.ExitCode, nil
}

// Stop attempts a graceful shutdown (5s timeout) and force-removes
// the container regardless of stop outcome. Best-effort: stop
// failures are logged but do not block remove; only remove failures
// surface as errors (caller cannot meaningfully retry stop, but a
// remove failure indicates a leaked container worth alerting on).
func (c *Container) Stop(ctx context.Context) error {
	timeout := 5
	if err := c.cli.ContainerStop(ctx, c.ID, container.StopOptions{Timeout: &timeout}); err != nil {
		c.log.Warn().Err(err).Msg("container stop failed; will force remove")
	}
	if err := c.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true}); err != nil {
		return fmt.Errorf("docker: container remove %s: %w", shortID(c.ID), err)
	}
	return nil
}

// shortID truncates a container ID to 12 chars for log readability,
// matching the docker CLI convention. Returns the full ID unchanged
// if shorter than 12 chars (defensive; tests sometimes use synthetic
// short IDs).
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

// dockerImagePullOptions is a zero-allocation passthrough adapter
// kept here so future callers can extend pull options (registry
// auth, all-tags, etc.) without touching call sites. At present the
// default is the empty struct.
type dockerImagePullOptions struct{}

func (dockerImagePullOptions) toSDK() image.PullOptions {
	return image.PullOptions{}
}
