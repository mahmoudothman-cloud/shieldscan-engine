package service

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/go-connections/nat"
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
)

// ServiceContainerOpts configures the service-shape ContainerFactory.
// ContainerPort is the port the service listens on inside the
// container (e.g., 8080 for ZAP). Readiness fields configure the
// post-start probe; zero-values use framework defaults.
type ServiceContainerOpts struct {
	ContainerPort           int
	ReadinessEndpoint       string
	ReadinessExpectedStatus int
	ReadinessTimeout        time.Duration
	ReadinessPollInterval   time.Duration

	// Cmd overrides the container's launch command. Empty leaves the
	// image's default entrypoint intact. Needed by services whose daemon
	// must be started with args — e.g. ZAP's
	// `zap.sh -daemon -config api.key=...`. The port is still bound to
	// 127.0.0.1 only (see PortBindings below), so an API-key + open
	// api.addrs combo is not publicly reachable.
	Cmd []string

	// APIProxyHost selects the addressing model for the readiness probe
	// (see serviceAddressing). Empty (default) probes the mapped address
	// directly. Non-empty (ZAP: "zap") routes the probe THROUGH the mapped
	// port as an HTTP forward-proxy, targeting http://<APIProxyHost>/...;
	// required because ZAP's API shares the proxy port and 502s a direct
	// probe.
	APIProxyHost string

	// Labels are stamped on the container at create, and exist for the
	// same reason WarmPool.Config.Labels does: ReapOrphans keys on
	// io.shieldscan.managed and NOTHING else, so an unlabelled container
	// is invisible to it by construction.
	//
	// Ephemeral service containers were unlabelled from the day this
	// factory was written. The warm-pool path threads labels through and
	// this one never did, so a ZAP or MobSF container surviving a SIGKILL
	// — precisely the case orphan reaping exists for — would sit on the
	// host forever, holding its memory, with no worker willing to touch
	// it. Nil is still legal and still means unlabelled; it just now
	// means someone chose that.
	Labels map[string]string
}

// ServiceContainerFactory returns a docker.ContainerFactoryFunc
// suitable for WarmPool.Config.ContainerFactory (or direct invocation
// for cfg.EphemeralContainer = true paths).
//
// The factory:
//
//  1. Pulls image (Docker SDK short-circuits if already cached).
//  2. Creates container with PortBindings binding ContainerPort/tcp
//     to a dynamic port on 127.0.0.1 (Q7 lock; multi-container-safe;
//     defense-in-depth via localhost-only).
//  3. Starts the container WITHOUT overriding Cmd — the consumer
//     image's entrypoint runs (asymmetric with newContainer's
//     `sleep infinity` exec-shape).
//  4. Inspects the container to discover the dynamically-allocated
//     host port.
//  5. Sets Container.BaseURL = "http://127.0.0.1:<dynamic-port>".
//  6. Calls waitForReady (per Q6 readiness-at-spin-up-only).
//
// On readiness failure, stops + removes the container before
// returning the error.
//
// Per Task 7.5b V2 + V8 locks (design doc 3067c92).
func ServiceContainerFactory(opts ServiceContainerOpts) docker.ContainerFactoryFunc {
	return func(ctx context.Context, cli docker.DockerClient, imageRef string, log zerolog.Logger) (*docker.Container, error) {
		scopedLog := log.With().Str("image", imageRef).Logger()

		if opts.ContainerPort <= 0 {
			return nil, fmt.Errorf("service container factory: ContainerPort required (got %d)", opts.ContainerPort)
		}

		// 1. Pull image (drain progress stream per Docker SDK contract).
		pullReader, err := cli.ImagePull(ctx, imageRef, image.PullOptions{})
		if err != nil {
			return nil, fmt.Errorf("service container factory: image pull %s: %w", imageRef, err)
		}
		if _, copyErr := io.Copy(io.Discard, pullReader); copyErr != nil {
			scopedLog.Warn().Err(copyErr).Msg("draining pull stream errored; continuing")
		}
		_ = pullReader.Close()

		// 2. Create container with PortBindings (no Cmd override).
		portKey, err := nat.NewPort("tcp", fmt.Sprintf("%d", opts.ContainerPort))
		if err != nil {
			return nil, fmt.Errorf("service container factory: nat.NewPort %d: %w", opts.ContainerPort, err)
		}
		cfg := &container.Config{
			Image:        imageRef,
			ExposedPorts: nat.PortSet{portKey: struct{}{}},
			Labels:       opts.Labels,
		}
		// Optional launch-command override (empty → image default entrypoint).
		if len(opts.Cmd) > 0 {
			cfg.Cmd = opts.Cmd
		}
		hostCfg := &container.HostConfig{
			PortBindings: nat.PortMap{
				portKey: []nat.PortBinding{
					{HostIP: "127.0.0.1", HostPort: ""}, // dynamic
				},
			},
			AutoRemove: false, // pool manages lifecycle
		}
		createResp, err := cli.ContainerCreate(ctx, cfg, hostCfg, nil, nil, "")
		if err != nil {
			return nil, fmt.Errorf("service container factory: container create: %w", err)
		}

		// 3. Start container.
		if err := cli.ContainerStart(ctx, createResp.ID, container.StartOptions{}); err != nil {
			_ = cli.ContainerRemove(ctx, createResp.ID, container.RemoveOptions{Force: true})
			return nil, fmt.Errorf("service container factory: container start %s: %w", createResp.ID, err)
		}

		// 4. Inspect for dynamic port.
		insp, err := cli.ContainerInspect(ctx, createResp.ID)
		if err != nil {
			_ = cli.ContainerStop(ctx, createResp.ID, container.StopOptions{})
			_ = cli.ContainerRemove(ctx, createResp.ID, container.RemoveOptions{Force: true})
			return nil, fmt.Errorf("service container factory: container inspect: %w", err)
		}
		hostPort, err := dynamicHostPort(insp, portKey)
		if err != nil {
			_ = cli.ContainerStop(ctx, createResp.ID, container.StopOptions{})
			_ = cli.ContainerRemove(ctx, createResp.ID, container.RemoveOptions{Force: true})
			return nil, fmt.Errorf("service container factory: %w", err)
		}

		// 5. Construct BaseURL.
		baseURL := fmt.Sprintf("http://127.0.0.1:%s", hostPort)

		// 6. Readiness probe.
		if opts.ReadinessEndpoint != "" {
			if err := waitForReady(ctx, baseURL, opts.ReadinessEndpoint, opts.ReadinessExpectedStatus,
				opts.ReadinessTimeout, opts.ReadinessPollInterval, opts.APIProxyHost,
				containerAliveCheck(cli, createResp.ID)); err != nil {
				// Read the evidence BEFORE destroying it. This used to stop
				// and remove the container first and report only the HTTP
				// symptom, which is why three separate ZAP readiness failures
				// produced nothing anyone could diagnose: the error handler
				// deleted the logs, the exit code and the OOMKilled flag of
				// the very container it was complaining about.
				state, logs := postMortem(ctx, cli, createResp.ID)
				scopedLog.Error().
					Str("container_id", createResp.ID).
					Str("container_state", state).
					Str("container_logs", logs).
					Err(err).
					Msg("service container failed readiness; captured state and logs before removal")

				_ = cli.ContainerStop(ctx, createResp.ID, container.StopOptions{})
				_ = cli.ContainerRemove(ctx, createResp.ID, container.RemoveOptions{Force: true})
				if state != "" {
					return nil, fmt.Errorf("service container factory: readiness: %w (container %s)", err, state)
				}
				return nil, fmt.Errorf("service container factory: readiness: %w", err)
			}
		}

		return docker.NewServiceContainer(createResp.ID, imageRef, baseURL, cli, scopedLog), nil
	}
}

// maxCapturedLogBytes bounds the container output copied into a log
// line on a readiness failure. A boot failure explains itself in its
// last few KiB; more than this and the diagnostic becomes the incident.
const maxCapturedLogBytes = 16 * 1024

// containerAliveCheck adapts a container's Docker state to the
// aliveCheck the readiness poll consults.
//
// The readiness probe is an HTTP poll and, on its own, cannot tell "not
// listening yet" from "exited 90 seconds ago" — both are connection
// refused. Measured: a ZAP container started at 16:14:18 and its task
// was deleted at 16:14:52, while the probe kept polling the now-dead
// mapped port until 16:18:18 and then reported a four-minute timeout
// with a proxy error. Three and a half of those four minutes were spent
// waiting on a container that no longer existed, and the operator-facing
// error named the proxy rather than the death.
//
// ContainerInspect is already on the client interface, so this costs one
// local daemon round-trip per failed poll and turns that timeout into an
// immediate, correctly-attributed failure.
//
// Inconclusive results deliberately return nil (keep waiting): an
// inspect error may be a transient daemon hiccup, and a probe that gives
// up because it could not read the state would be a worse failure than
// the one being fixed.
func containerAliveCheck(cli docker.DockerClient, containerID string) aliveCheck {
	return func(ctx context.Context) error {
		insp, err := cli.ContainerInspect(ctx, containerID)
		// InspectResponse embeds *ContainerJSONBase, so insp.State panics
		// rather than reading nil when the base is absent — check the base
		// before the field.
		if err != nil || insp.ContainerJSONBase == nil || insp.State == nil {
			return nil // inconclusive — keep waiting
		}
		if insp.State.Running {
			return nil
		}
		return fmt.Errorf("container is no longer running: %s", docker.DescribeState(insp))
	}
}

// postMortem gathers what a container has to say for itself, for the
// caller to record before removing it. Both halves are best-effort and
// return descriptive strings rather than errors — the caller is already
// carrying the error that matters.
func postMortem(ctx context.Context, cli docker.DockerClient, containerID string) (state, logs string) {
	if insp, err := cli.ContainerInspect(ctx, containerID); err == nil {
		state = docker.DescribeState(insp)
	}
	return state, docker.CaptureLogs(ctx, cli, containerID, maxCapturedLogBytes)
}

// dynamicHostPort extracts the dynamically-allocated host port for
// the given container port from a ContainerInspect response.
func dynamicHostPort(insp container.InspectResponse, portKey nat.Port) (string, error) {
	if insp.NetworkSettings == nil {
		return "", fmt.Errorf("inspect: NetworkSettings nil")
	}
	bindings, ok := insp.NetworkSettings.Ports[portKey]
	if !ok || len(bindings) == 0 {
		return "", fmt.Errorf("inspect: no host port mapped for %s", portKey)
	}
	return bindings[0].HostPort, nil
}
