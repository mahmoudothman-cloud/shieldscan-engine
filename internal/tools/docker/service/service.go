package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
)

// DefaultRequestTimeout is the per-request HTTP timeout used when
// ServiceConfig.RequestTimeout is zero. 30s is the canonical default
// for ZAP/MobSF API calls (per existing internal/tools/docker_service.go
// pattern; preserved during V8 replace).
const DefaultRequestTimeout = 30 * time.Second

// ServiceConfig configures a DockerServiceRunner per Task 7.5b
// design doc 3067c92 §3.2.
//
// Required: Image; ContainerPort; ReadinessEndpoint.
// Optional: everything else; framework defaults apply on zero-value.
//
// EphemeralContainer = true bypasses the warm pool and creates a
// fresh container per scan (Q5 opt-out + V4 ZAP default v1).
type ServiceConfig struct {
	Image              string
	ContainerPort      int
	EphemeralContainer bool
	MaxPoolSize        int

	// Cmd overrides the container's launch command (empty → image
	// default entrypoint). First needed by ZAP, whose daemon must be
	// started with `-config api.key=...` matching the client's key.
	Cmd []string

	// APIProxyHost selects the addressing model for BOTH the readiness
	// probe and the per-scan Client (see serviceAddressing). Empty
	// (default) addresses the container's mapped host:port directly —
	// every normal HTTP service. Non-empty (ZAP: "zap") treats the mapped
	// port as an HTTP forward-proxy and targets http://<APIProxyHost>/...
	// through it, because ZAP serves its API on the same port as its
	// forward proxy and 502s a direct request.
	APIProxyHost string

	// Readiness probe (Q2; runs at spin-up only per Q6)
	ReadinessEndpoint       string
	ReadinessExpectedStatus int
	ReadinessTimeout        time.Duration
	ReadinessPollInterval   time.Duration

	// HTTP client (Q3)
	AuthFunc       AuthFunc
	RequestTimeout time.Duration

	// Cleanup (Q5; closure may capture consumer state per V5 MobSF md5-tracking)
	// Unused when EphemeralContainer = true (V4 ZAP default).
	CleanupFunc docker.CleanupFunc
}

// DockerServiceRunner is the M7 framework type for HTTP-API-shaped
// Docker tools (ZAP, MobSF, future Burp/Snyk/Wiz).
//
// Symmetric with internal/tools/docker.DockerRunner (Task 7.5a;
// exec-shape consumers). Both satisfy tools.ToolRunner.
//
// DockerServiceRunner runs HTTP-API-shaped tools as Docker containers, managing container
// lifecycle (warm pool OR ephemeral), readiness probing, HTTP client construction,
// and cleanup hook coordination. Consumer code provides BuildScan (which receives the
// framework Client + scan config and returns RawFindings) and ServiceConfig
// (which specifies image, port, readiness endpoint, auth, and cleanup behavior).
//
// Consumer integration pattern (generic example; consumer-specific auth
// shape varies — header-based tools use service.WithAPIKeyHeader; tools
// requiring query-param-based auth construct an AuthFunc closure as
// escape hatch per Q8 lock; see Task 7.3 ZAP consumer for query-param
// example):
//
//	runner := &service.DockerServiceRunner{
//	    ToolName:     "example-tool",
//	    ToolCategory: "dast",
//	    ServiceConfig: service.ServiceConfig{
//	        Image:              toolImageDigest,
//	        ContainerPort:      8080,
//	        EphemeralContainer: true,
//	        ReadinessEndpoint:  "/health",
//	        ReadinessTimeout:   120 * time.Second,
//	        AuthFunc:           service.WithAPIKeyHeader("X-API-Key", apiKey),
//	    },
//	    BuildScan: func(ctx context.Context, target tools.Target, cfg tools.ScanConfig, client *service.Client) ([]events.RawFinding, error) {
//	        // Tool-specific scan logic using client.Get/Post/PollUntil
//	        // ...
//	    },
//	    Log: log,
//	}
type DockerServiceRunner struct {
	ToolName     string
	ToolCategory string

	// Pool is the WarmPool of pre-warmed service containers. May be
	// nil when EphemeralContainer = true; in that mode each scan
	// creates a fresh container directly via cli + factory.
	Pool *docker.WarmPool

	// Cli is the docker client used by the EphemeralContainer path
	// (and by Container.Stop in both paths). Required.
	Cli docker.DockerClient

	ServiceConfig ServiceConfig

	// BuildScan is consumer-defined: receives target + scan config +
	// framework HTTP client; returns RawFindings or error. The
	// framework provides Client + container lifecycle; consumer drives
	// scan logic (create job → PollUntil status → fetch results →
	// parse to RawFindings).
	BuildScan func(ctx context.Context, target tools.Target, cfg tools.ScanConfig, client *Client) ([]events.RawFinding, error)

	Log zerolog.Logger
}

// Compile-time interface assertion. Mirrors NativeRunner +
// DockerRunner pattern; signature drift surfaces at `go build`.
var _ tools.ToolRunner = (*DockerServiceRunner)(nil)

// Name returns the canonical tool name.
func (r *DockerServiceRunner) Name() string { return r.ToolName }

// Category returns the engine category.
func (r *DockerServiceRunner) Category() string { return r.ToolCategory }

// Run implements tools.ToolRunner. Lifecycle per design doc 3067c92
// §3.3:
//   - IF EphemeralContainer: skip Pool; create fresh container via
//     ServiceContainerFactory; defer Container.Stop + remove
//   - ELSE: Pool.Checkout(ctx); defer Pool.Return(ctx, container)
//     [Pool.Return invokes CleanupFunc per WarmPool semantics; cleanup
//     uses detached context per DEVELOPMENT-PATTERNS entry #5]
//
// Then constructs Client, invokes BuildScan, returns findings.
func (r *DockerServiceRunner) Run(ctx context.Context, target tools.Target, cfg tools.ScanConfig) ([]events.RawFinding, error) {
	if r.BuildScan == nil {
		return nil, errors.New("docker service runner: BuildScan required")
	}
	if r.Cli == nil && r.ServiceConfig.EphemeralContainer {
		return nil, errors.New("docker service runner: Cli required for EphemeralContainer mode")
	}
	if r.Pool == nil && !r.ServiceConfig.EphemeralContainer {
		return nil, errors.New("docker service runner: Pool required for warm-pool mode")
	}

	c, releaseFn, err := r.acquireContainer(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: acquire container: %w", r.ToolName, err)
	}
	defer releaseFn()

	client, err := r.buildClient(c)
	if err != nil {
		return nil, fmt.Errorf("%s: build client: %w", r.ToolName, err)
	}
	findings, err := r.BuildScan(ctx, target, cfg, client)
	if err != nil {
		return nil, fmt.Errorf("%s: build scan: %w", r.ToolName, err)
	}

	// Enrichment (mirrors NativeRunner + DockerRunner pattern).
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range findings {
		findings[i].ToolName = r.ToolName
		findings[i].EngineCategory = r.ToolCategory
		findings[i].DiscoveredAt = now
		findings[i].Fingerprint = tools.ComputeFingerprint(findings[i])
	}
	return findings, nil
}

// acquireContainer returns a container + release closure per the
// ephemeral-vs-warm-pool branching. Release closure is idempotent
// at the framework level (defer-safe).
func (r *DockerServiceRunner) acquireContainer(ctx context.Context) (*docker.Container, func(), error) {
	if r.ServiceConfig.EphemeralContainer {
		return r.acquireEphemeral(ctx)
	}
	return r.acquireFromPool(ctx)
}

func (r *DockerServiceRunner) acquireEphemeral(ctx context.Context) (*docker.Container, func(), error) {
	factory := ServiceContainerFactory(ServiceContainerOpts{
		ContainerPort:           r.ServiceConfig.ContainerPort,
		ReadinessEndpoint:       r.ServiceConfig.ReadinessEndpoint,
		ReadinessExpectedStatus: r.ServiceConfig.ReadinessExpectedStatus,
		ReadinessTimeout:        r.ServiceConfig.ReadinessTimeout,
		ReadinessPollInterval:   r.ServiceConfig.ReadinessPollInterval,
		Cmd:                     r.ServiceConfig.Cmd,
		APIProxyHost:            r.ServiceConfig.APIProxyHost,
	})
	c, err := factory(ctx, r.Cli, r.ServiceConfig.Image, r.Log)
	if err != nil {
		return nil, nil, err
	}
	release := func() {
		// Detached context per DEVELOPMENT-PATTERNS entry #5
		// (cleanup-uses-detached-context; 3rd+ instance).
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if stopErr := c.Stop(stopCtx); stopErr != nil {
			r.Log.Warn().Err(stopErr).Str("container_id", c.ID).Msg("ephemeral container stop failed")
		}
	}
	return c, release, nil
}

func (r *DockerServiceRunner) acquireFromPool(ctx context.Context) (*docker.Container, func(), error) {
	c, err := r.Pool.Checkout(ctx)
	if err != nil {
		return nil, nil, err
	}
	release := func() {
		// Detached context per DEVELOPMENT-PATTERNS entry #5.
		returnCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if returnErr := r.Pool.Return(returnCtx, c); returnErr != nil {
			r.Log.Warn().Err(returnErr).Str("container_id", c.ID).Msg("pool return failed")
		}
	}
	return c, release, nil
}

func (r *DockerServiceRunner) buildClient(c *docker.Container) (*Client, error) {
	timeout := r.ServiceConfig.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	// HTTPClient.Timeout is 0 per V10 + design doc; per-request
	// timeout is enforced via ctx in Get/Post (which the consumer
	// constructs from the ctx passed to BuildScan, applying
	// timeout via context.WithTimeout as needed).
	_ = timeout // reserved for future per-tool override propagation

	// Addressing model per ServiceConfig.APIProxyHost: direct (nil
	// transport → DefaultTransport) for normal services, forward-proxy
	// to the magic host for ZAP. Same helper the readiness probe uses so
	// both sides agree on how the container is reached.
	baseURL, transport, err := serviceAddressing(c.BaseURL, r.ServiceConfig.APIProxyHost)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: 0}
	// Assign Transport only when non-nil: a typed-nil *http.Transport in
	// the RoundTripper interface field is non-nil and panics on use;
	// leaving it unset falls back to http.DefaultTransport (direct mode).
	if transport != nil {
		httpClient.Transport = transport
	}
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		AuthFunc:   r.ServiceConfig.AuthFunc,
		Log:        r.Log,
	}, nil
}
