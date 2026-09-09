package docker

import (
	"context"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// productionClient wraps *client.Client to satisfy the package's
// dockerClient interface. The only non-trivial adaptation is
// ContainerExecAttach: the SDK returns types.HijackedResponse with
// an embedded net.Conn we don't expose; we wrap its Reader + Close
// into our package-local HijackedResponse so tests can construct
// fakes without dragging the SDK's hijack assembly into test scope.
//
// Every other method is a direct passthrough — *client.Client's
// signatures match dockerClient's exactly per Docker SDK
// v28.5.2+incompatible.
type productionClient struct {
	cli *client.Client
}

// NewProductionClient wraps a *client.Client as a dockerClient,
// suitable for WarmPool wiring (Phase 2 caller). Exported so
// cmd/worker startup can construct it. The caller owns the
// *client.Client lifecycle; this wrapper does not Close it.
//
// Returns the package-local dockerClient interface intentionally —
// callers should depend on the abstraction, not the wrapper struct.
func NewProductionClient(cli *client.Client) dockerClient { //nolint:revive // intentional package-local interface return
	return &productionClient{cli: cli}
}

func (p *productionClient) ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error) {
	return p.cli.ImagePull(ctx, refStr, options)
}

func (p *productionClient) ContainerCreate(
	ctx context.Context,
	config *container.Config,
	hostConfig *container.HostConfig,
	networkingConfig *network.NetworkingConfig,
	platform *ocispec.Platform,
	containerName string,
) (container.CreateResponse, error) {
	return p.cli.ContainerCreate(ctx, config, hostConfig, networkingConfig, platform, containerName)
}

func (p *productionClient) ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error {
	return p.cli.ContainerStart(ctx, containerID, options)
}

func (p *productionClient) ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error) {
	return p.cli.ContainerInspect(ctx, containerID)
}

func (p *productionClient) ContainerExecCreate(ctx context.Context, containerID string, options container.ExecOptions) (container.ExecCreateResponse, error) {
	return p.cli.ContainerExecCreate(ctx, containerID, options)
}

func (p *productionClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (HijackedResponse, error) {
	sdk, err := p.cli.ContainerExecAttach(ctx, execID, config)
	if err != nil {
		return HijackedResponse{}, err
	}
	return HijackedResponse{
		Reader: sdk.Reader,
		close:  sdk.Close,
	}, nil
}

func (p *productionClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	return p.cli.ContainerExecInspect(ctx, execID)
}

func (p *productionClient) ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error {
	return p.cli.ContainerStop(ctx, containerID, options)
}

func (p *productionClient) ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error {
	return p.cli.ContainerRemove(ctx, containerID, options)
}

// ContainerLogs satisfies ContainerLogReader (reap.go), the narrow
// capability CaptureLogs type-asserts for. It is deliberately NOT part
// of dockerClient — see that interface's docstring for why widening it
// is expensive — so this compile-time assertion is what guarantees the
// production path keeps the capability. Delete the method and the
// package stops building rather than silently losing container logs at
// the one moment they matter.
var _ ContainerLogReader = (*productionClient)(nil)

func (p *productionClient) ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error) {
	return p.cli.ContainerLogs(ctx, containerID, options)
}
