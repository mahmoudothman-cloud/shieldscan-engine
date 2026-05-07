package nmap

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// stubDockerClient is an always-succeeds adapter that satisfies the
// (unexported) docker.dockerClient interface structurally — Go interface
// satisfaction is structural, so package-local interfaces can still be
// implemented from outside their declaring package as long as method
// sets match.
//
// Replicated from internal/tools/docker/testhelpers_test.go (option (a)
// per Phase 3 surface guidance) since the canonical stub is unexported.
// Future: move to a shared internal/tools/docker/dockertest/ subpackage
// when Trivy + SQLMap + ZAP + MobSF consumer tests need the same stub
// shape (3rd-instance promotion candidate).
type stubDockerClient struct {
	counter atomic.Int64
}

func newStubDockerClient(_ *testing.T) *stubDockerClient {
	return &stubDockerClient{}
}

func (s *stubDockerClient) ImagePull(_ context.Context, _ string, _ image.PullOptions) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (s *stubDockerClient) ContainerCreate(
	_ context.Context,
	_ *container.Config,
	_ *container.HostConfig,
	_ *network.NetworkingConfig,
	_ *ocispec.Platform,
	_ string,
) (container.CreateResponse, error) {
	id := fmt.Sprintf("stub-container-%d", s.counter.Add(1))
	return container.CreateResponse{ID: id}, nil
}

func (s *stubDockerClient) ContainerStart(_ context.Context, _ string, _ container.StartOptions) error {
	return nil
}

func (s *stubDockerClient) ContainerExecCreate(_ context.Context, _ string, _ container.ExecOptions) (container.ExecCreateResponse, error) {
	return container.ExecCreateResponse{}, nil
}

func (s *stubDockerClient) ContainerExecAttach(_ context.Context, _ string, _ container.ExecAttachOptions) (docker.HijackedResponse, error) {
	return docker.HijackedResponse{Reader: strings.NewReader("")}, nil
}

func (s *stubDockerClient) ContainerExecInspect(_ context.Context, _ string) (container.ExecInspect, error) {
	return container.ExecInspect{}, nil
}

func (s *stubDockerClient) ContainerStop(_ context.Context, _ string, _ container.StopOptions) error {
	return nil
}

func (s *stubDockerClient) ContainerRemove(_ context.Context, _ string, _ container.RemoveOptions) error {
	return nil
}
