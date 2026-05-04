package docker

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
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// stubDockerClient is a always-succeeds dockerClient suitable for
// WarmPool unit tests. Auto-generates unique container IDs per
// ContainerCreate call so spin-up tests can distinguish containers.
//
// Distinct from container_test.go's fakeClient (which is a per-test
// scenario fixture with caller-supplied responses + counters); this
// stub is for tests that don't care about Docker SDK details and
// just want the pool/runner machinery to work.
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

func (s *stubDockerClient) ContainerExecAttach(_ context.Context, _ string, _ container.ExecAttachOptions) (HijackedResponse, error) {
	// Empty reader so stdcopy.StdCopy returns immediately without
	// panicking on nil. Phase 3 DockerRunner tests exercise the full
	// Run path; tests that need specific stdout payload should use
	// fakeClient (container_test.go) instead.
	return HijackedResponse{Reader: strings.NewReader("")}, nil
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
