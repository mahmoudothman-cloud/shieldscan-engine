package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
)

// noopLog returns a zerolog.Logger that discards output.
func noopLog() zerolog.Logger {
	return zerolog.Nop()
}

// stubDockerClient mirrors the pattern from internal/tools/docker/nmap
// and internal/tools/docker testhelpers — always-succeeds adapter
// satisfying docker.DockerClient structurally. Per Task 7.5b service
// subpackage, additional behavior: ContainerInspect returns a
// configurable port-mapping for ServiceContainerFactory tests.
type stubDockerClient struct {
	counter atomic.Int64
	// inspectHostPort is the host port returned by ContainerInspect
	// for the service container's exposed port. Zero means "no
	// mapping" (factory will surface 'no host port mapped' error).
	inspectHostPort string
	inspectErr      error
}

func newStubDockerClient(_ *testing.T) *stubDockerClient {
	return &stubDockerClient{inspectHostPort: "32768"}
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
	id := fmt.Sprintf("stub-svc-%d", s.counter.Add(1))
	return container.CreateResponse{ID: id}, nil
}

func (s *stubDockerClient) ContainerStart(_ context.Context, _ string, _ container.StartOptions) error {
	return nil
}

func (s *stubDockerClient) ContainerInspect(_ context.Context, id string) (container.InspectResponse, error) {
	if s.inspectErr != nil {
		return container.InspectResponse{}, s.inspectErr
	}
	if s.inspectHostPort == "" {
		ns := &container.NetworkSettings{} //nolint:staticcheck // intentional: test fixture for ContainerInspect; NetworkSettingsBase is the only path to populate Ports in v28.5.x SDK
		ns.Ports = nat.PortMap{}
		return container.InspectResponse{NetworkSettings: ns}, nil
	}
	portKey, _ := nat.NewPort("tcp", "8080")
	ns := &container.NetworkSettings{} //nolint:staticcheck // see above; will migrate when SDK v29 lands
	ns.Ports = nat.PortMap{
		portKey: []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: s.inspectHostPort},
		},
	}
	return container.InspectResponse{NetworkSettings: ns}, nil
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

// newReadyServer returns an httptest.Server that responds 200 OK on
// the configured ready endpoint; used by readiness + integration
// tests that need a real HTTP responder.
func newReadyServer(t *testing.T, readyPath string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if readyPath != "" {
		mux.HandleFunc(readyPath, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	if handler != nil {
		mux.HandleFunc("/", handler)
	}
	return httptest.NewServer(mux)
}
