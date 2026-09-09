package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/pkg/stdcopy"
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
	// capturedConfig records the *container.Config passed to the most
	// recent ContainerCreate, so tests can assert Cmd/Image/etc.
	capturedConfig *container.Config

	// inspectState, when set, is returned as the container's State.
	// ContainerInspect otherwise returns a response with a NIL
	// ContainerJSONBase — which is what a hand-built InspectResponse
	// looks like and the reason both readers check the base before the
	// field.
	inspectState *container.State

	// logs is the container output ContainerLogs serves, framed the way
	// the daemon frames it for a non-TTY container (stdcopy headers).
	logs string

	// calls records Docker operations in order, so a test can assert
	// that logs were read BEFORE the container was removed — the whole
	// point of the post-mortem path.
	mu    sync.Mutex
	calls []string
}

func (s *stubDockerClient) record(op string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, op)
}

func (s *stubDockerClient) callOrder() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// ContainerLogs makes the stub satisfy docker.ContainerLogReader, the
// narrow capability docker.CaptureLogs type-asserts for. Output is
// stdcopy-framed because that is what a non-TTY container's log stream
// actually looks like, and CaptureLogs demultiplexes it.
func (s *stubDockerClient) ContainerLogs(_ context.Context, _ string, _ container.LogsOptions) (io.ReadCloser, error) {
	s.record("logs")
	var buf bytes.Buffer
	w := stdcopy.NewStdWriter(&buf, stdcopy.Stdout)
	_, _ = w.Write([]byte(s.logs))
	return io.NopCloser(&buf), nil
}

func newStubDockerClient(_ *testing.T) *stubDockerClient {
	return &stubDockerClient{inspectHostPort: "32768"}
}

func (s *stubDockerClient) ImagePull(_ context.Context, _ string, _ image.PullOptions) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (s *stubDockerClient) ContainerCreate(
	_ context.Context,
	cfg *container.Config,
	_ *container.HostConfig,
	_ *network.NetworkingConfig,
	_ *ocispec.Platform,
	_ string,
) (container.CreateResponse, error) {
	s.capturedConfig = cfg
	id := fmt.Sprintf("stub-svc-%d", s.counter.Add(1))
	return container.CreateResponse{ID: id}, nil
}

func (s *stubDockerClient) ContainerStart(_ context.Context, _ string, _ container.StartOptions) error {
	return nil
}

func (s *stubDockerClient) ContainerInspect(_ context.Context, id string) (container.InspectResponse, error) {
	s.record("inspect")
	if s.inspectErr != nil {
		return container.InspectResponse{}, s.inspectErr
	}
	var base *container.ContainerJSONBase
	if s.inspectState != nil {
		base = &container.ContainerJSONBase{State: s.inspectState}
	}
	if s.inspectHostPort == "" {
		ns := &container.NetworkSettings{} //nolint:staticcheck // intentional: test fixture for ContainerInspect; NetworkSettingsBase is the only path to populate Ports in v28.5.x SDK
		ns.Ports = nat.PortMap{}
		return container.InspectResponse{ContainerJSONBase: base, NetworkSettings: ns}, nil
	}
	portKey, _ := nat.NewPort("tcp", "8080")
	ns := &container.NetworkSettings{} //nolint:staticcheck // see above; will migrate when SDK v29 lands
	ns.Ports = nat.PortMap{
		portKey: []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: s.inspectHostPort},
		},
	}
	return container.InspectResponse{ContainerJSONBase: base, NetworkSettings: ns}, nil
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
	s.record("stop")
	return nil
}

func (s *stubDockerClient) ContainerRemove(_ context.Context, _ string, _ container.RemoveOptions) error {
	s.record("remove")
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
