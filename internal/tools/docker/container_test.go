package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopLog returns a discard zerolog.Logger; tests don't assert on
// log output. Mirrors the project pattern at e.g.
// internal/tools/nuclei/nuclei_test.go.
func noopLog() zerolog.Logger {
	return zerolog.New(io.Discard).Level(zerolog.Disabled)
}

// stdcopyFrame builds a single stdcopy-multiplexed frame for the
// given stream type (1=stdout, 2=stderr) and payload. The Docker
// SDK's stdcopy.StdCopy demultiplexes streams encoded this way.
//
// Frame layout: 1 byte stream type, 3 bytes zero pad, 4 bytes
// big-endian length, then the payload bytes.
func stdcopyFrame(streamType byte, payload []byte) []byte {
	header := make([]byte, 8)
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	return append(header, payload...)
}

// fakeClient implements dockerClient with caller-supplied responses.
// Tests construct one per scenario and pass it to a Container.
type fakeClient struct {
	pullResp        io.ReadCloser
	pullErr         error
	createResp      container.CreateResponse
	createErr       error
	startErr        error
	execCreateResp  container.ExecCreateResponse
	execCreateErr   error
	execAttachResp  HijackedResponse
	execAttachErr   error
	execInspectResp container.ExecInspect
	execInspectErr  error
	stopErr         error
	removeErr       error

	// Counters / capture
	pullCalls      atomic.Int32
	createCalls    atomic.Int32
	startCalls     atomic.Int32
	stopCalls      atomic.Int32
	removeCalls    atomic.Int32
	lastRemoveOpts container.RemoveOptions
}

func (f *fakeClient) ImagePull(ctx context.Context, refStr string, options image.PullOptions) (io.ReadCloser, error) {
	f.pullCalls.Add(1)
	if f.pullErr != nil {
		return nil, f.pullErr
	}
	if f.pullResp == nil {
		return io.NopCloser(strings.NewReader("")), nil
	}
	return f.pullResp, nil
}

func (f *fakeClient) ContainerCreate(
	ctx context.Context,
	cfg *container.Config,
	hostCfg *container.HostConfig,
	netCfg *network.NetworkingConfig,
	platform *ocispec.Platform,
	name string,
) (container.CreateResponse, error) {
	f.createCalls.Add(1)
	return f.createResp, f.createErr
}

func (f *fakeClient) ContainerStart(ctx context.Context, id string, options container.StartOptions) error {
	f.startCalls.Add(1)
	return f.startErr
}

func (f *fakeClient) ContainerInspect(ctx context.Context, id string) (container.InspectResponse, error) {
	return container.InspectResponse{}, nil
}

func (f *fakeClient) ContainerExecCreate(ctx context.Context, id string, options container.ExecOptions) (container.ExecCreateResponse, error) {
	return f.execCreateResp, f.execCreateErr
}

func (f *fakeClient) ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (HijackedResponse, error) {
	if f.execAttachErr != nil {
		return HijackedResponse{}, f.execAttachErr
	}
	// If ctx already canceled, propagate (mirrors SDK behavior).
	if err := ctx.Err(); err != nil {
		return HijackedResponse{}, err
	}
	return f.execAttachResp, nil
}

func (f *fakeClient) ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error) {
	return f.execInspectResp, f.execInspectErr
}

func (f *fakeClient) ContainerStop(ctx context.Context, id string, options container.StopOptions) error {
	f.stopCalls.Add(1)
	return f.stopErr
}

func (f *fakeClient) ContainerRemove(ctx context.Context, id string, options container.RemoveOptions) error {
	f.removeCalls.Add(1)
	f.lastRemoveOpts = options
	return f.removeErr
}

// ─── TestContainer_NewContainer_PullsImageIfMissing ────────────────────

// Pins newContainer's pull → create → start sequence. Fake client
// records each call; assert all three fired in order with the
// expected image.
func TestContainer_NewContainer_PullsImageIfMissing(t *testing.T) {
	fc := &fakeClient{
		pullResp:   io.NopCloser(strings.NewReader(`{"status":"Pulling"}`)),
		createResp: container.CreateResponse{ID: "abc123def456789"},
	}

	c, err := newContainer(context.Background(), fc, "trivy:latest", noopLog())
	require.NoError(t, err)
	require.NotNil(t, c)

	assert.Equal(t, int32(1), fc.pullCalls.Load(), "ImagePull called once")
	assert.Equal(t, int32(1), fc.createCalls.Load(), "ContainerCreate called once")
	assert.Equal(t, int32(1), fc.startCalls.Load(), "ContainerStart called once")
	assert.Equal(t, "abc123def456789", c.ID)
	assert.Equal(t, "trivy:latest", c.Image)
}

// TestContainer_NewContainer_StartFailureCleansUp pins the
// post-start-failure cleanup behavior: if ContainerStart errors,
// the just-created container is force-removed so we don't leak
// stopped containers across retries.
func TestContainer_NewContainer_StartFailureCleansUp(t *testing.T) {
	fc := &fakeClient{
		pullResp:   io.NopCloser(strings.NewReader("")),
		createResp: container.CreateResponse{ID: "leaky-container-xyz"},
		startErr:   errors.New("daemon refused start"),
	}

	c, err := newContainer(context.Background(), fc, "trivy:latest", noopLog())
	require.Error(t, err)
	assert.Nil(t, c)

	assert.Equal(t, int32(1), fc.removeCalls.Load(),
		"failed-start container must be force-removed to avoid leaks")
	assert.True(t, fc.lastRemoveOpts.Force,
		"cleanup remove must use Force:true")
}

// ─── TestContainer_Exec_CapturesStdout ─────────────────────────────────

// Pins that Exec returns the stdout payload demultiplexed from
// the stdcopy stream (the 8-byte-header framing the Docker daemon
// uses to interleave stdout + stderr).
func TestContainer_Exec_CapturesStdout(t *testing.T) {
	stdoutPayload := []byte("hello\n")
	frame := stdcopyFrame(1, stdoutPayload) // stream type 1 = stdout
	fc := &fakeClient{
		execCreateResp:  container.ExecCreateResponse{ID: "exec-id-1"},
		execAttachResp:  HijackedResponse{Reader: bytes.NewReader(frame)},
		execInspectResp: container.ExecInspect{ExitCode: 0},
	}
	c := &Container{ID: "container-1", Image: "img", cli: fc, log: noopLog()}

	stdout, exitCode, err := c.Exec(context.Background(), []string{"echo", "hello"})
	require.NoError(t, err)
	assert.Equal(t, stdoutPayload, stdout)
	assert.Equal(t, 0, exitCode)
}

// ─── TestContainer_Exec_CapturesExitCode ───────────────────────────────

// Pins that Exec propagates the inspect-phase ExitCode. Many tools
// signal findings vs no-findings via exit code (Trivy: 0 clean, 1
// findings, 2 error); per-tool runners interpret accordingly.
func TestContainer_Exec_CapturesExitCode(t *testing.T) {
	frame := stdcopyFrame(1, []byte("findings present\n"))
	fc := &fakeClient{
		execCreateResp:  container.ExecCreateResponse{ID: "exec-id-2"},
		execAttachResp:  HijackedResponse{Reader: bytes.NewReader(frame)},
		execInspectResp: container.ExecInspect{ExitCode: 2},
	}
	c := &Container{ID: "container-2", Image: "img", cli: fc, log: noopLog()}

	_, exitCode, err := c.Exec(context.Background(), []string{"trivy", "fs"})
	require.NoError(t, err)
	assert.Equal(t, 2, exitCode, "non-zero exit code must propagate")
}

// ─── TestContainer_Exec_RespectsContextCancellation ────────────────────

// Pins ADR-021 ctx-discipline: cancel ctx before Exec; ContainerExec
// Attach surfaces the ctx error. Production-side, the SDK propagates
// cancellation to the daemon-side exec process; here we verify the
// error path returns it cleanly.
func TestContainer_Exec_RespectsContextCancellation(t *testing.T) {
	fc := &fakeClient{
		execCreateResp: container.ExecCreateResponse{ID: "exec-id-3"},
		// execAttach handler checks ctx.Err() before returning a fake
		// response; canceling ctx surfaces context.Canceled.
	}
	c := &Container{ID: "container-3", Image: "img", cli: fc, log: noopLog()}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE calling Exec

	_, _, err := c.Exec(ctx, []string{"sleep", "100"})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled,
		"ctx.Err must surface from canceled exec attach")
}

// ─── TestContainer_Stop_RemovesContainer ───────────────────────────────

// Pins Stop's two-step shutdown: ContainerStop (graceful) then
// ContainerRemove (force-true cleanup). Even if Stop fails, Remove
// runs unconditionally so a leaked container doesn't survive.
func TestContainer_Stop_RemovesContainer(t *testing.T) {
	fc := &fakeClient{}
	c := &Container{ID: "stoppable", Image: "img", cli: fc, log: noopLog()}

	err := c.Stop(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(1), fc.stopCalls.Load(), "ContainerStop called once")
	assert.Equal(t, int32(1), fc.removeCalls.Load(), "ContainerRemove called once")
	assert.True(t, fc.lastRemoveOpts.Force,
		"Stop's remove MUST use Force:true so the container is killed even mid-stop")
}

// TestContainer_Stop_RemoveStillCalledWhenStopFails pins the
// best-effort posture: ContainerStop failure does NOT block
// ContainerRemove. A leaked stopped-container is worse than a
// loud-stop-error; the remove is unconditional.
func TestContainer_Stop_RemoveStillCalledWhenStopFails(t *testing.T) {
	fc := &fakeClient{
		stopErr: errors.New("daemon timeout on stop"),
	}
	c := &Container{ID: "ungraceful", Image: "img", cli: fc, log: noopLog()}

	err := c.Stop(context.Background())
	require.NoError(t, err, "remove succeeded despite stop failure")
	assert.Equal(t, int32(1), fc.removeCalls.Load(),
		"Remove must run even when Stop errors")
}
