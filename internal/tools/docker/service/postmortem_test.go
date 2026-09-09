package service

import (
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the ZAP readiness failure that was reported three
// times over two months and diagnosed none of them. The mechanism, from
// the Docker journal: the container started at 16:14:18, its task was
// deleted at 16:14:52 — it died 34 seconds in — and the readiness probe
// went on polling the dead mapped port until 16:18:18 before reporting a
// four-minute timeout with "proxyconnect: connection refused". The
// failure path then stopped and removed the container, so the logs, the
// exit code and the OOMKilled flag were gone by the time anyone looked.
//
// Two independent defects, both covered below: a readiness probe that
// could not tell "not listening yet" from "exited", and an error handler
// that destroyed the only evidence of the error it was reporting.

// TestWaitForReady_AbortsWhenTheContainerDies pins the first.
//
// Without the alive check this call sits out the whole timeout window.
// The assertion is on BOTH the error text and the elapsed time: reporting
// the death but still taking four minutes to do it would fix the wrong
// half.
func TestWaitForReady_AbortsWhenTheContainerDies(t *testing.T) {

	cli := newStubDockerClient(t)
	cli.inspectState = &container.State{
		Status:    "exited",
		Running:   false,
		ExitCode:  137,
		OOMKilled: true,
	}

	start := time.Now()
	// Port 1 on localhost refuses instantly — the same symptom the live
	// failure showed for three and a half minutes.
	err := waitForReady(t.Context(), "http://127.0.0.1:1", "/ready", 200,
		30*time.Second, 10*time.Millisecond, "",
		containerAliveCheck(cli, "stub-svc-1"))
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer running",
		"the error must name the death, not the connection refusal it causes")
	assert.Contains(t, err.Error(), "exit_code=137")
	assert.Contains(t, err.Error(), "oom_killed=true",
		"OOMKilled is the single most useful bit for a container that died "+
			"during boot; it must survive into the error")
	assert.Less(t, elapsed, 5*time.Second,
		"must abort on the first failed poll, not sit out the timeout")
}

// TestWaitForReady_KeepsWaitingWhileTheContainerLives is the
// counterweight: a slow-booting service must not be killed off by the
// new check. ZAP legitimately takes ~15s to listen.
func TestWaitForReady_KeepsWaitingWhileTheContainerLives(t *testing.T) {
	cli := newStubDockerClient(t)
	cli.inspectState = &container.State{Status: "running", Running: true}

	err := waitForReady(t.Context(), "http://127.0.0.1:1", "/ready", 200,
		120*time.Millisecond, 20*time.Millisecond, "",
		containerAliveCheck(cli, "stub-svc-1"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out",
		"a live container that is not ready yet must run to the timeout")
}

// TestWaitForReady_InconclusiveStateKeepsWaiting covers the fail-safe.
// A hand-built InspectResponse has a nil ContainerJSONBase, and reading
// .State through the embedded POINTER panics rather than yielding nil —
// so "cannot determine" must be a supported answer, and it must mean
// keep waiting. Giving up because the state could not be read would be a
// worse failure than the one being fixed.
func TestWaitForReady_InconclusiveStateKeepsWaiting(t *testing.T) {
	cli := newStubDockerClient(t) // inspectState nil → nil base

	require.NotPanics(t, func() {
		err := waitForReady(t.Context(), "http://127.0.0.1:1", "/ready", 200,
			120*time.Millisecond, 20*time.Millisecond, "",
			containerAliveCheck(cli, "stub-svc-1"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})
}

// TestServiceContainerFactory_CapturesEvidenceBeforeRemoval pins the
// second defect, and the ordering IS the assertion. Reading the logs
// after ContainerRemove returns nothing; that is precisely what the old
// code did, and why three occurrences of this failure left nothing to
// read.
func TestServiceContainerFactory_CapturesEvidenceBeforeRemoval(t *testing.T) {
	cli := newStubDockerClient(t)
	cli.inspectState = &container.State{
		Status: "exited", Running: false, ExitCode: 1,
	}
	cli.logs = "Failed to install add-on ascanrules: java.net.UnknownHostException"

	factory := ServiceContainerFactory(ServiceContainerOpts{
		ContainerPort:         8080,
		ReadinessEndpoint:     "/ready",
		ReadinessTimeout:      10 * time.Second,
		ReadinessPollInterval: 10 * time.Millisecond,
	})
	start := time.Now()
	_, err := factory(t.Context(), cli, "ghcr.io/example/zap@sha256:deadbeef", noopLog())
	elapsed := time.Since(start)
	require.Error(t, err)

	// The alive check must be WIRED here, not merely implemented: a dead
	// container has to end the wait now rather than at the timeout. This
	// is the assertion that fails if the factory stops passing
	// containerAliveCheck to waitForReady.
	assert.Less(t, elapsed, 3*time.Second,
		"a container that is already dead must fail readiness immediately, "+
			"not after the full timeout window")

	order := cli.callOrder()
	logsAt := indexOf(order, "logs")
	removeAt := indexOf(order, "remove")
	require.NotEqual(t, -1, logsAt, "container logs must be read on the failure path")
	require.NotEqual(t, -1, removeAt, "the container must still be cleaned up")
	assert.Less(t, logsAt, removeAt,
		"logs must be captured BEFORE removal; afterwards there is nothing to read")

	assert.Contains(t, err.Error(), "exit_code=1",
		"the returned error must carry the container's exit state, not only "+
			"the HTTP symptom")
}

// TestServiceContainerFactory_StampsLabels pins the reaping gap.
//
// ReapOrphans keys on io.shieldscan.managed and nothing else — never on
// image ancestry, deliberately, so that a container an operator started
// by hand is never touched. The consequence is that an UNLABELLED
// container can never be reaped. The warm-pool path threads labels
// through; this factory did not, so a ZAP or MobSF container surviving a
// SIGKILL was invisible to every future worker.
func TestServiceContainerFactory_StampsLabels(t *testing.T) {
	cli := newStubDockerClient(t)
	labels := map[string]string{
		"io.shieldscan.managed":   "true",
		"io.shieldscan.worker-id": "shie-19d7fe03",
		"io.shieldscan.pool":      "zap",
	}
	// No ReadinessEndpoint: this is about what reaches ContainerCreate.
	factory := ServiceContainerFactory(ServiceContainerOpts{
		ContainerPort: 8080,
		Labels:        labels,
	})
	_, err := factory(t.Context(), cli, "ghcr.io/example/zap@sha256:deadbeef", noopLog())
	require.NoError(t, err)

	require.NotNil(t, cli.capturedConfig)
	assert.Equal(t, labels, cli.capturedConfig.Labels,
		"labels must reach container.Config, or the container is unreapable")
}

func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if strings.EqualFold(s, needle) {
			return i
		}
	}
	return -1
}
