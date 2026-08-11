package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceContainerFactory_RequiresContainerPort(t *testing.T) {
	factory := ServiceContainerFactory(ServiceContainerOpts{})
	cli := newStubDockerClient(t)
	_, err := factory(context.Background(), cli, "img:1", noopLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ContainerPort required")
}

func TestServiceContainerFactory_BuildsBaseURL(t *testing.T) {
	cli := newStubDockerClient(t)
	cli.inspectHostPort = "55555"
	factory := ServiceContainerFactory(ServiceContainerOpts{
		ContainerPort: 8080,
		// ReadinessEndpoint omitted → readiness probe skipped
	})
	c, err := factory(context.Background(), cli, "img:1", noopLog())
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.NotEmpty(t, c.ID)
	assert.Equal(t, "img:1", c.Image)

	parsed, err := url.Parse(c.BaseURL)
	require.NoError(t, err)
	assert.Equal(t, "http", parsed.Scheme)
	assert.Equal(t, "127.0.0.1:55555", parsed.Host, "BaseURL must bind 127.0.0.1 + dynamic port")
}

// TestServiceContainerFactory_CmdInjected pins the daemon-launch Cmd
// override: when Opts.Cmd is set, it reaches container.Config.Cmd (ZAP
// needs `zap.sh -daemon -config api.key=...`); when empty, Config.Cmd
// stays nil so the image's default entrypoint runs (existing tools
// — nmap/trivy/sqlmap use one-shot DockerRunner, but any future
// stdout-mode service must be unaffected).
func TestServiceContainerFactory_CmdInjected(t *testing.T) {
	cli := newStubDockerClient(t)
	factory := ServiceContainerFactory(ServiceContainerOpts{
		ContainerPort: 8080,
		Cmd:           []string{"zap.sh", "-daemon", "-config", "api.key=K1"},
	})
	_, err := factory(context.Background(), cli, "img:1", noopLog())
	require.NoError(t, err)
	require.NotNil(t, cli.capturedConfig)
	assert.Equal(t,
		[]string{"zap.sh", "-daemon", "-config", "api.key=K1"},
		[]string(cli.capturedConfig.Cmd), // container.Config.Cmd is strslice.StrSlice
		"Opts.Cmd must reach container.Config.Cmd")
}

func TestServiceContainerFactory_NoCmd_LeavesConfigCmdNil(t *testing.T) {
	cli := newStubDockerClient(t)
	factory := ServiceContainerFactory(ServiceContainerOpts{ContainerPort: 8080})
	_, err := factory(context.Background(), cli, "img:1", noopLog())
	require.NoError(t, err)
	require.NotNil(t, cli.capturedConfig)
	assert.Nil(t, cli.capturedConfig.Cmd,
		"empty Opts.Cmd must leave Config.Cmd nil (image default entrypoint)")
}

func TestServiceContainerFactory_NoHostPortMapped_Errors(t *testing.T) {
	cli := newStubDockerClient(t)
	cli.inspectHostPort = "" // no mapping returned
	factory := ServiceContainerFactory(ServiceContainerOpts{ContainerPort: 8080})
	_, err := factory(context.Background(), cli, "img:1", noopLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no host port mapped")
}

func TestServiceContainerFactory_InspectErrorPropagates(t *testing.T) {
	cli := newStubDockerClient(t)
	cli.inspectErr = errors.New("inspect boom")
	factory := ServiceContainerFactory(ServiceContainerOpts{ContainerPort: 8080})
	_, err := factory(context.Background(), cli, "img:1", noopLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inspect")
}

func TestServiceContainerFactory_ReturnedContainerHasUsableCli(t *testing.T) {
	// Verifies the V8 architectural concern: container returned by
	// the factory has a non-nil cli (via NewServiceContainer), so
	// later Stop/Exec calls don't panic.
	cli := newStubDockerClient(t)
	factory := ServiceContainerFactory(ServiceContainerOpts{ContainerPort: 8080})
	c, err := factory(context.Background(), cli, "img:1", noopLog())
	require.NoError(t, err)
	// Stop should not panic + return error from stub-backed cli
	stopErr := c.Stop(context.Background())
	require.NoError(t, stopErr, "container Stop must work; verifies cli wired")
}

func TestDynamicHostPort_NilNetworkSettings(t *testing.T) {
	// White-box check via factory error path
	cli := newStubDockerClient(t)
	cli.inspectHostPort = "" // results in empty Ports map
	factory := ServiceContainerFactory(ServiceContainerOpts{ContainerPort: 8080})
	_, err := factory(context.Background(), cli, "img:1", noopLog())
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "no host port mapped") ||
			strings.Contains(err.Error(), "NetworkSettings"),
		"missing network settings or port mapping should surface clearly: %v", err)
}
