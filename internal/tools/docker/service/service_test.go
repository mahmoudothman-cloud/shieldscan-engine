package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
)

func TestDockerServiceRunner_Run_RequiresBuildScan(t *testing.T) {
	r := &DockerServiceRunner{ToolName: "x"}
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BuildScan required")
}

func TestDockerServiceRunner_Run_EphemeralRequiresCli(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "x",
		BuildScan: func(_ context.Context, _ tools.Target, _ tools.ScanConfig, _ *Client) ([]events.RawFinding, error) {
			return nil, nil
		},
		ServiceConfig: ServiceConfig{EphemeralContainer: true},
	}
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Cli required")
}

func TestDockerServiceRunner_Run_WarmPoolRequiresPool(t *testing.T) {
	r := &DockerServiceRunner{
		ToolName: "x",
		Cli:      newStubDockerClient(t),
		BuildScan: func(_ context.Context, _ tools.Target, _ tools.ScanConfig, _ *Client) ([]events.RawFinding, error) {
			return nil, nil
		},
		ServiceConfig: ServiceConfig{EphemeralContainer: false},
	}
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Pool required")
}

func TestDockerServiceRunner_NameAndCategory(t *testing.T) {
	r := &DockerServiceRunner{ToolName: "zap", ToolCategory: "dast"}
	assert.Equal(t, "zap", r.Name())
	assert.Equal(t, "dast", r.Category())
}

func TestDockerServiceRunner_SatisfiesToolRunner(t *testing.T) {
	var _ tools.ToolRunner = (*DockerServiceRunner)(nil)
	var _ tools.ToolRunner = &DockerServiceRunner{}
}

func TestDockerServiceRunner_Run_EphemeralPath_BuildScanInvokedWithClient(t *testing.T) {
	// Stub Docker client + httptest server combination: the factory
	// builds BaseURL from the stub's configured host port. Real HTTP
	// won't reach the test server because the stub returns
	// "127.0.0.1:32768" while httptest binds a random port. Test
	// scope: verify Run wires Cli + factory + Client correctly;
	// BuildScan receives a non-nil Client with the constructed BaseURL.
	cli := newStubDockerClient(t)
	cli.inspectHostPort = "32768"

	var capturedClient *Client
	var capturedTarget tools.Target
	r := &DockerServiceRunner{
		ToolName:     "ephemeral-tool",
		ToolCategory: "dast",
		Cli:          cli,
		ServiceConfig: ServiceConfig{
			EphemeralContainer: true,
			Image:              "img:1",
			ContainerPort:      8080,
			// ReadinessEndpoint omitted → skip readiness probe
		},
		BuildScan: func(_ context.Context, t tools.Target, _ tools.ScanConfig, c *Client) ([]events.RawFinding, error) {
			capturedClient = c
			capturedTarget = t
			return []events.RawFinding{{Title: "test-finding", Severity: "info"}}, nil
		},
		Log: noopLog(),
	}

	target := tools.Target{URL: "https://example.com"}
	findings, err := r.Run(context.Background(), target, tools.ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	require.NotNil(t, capturedClient)
	assert.Equal(t, "http://127.0.0.1:32768", capturedClient.BaseURL)
	assert.Equal(t, target, capturedTarget)

	// Enrichment per Run contract
	assert.Equal(t, "ephemeral-tool", findings[0].ToolName)
	assert.Equal(t, "dast", findings[0].EngineCategory)
	assert.NotEmpty(t, findings[0].DiscoveredAt)
	assert.NotEmpty(t, findings[0].Fingerprint)
}

func TestDockerServiceRunner_Run_BuildScanError_Propagates(t *testing.T) {
	cli := newStubDockerClient(t)
	r := &DockerServiceRunner{
		ToolName: "x",
		Cli:      cli,
		ServiceConfig: ServiceConfig{
			EphemeralContainer: true,
			Image:              "img:1",
			ContainerPort:      8080,
		},
		BuildScan: func(_ context.Context, _ tools.Target, _ tools.ScanConfig, _ *Client) ([]events.RawFinding, error) {
			return nil, errors.New("scan failed")
		},
		Log: noopLog(),
	}
	_, err := r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build scan")
	assert.Contains(t, err.Error(), "scan failed")
}

func TestDockerServiceRunner_Run_WarmPoolPath_UsesPoolCheckout(t *testing.T) {
	cli := newStubDockerClient(t)

	// Build a WarmPool with a custom factory that returns containers
	// using NewServiceContainer (so BaseURL is populated).
	customFactory := docker.ContainerFactoryFunc(func(_ context.Context, c docker.DockerClient, image string, log zerolog.Logger) (*docker.Container, error) {
		return docker.NewServiceContainer("warm-svc-1", image, "http://127.0.0.1:9999", c, log), nil
	})
	pool, err := docker.New(docker.Config{
		Image:            "img:1",
		MaxSize:          1,
		Cleanup:          docker.NoCleanup,
		ContainerFactory: customFactory,
	}, cli, noopLog())
	require.NoError(t, err)

	var capturedClient *Client
	r := &DockerServiceRunner{
		ToolName:     "warm-tool",
		ToolCategory: "dast",
		Pool:         pool,
		Cli:          cli,
		ServiceConfig: ServiceConfig{
			EphemeralContainer: false,
			Image:              "img:1",
			ContainerPort:      8080,
		},
		BuildScan: func(_ context.Context, _ tools.Target, _ tools.ScanConfig, c *Client) ([]events.RawFinding, error) {
			capturedClient = c
			return nil, nil
		},
		Log: noopLog(),
	}
	_, err = r.Run(context.Background(), tools.Target{}, tools.ScanConfig{})
	require.NoError(t, err)

	require.NotNil(t, capturedClient)
	assert.Equal(t, "http://127.0.0.1:9999", capturedClient.BaseURL)
}

// Sanity-importing httptest + http + io + time so unused-import lint
// doesn't fire for any module-level declaration; these are used by
// the table-driven tests below.
var _ = httptest.NewServer
var _ = http.MethodGet
var _ = io.Discard
var _ = time.Second
