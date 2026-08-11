package zap

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBuildScan_RequiresAPIKey(t *testing.T) {
	bs := NewBuildScan(Config{})
	_, err := bs(context.Background(),
		tools.Target{URL: "https://example.com/"},
		tools.ScanConfig{},
		nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "APIKey required")
}

func newRunnerClient(t *testing.T, stub *stubZAPServer) *service.Client {
	t.Helper()
	return &service.Client{
		BaseURL:    stub.URL(),
		HTTPClient: &http.Client{Timeout: 0},
		AuthFunc:   zapQueryParamAuth(stubAPIKey),
		Log:        noopLog(),
	}
}

func TestNewBuildScan_ModeQuick_EndToEnd(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	findings, err := bs(context.Background(),
		tools.Target{URL: "https://example.com/"},
		tools.ScanConfig{Depth: "quick"},
		newRunnerClient(t, stub))
	require.NoError(t, err)
	require.Len(t, findings, 2, "False Positive dropped; CSP + XSS retained")
	assert.Equal(t, int32(1), stub.spiderScanCalls.Load())
	assert.Equal(t, int32(0), stub.ascanScanCalls.Load(), "Mode B (quick) — ascan must NOT run")
	assert.Equal(t, int32(1), stub.alertsCalls.Load())
}

func TestNewBuildScan_ModeFull_RunsActiveScan(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	findings, err := bs(context.Background(),
		tools.Target{URL: "https://example.com/"},
		tools.ScanConfig{Depth: "standard"},
		newRunnerClient(t, stub))
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, int32(1), stub.spiderScanCalls.Load())
	assert.Equal(t, int32(1), stub.ascanScanCalls.Load(), "Mode C — ascan MUST run")
}

func TestNewBuildScan_ModeFull_PolicyFromExtraArgs(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := bs(context.Background(),
		tools.Target{URL: "https://example.com/"},
		tools.ScanConfig{
			Depth:     "deep",
			ExtraArgs: map[string]string{"zap.scan_policy": "API"},
		},
		newRunnerClient(t, stub))
	require.NoError(t, err)
	assert.Equal(t, "API", stub.lastPolicyArg)
}

func TestNewBuildScan_ModeFull_RejectsInvalidPolicy(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := bs(context.Background(),
		tools.Target{URL: "https://example.com/"},
		tools.ScanConfig{
			Depth:     "deep",
			ExtraArgs: map[string]string{"zap.scan_policy": "Penetration Tester Policy"},
		},
		newRunnerClient(t, stub))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
}

func TestNewBuildScan_TargetValidation_RejectsRFC1918(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := bs(context.Background(),
		tools.Target{URL: "http://10.0.0.1/"},
		tools.ScanConfig{Depth: "quick", AllowPrivateTargets: false},
		newRunnerClient(t, stub))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC1918")
	assert.Equal(t, int32(0), stub.spiderScanCalls.Load(), "validation rejection precedes spider")
}

func TestNewBuildScan_CookieAuthPath_Triggers_HTTPSessionsCalls(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := bs(context.Background(),
		tools.Target{
			URL: "https://example.com/",
			AuthConfig: &tools.AuthConfig{
				Type: "cookie",
				Data: "session=abc123",
			},
		},
		tools.ScanConfig{Depth: "quick"},
		newRunnerClient(t, stub))
	require.NoError(t, err)
	assert.Equal(t, int32(1), stub.createSessionCalls.Load())
	assert.Equal(t, int32(1), stub.setTokenCalls.Load())
}

func TestNewBuildScan_NonCookieAuthSkipsHTTPSessions(t *testing.T) {
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := bs(context.Background(),
		tools.Target{
			URL: "https://example.com/",
			AuthConfig: &tools.AuthConfig{
				Type: "form", // v1 not yet implemented; should not invoke httpSessions
				Data: "",
			},
		},
		tools.ScanConfig{Depth: "quick"},
		newRunnerClient(t, stub))
	require.NoError(t, err)
	assert.Equal(t, int32(0), stub.createSessionCalls.Load())
}

func TestNewBuildScan_ExtraArgsAuthLogged(t *testing.T) {
	// Just verifies no error; log assertion would require capture infra.
	stub := newStubZAPServer(t)
	bs := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := bs(context.Background(),
		tools.Target{URL: "https://example.com/"},
		tools.ScanConfig{
			Depth: "quick",
			ExtraArgs: map[string]string{
				"zap.auth.login_url":          "https://example.com/login",
				"zap.auth.login_request_data": "u={%username%}&p={%password%}",
			},
		},
		newRunnerClient(t, stub))
	require.NoError(t, err)
}

func TestScanModeFor(t *testing.T) {
	assert.Equal(t, ScanModeQuick, scanModeFor("quick"))
	assert.Equal(t, ScanModeFull, scanModeFor("standard"))
	assert.Equal(t, ScanModeFull, scanModeFor("deep"))
	assert.Equal(t, ScanModeQuick, scanModeFor(""))
	assert.Equal(t, ScanModeQuick, scanModeFor("unknown"))
}

func TestNewRunner_Smoke(t *testing.T) {
	// Smoke test — verify NewRunner returns non-nil with expected fields;
	// full lifecycle integration requires a real Docker client.
	r := NewRunner(nil, Config{APIKey: stubAPIKey}, noopLog())
	require.NotNil(t, r)
	assert.Equal(t, "zap", r.ToolName)
	assert.Equal(t, "dast", r.ToolCategory)
	assert.True(t, r.ServiceConfig.EphemeralContainer, "V4 ephemeral default")
	assert.Equal(t, Image, r.ServiceConfig.Image)
	assert.Equal(t, ContainerPort, r.ServiceConfig.ContainerPort)
	// ZAP addressing fix: every API call (readiness + scan) must proxy to
	// the "zap" magic host, and cold boot needs a raised readiness margin.
	assert.Equal(t, "zap", r.ServiceConfig.APIProxyHost,
		"ZAP must use proxy addressing (its API shares the proxy port; direct GET → 502)")
	assert.Equal(t, 240*time.Second, r.ServiceConfig.ReadinessTimeout,
		"raised readiness margin for ZAP cold boot")
}

// TestNewRunner_ApiKeyReachesBothSides pins the load-bearing invariant: the
// SAME APIKey must reach BOTH (a) the HTTP client side (ReadinessEndpoint +
// AuthFunc) AND (b) the container-launch Cmd (`-config api.key=...`). If they
// diverge the daemon rejects the client's key and every ZAP scan fails. Both
// derive from cfg.APIKey inside NewRunner, so they match by construction — this
// test guards that the Cmd side was actually wired.
func TestNewRunner_ApiKeyReachesBothSides(t *testing.T) {
	const key = "K123-unique-test-key"
	r := NewRunner(nil, Config{APIKey: key}, noopLog())

	// (a) client side — readiness endpoint carries the key.
	assert.Contains(t, r.ServiceConfig.ReadinessEndpoint, "apikey="+key,
		"client readiness must use the API key")

	// (b) container side — the daemon Cmd sets the matching -config api.key.
	joined := strings.Join(r.ServiceConfig.Cmd, " ")
	assert.Contains(t, joined, "api.key="+key,
		"container Cmd must launch the ZAP daemon with the matching -config api.key")
	assert.Contains(t, joined, "-daemon", "ZAP must run in daemon mode")
}
