package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServiceAddressing_DirectMode pins that an empty APIProxyHost keeps
// the pre-existing direct addressing: base = mapped address, no proxy
// transport (nil → net/http DefaultTransport). Guards MobSF and every
// normal HTTP service from the ZAP-specific proxy behavior.
func TestServiceAddressing_DirectMode(t *testing.T) {
	base, transport, err := serviceAddressing("http://127.0.0.1:49999", "")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:49999", base)
	assert.Nil(t, transport, "direct mode must not attach a proxy transport")
}

// TestServiceAddressing_ProxyMode pins the ZAP fix: requests target the
// magic host (http://zap) and the transport routes every one of them
// THROUGH the container's mapped port as an HTTP forward-proxy.
func TestServiceAddressing_ProxyMode(t *testing.T) {
	base, transport, err := serviceAddressing("http://127.0.0.1:49999", "zap")
	require.NoError(t, err)
	assert.Equal(t, "http://zap", base, "proxy mode addresses the magic host, not the mapped port")
	require.NotNil(t, transport)
	require.NotNil(t, transport.Proxy, "transport must carry a Proxy resolver")

	req, err := http.NewRequest(http.MethodGet, "http://zap/JSON/core/view/version/", nil)
	require.NoError(t, err)
	proxyURL, err := transport.Proxy(req)
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	assert.Equal(t, "http://127.0.0.1:49999", proxyURL.String(),
		"proxy must be the container's mapped address")
}

// TestClient_ProxyAddressing_RoutesThroughMappedPort is the end-to-end
// proof that a Client built with proxy addressing sends absolute-form
// requests to the magic host through the mapped port — exactly the
// curl -x behavior that returns 200 from ZAP (vs 502 for a direct GET).
func TestClient_ProxyAddressing_RoutesThroughMappedPort(t *testing.T) {
	var gotHost, gotPath string
	var gotAbsolute bool
	// Stand-in for the mapped ZAP port: a plain server that receives the
	// proxied (absolute-URI) request.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		gotAbsolute = r.URL.IsAbs()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"2.17.0"}`))
	}))
	defer proxy.Close()

	base, transport, err := serviceAddressing(proxy.URL, "zap")
	require.NoError(t, err)
	c := &Client{
		BaseURL:    base,
		HTTPClient: &http.Client{Timeout: 0, Transport: transport},
		Log:        zerolog.Nop(),
	}

	body, err := c.Get(context.Background(), "/JSON/core/view/version/?apikey=K")
	require.NoError(t, err)
	assert.Contains(t, string(body), "2.17.0")
	assert.Equal(t, "zap", gotHost, "request must be addressed to the magic host zap")
	assert.Equal(t, "/JSON/core/view/version/", gotPath)
	assert.True(t, gotAbsolute, "proxied request must use an absolute-form request URI")
}

// TestWaitForReady_ProxyMode_RoutesThroughMappedPort pins that the
// readiness probe (the path that 502-timed-out live) also honors proxy
// addressing: it must reach the magic host through the mapped port.
func TestWaitForReady_ProxyMode_RoutesThroughMappedPort(t *testing.T) {
	var gotHost string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	err := waitForReady(context.Background(), proxy.URL, "/JSON/core/view/version/",
		200, 2*time.Second, 10*time.Millisecond, "zap")
	require.NoError(t, err)
	assert.Equal(t, "zap", gotHost, "readiness probe must proxy to the magic host zap")
}
